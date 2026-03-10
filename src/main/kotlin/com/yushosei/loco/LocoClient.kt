package com.yushosei.loco

import com.yushosei.model.KakaoCredentials
import com.yushosei.model.LocoChatListing
import com.yushosei.model.LocoChatMember
import com.yushosei.model.LocoChatMessage
import com.yushosei.model.LocoCheckinResult
import com.yushosei.model.LocoObservedPacket
import com.yushosei.model.LocoServer
import com.yushosei.logging.ProtocolLogDirection
import com.yushosei.logging.ProtocolLogStore
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.bson.BsonArray
import org.bson.BsonBoolean
import org.bson.BsonDocument
import org.bson.BsonInt32
import org.bson.BsonInt64
import org.bson.BsonNull
import org.bson.BsonString
import java.io.Closeable
import java.io.DataInputStream
import java.io.DataOutputStream
import java.net.Socket
import java.net.SocketTimeoutException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Paths
import javax.net.ssl.SSLSocketFactory
import kotlin.io.path.exists
import kotlin.io.path.readText

class LocoClient(
    val credentials: KakaoCredentials,
) : Closeable {
    private var packetBuilder = PacketBuilder()
    private var nextMessageId = 0
    private var transport: LocoTransport? = null
    private var lastLoginResponse: BsonDocument? = null

    fun booking(): JsonObject {
        val packetBuilder = PacketBuilder()
        val response = oneshot(
            host = BOOKING_HOST,
            port = BOOKING_PORT,
            packet = packetBuilder.build(
                "GETCONF",
                BsonSupport.docOf(
                    "MCCMNC" to BsonString(DEFAULT_MCCMNC),
                    "model" to BsonString(DEFAULT_DEVICE_MODEL),
                    "os" to BsonString(DEFAULT_AGENT),
                ),
            ),
            transport = LocoTransportType.TLS,
        )
        return BsonSupport.toJson(response.body)
    }

    fun checkin(): LocoCheckinResult {
        val config = booking()
        val checkinHosts =
            config["ticket"]?.jsonObject?.get("lsl")?.jsonArray.orEmpty()
                .mapNotNull { it.jsonPrimitive.contentOrNull?.trim() }
                .filter { it.isNotBlank() }
                .distinct()
                .ifEmpty { error("no checkin host in booking response") }
        val advertisedPorts =
            config["wifi"]?.jsonObject?.get("ports")?.jsonArray.orEmpty()
                .mapNotNull { it.jsonPrimitive.intOrNull?.takeIf { port -> port > 0 } }
                .distinct()
                .ifEmpty { listOf(DEFAULT_LOCO_PORT) }

        // Follow node-kakao's sequencing: booking over TLS, then CHECKIN over secure-layer TCP.
        val attempts = linkedSetOf<Int>().apply {
            advertisedPorts.forEach(::add)
            add(DEFAULT_LOCO_PORT)
        }.toList()
        val profiles =
            listOf(
                LocoEncryptor.Profile.NODE_KAKAO,
                LocoEncryptor.Profile.OPEN_KAKAO_GCM,
            )

        ProtocolLogStore.recordSystem("checkin hosts=${checkinHosts.joinToString(",")}")

        for (profile in profiles) {
            for (checkinHost in checkinHosts) {
                for (port in attempts) {
                    val packet =
                        PacketBuilder().build(
                            "CHECKIN",
                            BsonSupport.docOf(
                                "userId" to BsonInt64(credentials.userId),
                                "appVer" to BsonString(credentials.appVersion),
                                "countryISO" to BsonString(DEFAULT_COUNTRY_ISO),
                                "lang" to BsonString(DEFAULT_LANGUAGE),
                                "ntype" to BsonInt32(DEFAULT_NET_TYPE),
                                "useSub" to BsonBoolean(DEFAULT_USE_SUB_DEVICE),
                                "os" to BsonString(DEFAULT_AGENT),
                                "MCCMNC" to BsonString(DEFAULT_MCCMNC),
                            ),
                        )
                    ProtocolLogStore.recordSystem("checkin attempt host=$checkinHost port=$port transport=SECURE profile=${profile.name}")
                    runCatching {
                        oneshot(
                            checkinHost,
                            port,
                            packet,
                            transport = LocoTransportType.SECURE,
                            secureProfile = profile,
                        )
                    }.onFailure { error ->
                        ProtocolLogStore.recordSystem(
                            "checkin attempt failed host=$checkinHost port=$port transport=SECURE profile=${profile.name} error=${error.message ?: error::class.simpleName}",
                        )
                    }.getOrNull()?.let { response ->
                        val host = response.body.string("host")
                        if (host.isNotBlank()) {
                            ProtocolLogStore.recordSystem(
                                "checkin succeeded host=$host port=${response.body.int("port")} transport=SECURE profile=${profile.name}",
                            )
                            val locoPort = response.body.int("port").takeIf { it > 0 } ?: DEFAULT_LOCO_PORT
                            return LocoCheckinResult(
                                server = LocoServer(host, locoPort),
                                usedTls = false,
                                secureProfile = profile.name,
                                bookingRevision = config["revision"]?.jsonPrimitive?.intOrNull,
                                raw = BsonSupport.toJson(response.body),
                            )
                        }
                        ProtocolLogStore.recordSystem(
                            "checkin response missing host host=$checkinHost port=$port transport=SECURE profile=${profile.name}",
                        )
                    }
                }
            }
        }

        error("all checkin attempts failed")
    }

    fun connect(host: String, port: Int, useTls: Boolean) {
        val requestedTransport = if (useTls) LocoTransportType.TLS else LocoTransportType.SECURE
        connect(host, port, requestedTransport, secureProfile = LocoEncryptor.Profile.NODE_KAKAO)
    }

    fun connect(
        host: String,
        port: Int,
        transportType: LocoTransportType = LocoTransportType.SECURE,
        secureProfile: LocoEncryptor.Profile = LocoEncryptor.Profile.NODE_KAKAO,
    ) {
        disconnect()
        ProtocolLogStore.recordSystem("connect $host:$port profile=${secureProfile.name}", transport = transportType.logName)
        transport = when (transportType) {
            LocoTransportType.TLS -> createTlsTransport(host, port)
            LocoTransportType.SECURE ->
                createSecureTransport(
                    host,
                    port,
                    keepAlive = true,
                    note = "secure handshake profile=${secureProfile.name}",
                    profile = secureProfile,
                )
        }
        packetBuilder = PacketBuilder()
        nextMessageId = 0
    }

    fun login(): JsonObject {
        val token = loginTokenCandidates().firstOrNull()?.value ?: credentials.accessToken()
        val duuid = loginDuuidCandidates().firstOrNull()?.value ?: credentials.deviceUuid
        return BsonSupport.toJson(loginPacket(token, revision = 0, duuid = duuid).body)
    }

    fun fullConnect(): JsonObject {
        val checkin = checkin()
        val secureProfile =
            checkin.secureProfile
                ?.let { profileName -> runCatching { LocoEncryptor.Profile.valueOf(profileName) }.getOrNull() }
                ?: LocoEncryptor.Profile.NODE_KAKAO
        val revisions =
            linkedSetOf<Int>().apply {
                add(0)
                checkin.bookingRevision?.takeIf { it >= 0 }?.let(::add)
            }
        var lastResponse: LocoPacket? = null
        lastLoginResponse = null

        for ((label, token) in loginTokenCandidates()) {
            for ((duuidLabel, duuid) in loginDuuidCandidates()) {
                for (revision in revisions) {
                    connect(checkin.server.host, checkin.server.port, LocoTransportType.SECURE, secureProfile)
                    val response = loginPacket(token, revision, duuid)
                    lastResponse = response
                    if (response.status() == 0L) {
                        lastLoginResponse = response.body
                        ProtocolLogStore.recordSystem("login succeeded tokenVariant=$label duuidVariant=$duuidLabel revision=$revision")
                        return BsonSupport.toJson(response.body)
                    }
                    ProtocolLogStore.recordSystem(
                        "login failed status=${response.status()} tokenVariant=$label duuidVariant=$duuidLabel revision=$revision",
                    )
                }
            }
        }

        return BsonSupport.toJson(lastResponse?.body ?: BsonDocument())
    }

    fun watchEvents(
        durationMs: Long,
        idleTimeoutMs: Int = 1_000,
        maxPackets: Int = 100,
    ): List<LocoObservedPacket> {
        require(durationMs >= 0) { "durationMs must be >= 0" }
        require(idleTimeoutMs > 0) { "idleTimeoutMs must be > 0" }
        require(maxPackets > 0) { "maxPackets must be > 0" }

        val stream = transport ?: error("not connected")
        val deadline = System.currentTimeMillis() + durationMs
        val observed = mutableListOf<LocoObservedPacket>()

        while (System.currentTimeMillis() < deadline && observed.size < maxPackets) {
            val remaining = (deadline - System.currentTimeMillis()).coerceAtLeast(1)
            val packet = stream.receivePacket(timeoutMs = minOf(idleTimeoutMs.toLong(), remaining).toInt()) ?: continue
            observed +=
                LocoObservedPacket(
                    receivedAt = System.currentTimeMillis(),
                    packetId = packet.packetId,
                    status = packet.status(),
                    method = packet.method,
                    body = BsonSupport.toJson(packet.body),
                )
        }

        return observed
    }

    fun getChatInfo(chatId: Long): BsonDocument =
        sendCommand(
            "CHATONROOM",
            BsonSupport.docOf(
                "chatId" to BsonInt64(chatId),
                "token" to BsonInt64(0),
                "opt" to BsonInt64(0),
            ),
        ).body

    fun listChats(): List<LocoChatListing> {
        val chats = linkedMapOf<Long, LocoChatListing>()

        lastLoginResponse?.let { loginPage ->
            appendChatListings(loginPage, chats)
            if (chats.isNotEmpty()) {
                return chats.values.toList()
            }
        }

        var lastTokenId = 0L
        var lastChatId = 0L

        repeat(MAX_CHAT_PAGE_COUNT) {
            val response = sendCommand(
                "LCHATLIST",
                BsonSupport.docOf(
                    "lastTokenId" to BsonInt64(lastTokenId),
                    "lastChatId" to BsonInt64(lastChatId),
                ),
            )
            if (response.status() != 0L) {
                error("LCHATLIST failed with status=${response.status()}")
            }
            appendChatListings(response.body, chats)
            val nextTokenId = response.body.long("lastTokenId")
            val nextChatId = response.body.long("lastChatId")
            if (response.body.bool("eof") || (nextTokenId == lastTokenId && nextChatId == lastChatId)) {
                return chats.values.toList()
            }
            lastTokenId = nextTokenId
            lastChatId = nextChatId
        }

        return chats.values.toList()
    }

    fun getMembers(chatId: Long): List<LocoChatMember> {
        val response = sendCommand("GETMEM", BsonSupport.docOf("chatId" to BsonInt64(chatId)))
        check(response.status() == 0L) { "GETMEM failed with status=${response.status()}" }
        return response.body.array("members").mapNotNull { value ->
            val doc = value.asDocumentOrNull() ?: return@mapNotNull null
            LocoChatMember(
                userId = doc.long("userId"),
                nickname = doc.string("nickName", "nickname"),
                countryIso = doc.string("countryIso"),
            )
        }
    }

    fun readMessages(
        chatId: Long,
        cursor: Long?,
        fetchAll: Boolean,
        limit: Int,
        delayMs: Long,
        allowOpenChatUnsafe: Boolean,
    ): List<LocoChatMessage> {
        val roomInfo = getChatInfo(chatId)
        val chatType = extractChatType(roomInfo)
        if (isOpenChat(chatType) && fetchAll && !allowOpenChatUnsafe) {
            error("open chat full-history read blocked; set allowOpenChatUnsafe=true to override")
        }

        val lastLogId = roomInfo.long("l")
        check(lastLogId > 0L) { "no messages in chat" }

        val memberNames = roomInfo.array("m")
            .mapNotNull { it.asDocumentOrNull() }
            .mapNotNull { doc ->
                val userId = doc.long("userId")
                val nickname = doc.string("nickName", "nickname")
                if (userId <= 0 || nickname.isBlank()) null else userId to nickname
            }
            .toMap()

        val messages = linkedMapOf<Long, LocoChatMessage>()
        var currentCursor = cursor ?: 0L

        while (true) {
            val response = sendCommand(
                "SYNCMSG",
                BsonSupport.docOf(
                    "chatId" to BsonInt64(chatId),
                    "cur" to BsonInt64(currentCursor),
                    "cnt" to BsonInt32(0),
                    "max" to BsonInt64(lastLogId),
                ),
            )
            check(response.status() == 0L) { "SYNCMSG failed with status=${response.status()}" }
            val chatLogs = response.body.array("chatLogs")
            if (chatLogs.isEmpty()) {
                break
            }
            var maxLogInBatch = 0L
            chatLogs.forEach { value ->
                val doc = value.asDocumentOrNull() ?: return@forEach
                val logId = doc.long("logId")
                maxLogInBatch = maxOf(maxLogInBatch, logId)
                val authorId = doc.long("authorId")
                val nickname = doc.string("authorNickname").ifBlank { memberNames[authorId].orEmpty() }
                messages[logId] = LocoChatMessage(
                    logId = logId,
                    authorId = authorId,
                    authorNickname = nickname,
                    messageType = doc.int("type"),
                    message = doc.string("message"),
                    attachment = doc.string("attachment"),
                    sendAt = doc.long("sendAt"),
                )
            }
            val isOk = response.body.bool("isOK")
            if (isOk || maxLogInBatch == 0L) {
                break
            }
            currentCursor = maxLogInBatch
            if (delayMs > 0) {
                Thread.sleep(delayMs)
            }
        }

        val sorted = messages.values.sortedBy { it.sendAt }
        return if (fetchAll) sorted else sorted.takeLast(limit.coerceAtLeast(1))
    }

    fun sendTextMessage(chatId: Long, message: String, allowOpenChatUnsafe: Boolean): JsonObject {
        val roomInfo = getChatInfo(chatId)
        val chatType = extractChatType(roomInfo)
        if (isOpenChat(chatType) && !allowOpenChatUnsafe) {
            error("sending to open chat is blocked by default; set allowOpenChatUnsafe=true to override")
        }
        val response = sendCommand(
            "WRITE",
            BsonSupport.docOf(
                "chatId" to BsonInt64(chatId),
                "msgId" to BsonInt32(++nextMessageId),
                "msg" to BsonString(message),
                "type" to BsonInt32(1),
                "noSeen" to BsonBoolean(true),
            ),
        )
        return BsonSupport.toJson(response.body)
    }

    fun sendCommand(method: String, body: BsonDocument): LocoPacket {
        val packet = packetBuilder.build(method, body)
        val stream = transport ?: error("not connected")
        stream.sendPacket(packet)
        while (true) {
            val response = stream.receivePacket() ?: error("connection closed while waiting for $method")
            if (response.packetId == packet.packetId) {
                return response
            }
        }
    }

    fun disconnect() {
        if (transport != null) {
            ProtocolLogStore.recordSystem("disconnect")
        }
        transport?.close()
        transport = null
    }

    override fun close() {
        disconnect()
    }

    private fun oneshot(
        host: String,
        port: Int,
        packet: LocoPacket,
        transport: LocoTransportType,
        secureProfile: LocoEncryptor.Profile = LocoEncryptor.Profile.NODE_KAKAO,
    ): LocoPacket =
        when (transport) {
            LocoTransportType.TLS -> createTlsTransport(host, port).use { stream ->
                stream.sendPacket(packet)
                stream.receivePacket() ?: error("connection closed during $host:$port oneshot")
            }

            LocoTransportType.SECURE ->
                createSecureTransport(
                    host,
                    port,
                    keepAlive = false,
                    note = "secure oneshot handshake profile=${secureProfile.name}",
                    profile = secureProfile,
                ).use { stream ->
                    stream.sendPacket(packet)
                    stream.receivePacket() ?: error("connection closed during $host:$port oneshot")
                }
        }

    private fun createTlsTransport(host: String, port: Int): LocoTransport.Tls =
        LocoTransport.Tls(
            socket = SSLSocketFactory.getDefault().createSocket(host, port) as javax.net.ssl.SSLSocket,
        )

    private fun createSecureTransport(
        host: String,
        port: Int,
        keepAlive: Boolean,
        note: String,
        profile: LocoEncryptor.Profile,
    ): LocoTransport.Secure {
        val socket = Socket(host, port).apply {
            this.keepAlive = keepAlive
        }
        val encryptor = LocoEncryptor.create(profile = profile)
        val transport = LocoTransport.Secure(socket, encryptor)
        val handshake = encryptor.buildHandshakePacket()
        ProtocolLogStore.recordRaw(ProtocolLogDirection.TX, LocoTransportType.SECURE.logName, handshake, note)
        transport.sendRaw(handshake)
        return transport
    }

    private fun extractChatType(roomInfo: BsonDocument): String =
        roomInfo["chatInfo"]?.asDocumentOrNull()?.string("type").orEmpty().ifBlank {
            roomInfo.string("t")
        }.ifBlank { "Unknown" }

    private fun appendChatListings(page: BsonDocument, chats: MutableMap<Long, LocoChatListing>) {
        page.array("chatDatas").forEach { value ->
            val doc = value.asDocumentOrNull() ?: return@forEach
            val chatId = doc.long("c", "chatId")
            if (chatId <= 0L) {
                return@forEach
            }
            val kind = doc.string("t", "type")
            val lastLogId = doc.long("s", "lastLogId")
            val lastSeen = doc.long("ll", "lastSeenLogId")
            val title = doc["chatInfo"]?.asDocumentOrNull()?.string("name").orEmpty().ifBlank {
                doc.array("k").mapNotNull { it.asStringOrNull() }.joinToString(", ")
            }
            chats[chatId] =
                LocoChatListing(
                    chatId = chatId,
                    kind = kind,
                    title = title,
                    hasUnread = lastLogId > lastSeen,
                    activeMembers = doc.int("a", "activeMembersCount"),
                    lastLogId = lastLogId,
                    lastSeenLogId = lastSeen,
                )
        }
    }

    private fun loginPacket(oauthToken: String, revision: Int, duuid: String): LocoPacket =
        loadPcLoginState().let { loginState ->
            sendCommand(
                "LOGINLIST",
                BsonSupport.docOf(
                    "appVer" to BsonString(credentials.appVersion),
                    "prtVer" to BsonString("1"),
                    "os" to BsonString(DEFAULT_AGENT),
                    "lang" to BsonString(DEFAULT_LANGUAGE),
                    "duuid" to BsonString(duuid),
                    "oauthToken" to BsonString(oauthToken),
                    "dtype" to BsonInt32(DEFAULT_DEVICE_TYPE),
                    "ntype" to BsonInt32(DEFAULT_NET_TYPE),
                    "MCCMNC" to BsonString(DEFAULT_MCCMNC),
                    "revision" to BsonInt32(revision),
                    "chatIds" to BsonArray(),
                    "maxIds" to BsonArray(),
                    "lastTokenId" to BsonInt64(0),
                    "lbk" to BsonInt32(loginState.lbk),
                    "rp" to loginState.rp,
                    "bg" to BsonBoolean(false),
                ),
            )
        }

    private fun loginTokenCandidates(): List<Map.Entry<String, String>> {
        val values = linkedMapOf<String, String>()
        credentials.authorizationHeader
            ?.trim()
            ?.takeIf { it.isNotBlank() }
            ?.let { values["authorizationHeader"] = it }
        credentials.authorizationToken()
            .trim()
            .takeIf { it.isNotBlank() && it !in values.values }
            ?.let { values["authorizationToken"] = it }
        credentials.accessToken()
            .trim()
            .takeIf { it.isNotBlank() && it !in values.values }
            ?.let { values["accessToken"] = it }
        return values.entries.toList()
    }

    private fun loginDuuidCandidates(): List<Map.Entry<String, String>> {
        val values = linkedMapOf<String, String>()
        credentials.deviceUuid
            .trim()
            .takeIf { it.isNotBlank() }
            ?.let { values["sys_uuid"] = it }

        credentials.authorizationSuffix()
            ?.trim()
            ?.takeIf { it.isNotBlank() }
            ?.let { suffix ->
                if (suffix !in values.values) {
                    values["authorization_suffix"] = suffix
                }
                if (suffix.length >= AUTH_SUFFIX_DEV_ID_LENGTH) {
                    val devId = suffix.take(AUTH_SUFFIX_DEV_ID_LENGTH)
                    if (devId !in values.values) {
                        values["auth_dev_id_prefix"] = devId
                    }
                }
            }

        return values.entries.toList()
    }

    private fun loadPcLoginState(): PcLoginState {
        val localAppData = System.getenv("LOCALAPPDATA").orEmpty()
        if (localAppData.isBlank()) {
            return PcLoginState()
        }

        val path = Paths.get(localAppData, "Kakao", "KakaoTalk", "users", "last_pc_login.dat")
        if (!path.exists()) {
            return PcLoginState()
        }

        val raw = runCatching { path.readText() }.getOrNull()?.trim() ?: return PcLoginState()
        val parts = raw.split('|')
        val lbk = parts.getOrNull(0)?.toIntOrNull() ?: 0
        val rpText = parts.getOrNull(2)?.takeIf { it.isNotBlank() }
        val rp = rpText?.let(::BsonString) ?: BsonNull.VALUE
        if (rpText != null) {
            ProtocolLogStore.recordSystem("loaded last_pc_login.dat lbk=$lbk rpLength=${rpText.length}")
        }
        return PcLoginState(lbk = lbk, rp = rp)
    }

    private data class PcLoginState(
        val lbk: Int = 0,
        val rp: org.bson.BsonValue = BsonNull.VALUE,
    )

    private fun isOpenChat(type: String): Boolean =
        type == "OpenMultiChat" || type == "OpenDirectChat"

    enum class LocoTransportType(val logName: String) {
        TLS("TLS"),
        SECURE("SECURE"),
    }

    private sealed class LocoTransport : Closeable {
        abstract fun sendRaw(bytes: ByteArray)
        abstract fun sendPacket(packet: LocoPacket)
        abstract fun receivePacket(timeoutMs: Int? = null): LocoPacket?

        class Tls(private val socket: javax.net.ssl.SSLSocket) : LocoTransport() {
            private val input = DataInputStream(socket.inputStream)
            private val output = DataOutputStream(socket.outputStream)

            override fun sendRaw(bytes: ByteArray) {
                output.write(bytes)
                output.flush()
            }

            override fun sendPacket(packet: LocoPacket) {
                ProtocolLogStore.recordPacket(ProtocolLogDirection.TX, "TLS", packet)
                sendRaw(packet.encode())
            }

            override fun receivePacket(timeoutMs: Int?): LocoPacket? =
                receiveWithTimeout(socket, timeoutMs) {
                    val headerBytes = ByteArray(LocoPacket.HEADER_SIZE)
                    input.readFully(headerBytes)
                    val header = LocoPacket.decodeHeader(headerBytes)
                    val bodyBytes = ByteArray(header.bodyLength)
                    input.readFully(bodyBytes)
                    val rawPacket = headerBytes + bodyBytes
                    try {
                        LocoPacket.decode(rawPacket).also {
                            ProtocolLogStore.recordPacket(ProtocolLogDirection.RX, "TLS", it)
                        }
                    } catch (error: Throwable) {
                        ProtocolLogStore.recordError(
                            ProtocolLogDirection.RX,
                            "TLS",
                            rawPacket,
                            "failed to parse tls packet: ${error.message ?: error::class.simpleName}",
                        )
                        throw error
                    }
                }

            private fun <T> receiveWithTimeout(socket: javax.net.ssl.SSLSocket, timeoutMs: Int?, block: () -> T): T? {
                val previousTimeout = socket.soTimeout
                if (timeoutMs != null) {
                    socket.soTimeout = timeoutMs
                }
                return try {
                    block()
                } catch (_: SocketTimeoutException) {
                    null
                } finally {
                    if (timeoutMs != null) {
                        socket.soTimeout = previousTimeout
                    }
                }
            }

            override fun close() {
                socket.close()
            }
        }

        class Secure(private val socket: Socket, private val encryptor: LocoEncryptor) : LocoTransport() {
            private val input = DataInputStream(socket.inputStream)
            private val output = DataOutputStream(socket.outputStream)

            override fun sendRaw(bytes: ByteArray) {
                output.write(bytes)
                output.flush()
            }

            override fun sendPacket(packet: LocoPacket) {
                ProtocolLogStore.recordPacket(ProtocolLogDirection.TX, "SECURE", packet)
                sendRaw(encryptor.encrypt(packet.encode()))
            }

            override fun receivePacket(timeoutMs: Int?): LocoPacket? =
                receiveWithTimeout(socket, timeoutMs) {
                    val firstFrame = readEncryptedFrame()
                    var decrypted = encryptor.decrypt(firstFrame)
                    if (decrypted.size >= LocoPacket.HEADER_SIZE) {
                        val header = LocoPacket.decodeHeader(decrypted.copyOfRange(0, LocoPacket.HEADER_SIZE))
                        val totalSize = LocoPacket.HEADER_SIZE + header.bodyLength
                        while (decrypted.size < totalSize) {
                            decrypted += encryptor.decrypt(readEncryptedFrame())
                        }
                    }
                    try {
                        LocoPacket.decode(decrypted).also {
                            ProtocolLogStore.recordPacket(ProtocolLogDirection.RX, "SECURE", it)
                        }
                    } catch (error: Throwable) {
                        ProtocolLogStore.recordError(
                            ProtocolLogDirection.RX,
                            "SECURE",
                            decrypted,
                            "failed to parse secure packet: ${error.message ?: error::class.simpleName}",
                        )
                        throw error
                    }
                }

            private fun <T> receiveWithTimeout(socket: Socket, timeoutMs: Int?, block: () -> T): T? {
                val previousTimeout = socket.soTimeout
                if (timeoutMs != null) {
                    socket.soTimeout = timeoutMs
                }
                return try {
                    block()
                } catch (_: SocketTimeoutException) {
                    null
                } finally {
                    if (timeoutMs != null) {
                        socket.soTimeout = previousTimeout
                    }
                }
            }

            private fun readEncryptedFrame(): ByteArray {
                val sizeBytes = ByteArray(4)
                input.readFully(sizeBytes)
                val bodySize = ByteBuffer.wrap(sizeBytes).order(ByteOrder.LITTLE_ENDIAN).int
                val frame = ByteArray(bodySize)
                input.readFully(frame)
                return frame
            }

            override fun close() {
                socket.close()
            }
        }
    }

    companion object {
        private const val BOOKING_HOST = "booking-loco.kakao.com"
        private const val BOOKING_PORT = 443
        private const val DEFAULT_LOCO_PORT = 5223
        private const val DEFAULT_AGENT = "win32"
        private const val DEFAULT_MCCMNC = "999"
        private const val DEFAULT_LANGUAGE = "ko"
        private const val DEFAULT_COUNTRY_ISO = "KR"
        private const val DEFAULT_DEVICE_MODEL = ""
        private const val DEFAULT_DEVICE_TYPE = 2
        private const val DEFAULT_NET_TYPE = 0
        private const val DEFAULT_USE_SUB_DEVICE = true
        private const val MAX_CHAT_PAGE_COUNT = 100
        private const val AUTH_SUFFIX_DEV_ID_LENGTH = 32
    }
}
