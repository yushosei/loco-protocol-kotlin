package com.yushosei.rest

import com.yushosei.model.ChatMember
import com.yushosei.model.ChatMessage
import com.yushosei.model.ChatRoom
import com.yushosei.model.Friend
import com.yushosei.model.KakaoCredentials
import com.yushosei.model.MyProfile
import com.yushosei.model.OpenLinkAnonProfile
import com.yushosei.model.OpenPostUploadInfo
import com.yushosei.model.OpenPostUploadInfoItem
import com.yushosei.model.OpenProfilePostUpload
import com.yushosei.model.OpenProfileUpload
import com.yushosei.model.RestChatPage
import com.yushosei.model.UploadedAttachment
import com.yushosei.util.jsonLong
import com.yushosei.util.jsonString
import io.ktor.client.HttpClient
import io.ktor.client.engine.cio.CIO
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.request.accept
import io.ktor.client.request.forms.MultiPartFormDataContent
import io.ktor.client.request.forms.formData
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.Headers
import io.ktor.http.HttpHeaders
import io.ktor.http.contentType
import io.ktor.serialization.kotlinx.json.json
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import java.net.URLEncoder
import java.io.ByteArrayOutputStream
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.util.Locale

class KakaoRestClient(
    private val credentials: KakaoCredentials,
) : AutoCloseable {
    private val json = Json {
        ignoreUnknownKeys = true
        isLenient = true
        prettyPrint = true
    }

    private val client = HttpClient(CIO) {
        install(ContentNegotiation) {
            json(json)
        }
        engine {
            requestTimeout = 15_000
        }
    }
    private var activeCredentials: KakaoCredentials = credentials

    fun currentCredentials(): KakaoCredentials = activeCredentials

    fun verifyToken(): Boolean = runBlocking {
        val response = requestRaw(settingsRequestMethod(), settingsUrl(), settingsBody())
        response["status"]?.jsonPrimitive?.longOrNull == 0L
    }

    fun getMyProfile(): MyProfile = runBlocking {
        val profile = request(HttpMethod.POST, "$BASE_URL/mac/profile3/me.json", "since=0")
        val settings = request(HttpMethod.POST, "$BASE_URL/mac/account/more_settings.json", "since=0&locale_country=KR")
        val payload = profile["profile"]?.jsonObject ?: JsonObject(emptyMap())

        MyProfile(
            nickname = payload.jsonString("nickname"),
            statusMessage = payload.jsonString("statusMessage"),
            accountId = settings.jsonLong("accountId"),
            email = settings.jsonString("emailAddress"),
            userId = payload.jsonLong("userId").takeIf { it != 0L } ?: credentials.userId,
            profileImageUrl = payload.jsonString("fullProfileImageUrl"),
        )
    }

    fun getFriends(): List<Friend> = runBlocking {
        val response = request(HttpMethod.POST, "$BASE_URL/mac/friends/update.json", "since=0")
        val source = (response["friends"] ?: response["added"] ?: JsonArray(emptyList())).jsonArray
        source.map { item ->
            Friend(
                userId = item.jsonLong("userId"),
                nickname = item.jsonString("nickName"),
                friendNickname = item.jsonString("friendNickName"),
                phoneNumber = item.jsonString("phoneNumber"),
                statusMessage = item.jsonString("statusMessage"),
                favorite = item.jsonObject["favorite"]?.jsonPrimitive?.booleanOrNull ?: false,
                hidden = item.jsonObject["hidden"]?.jsonPrimitive?.booleanOrNull ?: false,
            )
        }
    }

    fun searchFriends(query: String, pageNum: Int? = null, pageSize: Int? = null): JsonObject = runBlocking {
        val params =
            linkedMapOf(
                "query" to query,
            ).apply {
                if (pageNum != null && pageSize != null) {
                    put("page_num", pageNum.toString())
                    put("page_size", pageSize.toString())
                }
        }
        requestRaw(HttpMethod.GET, buildUrl("${serviceAgent()}/friends/search.json", params))
    }

    fun addFriend(userId: Long, pa: String = ""): JsonObject = runBlocking {
        val path = "${serviceAgent()}/friends/add/${urlEncode(userId.toString())}.json"
        requestRaw(HttpMethod.GET, buildUrl(path, linkedMapOf("pa" to pa)))
    }

    fun addFriendByPhoneNumber(
        nickname: String,
        countryIso: String,
        countryCode: String,
        phoneNumber: String,
    ): JsonObject = runBlocking {
        requestRaw(
            HttpMethod.POST,
            "$BASE_URL/${serviceAgent()}/friends/add_by_phonenumber.json",
            formBody(
                linkedMapOf(
                    "nickname" to nickname,
                    "country_iso" to countryIso,
                    "country_code" to countryCode,
                    "phonenumber" to phoneNumber,
                ),
            ),
        )
    }

    fun findFriendById(userId: Long): JsonObject = runBlocking {
        requestRaw(HttpMethod.GET, "$BASE_URL/${serviceAgent()}/friends/${urlEncode(userId.toString())}.json")
    }

    fun hideFriend(userId: Long, pa: String = ""): JsonObject = runBlocking {
        requestRaw(
            HttpMethod.POST,
            "$BASE_URL/${serviceAgent()}/friends/hide.json",
            formBody(
                linkedMapOf(
                    "id" to userId.toString(),
                    "pa" to pa,
                ),
            ),
        )
    }

    fun unhideFriend(userId: Long): JsonObject = runBlocking {
        requestRaw(
            HttpMethod.POST,
            "$BASE_URL/${serviceAgent()}/friends/unhide.json",
            formBody(linkedMapOf("id" to userId.toString())),
        )
    }

    fun removeFriend(userId: Long): JsonObject = runBlocking {
        requestRaw(
            HttpMethod.POST,
            "$BASE_URL/${serviceAgent()}/friends/purge.json",
            formBody(linkedMapOf("id" to userId.toString())),
        )
    }

    fun requestFriendsDiff(): JsonObject = runBlocking {
        requestRaw(HttpMethod.POST, "$BASE_URL/${serviceAgent()}/friends/diff.json", "")
    }

    fun requestFriendList(
        types: List<String> = listOf("plus", "normal"),
        eventTypes: List<String> = listOf("create"),
        token: Long = 0L,
    ): JsonObject = runBlocking {
        requestRaw(
            HttpMethod.GET,
            buildUrl(
                "${serviceAgent()}/friends/list.json",
                linkedMapOf(
                    "type" to json.encodeToString(JsonArray.serializer(), JsonArray(types.map(::stringElement))),
                    "event_types" to json.encodeToString(JsonArray.serializer(), JsonArray(eventTypes.map(::stringElement))),
                    "token" to token.toString(),
                ),
            ),
        )
    }

    fun removeFriendList(userIds: List<Long>): JsonObject = runBlocking {
        requestRaw(
            HttpMethod.POST,
            "$BASE_URL/${serviceAgent()}/friends/delete.json",
            formBody(linkedMapOf("ids" to encodeIdList(userIds))),
        )
    }

    fun setFriendNickname(userId: Long, nickname: String): JsonObject = runBlocking {
        requestRaw(
            HttpMethod.POST,
            "$BASE_URL/${serviceAgent()}/friends/nickname.json",
            formBody(
                linkedMapOf(
                    "id" to userId.toString(),
                    "nickname" to nickname,
                ),
            ),
        )
    }

    fun addFavoriteFriends(userIds: List<Long>): JsonObject = runBlocking {
        requestRaw(
            HttpMethod.POST,
            "$BASE_URL/${serviceAgent()}/friends/add_favorite.json",
            formBody(linkedMapOf("ids" to encodeIdList(userIds))),
        )
    }

    fun removeFavoriteFriend(userId: Long): JsonObject = runBlocking {
        requestRaw(
            HttpMethod.POST,
            "$BASE_URL/${serviceAgent()}/friends/remove_favorite.json",
            formBody(linkedMapOf("id" to userId.toString())),
        )
    }

    fun findFriendByUUID(uuid: String): JsonObject = runBlocking {
        requestRaw(
            HttpMethod.POST,
            "$BASE_URL/${serviceAgent()}/friends/find_by_uuid.json",
            formBody(linkedMapOf("uuid" to uuid)),
        )
    }

    fun getFriendProfile(userId: Long): JsonObject = runBlocking {
        requestRaw(
            HttpMethod.GET,
            buildUrl("${serviceAgent()}/profile3/friend_info.json", linkedMapOf("id" to userId.toString())),
        )
    }

    fun getFriendMusicList(userId: Long): JsonObject = runBlocking {
        requestRaw(
            HttpMethod.GET,
            buildUrl("${serviceAgent()}/profile/music/list.json", linkedMapOf("id" to userId.toString())),
        )
    }

    fun getProfileList(): JsonObject = runBlocking {
        requestRaw(HttpMethod.GET, "$BASE_URL/${serviceAgent()}/profile/list")
    }

    fun getDesignatedFriends(): JsonObject = runBlocking {
        requestRaw(HttpMethod.GET, "$BASE_URL/${serviceAgent()}/profile/designated_friends")
    }

    fun requestMyProfileRaw(): JsonObject = runBlocking {
        requestRaw(HttpMethod.GET, "$BASE_URL/${serviceAgent()}/profile3/me.json")
    }

    fun getSettings(): JsonObject = runBlocking {
        request(settingsRequestMethod(), settingsUrl(), settingsBody())
    }

    fun getMoreSettings(since: Long = 0L): JsonObject = runBlocking {
        requestRaw(
            HttpMethod.GET,
            buildUrl(
                "${serviceAgent()}/account/more_settings.json",
                linkedMapOf(
                    "since" to since.toString(),
                    "lang" to loginLanguage(),
                ),
            ),
        )
    }

    fun getLessSettings(since: Long = 0L): JsonObject = runBlocking {
        requestRaw(
            HttpMethod.GET,
            buildUrl(
                "${serviceAgent()}/account/less_settings.json",
                linkedMapOf(
                    "since" to since.toString(),
                    "lang" to loginLanguage(),
                ),
            ),
        )
    }

    fun updateSettings(settings: JsonObject): JsonObject = runBlocking {
        requestRaw(
            HttpMethod.POST,
            "$BASE_URL/${serviceAgent()}/account/update_settings.json",
            formBody(settings.mapValues { (_, value) -> jsonElementToFormValue(value) }),
        )
    }

    fun requestWebLoginToken(): JsonObject = runBlocking {
        requestRaw(HttpMethod.GET, "$BASE_URL/${serviceAgent()}/account/login_token.json")
    }

    fun requestSessionUrl(redirectUrl: String): Pair<JsonObject, String?> {
        val response = requestWebLoginToken()
        val token = response["token"]?.jsonPrimitive?.contentOrNull
        val sessionUrl = token?.let { createSessionUrl(it, redirectUrl) }
        return response to sessionUrl
    }

    fun canChangeUuid(uuid: String): JsonObject = runBlocking {
        requestRaw(
            HttpMethod.POST,
            "$BASE_URL/${serviceAgent()}/account/can_change_uuid.json",
            formBody(linkedMapOf("uuid" to uuid)),
        )
    }

    fun changeUuid(uuid: String): JsonObject = runBlocking {
        requestRaw(
            HttpMethod.POST,
            "$BASE_URL/${serviceAgent()}/account/change_uuid.json",
            formBody(linkedMapOf("uuid" to uuid)),
        )
    }

    fun getScrapPreview(url: String): JsonObject = runBlocking {
        requestRaw(
            HttpMethod.POST,
            "$BASE_URL/${serviceAgent()}/scrap/preview.json",
            formBody(linkedMapOf("url" to url)),
        )
    }

    fun uploadAttachment(
        kind: String,
        fileName: String,
        data: ByteArray,
        contentType: String? = null,
    ): UploadedAttachment = runBlocking {
        val resolvedKind = kind.lowercase(Locale.ROOT)
        val resolvedContentType = resolveAttachmentContentType(resolvedKind, fileName, contentType)
        val failures = mutableListOf<String>()
        for (host in attachmentUploadHosts(resolvedKind)) {
            try {
                val response =
                    executeMultipartRequest(
                        url = "https://$host/upload",
                        headers = attachmentUploadHeaders(),
                        fields =
                            linkedMapOf(
                                "user_id" to "0",
                                "attachment_type" to resolvedContentType,
                            ),
                        fileFieldName = "attachment",
                        fileName = fileName,
                        fileContentType = resolvedContentType,
                        data = data,
                    )
                return@runBlocking UploadedAttachment(
                    path = response.trim().removeSurrounding("\""),
                    size = data.size.toLong(),
                    host = host,
                    attachmentType = resolvedContentType,
                    fileName = fileName,
                )
            } catch (error: Throwable) {
                failures += "$host -> ${error.message ?: error::class.simpleName.orEmpty()}"
            }
        }
        error(
            failures.joinToString(separator = "; ")
                .ifBlank {
                    "attachment upload failed for hosts=${attachmentUploadHosts(resolvedKind).joinToString()}"
                },
        )
    }

    fun uploadAttachmentFile(
        kind: String,
        filePath: Path,
        fileName: String? = null,
        contentType: String? = null,
    ): UploadedAttachment {
        val resolvedPath = filePath.toAbsolutePath().normalize()
        val resolvedFileName = fileName?.takeIf { it.isNotBlank() } ?: resolvedPath.fileName.toString()
        return uploadAttachment(
            kind = kind,
            fileName = resolvedFileName,
            data = Files.readAllBytes(resolvedPath),
            contentType = contentType,
        )
    }

    fun uploadOpenLinkImage(
        fileName: String,
        data: ByteArray,
        contentType: String = "image/jpeg",
    ): OpenProfileUpload = runBlocking {
        executeOpenUpload(
            path = "up/open-chat-profile",
            fileName = fileName,
            data = data,
            contentType = contentType,
            parser = ::parseOpenProfileUpload,
        )
    }

    fun uploadOpenLinkImageFile(
        filePath: Path,
        fileName: String? = null,
        contentType: String? = null,
    ): OpenProfileUpload {
        val resolvedPath = filePath.toAbsolutePath().normalize()
        val resolvedFileName = fileName?.takeIf { it.isNotBlank() } ?: resolvedPath.fileName.toString()
        return uploadOpenLinkImage(
            fileName = resolvedFileName,
            data = Files.readAllBytes(resolvedPath),
            contentType = resolveOpenUploadContentType(resolvedFileName, contentType),
        )
    }

    fun uploadOpenLinkPostImage(
        fileName: String,
        data: ByteArray,
        contentType: String = "image/jpeg",
    ): OpenProfilePostUpload = runBlocking {
        executeOpenUpload(
            path = "up/open-chat-profile-post",
            fileName = fileName,
            data = data,
            contentType = contentType,
            parser = ::parseOpenProfilePostUpload,
        )
    }

    fun uploadOpenLinkPostImageFile(
        filePath: Path,
        fileName: String? = null,
        contentType: String? = null,
    ): OpenProfilePostUpload {
        val resolvedPath = filePath.toAbsolutePath().normalize()
        val resolvedFileName = fileName?.takeIf { it.isNotBlank() } ?: resolvedPath.fileName.toString()
        return uploadOpenLinkPostImage(
            fileName = resolvedFileName,
            data = Files.readAllBytes(resolvedPath),
            contentType = resolveOpenUploadContentType(resolvedFileName, contentType),
        )
    }

    fun buildOpenLinkProfile(
        nickname: String,
        filePath: Path,
        fileName: String? = null,
        contentType: String? = null,
    ): OpenLinkAnonProfile {
        val upload = uploadOpenLinkImageFile(filePath, fileName, contentType)
        return OpenLinkAnonProfile(nickname = nickname, profilePath = upload.accessKey)
    }

    fun getChats(cursor: Long?): RestChatPage = runBlocking {
        val url = if (cursor == null) "$PILSNER_URL/messaging/chats" else "$PILSNER_URL/messaging/chats?cursor=$cursor"
        val response = request(HttpMethod.GET, url)
        val rooms = response["chats"]?.jsonArray.orEmpty().map { chat ->
            ChatRoom(
                chatId = chat.jsonLong("chatId"),
                kind = chat.jsonString("type"),
                title = chat.jsonString("title"),
                unreadCount = chat.jsonLong("unreadCount"),
            )
        }
        val nextCursor = if (response["last"]?.jsonPrimitive?.booleanOrNull == true) {
            null
        } else {
            response["nextCursor"]?.jsonPrimitive?.longOrNull?.takeIf { it != 0L }
        }
        RestChatPage(rooms, nextCursor)
    }

    fun getAllChats(): List<ChatRoom> {
        val all = mutableListOf<ChatRoom>()
        var cursor: Long? = null
        while (true) {
            val page = getChats(cursor)
            all += page.rooms
            cursor = page.nextCursor ?: break
        }
        return all
    }

    fun getChatMembers(chatId: Long): List<ChatMember> = runBlocking {
        val response = request(HttpMethod.GET, "$PILSNER_URL/messaging/chats/$chatId/members")
        response["members"]?.jsonArray.orEmpty().map { member ->
            ChatMember(
                userId = member.jsonLong("userId"),
                nickname = member.jsonString("nickName"),
                friendNickname = member.jsonString("friendNickName"),
                countryIso = member.jsonString("countryIso"),
            )
        }
    }

    fun getMessages(chatId: Long, cursor: Long?): JsonObject = runBlocking {
        val url =
            if (cursor == null) "$PILSNER_URL/messaging/chats/$chatId/messages"
            else "$PILSNER_URL/messaging/chats/$chatId/messages?cursor=$cursor"
        request(HttpMethod.GET, url)
    }

    fun getAllMessages(chatId: Long, maxPages: Int = 10): List<ChatMessage> {
        val messages = linkedMapOf<Long, ChatMessage>()
        var cursor: Long? = null
        repeat(maxPages.coerceAtLeast(1)) {
            val response = getMessages(chatId, cursor)
            val chatLogs = response["chatLogs"]?.jsonArray.orEmpty()
            if (chatLogs.isEmpty()) {
                return@repeat
            }
            chatLogs.forEach { log ->
                val message = ChatMessage(
                    logId = log.jsonLong("logId"),
                    authorId = log.jsonLong("authorId"),
                    messageType = log.jsonLong("type"),
                    message = log.jsonString("message"),
                    attachment = log.jsonString("attachment"),
                    sendAt = log.jsonLong("sendAt"),
                )
                messages[message.logId] = message
            }
            val nextCursor = response["nextCursor"]?.jsonPrimitive?.longOrNull ?: 0L
            if (nextCursor == 0L) {
                return@repeat
            }
            cursor = nextCursor
        }
        return messages.values.sortedBy { it.logId }
    }

    fun loginDirect(email: String, password: String, deviceUuid: String, deviceName: String, xVc: String): JsonObject =
        runBlocking {
            authRequest(
                path = "${authAgent()}/account/login.json",
                form =
                    linkedMapOf(
                        "device_name" to deviceName,
                        "device_uuid" to deviceUuid,
                        "email" to email,
                        "password" to password,
                        "forced" to "false",
                    ),
                xVc = xVc,
            )
        }

    fun loginWithXvc(
        email: String,
        password: String,
        deviceUuid: String,
        deviceName: String,
        forced: Boolean = false,
    ): JsonObject {
        val userAgent = loginUserAgent()
        val xVc = generateXvc(userAgent, email, deviceUuid)
        return runBlocking {
            authRequest(
                path = "${authAgent()}/account/login.json",
                form =
                    linkedMapOf(
                        "device_name" to deviceName,
                        "device_uuid" to deviceUuid,
                        "email" to email,
                        "password" to password,
                        "forced" to forced.toString(),
                    ),
                xVc = xVc,
            )
        }
    }

    fun requestPasscode(email: String, password: String, deviceUuid: String, deviceName: String): JsonObject {
        val xVc = generateXvc(loginUserAgent(), email, deviceUuid)
        return runBlocking {
            authRequest(
                path = "${authAgent()}/account/request_passcode.json",
                form =
                    linkedMapOf(
                        "device_name" to deviceName,
                        "device_uuid" to deviceUuid,
                        "email" to email,
                        "password" to password,
                    ),
                xVc = xVc,
            )
        }
    }

    fun registerDevice(
        email: String,
        password: String,
        deviceUuid: String,
        deviceName: String,
        passcode: String,
        permanent: Boolean = true,
    ): JsonObject {
        val xVc = generateXvc(loginUserAgent(), email, deviceUuid)
        return runBlocking {
            authRequest(
                path = "${authAgent()}/account/register_device.json",
                form =
                    linkedMapOf(
                        "device_name" to deviceName,
                        "device_uuid" to deviceUuid,
                        "email" to email,
                        "password" to password,
                        "passcode" to passcode,
                        "permanent" to permanent.toString(),
                    ),
                xVc = xVc,
            )
        }
    }

    fun renewOAuth(refreshToken: String = activeCredentials.refreshToken.orEmpty()): JsonObject = runBlocking {
        require(refreshToken.isNotBlank()) { "refresh token is blank" }
        val response =
            client.post("$BASE_URL/${authAgent()}/account/oauth2_token.json") {
                accept(ContentType.Application.Json)
                contentType(ContentType.Application.FormUrlEncoded)
                header(HttpHeaders.Authorization, activeCredentials.authorizationToken())
                header(HttpHeaders.AcceptLanguage, loginLanguage())
                header("A", loginAHeader())
                header("User-Agent", loginUserAgent())
                setBody(
                    "grant_type=refresh_token" +
                        "&access_token=${urlEncode(activeCredentials.accessToken())}" +
                        "&refresh_token=${urlEncode(refreshToken)}",
                )
            }
        val parsed = parseJsonObject(response.bodyAsText())
        if (parsed["status"]?.jsonPrimitive?.longOrNull == 0L) {
            activeCredentials =
                activeCredentials.withUpdatedTokens(
                    accessToken = parsed["access_token"]?.jsonPrimitive?.contentOrNull ?: activeCredentials.accessToken(),
                    refreshToken = parsed["refresh_token"]?.jsonPrimitive?.contentOrNull ?: refreshToken,
                )
        }
        parsed
    }

    override fun close() {
        client.close()
    }

    private suspend fun request(method: HttpMethod, url: String, body: String? = null): JsonObject {
        val parsed = requestRaw(method, url, body)
        val status = parsed["status"]?.jsonPrimitive?.longOrNull
        if (status != null && status != 0L) {
            error("Kakao API error status=$status")
        }
        return parsed
    }

    private suspend fun requestRaw(
        method: HttpMethod,
        url: String,
        body: String? = null,
        allowRefresh: Boolean = true,
    ): JsonObject {
        val parsed = executeAuthorizedRequest(method, url, body)
        val status = parsed["status"]?.jsonPrimitive?.longOrNull
        if (allowRefresh && status in setOf(STATUS_EXPIRED, STATUS_DISCONNECTED)) {
            val refreshToken = activeCredentials.refreshToken.orEmpty()
            if (refreshToken.isNotBlank()) {
                val refreshResponse = runCatching { renewOAuth(refreshToken) }.getOrNull()
                if (refreshResponse?.get("status")?.jsonPrimitive?.longOrNull == 0L) {
                    return requestRaw(method, url, body, allowRefresh = false)
                }
            }
        }
        return parsed
    }

    private suspend fun authRequest(
        path: String,
        form: LinkedHashMap<String, String>,
        xVc: String,
    ): JsonObject {
        val body = formBody(form)
        val response =
            client.post("$BASE_URL/$path") {
                accept(ContentType.Application.Json)
                contentType(ContentType.Application.FormUrlEncoded)
                header(HttpHeaders.AcceptLanguage, loginLanguage())
                header("A", loginAHeader())
                header("User-Agent", loginUserAgent())
                if (xVc.isNotBlank()) {
                    header("X-VC", xVc)
                }
                setBody(body)
            }
        return parseJsonObject(response.bodyAsText())
    }

    private fun authAgent(): String =
        activeCredentials.aHeader.substringBefore('/').ifBlank { DEFAULT_AUTH_AGENT }

    private fun serviceAgent(): String = authAgent()

    private fun settingsUrl(): String =
        when (authAgent()) {
            "win32" -> "$BASE_URL/win32/account/more_settings.json?since=0&lang=${loginLanguage()}"
            else -> "$BASE_URL/mac/account/more_settings.json"
        }

    private fun settingsRequestMethod(): HttpMethod =
        when (authAgent()) {
            "win32" -> HttpMethod.GET
            else -> HttpMethod.POST
        }

    private fun settingsBody(): String? =
        when (authAgent()) {
            "win32" -> null
            else -> "since=0&locale_country=KR"
        }

    private fun loginAHeader(): String =
        activeCredentials.aHeader.ifBlank {
            "$DEFAULT_AUTH_AGENT/${clientVersionFromAppVersion(activeCredentials.appVersion)}/$DEFAULT_LANGUAGE"
        }

    private fun loginUserAgent(): String =
        activeCredentials.userAgent.ifBlank {
            defaultUserAgent(
                agent = authAgent(),
                version = clientVersionFromAppVersion(activeCredentials.appVersion),
                osVersion = DEFAULT_OS_VERSION,
                language = loginLanguage(),
            )
        }

    private fun loginLanguage(): String =
        activeCredentials.aHeader.substringAfterLast('/', DEFAULT_LANGUAGE).ifBlank { DEFAULT_LANGUAGE }

    private fun urlEncode(value: String): String =
        URLEncoder.encode(value, Charsets.UTF_8)

    private fun formBody(values: Map<String, String>): String =
        values.entries.joinToString("&") { (key, value) ->
            "${urlEncode(key)}=${urlEncode(value)}"
        }

    private fun buildUrl(path: String, query: Map<String, String> = emptyMap()): String {
        val base = "$BASE_URL/$path"
        if (query.isEmpty()) {
            return base
        }
        val suffix =
            query.entries.joinToString("&") { (key, value) ->
                "${urlEncode(key)}=${urlEncode(value)}"
        }
        return "$base?$suffix"
    }

    private fun encodeIdList(ids: List<Long>): String =
        ids.joinToString(prefix = "[", postfix = "]")

    private fun jsonElementToFormValue(element: JsonElement): String =
        element.jsonPrimitive.contentOrNull ?: element.toString()

    private fun stringElement(value: String) = kotlinx.serialization.json.JsonPrimitive(value)

    private fun parseJsonObject(body: String): JsonObject =
        if (body.isBlank()) {
            JsonObject(mapOf("status" to kotlinx.serialization.json.JsonPrimitive(0)))
        } else {
            json.parseToJsonElement(body).jsonObject
        }

    private fun attachmentUploadHeaders(): Map<String, String> =
        linkedMapOf(
            HttpHeaders.Accept to "*/*",
            HttpHeaders.AcceptLanguage to loginLanguage(),
            HttpHeaders.UserAgent to loginUserAgent(),
        )

    private fun attachmentUploadHosts(kind: String): List<String> =
        when (kind) {
            "video" -> listOf("up-v.talk.kakao.com")
            "audio" -> listOf("up-a.talk.kakao.com")
            else -> listOf("up-p.talk.kakao.com", "up-gp.talk.kakao.com", "up-m.talk.kakao.com")
        }

    private fun resolveAttachmentContentType(kind: String, fileName: String, explicit: String?): String =
        explicit?.takeIf { it.isNotBlank() }
            ?: guessContentType(fileName)
            ?: when (kind) {
                "contact" -> "text/x-vcard"
                "video" -> "video/mp4"
                "audio" -> "audio/m4a"
                else -> "image/jpeg"
            }

    private fun resolveOpenUploadContentType(fileName: String, explicit: String?): String =
        explicit?.takeIf { it.isNotBlank() }
            ?: guessContentType(fileName)
            ?: "image/jpeg"

    private fun guessContentType(fileName: String): String? =
        when (fileName.substringAfterLast('.', "").lowercase(Locale.ROOT)) {
            "jpg", "jpeg" -> "image/jpeg"
            "png" -> "image/png"
            "gif" -> "image/gif"
            "webp" -> "image/webp"
            "bmp" -> "image/bmp"
            "mp4" -> "video/mp4"
            "mov" -> "video/quicktime"
            "m4a" -> "audio/m4a"
            "mp3" -> "audio/mpeg"
            "wav" -> "audio/wav"
            "vcf" -> "text/x-vcard"
            "txt" -> "text/plain"
            "pdf" -> "application/pdf"
            else -> null
        }

    private suspend fun executeMultipartRequest(
        url: String,
        headers: Map<String, String> = emptyMap(),
        fields: Map<String, String> = emptyMap(),
        fileFieldName: String,
        fileName: String,
        fileContentType: String,
        data: ByteArray,
    ): String {
        val boundary = "----KakaoKotlin${System.currentTimeMillis()}"
        val payload =
            buildMultipartPayload(
                boundary = boundary,
                fields = fields,
                fileFieldName = fileFieldName,
                fileName = fileName,
                fileContentType = fileContentType,
                data = data,
            )
        val response =
            client.post(url) {
                headers.forEach { (key, value) -> header(key, value) }
                header(HttpHeaders.ContentType, "multipart/form-data; boundary=$boundary")
                setBody(payload)
            }
        val body = response.bodyAsText()
        if (response.status.value !in 200..299) {
            error("multipart upload failed status=${response.status.value} url=$url body=${body.take(200)}")
        }
        return body
    }

    private fun buildMultipartPayload(
        boundary: String,
        fields: Map<String, String>,
        fileFieldName: String,
        fileName: String,
        fileContentType: String,
        data: ByteArray,
    ): ByteArray {
        val lineBreak = "\r\n"
        val output = ByteArrayOutputStream()

        fun writeText(value: String) {
            output.write(value.toByteArray(Charsets.UTF_8))
        }

        fields.forEach { (key, value) ->
            writeText("--$boundary$lineBreak")
            writeText("Content-Disposition: form-data; name=\"$key\"$lineBreak$lineBreak")
            writeText(value)
            writeText(lineBreak)
        }

        writeText("--$boundary$lineBreak")
        writeText("Content-Disposition: form-data; name=\"$fileFieldName\"; filename=\"$fileName\"$lineBreak")
        writeText("Content-Type: $fileContentType$lineBreak$lineBreak")
        output.write(data)
        writeText(lineBreak)
        writeText("--$boundary--$lineBreak")

        return output.toByteArray()
    }

    private suspend fun <T> executeOpenUpload(
        path: String,
        fileName: String,
        data: ByteArray,
        contentType: String,
        parser: (String) -> T,
    ): T {
        val failures = mutableListOf<String>()
        for (baseUrl in openUploadBaseUrls()) {
            try {
                val body =
                    executeMultipartRequest(
                        url = "$baseUrl/$path",
                        fileFieldName = "file_1",
                        fileName = fileName,
                        fileContentType = contentType,
                        data = data,
                    )
                return parser(body)
            } catch (error: Throwable) {
                failures += "$baseUrl/$path -> ${error.message ?: error::class.simpleName.orEmpty()}"
            }
        }
        error(failures.joinToString(separator = "; ").ifBlank { "open upload failed path=$path" })
    }

    private fun parseOpenProfileUpload(body: String): OpenProfileUpload {
        val payload = parseJsonObject(body)
        val accessKey = payload["access_key"]?.jsonPrimitive?.contentOrNull ?: error("missing access_key")
        return OpenProfileUpload(accessKey = accessKey)
    }

    private fun parseOpenProfilePostUpload(body: String): OpenProfilePostUpload {
        val payload = parseJsonObject(body)
        val accessKey = payload["access_key"]?.jsonPrimitive?.contentOrNull ?: error("missing access_key")
        val info = payload["info"]?.jsonObject ?: error("missing info")
        return OpenProfilePostUpload(
            accessKey = accessKey,
            info =
                OpenPostUploadInfo(
                    original = parseOpenPostUploadInfoItem(info["original"]?.jsonObject ?: error("missing original info")),
                    small = parseOpenPostUploadInfoItem(info["small"]?.jsonObject ?: error("missing small info")),
                    large = parseOpenPostUploadInfoItem(info["large"]?.jsonObject ?: error("missing large info")),
                ),
        )
    }

    private fun parseOpenPostUploadInfoItem(payload: JsonObject): OpenPostUploadInfoItem =
        OpenPostUploadInfoItem(
            filename = payload["filename"]?.jsonPrimitive?.contentOrNull.orEmpty(),
            width = payload["width"]?.jsonPrimitive?.contentOrNull?.toIntOrNull() ?: 0,
            contentType = payload["content_type"]?.jsonPrimitive?.contentOrNull.orEmpty(),
            length = payload["length"]?.jsonPrimitive?.contentOrNull?.toLongOrNull() ?: 0L,
            height = payload["height"]?.jsonPrimitive?.contentOrNull?.toIntOrNull() ?: 0,
        )

    private suspend fun executeAuthorizedRequest(method: HttpMethod, url: String, body: String?): JsonObject {
        val response = when (method) {
            HttpMethod.GET ->
                client.get(url) {
                    accept(ContentType.Application.Json)
                    header(HttpHeaders.Authorization, activeCredentials.authorizationToken())
                    header(HttpHeaders.AcceptLanguage, loginLanguage())
                    header("A", loginAHeader())
                    header("User-Agent", loginUserAgent())
                }

            HttpMethod.POST ->
                client.post(url) {
                    accept(ContentType.Application.Json)
                    contentType(ContentType.Application.FormUrlEncoded)
                    header(HttpHeaders.Authorization, activeCredentials.authorizationToken())
                    header(HttpHeaders.AcceptLanguage, loginLanguage())
                    header("A", loginAHeader())
                    header("User-Agent", loginUserAgent())
                    setBody(body.orEmpty())
                }
        }
        return parseJsonObject(response.bodyAsText())
    }

    enum class HttpMethod {
        GET,
        POST,
    }

    companion object {
        private const val BASE_URL = "https://katalk.kakao.com"
        private const val PILSNER_URL = "https://talk-pilsner.kakao.com"
        private const val DEFAULT_AUTH_AGENT = "win32"
        private const val DEFAULT_OS_VERSION = "10.0"
        private const val DEFAULT_LANGUAGE = "ko"
        private const val STATUS_EXPIRED = -950L
        private const val STATUS_DISCONNECTED = -998L

        fun generateXvc(userAgent: String, loginId: String, deviceUuid: String): String {
            val input = "JAYDEN|$userAgent|JAYMOND|$loginId|$deviceUuid"
            val digest = MessageDigest.getInstance("SHA-512").digest(input.toByteArray())
            return digest.joinToString("") { byte -> "%02x".format(byte) }.take(16)
        }

        fun clientVersionFromAppVersion(appVersion: String): String =
            appVersion.split('.').take(3).joinToString(".").ifBlank { appVersion }

        fun defaultUserAgent(agent: String, version: String, osVersion: String, language: String): String {
            val osPrefix =
                when (agent) {
                    "mac" -> "Mc"
                    "android" -> "An"
                    else -> "Wd"
                }
            return "KT/$version $osPrefix/$osVersion $language"
        }

        fun createSessionUrl(token: String, redirectUrl: String): String =
            "https://accounts.kakao.com/weblogin/login_redirect?continue=${URLEncoder.encode(redirectUrl, Charsets.UTF_8)}&token=$token"

        fun openLinkOriginalImageUrl(accessKey: String): String =
            "http://open.kakaocdn.net/dn/$accessKey/img.jpg"

        fun openLinkSmallImageUrl(accessKey: String): String =
            "http://open.kakaocdn.net/dn/$accessKey/img_s.jpg"

        fun openLinkLargeImageUrl(accessKey: String): String =
            "http://open.kakaocdn.net/dn/$accessKey/img_l.jpg"
    }

    private fun openUploadBaseUrls(): List<String> =
        listOf(
            "https://up-api1-kage.kakao.com",
            "https://up.api1.kage.kakao.com",
        )
}
