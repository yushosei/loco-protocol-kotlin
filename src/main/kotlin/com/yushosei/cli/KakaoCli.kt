package com.yushosei.cli

import com.yushosei.api.CredentialsExtractResponse
import com.yushosei.auth.CredentialsStore
import com.yushosei.auth.KakaoCredentialExtractor
import com.yushosei.loco.BsonSupport
import com.yushosei.loco.LocoClient
import com.yushosei.model.KakaoCredentials
import com.yushosei.rest.KakaoRestClient
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import kotlin.io.path.exists

object KakaoCli {
    private const val checkinWatchKinds = "runtime_log,http_request,keyword,tcp_connection"
    private const val checkinWatchKeywords = "ticket-loco.kakao.com,booking-loco.kakao.com,CHECKIN,GETCONF,LOGINLIST"
    private const val checkinWatchRuntimeContains = "CHECKIN,GETCONF,LOGINLIST,ticket-loco,booking-loco,handshake,secure,tls,ssl,connect,port"
    private const val defaultAuthAppVersion = "3.2.3.2698"
    private const val defaultAuthAgent = "win32"
    private const val defaultAuthOsVersion = "10.0"
    private const val defaultAuthLanguage = "ko"

    private val json = Json {
        prettyPrint = true
        ignoreUnknownKeys = true
        encodeDefaults = true
        isLenient = true
    }

    fun run(args: List<String>): Int {
        if (args.isEmpty()) {
            printUsage()
            return 0
        }

        val command = args.first().lowercase()
        val parsed = ParsedArgs.parse(args.drop(1))

        return runCatching {
            when (command) {
                "help", "--help", "-h" -> {
                    printUsage()
                    0
                }

                "bootstrap" -> handleBootstrap(parsed)
                "api-list", "apis", "endpoints" -> {
                    printApiList(verbose = parsed.booleanOption("verbose", false))
                    0
                }
                "extract" -> handleExtract(parsed)
                "credentials" -> handleCredentials()
                "refresh" -> handleRefresh(parsed)
                "manual-login", "auth-login" -> handleManualLogin(parsed)
                "passcode-request" -> handlePasscodeRequest(parsed)
                "passcode-register" -> handlePasscodeRegister(parsed)
                "friend-search" -> handleFriendSearch(parsed)
                "friend-find" -> handleFriendFind(parsed)
                "friend-add" -> handleFriendAdd(parsed)
                "friend-add-by-phone" -> handleFriendAddByPhone(parsed)
                "login" -> handleLocoLogin()
                "rooms" -> handleRooms(parsed)
                "room", "chat" -> handleRoom(parsed)
                "read" -> handleRead(parsed)
                "send" -> handleSend(parsed)
                "settings" -> handleSettings()
                "profile" -> handleProfile()
                "friends" -> handleFriends()
                "chats" -> handleChats(parsed)
                "members" -> handleMembers(parsed)
                "messages" -> handleMessages(parsed)
                "watch-memory" -> handleWatchMemory(parsed, runtimeOnly = false)
                "watch-runtime" -> handleWatchMemory(parsed, runtimeOnly = true)
                "watch-checkin" -> handleWatchCheckin(parsed)
                else -> error("unknown command: $command")
            }
        }.getOrElse { error ->
            System.err.println(error.message ?: (error::class.simpleName ?: "command failed"))
            1
        }
    }

    private fun handleBootstrap(parsed: ParsedArgs): Int {
        val normalized =
            parsed.withDefaults(
                options =
                    linkedMapOf(
                        "save" to "true",
                        "refresh" to "true",
                        "verify-rest" to "true",
                    ),
            )
        return handleExtract(normalized)
    }

    private fun handleExtract(parsed: ParsedArgs): Int {
        val maxCandidates = parsed.intOption("max-candidates", 8)
        val save = parsed.booleanOption("save", true)
        val refresh = parsed.booleanOption("refresh", true)
        val verifyRest = parsed.booleanOption("verify-rest", refresh)

        val candidates = KakaoCredentialExtractor.getCredentialCandidates(maxCandidates)
        val selected = candidates.firstOrNull()
        val refreshed = refreshExtractedCredentials(selected, refresh)
        val resolved = backfillUserIdFromRest(refreshed.credentials)
        val restVerified = verifyRestLogin(resolved, verifyRest)
        val shouldPersist = save && canPersistCredentials(resolved, restVerified)

        if (shouldPersist && resolved != null) {
            CredentialsStore.save(resolved)
        }

        printJson(
            CredentialsExtractResponse(
                saved = shouldPersist && resolved != null,
                refreshed = refreshed.refreshed,
                refreshStatus = refreshed.refreshStatus,
                restVerified = restVerified,
                selected = resolved,
                candidates = candidates,
            ),
        )
        return if (resolved != null) 0 else 1
    }

    private fun handleCredentials(): Int {
        val credentials = requireStoredCredentials()
        printJson(credentials)
        return 0
    }

    private fun handleRefresh(parsed: ParsedArgs): Int {
        val stored = requireStoredCredentials()
        val refreshToken = parsed.stringOption("refresh-token") ?: stored.refreshToken.orEmpty()
        require(refreshToken.isNotBlank()) { "refresh token not available" }
        val save = parsed.booleanOption("save", true)
        val verifyRest = parsed.booleanOption("verify-rest", true)

        KakaoRestClient(stored).use { client ->
            val response = client.renewOAuth(refreshToken)
            val status = response.statusOrNull()
            val updated =
                if (status == 0L) {
                    client.currentCredentials()
                } else {
                    null
                }
            val saved =
                if (save && updated != null) {
                    CredentialsStore.save(updated)
                    true
                } else {
                    false
                }

            printJson(
                CliRefreshResult(
                    success = status == 0L && updated != null,
                    status = status,
                    saved = saved,
                    restVerified = verifyRestLogin(updated, verifyRest),
                    credentials = updated,
                    response = response,
                ),
            )
        }
        return 0
    }

    private fun handleLocoLogin(): Int {
        val stored = prepareLocoCredentials()
        return LocoClient(stored).use { client ->
            val response = client.fullConnect()
            printJson(response)
            if (response.statusOrNull().let { it == null || it == 0L }) 0 else 1
        }
    }

    private fun handleManualLogin(parsed: ParsedArgs): Int {
        val resolved =
            resolveManualLoginContext(
                email = parsed.stringOption("email") ?: parsed.positional.getOrNull(0),
                password = parsed.stringOption("password") ?: parsed.positional.getOrNull(1),
                deviceUuid = parsed.stringOption("device-uuid"),
                deviceName = parsed.stringOption("device-name"),
                useCachedParams = parsed.booleanOption("use-cached-params", true),
            )
        val provisional =
            buildProvisionalCredentials(
                appVersion = parsed.stringOption("app-version") ?: defaultAuthAppVersion,
                agent = parsed.stringOption("agent") ?: defaultAuthAgent,
                osVersion = parsed.stringOption("os-version") ?: defaultAuthOsVersion,
                language = parsed.stringOption("language") ?: defaultAuthLanguage,
                userAgent = parsed.stringOption("user-agent"),
                aHeader = parsed.stringOption("a-header"),
                deviceUuid = resolved.deviceUuid,
                deviceName = resolved.deviceName,
            )
        val save = parsed.booleanOption("save", true)
        val verifyRest = parsed.booleanOption("verify-rest", true)
        val verifyLoco = parsed.booleanOption("verify-loco", false)
        val forced = parsed.booleanOption("forced", false)

        KakaoRestClient(provisional).use { client ->
            val response =
                client.loginWithXvc(
                    email = resolved.email,
                    password = resolved.password,
                    deviceUuid = resolved.deviceUuid,
                    deviceName = resolved.deviceName,
                    forced = forced,
                )
            val credentials = buildCredentialsFromLoginResponse(provisional, response)
            val saved =
                if (save && credentials != null) {
                    CredentialsStore.save(credentials)
                    true
                } else {
                    false
                }
            printJson(
                CliManualLoginResult(
                    success = response.statusOrNull() == 0L && credentials != null,
                    status = response.statusOrNull(),
                    usedCachedParams = resolved.usedCachedParams,
                    saved = saved,
                    restVerified = verifyRestLogin(credentials, verifyRest),
                    locoVerified = verifyLocoLogin(credentials, verifyLoco),
                    credentials = credentials,
                    response = response,
                ),
            )
            return if (response.statusOrNull() == 0L && credentials != null) 0 else 1
        }
    }

    private fun handlePasscodeRequest(parsed: ParsedArgs): Int {
        val resolved =
            resolveManualLoginContext(
                email = parsed.stringOption("email") ?: parsed.positional.getOrNull(0),
                password = parsed.stringOption("password") ?: parsed.positional.getOrNull(1),
                deviceUuid = parsed.stringOption("device-uuid"),
                deviceName = parsed.stringOption("device-name"),
                useCachedParams = parsed.booleanOption("use-cached-params", true),
            )
        val provisional =
            buildProvisionalCredentials(
                appVersion = parsed.stringOption("app-version") ?: defaultAuthAppVersion,
                agent = parsed.stringOption("agent") ?: defaultAuthAgent,
                osVersion = parsed.stringOption("os-version") ?: defaultAuthOsVersion,
                language = parsed.stringOption("language") ?: defaultAuthLanguage,
                userAgent = parsed.stringOption("user-agent"),
                aHeader = parsed.stringOption("a-header"),
                deviceUuid = resolved.deviceUuid,
                deviceName = resolved.deviceName,
            )
        KakaoRestClient(provisional).use { client ->
            val response =
                client.requestPasscode(
                    email = resolved.email,
                    password = resolved.password,
                    deviceUuid = resolved.deviceUuid,
                    deviceName = resolved.deviceName,
                )
            printJson(
                CliPasscodeRequestResult(
                    success = response.statusOrNull() == 0L,
                    status = response.statusOrNull(),
                    usedCachedParams = resolved.usedCachedParams,
                    response = response,
                ),
            )
            return if (response.statusOrNull() == 0L) 0 else 1
        }
    }

    private fun handlePasscodeRegister(parsed: ParsedArgs): Int {
        val passcode =
            parsed.stringOption("passcode")
                ?: parsed.positional.getOrNull(2)
                ?: error("passcode is required")
        val resolved =
            resolveManualLoginContext(
                email = parsed.stringOption("email") ?: parsed.positional.getOrNull(0),
                password = parsed.stringOption("password") ?: parsed.positional.getOrNull(1),
                deviceUuid = parsed.stringOption("device-uuid"),
                deviceName = parsed.stringOption("device-name"),
                useCachedParams = parsed.booleanOption("use-cached-params", true),
            )
        val provisional =
            buildProvisionalCredentials(
                appVersion = parsed.stringOption("app-version") ?: defaultAuthAppVersion,
                agent = parsed.stringOption("agent") ?: defaultAuthAgent,
                osVersion = parsed.stringOption("os-version") ?: defaultAuthOsVersion,
                language = parsed.stringOption("language") ?: defaultAuthLanguage,
                userAgent = parsed.stringOption("user-agent"),
                aHeader = parsed.stringOption("a-header"),
                deviceUuid = resolved.deviceUuid,
                deviceName = resolved.deviceName,
            )
        val save = parsed.booleanOption("save", true)
        val verifyRest = parsed.booleanOption("verify-rest", true)
        val verifyLoco = parsed.booleanOption("verify-loco", false)
        val forced = parsed.booleanOption("forced", false)
        val permanent = parsed.booleanOption("permanent", true)

        KakaoRestClient(provisional).use { client ->
            val registerResponse =
                client.registerDevice(
                    email = resolved.email,
                    password = resolved.password,
                    deviceUuid = resolved.deviceUuid,
                    deviceName = resolved.deviceName,
                    passcode = passcode,
                    permanent = permanent,
                )

            var loginResponse: JsonObject? = null
            var credentials: KakaoCredentials? = null
            var saved = false
            var restVerified: Boolean? = null
            var locoVerified: Boolean? = null

            if (registerResponse.statusOrNull() == 0L) {
                loginResponse =
                    client.loginWithXvc(
                        email = resolved.email,
                        password = resolved.password,
                        deviceUuid = resolved.deviceUuid,
                        deviceName = resolved.deviceName,
                        forced = forced,
                    )
                credentials = buildCredentialsFromLoginResponse(provisional, loginResponse)
                saved =
                    if (save && credentials != null) {
                        CredentialsStore.save(credentials)
                        true
                    } else {
                        false
                    }
                restVerified = verifyRestLogin(credentials, verifyRest)
                locoVerified = verifyLocoLogin(credentials, verifyLoco)
            }

            printJson(
                CliPasscodeRegisterResult(
                    success = registerResponse.statusOrNull() == 0L && loginResponse?.statusOrNull() == 0L && credentials != null,
                    registerStatus = registerResponse.statusOrNull(),
                    loginStatus = loginResponse?.statusOrNull(),
                    usedCachedParams = resolved.usedCachedParams,
                    saved = saved,
                    restVerified = restVerified,
                    locoVerified = locoVerified,
                    credentials = credentials,
                    registerResponse = registerResponse,
                    loginResponse = loginResponse,
                ),
            )
            return if (registerResponse.statusOrNull() == 0L && loginResponse?.statusOrNull() == 0L && credentials != null) 0 else 1
        }
    }

    private fun handleFriendSearch(parsed: ParsedArgs): Int =
        useStoredRestClient { client ->
            val query =
                parsed.stringOption("query")
                    ?: parsed.positional.getOrNull(0)
                    ?: error("query is required")
            val pageNum = parsed.intOptionOrNull("page-num")
            val pageSize = parsed.intOptionOrNull("page-size")
            val response = client.searchFriends(query, pageNum, pageSize)
            printJson(
                CliRestActionResult(
                    action = "friend-search",
                    success = response.statusOrNull() == 0L,
                    status = response.statusOrNull(),
                    response = response,
                ),
            )
            if (response.statusOrNull() == 0L) 0 else 1
        }

    private fun handleFriendFind(parsed: ParsedArgs): Int =
        useStoredRestClient { client ->
            val userId = parsed.requiredLongPositional(0, "userId")
            val response = client.findFriendById(userId)
            printJson(
                CliRestActionResult(
                    action = "friend-find",
                    success = response.statusOrNull() == 0L,
                    status = response.statusOrNull(),
                    response = response,
                ),
            )
            if (response.statusOrNull() == 0L) 0 else 1
        }

    private fun handleFriendAdd(parsed: ParsedArgs): Int =
        useStoredRestClient { client ->
            val userId = parsed.requiredLongPositional(0, "userId")
            val pa = parsed.stringOption("pa") ?: ""
            val refreshDiff = parsed.booleanOption("refresh-diff", true)
            val response = client.addFriend(userId, pa)
            val diff = if (refreshDiff) client.requestFriendsDiff() else null
            printJson(
                CliRestActionResult(
                    action = "friend-add",
                    success = response.statusOrNull() == 0L,
                    status = response.statusOrNull(),
                    diffStatus = diff?.statusOrNull(),
                    response = response,
                    diff = diff,
                ),
            )
            if (response.statusOrNull() == 0L) 0 else 1
        }

    private fun handleFriendAddByPhone(parsed: ParsedArgs): Int =
        useStoredRestClient { client ->
            val nickname =
                parsed.stringOption("nickname")
                    ?: error("nickname is required")
            val phoneNumber =
                parsed.stringOption("phone-number")
                    ?: parsed.stringOption("phone")
                    ?: error("phone-number is required")
            val countryIso = parsed.stringOption("country-iso") ?: "KR"
            val countryCode = parsed.stringOption("country-code") ?: "82"
            val refreshDiff = parsed.booleanOption("refresh-diff", true)
            val response =
                client.addFriendByPhoneNumber(
                    nickname = nickname,
                    countryIso = countryIso,
                    countryCode = countryCode,
                    phoneNumber = phoneNumber,
                )
            val diff = if (refreshDiff) client.requestFriendsDiff() else null
            printJson(
                CliRestActionResult(
                    action = "friend-add-by-phone",
                    success = response.statusOrNull() == 0L,
                    status = response.statusOrNull(),
                    diffStatus = diff?.statusOrNull(),
                    response = response,
                    diff = diff,
                ),
            )
            if (response.statusOrNull() == 0L) 0 else 1
        }

    private fun handleRooms(parsed: ParsedArgs): Int =
        useConnectedLocoClient { client ->
            val limit = parsed.intOption("limit", 50).coerceAtLeast(1)
            printJson(client.listChats().take(limit))
            0
        }

    private fun handleRoom(parsed: ParsedArgs): Int =
        useConnectedLocoClient { client ->
            val chatId = parsed.requiredLongPositional(0, "chatId")
            printJson(BsonSupport.toJson(client.getChatInfo(chatId)))
            0
        }

    private fun handleRead(parsed: ParsedArgs): Int =
        useConnectedLocoClient { client ->
            val chatId = parsed.requiredLongPositional(0, "chatId")
            val cursor = parsed.longOption("cursor")
            val fetchAll = parsed.booleanOption("fetch-all", false)
            val limit = parsed.intOption("limit", 30)
            val delayMs = parsed.longOption("delay-ms") ?: 0L
            val allowOpenChatUnsafe = parsed.booleanOption("allow-open-chat-unsafe", false)
            printJson(
                client.readMessages(
                    chatId = chatId,
                    cursor = cursor,
                    fetchAll = fetchAll,
                    limit = limit,
                    delayMs = delayMs,
                    allowOpenChatUnsafe = allowOpenChatUnsafe,
                ),
            )
            0
        }

    private fun handleSend(parsed: ParsedArgs): Int =
        useConnectedLocoClient { client ->
            val chatId = parsed.requiredLongPositional(0, "chatId")
            val message =
                parsed.stringOption("message")
                    ?: parsed.positional.drop(1).joinToString(" ").takeIf { it.isNotBlank() }
                    ?: error("message is required")
            val allowOpenChatUnsafe = parsed.booleanOption("allow-open-chat-unsafe", false)
            printJson(client.sendTextMessage(chatId, message, allowOpenChatUnsafe))
            0
        }

    private fun handleSettings(): Int =
        useStoredRestClient {
            printJson(it.getSettings())
            0
        }

    private fun handleProfile(): Int =
        useStoredRestClient {
            printJson(it.getMyProfile())
            0
        }

    private fun handleFriends(): Int =
        useStoredRestClient {
            printJson(it.getFriends())
            0
        }

    private fun handleChats(parsed: ParsedArgs): Int =
        useStoredRestClient { client ->
            val all = parsed.booleanOption("all", true)
            val result = if (all) client.getAllChats() else client.getChats(null).rooms
            printJson(result)
            0
        }

    private fun handleMembers(parsed: ParsedArgs): Int =
        useStoredRestClient { client ->
            val chatId = parsed.requiredLongPositional(0, "chatId")
            printJson(client.getChatMembers(chatId))
            0
        }

    private fun handleMessages(parsed: ParsedArgs): Int =
        useStoredRestClient { client ->
            val chatId = parsed.requiredLongPositional(0, "chatId")
            val cursor = parsed.longOption("cursor")
            val maxPages = parsed.intOption("max-pages", 10)
            if (cursor == null) {
                printJson(client.getAllMessages(chatId, maxPages))
            } else {
                printJson(client.getMessages(chatId, cursor))
            }
            0
        }

    private fun handleWatchMemory(parsed: ParsedArgs, runtimeOnly: Boolean): Int {
        val only =
            when {
                runtimeOnly -> parsed.stringOption("only") ?: "runtime_log"
                else -> parsed.stringOption("only")
            }
        val prime = if (runtimeOnly) parsed.booleanOption("prime", true) else parsed.booleanOption("prime", false)
        return runInteractive(buildWatchMemoryCommand(parsed, only = only, prime = prime))
    }

    private fun handleWatchCheckin(parsed: ParsedArgs): Int {
        val only = parsed.stringOption("only") ?: checkinWatchKinds
        val prime = parsed.booleanOption("prime", true)
        val keyword = parsed.stringOption("keyword") ?: checkinWatchKeywords
        val runtimeContains = parsed.stringOption("runtime-contains") ?: checkinWatchRuntimeContains
        val includeConnections = parsed.booleanOption("connections", true)
        return runInteractive(
            buildWatchMemoryCommand(
                parsed,
                only = only,
                prime = prime,
                keyword = keyword,
                runtimeContains = runtimeContains,
                connections = includeConnections,
                replaceKeywords = true,
            ),
        )
    }

    private fun buildWatchMemoryCommand(
        parsed: ParsedArgs,
        only: String?,
        prime: Boolean,
        keyword: String? = parsed.stringOption("keyword"),
        runtimeContains: String? = parsed.stringOption("runtime-contains"),
        connections: Boolean = parsed.booleanOption("connections", false),
        replaceKeywords: Boolean = parsed.booleanOption("replace-keywords", false),
    ): List<String> {
        val script = requireScriptPath("scripts", "kakao_memory_watch.py")
        val interval = parsed.stringOption("interval") ?: "1"
        val duration = parsed.stringOption("duration")
        val jsonl = parsed.stringOption("jsonl")

        val command = mutableListOf("python", script.toString(), "--interval", interval)
        if (!duration.isNullOrBlank()) {
            command += listOf("--duration", duration)
        }
        if (!only.isNullOrBlank()) {
            command += listOf("--only", only)
        }
        if (prime) {
            command += "--prime"
        }
        if (!keyword.isNullOrBlank()) {
            command += listOf("--keyword", keyword)
        }
        if (replaceKeywords) {
            command += "--replace-keywords"
        }
        if (!runtimeContains.isNullOrBlank()) {
            command += listOf("--runtime-contains", runtimeContains)
        }
        if (connections) {
            command += "--connections"
        }
        if (!jsonl.isNullOrBlank()) {
            command += listOf("--jsonl", jsonl)
        }
        return command
    }

    private inline fun <T> useStoredRestClient(block: (KakaoRestClient) -> T): T {
        val stored = requireStoredOrExtractedCredentials()
        return KakaoRestClient(stored).use { client ->
            val result = block(client)
            val updated = client.currentCredentials()
            if (updated != stored) {
                CredentialsStore.save(updated)
            }
            result
        }
    }

    private inline fun <T> useConnectedLocoClient(block: (LocoClient) -> T): T {
        val stored = prepareLocoCredentials()
        return LocoClient(stored).use { client ->
            val login = client.fullConnect()
            login.statusOrNull()?.takeIf { it != 0L }?.let { status ->
                error("LOCO login failed with status=$status; run `bootstrap` first")
            }
            block(client)
        }
    }

    private fun prepareLocoCredentials(): KakaoCredentials {
        val stored = backfillUserIdFromRest(requireStoredOrExtractedCredentials()) ?: requireStoredOrExtractedCredentials()
        val refreshToken = stored.refreshToken?.takeIf { it.isNotBlank() } ?: return stored
        return runCatching {
            KakaoRestClient(stored).use { client ->
                val response = client.renewOAuth(refreshToken)
                if (response.statusOrNull() == 0L) {
                    client.currentCredentials().also { updated ->
                        if (updated != stored) {
                            CredentialsStore.save(updated)
                        }
                    }
                } else {
                    stored
                }
            }
        }.getOrElse { stored }
    }

    private fun backfillUserIdFromRest(credentials: KakaoCredentials?): KakaoCredentials? {
        if (credentials == null || credentials.userId > 0L) {
            return credentials
        }
        return runCatching {
            KakaoRestClient(credentials).use { client ->
                val profile = client.getMyProfile()
                if (profile.userId > 0L) {
                    credentials.copy(userId = profile.userId)
                } else {
                    credentials
                }
            }
        }.getOrElse { credentials }
    }

    private fun resolveManualLoginContext(
        email: String?,
        password: String?,
        deviceUuid: String?,
        deviceName: String?,
        useCachedParams: Boolean,
    ): ResolvedManualLoginContext {
        val cached = if (useCachedParams) KakaoCredentialExtractor.extractLoginParams() else null
        val stored = CredentialsStore.load()

        fun requireField(primary: String?, fallback: String?, field: String): String =
            primary?.takeIf { it.isNotBlank() }
                ?: fallback?.takeIf { it.isNotBlank() }
                ?: throw IllegalArgumentException("$field is required")

        return ResolvedManualLoginContext(
            email = requireField(email, cached?.email, "email"),
            password = requireField(password, cached?.password, "password"),
            deviceUuid = requireField(deviceUuid, cached?.deviceUuid ?: stored?.deviceUuid, "deviceUuid"),
            deviceName = requireField(deviceName, cached?.deviceName ?: stored?.deviceName, "deviceName"),
            usedCachedParams = cached != null,
        )
    }

    private fun buildProvisionalCredentials(
        appVersion: String,
        agent: String,
        osVersion: String,
        language: String,
        userAgent: String?,
        aHeader: String?,
        deviceUuid: String,
        deviceName: String,
    ): KakaoCredentials {
        val clientVersion = KakaoRestClient.clientVersionFromAppVersion(appVersion)
        val resolvedAHeader = aHeader?.takeIf { it.isNotBlank() } ?: "$agent/$clientVersion/$language"
        val resolvedUserAgent =
            userAgent?.takeIf { it.isNotBlank() }
                ?: KakaoRestClient.defaultUserAgent(
                    agent = agent,
                    version = clientVersion,
                    osVersion = osVersion,
                    language = language,
                )
        return KakaoCredentials(
            oauthToken = "",
            userId = 0,
            deviceUuid = deviceUuid,
            deviceName = deviceName,
            appVersion = appVersion,
            userAgent = resolvedUserAgent,
            aHeader = resolvedAHeader,
        )
    }

    private fun buildCredentialsFromLoginResponse(base: KakaoCredentials, response: JsonObject): KakaoCredentials? {
        val accessToken = response["access_token"]?.jsonPrimitive?.contentOrNull?.takeIf { it.isNotBlank() } ?: return null
        val userId =
            response["userId"]?.jsonPrimitive?.longOrNull
                ?: response["user_id"]?.jsonPrimitive?.longOrNull
                ?: base.userId
        return base.withUpdatedTokens(
            accessToken = accessToken,
            refreshToken = response["refresh_token"]?.jsonPrimitive?.contentOrNull ?: base.refreshToken,
        ).copy(userId = userId)
    }

    private fun requireStoredCredentials(): KakaoCredentials =
        CredentialsStore.load() ?: error("stored credentials not found; run `extract` first")

    private fun requireStoredOrExtractedCredentials(): KakaoCredentials {
        val stored = CredentialsStore.load()
        if (credentialScore(stored) >= 4) {
            return stored!!
        }
        val candidates = KakaoCredentialExtractor.getCredentialCandidates(5)
        val selected = candidates.firstOrNull() ?: error("no stored credentials and no live session found; run `extract` first")
        val extracted =
            backfillUserIdFromRest(
                refreshExtractedCredentials(selected, enabled = true).credentials ?: selected,
            ) ?: selected
        val preferred =
            listOfNotNull(stored, extracted)
                .maxByOrNull(::credentialScore)
                ?: error("no usable credentials found; run `bootstrap` first")
        if (preferred != stored && canPersistCredentials(preferred, restVerified = null)) {
            CredentialsStore.save(preferred)
        }
        return preferred
    }

    private fun verifyRestLogin(credentials: KakaoCredentials?, enabled: Boolean): Boolean? =
        if (enabled && credentials != null) {
            runCatching { KakaoRestClient(credentials).use { it.verifyToken() } }.getOrNull()
        } else {
            null
        }

    private fun verifyLocoLogin(credentials: KakaoCredentials?, enabled: Boolean): Boolean? =
        if (enabled && credentials != null) {
            runCatching {
                LocoClient(backfillUserIdFromRest(credentials) ?: credentials).use {
                    it.fullConnect()
                    true
                }
            }.getOrNull()
        } else {
            null
        }

    private fun canPersistCredentials(credentials: KakaoCredentials?, restVerified: Boolean?): Boolean =
        credentials != null &&
            (
                credentials.userId > 0L ||
                    restVerified == true ||
                    !credentials.refreshToken.isNullOrBlank()
            )

    private fun credentialScore(credentials: KakaoCredentials?): Int {
        if (credentials == null) {
            return Int.MIN_VALUE
        }
        var score = 0
        if (credentials.userId > 0L) {
            score += 4
        }
        if (!credentials.refreshToken.isNullOrBlank()) {
            score += 2
        }
        if (!credentials.authorizationHeader.isNullOrBlank()) {
            score += 1
        }
        return score
    }

    private fun refreshExtractedCredentials(credentials: KakaoCredentials?, enabled: Boolean): RefreshedCredentialsResult {
        if (!enabled || credentials == null || credentials.refreshToken.isNullOrBlank()) {
            return RefreshedCredentialsResult(credentials = credentials)
        }

        return runCatching {
            KakaoRestClient(credentials).use { client ->
                val response = client.renewOAuth(credentials.refreshToken)
                val status = response.statusOrNull()
                if (status == 0L) {
                    RefreshedCredentialsResult(
                        credentials = client.currentCredentials(),
                        refreshed = true,
                        refreshStatus = status,
                    )
                } else {
                    RefreshedCredentialsResult(
                        credentials = credentials,
                        refreshed = false,
                        refreshStatus = status,
                    )
                }
            }
        }.getOrElse {
            RefreshedCredentialsResult(credentials = credentials)
        }
    }

    private fun requireScriptPath(vararg parts: String): Path {
        val direct = Paths.get(System.getProperty("user.dir"), *parts)
        if (direct.exists()) {
            return direct
        }
        error("script not found: ${parts.joinToString("/")}")
    }

    private fun runInteractive(command: List<String>): Int {
        val process = ProcessBuilder(command).directory(Files.createDirectories(Paths.get(System.getProperty("user.dir"))).toFile()).inheritIO().start()
        return process.waitFor()
    }

    private fun JsonObject.statusOrNull(): Long? =
        this["status"]?.jsonPrimitive?.longOrNull

    private inline fun <reified T> printJson(value: T) {
        println(json.encodeToString(value))
    }

    private fun printUsage() {
        println(
            """
            사용법

            인자 없이 실행하면 대화형 셸이 열립니다.

            기본 흐름:
              bootstrap
              rooms [--limit 50]
              read <chatId> [--limit 30]
              send <chatId> --message "안녕하세요"

            세션:
              api-list [--verbose]
              bootstrap
              extract [--save] [--refresh] [--verify-rest] [--max-candidates 8]
              manual-login --email me@example.com --password secret
              passcode-request --email me@example.com --password secret
              passcode-register --email me@example.com --password secret --passcode 123456
              credentials
              refresh [--save] [--verify-rest]

            LOCO:
              login
              rooms [--limit 50]
              room <chatId>
              read <chatId> [--cursor 0] [--limit 30] [--fetch-all false] [--delay-ms 0]
              send <chatId> --message "안녕하세요" [--allow-open-chat-unsafe]

            REST:
              settings
              profile
              friends
              chats [--all true|false]
              members <chatId>
              messages <chatId> [--max-pages 10]

            확장 REST:
              friend-search <query>
              friend-find <userId>
              friend-add <userId> [--pa value]
              friend-add-by-phone --nickname TEST --phone-number 01012345678

            디버그:
              watch-memory [--interval 1] [--duration 0] [--only runtime_log] [--prime] [--connections] [--keyword csv] [--runtime-contains csv]
              watch-runtime [--interval 1] [--duration 0]
              watch-checkin [--interval 1] [--duration 0] [--jsonl trace.jsonl]

            서버:
              server
              serve
            """.trimIndent(),
        )
    }

    private fun printApiList(verbose: Boolean) {
        if (!verbose) {
            println(
                """
                주요 명령:
                  bootstrap
                  login
                  rooms
                  room
                  read
                  send

                세션:
                  extract
                  credentials
                  refresh
                  manual-login
                  passcode-request
                  passcode-register

                REST 조회:
                  profile
                  friends
                  chats
                  members
                  messages

                확장 REST:
                  friend-search
                  friend-find
                  friend-add
                  friend-add-by-phone

                전체 목록:
                  api-list --verbose
                """.trimIndent(),
            )
            return
        }

        println(
            """
            전체 API 목록

            주요 명령:
              bootstrap
              login
              rooms
              room
              read
              send

            세션:
              extract
              credentials
              refresh
              manual-login
              passcode-request
              passcode-register

            REST 조회:
              profile
              friends
              chats
              members
              messages

            확장 REST:
              friend-search
              friend-find
              friend-add
              friend-add-by-phone

            HTTP 라우트

            인증:
              POST /api/credentials/extract
              GET  /api/credentials
              POST /api/auth/refresh
              POST /api/auth/login/xvc
              POST /api/auth/passcode/request
              POST /api/auth/passcode/register

            계정/설정:
              GET  /api/rest/profile
              GET  /api/rest/profiles/me
              GET  /api/rest/settings/more
              GET  /api/rest/settings/less
              POST /api/rest/settings/update
              GET  /api/rest/account/login-token
              POST /api/rest/account/session-url
              POST /api/rest/account/can-change-uuid
              POST /api/rest/account/change-uuid

            친구:
              GET  /api/rest/friends
              POST /api/rest/friends/list
              GET  /api/rest/friends/search?query=...
              GET  /api/rest/friends/{userId}
              POST /api/rest/friends/add
              POST /api/rest/friends/add-by-phone
              POST /api/rest/friends/hide
              POST /api/rest/friends/unhide
              POST /api/rest/friends/remove
              POST /api/rest/friends/delete
              POST /api/rest/friends/nickname
              POST /api/rest/friends/favorite/add
              POST /api/rest/friends/favorite/remove
              POST /api/rest/friends/find-by-uuid
              POST /api/rest/friends/diff

            프로필:
              GET  /api/rest/profiles/list
              GET  /api/rest/profiles/designated-friends
              GET  /api/rest/profiles/friends/{userId}
              GET  /api/rest/profiles/friends/{userId}/music

            채팅/업로드:
              GET  /api/rest/chats
              GET  /api/rest/chats/{chatId}/messages
              POST /api/rest/attachments/upload
              POST /api/rest/open-upload/profile-image
              POST /api/rest/open-upload/post-image
              POST /api/rest/open-upload/build-profile
              POST /api/rest/scrap/preview

            LOCO:
              POST /api/loco/booking
              POST /api/loco/checkin
              POST /api/loco/login
              POST /api/loco/chats
              POST /api/loco/chat-info
              POST /api/loco/members
              POST /api/loco/messages/read
              POST /api/loco/messages/send
              POST /api/loco/events/watch
              POST /api/loco/command
            """.trimIndent(),
        )
    }

    @Serializable
    private data class CliRefreshResult(
        val success: Boolean,
        val status: Long?,
        val saved: Boolean,
        val restVerified: Boolean?,
        val credentials: KakaoCredentials? = null,
        val response: JsonObject,
    )

    @Serializable
    private data class CliManualLoginResult(
        val success: Boolean,
        val status: Long?,
        val usedCachedParams: Boolean,
        val saved: Boolean,
        val restVerified: Boolean?,
        val locoVerified: Boolean?,
        val credentials: KakaoCredentials? = null,
        val response: JsonObject,
    )

    @Serializable
    private data class CliPasscodeRequestResult(
        val success: Boolean,
        val status: Long?,
        val usedCachedParams: Boolean,
        val response: JsonObject,
    )

    @Serializable
    private data class CliPasscodeRegisterResult(
        val success: Boolean,
        val registerStatus: Long?,
        val loginStatus: Long?,
        val usedCachedParams: Boolean,
        val saved: Boolean,
        val restVerified: Boolean?,
        val locoVerified: Boolean?,
        val credentials: KakaoCredentials? = null,
        val registerResponse: JsonObject,
        val loginResponse: JsonObject? = null,
    )

    @Serializable
    private data class CliRestActionResult(
        val action: String,
        val success: Boolean,
        val status: Long?,
        val diffStatus: Long? = null,
        val response: JsonObject,
        val diff: JsonObject? = null,
    )

    private data class RefreshedCredentialsResult(
        val credentials: KakaoCredentials?,
        val refreshed: Boolean = false,
        val refreshStatus: Long? = null,
    )

    private data class ResolvedManualLoginContext(
        val email: String,
        val password: String,
        val deviceUuid: String,
        val deviceName: String,
        val usedCachedParams: Boolean,
    )

    private data class ParsedArgs(
        val positional: List<String>,
        val options: Map<String, String>,
        val flags: Set<String>,
    ) {
        fun booleanOption(name: String, default: Boolean): Boolean =
            when {
                options.containsKey(name) -> options.getValue(name).toBooleanStrictOrNull() ?: default
                name in flags -> true
                else -> default
            }

        fun intOption(name: String, default: Int): Int =
            options[name]?.toIntOrNull() ?: default

        fun intOptionOrNull(name: String): Int? =
            options[name]?.toIntOrNull()

        fun longOption(name: String): Long? =
            options[name]?.toLongOrNull()

        fun stringOption(name: String): String? =
            options[name]

        fun requiredLongPositional(index: Int, field: String): Long =
            positional.getOrNull(index)?.toLongOrNull() ?: error("$field is required")

        fun withDefaults(
            options: Map<String, String> = emptyMap(),
            flags: Set<String> = emptySet(),
        ): ParsedArgs =
            ParsedArgs(
                positional = positional,
                options = LinkedHashMap(options).apply { putAll(this@ParsedArgs.options) },
                flags = LinkedHashSet(flags).apply { addAll(this@ParsedArgs.flags) },
            )

        companion object {
            fun parse(args: List<String>): ParsedArgs {
                val positional = mutableListOf<String>()
                val options = linkedMapOf<String, String>()
                val flags = linkedSetOf<String>()
                var index = 0

                while (index < args.size) {
                    val token = args[index]
                    if (!token.startsWith("--")) {
                        positional += token
                        index += 1
                        continue
                    }

                    val raw = token.removePrefix("--")
                    val separator = raw.indexOf('=')
                    if (separator >= 0) {
                        val key = raw.substring(0, separator)
                        val value = raw.substring(separator + 1)
                        options[key] = value
                        index += 1
                        continue
                    }

                    val next = args.getOrNull(index + 1)
                    if (next != null && !next.startsWith("--")) {
                        options[raw] = next
                        index += 2
                    } else {
                        flags += raw
                        index += 1
                    }
                }

                return ParsedArgs(
                    positional = positional,
                    options = options,
                    flags = flags,
                )
            }
        }
    }
}
