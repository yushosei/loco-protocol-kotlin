package com.yushosei.api

import com.yushosei.loco.BsonSupport
import com.yushosei.auth.CredentialsStore
import com.yushosei.auth.KakaoCredentialExtractor
import com.yushosei.loco.LocoClient
import com.yushosei.model.Friend
import com.yushosei.model.KakaoCredentials
import com.yushosei.rest.KakaoRestClient
import com.yushosei.util.jsonLong
import com.yushosei.util.jsonString
import com.yushosei.logging.ProtocolLogEntry
import com.yushosei.logging.ProtocolLogStore
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.Application
import io.ktor.server.application.ApplicationCall
import io.ktor.server.application.call
import io.ktor.server.request.receive
import io.ktor.server.response.header
import io.ktor.server.response.respond
import io.ktor.server.response.respondTextWriter
import io.ktor.server.routing.get
import io.ktor.server.routing.post
import io.ktor.server.routing.route
import io.ktor.server.routing.routing
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.collect
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.JsonObject
import com.yushosei.loco.toJson
import java.nio.file.Files
import java.nio.file.Path

private val protocolLogJson = Json { encodeDefaults = true }

fun Application.registerRoutes() {
    routing {
        route("/api") {
            route("/credentials") {
                get {
                    val credentials = CredentialsStore.load()
                    if (credentials == null) {
                        call.respond(HttpStatusCode.NotFound, mapOf("error" to "stored credentials not found"))
                    } else {
                        call.respond(credentials)
                    }
                }

                post("/store") {
                    val request = call.receive<StoreCredentialsRequest>()
                    CredentialsStore.save(request.credentials)
                    call.respond(HttpStatusCode.Created, request.credentials)
                }

                post("/extract") {
                    val save = call.request.queryParameters["save"]?.toBoolean() ?: true
                    val maxCandidates = call.request.queryParameters["maxCandidates"]?.toIntOrNull() ?: 8
                    val refresh = call.request.queryParameters["refresh"]?.toBoolean() ?: true
                    val verifyRest = call.request.queryParameters["verifyRest"]?.toBoolean() ?: refresh
                    val candidates = KakaoCredentialExtractor.getCredentialCandidates(maxCandidates)
                    val selected = candidates.firstOrNull()
                    val refreshed = refreshExtractedCredentials(selected, refresh)
                    val resolvedSelected = refreshed.credentials
                    if (save && selected != null) {
                        CredentialsStore.save(resolvedSelected ?: selected)
                    }
                    call.respond(
                        CredentialsExtractResponse(
                            saved = save && resolvedSelected != null,
                            refreshed = refreshed.refreshed,
                            refreshStatus = refreshed.refreshStatus,
                            restVerified = verifyRestLogin(refreshed.credentials, verifyRest),
                            selected = resolvedSelected,
                            candidates = candidates,
                        ),
                    )
                }

                get("/login-params") {
                    val params = KakaoCredentialExtractor.extractLoginParams()
                    if (params == null) {
                        call.respond(HttpStatusCode.NotFound, mapOf("error" to "login.json params not found in Cache.db"))
                    } else {
                        call.respond(params)
                    }
                }
            }

            route("/auth") {
                post("/login") {
                    call.respondLogin(call.receive())
                }

                post("/login/xvc") {
                    call.respondLogin(call.receive())
                }

                post("/passcode/request") {
                    val request = call.receive<PasscodeRequest>()
                    val resolved =
                        runCatching {
                            resolveLoginContext(
                                email = request.email,
                                password = request.password,
                                deviceUuid = request.deviceUuid,
                                deviceName = request.deviceName,
                                useCachedParams = request.useCachedParams,
                            )
                        }.getOrElse { error ->
                            call.respond(HttpStatusCode.BadRequest, mapOf("error" to (error.message ?: "invalid passcode request")))
                            return@post
                        }
                    val provisionalCreds =
                        buildProvisionalCredentials(
                            appVersion = request.appVersion,
                            agent = request.agent,
                            osVersion = request.osVersion,
                            language = request.language,
                            userAgent = request.userAgent,
                            aHeader = request.aHeader,
                            deviceUuid = resolved.deviceUuid,
                            deviceName = resolved.deviceName,
                        )
                    KakaoRestClient(provisionalCreds).use { client ->
                        val response =
                            client.requestPasscode(
                                email = resolved.email,
                                password = resolved.password,
                                deviceUuid = resolved.deviceUuid,
                                deviceName = resolved.deviceName,
                            )
                        call.respond(
                            mapOf(
                                "success" to (response.statusOrNull() == 0L),
                                "status" to response.statusOrNull(),
                                "usedCachedParams" to resolved.usedCachedParams,
                                "response" to response,
                            ),
                        )
                    }
                }

                post("/passcode/register") {
                    val request = call.receive<RegisterDeviceRequest>()
                    val resolved =
                        runCatching {
                            resolveLoginContext(
                                email = request.email,
                                password = request.password,
                                deviceUuid = request.deviceUuid,
                                deviceName = request.deviceName,
                                useCachedParams = request.useCachedParams,
                            )
                        }.getOrElse { error ->
                            call.respond(HttpStatusCode.BadRequest, mapOf("error" to (error.message ?: "invalid register request")))
                            return@post
                        }
                    val provisionalCreds =
                        buildProvisionalCredentials(
                            appVersion = request.appVersion,
                            agent = request.agent,
                            osVersion = request.osVersion,
                            language = request.language,
                            userAgent = request.userAgent,
                            aHeader = request.aHeader,
                            deviceUuid = resolved.deviceUuid,
                            deviceName = resolved.deviceName,
                        )
                    KakaoRestClient(provisionalCreds).use { client ->
                        val registerResponse =
                            client.registerDevice(
                                email = resolved.email,
                                password = resolved.password,
                                deviceUuid = resolved.deviceUuid,
                                deviceName = resolved.deviceName,
                                passcode = request.passcode,
                                permanent = request.permanent,
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
                                    forced = request.forced,
                                )
                            credentials = buildCredentialsFromLoginResponse(provisionalCreds, loginResponse)
                            saved = if (request.save && credentials != null) {
                                CredentialsStore.save(credentials)
                                true
                            } else {
                                false
                            }
                            restVerified = verifyRestLogin(credentials, request.verifyRest)
                            locoVerified = verifyLocoLogin(credentials, request.verifyLoco)
                        }

                        call.respond(
                            mapOf(
                                "success" to ((registerResponse.statusOrNull() == 0L) && (loginResponse?.statusOrNull() == 0L) && credentials != null),
                                "registerStatus" to registerResponse.statusOrNull(),
                                "loginStatus" to loginResponse?.statusOrNull(),
                                "usedCachedParams" to resolved.usedCachedParams,
                                "saved" to saved,
                                "credentials" to credentials,
                                "restVerified" to restVerified,
                                "locoVerified" to locoVerified,
                                "registerResponse" to registerResponse,
                                "loginResponse" to loginResponse,
                            ),
                        )
                    }
                }

                post("/refresh") {
                    val request = call.receive<RefreshTokenRequest>()
                    val stored = requireStoredCredentials()
                    val refreshToken = request.refreshToken ?: stored.refreshToken
                    if (refreshToken.isNullOrBlank()) {
                        call.respond(HttpStatusCode.BadRequest, mapOf("error" to "refresh token not available"))
                        return@post
                    }
                    KakaoRestClient(stored).use { client ->
                        val response = client.renewOAuth(refreshToken)
                        val status = response.statusOrNull()
                        val updatedCredentials =
                            if (status == 0L) {
                                stored.withUpdatedTokens(
                                    accessToken = response["access_token"]?.jsonPrimitive?.contentOrNull ?: stored.accessToken(),
                                    refreshToken = response["refresh_token"]?.jsonPrimitive?.contentOrNull ?: refreshToken,
                                )
                            } else {
                                null
                            }
                        val saved = if (request.save && updatedCredentials != null) {
                            CredentialsStore.save(updatedCredentials)
                            true
                        } else {
                            false
                        }
                        val restVerified = verifyRestLogin(updatedCredentials, request.verifyRest)
                        call.respond(
                            mapOf(
                                "success" to (status == 0L && updatedCredentials != null),
                                "status" to status,
                                "saved" to saved,
                                "credentials" to updatedCredentials,
                                "restVerified" to restVerified,
                                "response" to response,
                            ),
                        )
                    }
                }
            }

            route("/rest") {
                post("/verify") {
                    useStoredRestClient { client ->
                        call.respond(mapOf("valid" to client.verifyToken()))
                    }
                }

                get("/account/login-token") {
                    useStoredRestClient { client ->
                        val response = client.requestWebLoginToken()
                        call.respond(
                            RestWebLoginResponse(
                                success = (response.statusOrNull() == 0L),
                                status = response.statusOrNull(),
                                token = response["token"]?.jsonPrimitive?.contentOrNull,
                                response = response,
                            ),
                        )
                    }
                }

                post("/account/session-url") {
                    val request = call.receive<RestRedirectUrlRequest>()
                    useStoredRestClient { client ->
                        val (response, sessionUrl) = client.requestSessionUrl(request.redirectUrl)
                        call.respond(
                            RestWebLoginResponse(
                                success = (response.statusOrNull() == 0L && sessionUrl != null),
                                status = response.statusOrNull(),
                                token = response["token"]?.jsonPrimitive?.contentOrNull,
                                sessionUrl = sessionUrl,
                                response = response,
                            ),
                        )
                    }
                }

                post("/account/can-change-uuid") {
                    val request = call.receive<RestUuidRequest>()
                    useStoredRestClient { client ->
                        val response = client.canChangeUuid(request.uuid)
                        call.respond(
                            RestUuidActionResponse(
                                success = (response.statusOrNull() == 0L),
                                status = response.statusOrNull(),
                                uuid = request.uuid,
                                response = response,
                            ),
                        )
                    }
                }

                post("/account/change-uuid") {
                    val request = call.receive<RestUuidRequest>()
                    useStoredRestClient { client ->
                        val response = client.changeUuid(request.uuid)
                        call.respond(
                            RestUuidActionResponse(
                                success = (response.statusOrNull() == 0L),
                                status = response.statusOrNull(),
                                uuid = request.uuid,
                                response = response,
                            ),
                        )
                    }
                }

                get("/profile") {
                    useStoredRestClient { client ->
                        call.respond(client.getMyProfile())
                    }
                }

                get("/profiles/me") {
                    useStoredRestClient { client ->
                        val response = client.requestMyProfileRaw()
                        call.respond(
                            RestRawResponse(
                                success = (response.statusOrNull() == 0L),
                                status = response.statusOrNull(),
                                response = response,
                            ),
                        )
                    }
                }

                get("/profiles/list") {
                    useStoredRestClient { client ->
                        val response = client.getProfileList()
                        call.respond(
                            RestRawResponse(
                                success = (response.statusOrNull() == 0L),
                                status = response.statusOrNull(),
                                response = response,
                            ),
                        )
                    }
                }

                get("/profiles/designated-friends") {
                    useStoredRestClient { client ->
                        val response = client.getDesignatedFriends()
                        call.respond(
                            RestRawResponse(
                                success = (response.statusOrNull() == 0L),
                                status = response.statusOrNull(),
                                response = response,
                            ),
                        )
                    }
                }

                get("/friends") {
                    useStoredRestClient { client ->
                        call.respond(client.getFriends())
                    }
                }

                get("/friends/search") {
                    val query = call.request.queryParameters["query"]?.takeIf { it.isNotBlank() }
                    if (query == null) {
                        call.respond(HttpStatusCode.BadRequest, mapOf("error" to "query is required"))
                        return@get
                    }
                    val pageNum = call.request.queryParameters["pageNum"]?.toIntOrNull()
                    val pageSize = call.request.queryParameters["pageSize"]?.toIntOrNull()
                    useStoredRestClient { client ->
                        val remoteResponse = client.searchFriends(query, pageNum, pageSize)
                        val remoteStatus = remoteResponse.statusOrNull()
                        val matches =
                            if (remoteStatus == 0L) {
                                remoteResponse["user"]
                                    ?.jsonObject
                                    ?.get("list")
                                    ?.jsonArray
                                    .orEmpty()
                                    .map { item ->
                                        val friend = item.jsonObject
                                        Friend(
                                            userId = friend.jsonLong("userId"),
                                            nickname = friend.jsonString("nickName"),
                                            friendNickname = friend.jsonString("friendNickName"),
                                            phoneNumber = friend.jsonString("phoneNumber"),
                                            statusMessage = friend.jsonString("statusMessage"),
                                            favorite = friend["favorite"]?.jsonPrimitive?.booleanOrNull ?: false,
                                            hidden = friend["hidden"]?.jsonPrimitive?.booleanOrNull ?: false,
                                        )
                                    }
                            } else {
                                client.getFriends().filter { friend ->
                                    friend.nickname.contains(query, ignoreCase = true) ||
                                        friend.friendNickname.contains(query, ignoreCase = true) ||
                                        friend.phoneNumber.contains(query, ignoreCase = true)
                                }
                            }
                        call.respond(
                            RestFriendSearchResponse(
                                success = (remoteStatus == 0L || matches.isNotEmpty()),
                                status = remoteStatus,
                                source = if (remoteStatus == 0L) "remote-search" else "local-friends-filter",
                                query = query,
                                matchCount = matches.size,
                                matches = matches,
                                response = remoteResponse,
                            ),
                        )
                    }
                }

                post("/friends/add-by-phone") {
                    val request = call.receive<RestAddFriendByPhoneRequest>()
                    useStoredRestClient { client ->
                        val response =
                            client.addFriendByPhoneNumber(
                                nickname = request.nickname,
                                countryIso = request.countryIso,
                                countryCode = request.countryCode,
                                phoneNumber = request.phoneNumber,
                            )
                        val diffResponse = if (request.refreshDiff) client.requestFriendsDiff() else null
                        call.respond(
                            RestAddFriendByPhoneResponse(
                                success = (response.statusOrNull() == 0L),
                                status = response.statusOrNull(),
                                diffStatus = diffResponse?.statusOrNull(),
                                response = response,
                                diff = diffResponse,
                            ),
                        )
                    }
                }

                post("/friends/diff") {
                    useStoredRestClient { client ->
                        call.respond(client.requestFriendsDiff())
                    }
                }

                post("/friends/list") {
                    val request = call.receive<RestFriendListRequest>()
                    useStoredRestClient { client ->
                        val response = client.requestFriendList(request.types, request.eventTypes, request.token)
                        call.respond(
                            RestRawResponse(
                                success = (response.statusOrNull() == 0L),
                                status = response.statusOrNull(),
                                response = response,
                            ),
                        )
                    }
                }

                get("/friends/{userId}") {
                    val userId = call.parameters["userId"]?.toLongOrNull()
                    if (userId == null) {
                        call.respond(HttpStatusCode.BadRequest, mapOf("error" to "invalid userId"))
                        return@get
                    }
                    useStoredRestClient { client ->
                        val response = client.findFriendById(userId)
                        val status = response.statusOrNull()
                        val friend = client.getFriends().firstOrNull { it.userId == userId }
                        call.respond(
                            RestFriendLookupResponse(
                                success = (status == 0L || friend != null),
                                status = status,
                                source = if (status == 0L) "remote-find" else "local-friends-filter",
                                userId = userId,
                                friend = friend,
                                response = response,
                            ),
                        )
                    }
                }

                post("/friends/add") {
                    val request = call.receive<RestFriendIdRequest>()
                    useStoredRestClient { client ->
                        val response = client.addFriend(request.userId, request.pa)
                        val diffResponse = if (request.refreshDiff) client.requestFriendsDiff() else null
                        call.respond(
                            RestFriendActionResponse(
                                success = (response.statusOrNull() == 0L),
                                status = response.statusOrNull(),
                                diffStatus = diffResponse?.statusOrNull(),
                                action = "add",
                                userId = request.userId,
                                response = response,
                                diff = diffResponse,
                            ),
                        )
                    }
                }

                post("/friends/hide") {
                    val request = call.receive<RestFriendIdRequest>()
                    useStoredRestClient { client ->
                        val response = client.hideFriend(request.userId, request.pa)
                        val diffResponse = if (request.refreshDiff) client.requestFriendsDiff() else null
                        call.respond(
                            RestFriendActionResponse(
                                success = (response.statusOrNull() == 0L),
                                status = response.statusOrNull(),
                                diffStatus = diffResponse?.statusOrNull(),
                                action = "hide",
                                userId = request.userId,
                                response = response,
                                diff = diffResponse,
                            ),
                        )
                    }
                }

                post("/friends/unhide") {
                    val request = call.receive<RestFriendIdRequest>()
                    useStoredRestClient { client ->
                        val response = client.unhideFriend(request.userId)
                        val diffResponse = if (request.refreshDiff) client.requestFriendsDiff() else null
                        call.respond(
                            RestFriendActionResponse(
                                success = (response.statusOrNull() == 0L),
                                status = response.statusOrNull(),
                                diffStatus = diffResponse?.statusOrNull(),
                                action = "unhide",
                                userId = request.userId,
                                response = response,
                                diff = diffResponse,
                            ),
                        )
                    }
                }

                post("/friends/remove") {
                    val request = call.receive<RestFriendIdRequest>()
                    useStoredRestClient { client ->
                        val response = client.removeFriend(request.userId)
                        val diffResponse = if (request.refreshDiff) client.requestFriendsDiff() else null
                        call.respond(
                            RestFriendActionResponse(
                                success = (response.statusOrNull() == 0L),
                                status = response.statusOrNull(),
                                diffStatus = diffResponse?.statusOrNull(),
                                action = "remove",
                                userId = request.userId,
                                response = response,
                                diff = diffResponse,
                            ),
                        )
                    }
                }

                post("/friends/delete") {
                    val request = call.receive<RestFriendIdsRequest>()
                    useStoredRestClient { client ->
                        val response = client.removeFriendList(request.userIds)
                        val diffResponse = if (request.refreshDiff) client.requestFriendsDiff() else null
                        call.respond(
                            RestFriendIdsActionResponse(
                                success = (response.statusOrNull() == 0L),
                                status = response.statusOrNull(),
                                diffStatus = diffResponse?.statusOrNull(),
                                action = "delete",
                                userIds = request.userIds,
                                response = response,
                                diff = diffResponse,
                            ),
                        )
                    }
                }

                post("/friends/nickname") {
                    val request = call.receive<RestFriendNicknameRequest>()
                    useStoredRestClient { client ->
                        val response = client.setFriendNickname(request.userId, request.nickname)
                        val diffResponse = if (request.refreshDiff) client.requestFriendsDiff() else null
                        call.respond(
                            RestFriendActionResponse(
                                success = (response.statusOrNull() == 0L),
                                status = response.statusOrNull(),
                                diffStatus = diffResponse?.statusOrNull(),
                                action = "nickname",
                                userId = request.userId,
                                response = response,
                                diff = diffResponse,
                            ),
                        )
                    }
                }

                post("/friends/favorite/add") {
                    val request = call.receive<RestFriendIdsRequest>()
                    useStoredRestClient { client ->
                        val response = client.addFavoriteFriends(request.userIds)
                        val diffResponse = if (request.refreshDiff) client.requestFriendsDiff() else null
                        call.respond(
                            RestFriendIdsActionResponse(
                                success = (response.statusOrNull() == 0L),
                                status = response.statusOrNull(),
                                diffStatus = diffResponse?.statusOrNull(),
                                action = "favorite-add",
                                userIds = request.userIds,
                                response = response,
                                diff = diffResponse,
                            ),
                        )
                    }
                }

                post("/friends/favorite/remove") {
                    val request = call.receive<RestFriendIdRequest>()
                    useStoredRestClient { client ->
                        val response = client.removeFavoriteFriend(request.userId)
                        val diffResponse = if (request.refreshDiff) client.requestFriendsDiff() else null
                        call.respond(
                            RestFriendActionResponse(
                                success = (response.statusOrNull() == 0L),
                                status = response.statusOrNull(),
                                diffStatus = diffResponse?.statusOrNull(),
                                action = "favorite-remove",
                                userId = request.userId,
                                response = response,
                                diff = diffResponse,
                            ),
                        )
                    }
                }

                post("/friends/find-by-uuid") {
                    val request = call.receive<RestFriendUuidRequest>()
                    useStoredRestClient { client ->
                        val response = client.findFriendByUUID(request.uuid)
                        call.respond(
                            RestFriendUuidLookupResponse(
                                success = (response.statusOrNull() == 0L),
                                status = response.statusOrNull(),
                                uuid = request.uuid,
                                response = response,
                            ),
                        )
                    }
                }

                get("/profiles/friends/{userId}") {
                    val userId = call.parameters["userId"]?.toLongOrNull()
                    if (userId == null) {
                        call.respond(HttpStatusCode.BadRequest, mapOf("error" to "invalid userId"))
                        return@get
                    }
                    useStoredRestClient { client ->
                        val response = client.getFriendProfile(userId)
                        call.respond(
                            RestFriendProfileResponse(
                                success = (response.statusOrNull() == 0L),
                                status = response.statusOrNull(),
                                userId = userId,
                                response = response,
                            ),
                        )
                    }
                }

                get("/profiles/friends/{userId}/music") {
                    val userId = call.parameters["userId"]?.toLongOrNull()
                    if (userId == null) {
                        call.respond(HttpStatusCode.BadRequest, mapOf("error" to "invalid userId"))
                        return@get
                    }
                    useStoredRestClient { client ->
                        val response = client.getFriendMusicList(userId)
                        call.respond(
                            RestFriendProfileResponse(
                                success = (response.statusOrNull() == 0L),
                                status = response.statusOrNull(),
                                userId = userId,
                                response = response,
                            ),
                        )
                    }
                }

                get("/settings") {
                    useStoredRestClient { client ->
                        call.respond(client.getSettings())
                    }
                }

                get("/settings/more") {
                    val since = call.request.queryParameters["since"]?.toLongOrNull() ?: 0L
                    useStoredRestClient { client ->
                        val response = client.getMoreSettings(since)
                        call.respond(
                            RestRawResponse(
                                success = (response.statusOrNull() == 0L),
                                status = response.statusOrNull(),
                                response = response,
                            ),
                        )
                    }
                }

                get("/settings/less") {
                    val since = call.request.queryParameters["since"]?.toLongOrNull() ?: 0L
                    useStoredRestClient { client ->
                        val response = client.getLessSettings(since)
                        call.respond(
                            RestRawResponse(
                                success = (response.statusOrNull() == 0L),
                                status = response.statusOrNull(),
                                response = response,
                            ),
                        )
                    }
                }

                post("/settings/update") {
                    val request = call.receive<RestSettingsUpdateRequest>()
                    useStoredRestClient { client ->
                        val response = client.updateSettings(request.settings)
                        call.respond(
                            RestRawResponse(
                                success = (response.statusOrNull() == 0L),
                                status = response.statusOrNull(),
                                response = response,
                            ),
                        )
                    }
                }

                post("/scrap/preview") {
                    val request = call.receive<RestScrapPreviewRequest>()
                    useStoredRestClient { client ->
                        val response = client.getScrapPreview(request.url)
                        call.respond(
                            RestRawResponse(
                                success = (response.statusOrNull() == 0L),
                                status = response.statusOrNull(),
                                response = response,
                            ),
                        )
                    }
                }

                post("/attachments/upload") {
                    val request = call.receive<RestAttachmentUploadRequest>()
                    val uploadFile =
                        runCatching { resolveUploadFile(request.filePath, request.fileName) }.getOrElse { error ->
                            call.respond(HttpStatusCode.BadRequest, mapOf("error" to (error.message ?: "invalid filePath")))
                            return@post
                        }
                    useStoredRestClient { client ->
                        val result =
                            client.uploadAttachment(
                                kind = request.kind,
                                fileName = uploadFile.fileName,
                                data = uploadFile.bytes,
                                contentType = request.contentType,
                            )
                        call.respond(
                            RestAttachmentUploadResponse(
                                success = result.path.isNotBlank(),
                                kind = request.kind,
                                fileName = result.fileName,
                                fileSize = result.size,
                                result = result,
                            ),
                        )
                    }
                }

                post("/open-upload/profile-image") {
                    val request = call.receive<RestOpenUploadRequest>()
                    val uploadFile =
                        runCatching { resolveUploadFile(request.filePath, request.fileName) }.getOrElse { error ->
                            call.respond(HttpStatusCode.BadRequest, mapOf("error" to (error.message ?: "invalid filePath")))
                            return@post
                        }
                    useStoredRestClient { client ->
                        val result =
                            client.uploadOpenLinkImage(
                                fileName = uploadFile.fileName,
                                data = uploadFile.bytes,
                                contentType = request.contentType ?: inferImageContentType(uploadFile.fileName),
                            )
                        call.respond(
                            RestOpenLinkImageUploadResponse(
                                success = result.accessKey.isNotBlank(),
                                fileName = uploadFile.fileName,
                                fileSize = uploadFile.size,
                                result = result,
                                originalUrl = KakaoRestClient.openLinkOriginalImageUrl(result.accessKey),
                                smallUrl = KakaoRestClient.openLinkSmallImageUrl(result.accessKey),
                                largeUrl = KakaoRestClient.openLinkLargeImageUrl(result.accessKey),
                            ),
                        )
                    }
                }

                post("/open-upload/post-image") {
                    val request = call.receive<RestOpenUploadRequest>()
                    val uploadFile =
                        runCatching { resolveUploadFile(request.filePath, request.fileName) }.getOrElse { error ->
                            call.respond(HttpStatusCode.BadRequest, mapOf("error" to (error.message ?: "invalid filePath")))
                            return@post
                        }
                    useStoredRestClient { client ->
                        val result =
                            client.uploadOpenLinkPostImage(
                                fileName = uploadFile.fileName,
                                data = uploadFile.bytes,
                                contentType = request.contentType ?: inferImageContentType(uploadFile.fileName),
                            )
                        call.respond(
                            RestOpenLinkPostUploadResponse(
                                success = result.accessKey.isNotBlank(),
                                fileName = uploadFile.fileName,
                                fileSize = uploadFile.size,
                                result = result,
                                originalUrl = KakaoRestClient.openLinkOriginalImageUrl(result.accessKey),
                                smallUrl = KakaoRestClient.openLinkSmallImageUrl(result.accessKey),
                                largeUrl = KakaoRestClient.openLinkLargeImageUrl(result.accessKey),
                            ),
                        )
                    }
                }

                post("/open-upload/build-profile") {
                    val request = call.receive<RestOpenProfileBuildRequest>()
                    val uploadFile =
                        runCatching { resolveUploadFile(request.filePath, request.fileName) }.getOrElse { error ->
                            call.respond(HttpStatusCode.BadRequest, mapOf("error" to (error.message ?: "invalid filePath")))
                            return@post
                        }
                    useStoredRestClient { client ->
                        val profile =
                            client.buildOpenLinkProfile(
                                nickname = request.nickname,
                                filePath = uploadFile.path,
                                fileName = uploadFile.fileName,
                                contentType = request.contentType ?: inferImageContentType(uploadFile.fileName),
                            )
                        call.respond(
                            RestOpenProfileBuildResponse(
                                success = profile.profilePath.isNotBlank(),
                                fileName = uploadFile.fileName,
                                fileSize = uploadFile.size,
                                result = profile,
                                originalUrl = KakaoRestClient.openLinkOriginalImageUrl(profile.profilePath),
                                smallUrl = KakaoRestClient.openLinkSmallImageUrl(profile.profilePath),
                                largeUrl = KakaoRestClient.openLinkLargeImageUrl(profile.profilePath),
                            ),
                        )
                    }
                }

                get("/chats") {
                    val all = call.request.queryParameters["all"]?.toBoolean() ?: true
                    useStoredRestClient { client ->
                        val result = if (all) client.getAllChats() else client.getChats(null).rooms
                        call.respond(result)
                    }
                }

                get("/chats/{chatId}/members") {
                    val chatId = call.parameters["chatId"]?.toLongOrNull()
                    if (chatId == null) {
                        call.respond(HttpStatusCode.BadRequest, mapOf("error" to "invalid chatId"))
                        return@get
                    }
                    useStoredRestClient { client ->
                        call.respond(client.getChatMembers(chatId))
                    }
                }

                get("/chats/{chatId}/messages") {
                    val chatId = call.parameters["chatId"]?.toLongOrNull()
                    if (chatId == null) {
                        call.respond(HttpStatusCode.BadRequest, mapOf("error" to "invalid chatId"))
                        return@get
                    }
                    val maxPages = call.request.queryParameters["maxPages"]?.toIntOrNull() ?: 10
                    val cursor = call.request.queryParameters["cursor"]?.toLongOrNull()
                    useStoredRestClient { client ->
                        if (cursor == null) {
                            call.respond(client.getAllMessages(chatId, maxPages))
                        } else {
                            call.respond(client.getMessages(chatId, cursor))
                        }
                    }
                }
            }

            route("/loco") {
                post("/booking") {
                    useLocoClient { client ->
                        call.respond(client.booking())
                    }
                }

                post("/checkin") {
                    useLocoClient { client ->
                        call.respond(client.checkin())
                    }
                }

                post("/login") {
                    useLocoClient { client ->
                        call.respond(client.fullConnect())
                    }
                }

                post("/events/watch") {
                    val request = call.receive<LocoWatchRequest>()
                    useLocoClient { client ->
                        client.fullConnect()
                        call.respond(
                            client.watchEvents(
                                durationMs = request.durationMs,
                                idleTimeoutMs = request.idleTimeoutMs,
                                maxPackets = request.maxPackets,
                            ),
                        )
                    }
                }

                post("/chats") {
                    useLocoClient { client ->
                        client.fullConnect()
                        call.respond(client.listChats())
                    }
                }

                post("/chat-info") {
                    val request = call.receive<LocoChatRequest>()
                    useLocoClient { client ->
                        client.fullConnect()
                        call.respond(client.getChatInfo(request.chatId).toJson())
                    }
                }

                post("/members") {
                    val request = call.receive<LocoChatRequest>()
                    useLocoClient { client ->
                        client.fullConnect()
                        call.respond(client.getMembers(request.chatId))
                    }
                }

                post("/messages/read") {
                    val request = call.receive<LocoReadRequest>()
                    useLocoClient { client ->
                        client.fullConnect()
                        call.respond(
                            client.readMessages(
                                chatId = request.chatId,
                                cursor = request.cursor,
                                fetchAll = request.fetchAll,
                                limit = request.limit,
                                delayMs = request.delayMs,
                                allowOpenChatUnsafe = request.allowOpenChatUnsafe,
                            ),
                        )
                    }
                }

                post("/messages/send") {
                    val request = call.receive<LocoSendMessageRequest>()
                    useLocoClient { client ->
                        client.fullConnect()
                        call.respond(
                            client.sendTextMessage(
                                chatId = request.chatId,
                                message = request.message,
                                allowOpenChatUnsafe = request.allowOpenChatUnsafe,
                            ),
                        )
                    }
                }

                post("/command") {
                    val request = call.receive<LocoCommandRequest>()
                    useLocoClient { client ->
                        if (request.fullConnect) {
                            client.fullConnect()
                        }
                        val response = client.sendCommand(request.method.uppercase(), BsonSupport.fromJsonObject(request.body))
                        call.respond(
                            mapOf(
                                "packetId" to response.packetId,
                                "method" to response.method,
                                "status" to response.status(),
                                "body" to response.body.toJson(),
                            ),
                        )
                    }
                }
            }

            route("/logs") {
                get {
                    val limit = call.request.queryParameters["limit"]?.toIntOrNull() ?: 200
                    call.respond(ProtocolLogStore.snapshot(limit))
                }

                get("/stream") {
                    val backlogLimit = call.request.queryParameters["limit"]?.toIntOrNull() ?: 120
                    call.response.header(HttpHeaders.CacheControl, "no-cache")
                    call.response.header("X-Accel-Buffering", "no")
                    call.respondTextWriter(contentType = ContentType.parse("text/event-stream")) {
                        fun emit(entry: ProtocolLogEntry) {
                            write("data: ")
                            write(protocolLogJson.encodeToString(entry))
                            write("\n\n")
                            flush()
                        }

                        ProtocolLogStore.snapshot(backlogLimit).forEach(::emit)

                        try {
                            ProtocolLogStore.stream().collect(::emit)
                        } catch (_: CancellationException) {
                        }
                    }
                }
            }
        }
    }
}

private fun requireStoredCredentials(): KakaoCredentials =
    CredentialsStore.load() ?: error("stored credentials not found; use /api/credentials/extract or /api/auth/login/xvc first")

private suspend fun <T> useStoredRestClient(block: suspend (KakaoRestClient) -> T): T {
    val stored = requireStoredCredentials()
    return KakaoRestClient(stored).use { client ->
        val result = block(client)
        val updated = client.currentCredentials()
        if (updated != stored) {
            CredentialsStore.save(updated)
        }
        result
    }
}

private suspend fun <T> useLocoClient(block: suspend (LocoClient) -> T): T {
    LocoClient(resolveStoredLocoCredentials()).use { client ->
        return block(client)
    }
}

private suspend fun resolveStoredLocoCredentials(): KakaoCredentials {
    val stored = requireStoredCredentials()
    if (stored.userId > 0L) {
        return stored
    }

    ProtocolLogStore.recordSystem("stored credentials missing userId; resolving from REST profile")

    return runCatching {
        KakaoRestClient(stored).use { client ->
            val profile = client.getMyProfile()
            val updated = client.currentCredentials().copy(userId = profile.userId)
            CredentialsStore.save(updated)
            ProtocolLogStore.recordSystem("resolved userId=${profile.userId} from REST profile")
            updated
        }
    }.getOrElse { error ->
        ProtocolLogStore.recordSystem("failed to resolve userId from REST profile: ${error.message ?: error::class.simpleName}")
        stored
    }
}

private suspend fun ApplicationCall.respondLogin(request: XvcLoginRequest) {
    val resolved =
        runCatching {
            resolveLoginContext(
                email = request.email,
                password = request.password,
                deviceUuid = request.deviceUuid,
                deviceName = request.deviceName,
                useCachedParams = request.useCachedParams,
            )
        }.getOrElse { error ->
            respond(HttpStatusCode.BadRequest, mapOf("error" to (error.message ?: "invalid login request")))
            return
        }

    val provisionalCreds =
        buildProvisionalCredentials(
            appVersion = request.appVersion,
            agent = request.agent,
            osVersion = request.osVersion,
            language = request.language,
            userAgent = request.userAgent,
            aHeader = request.aHeader,
            deviceUuid = resolved.deviceUuid,
            deviceName = resolved.deviceName,
        )

    KakaoRestClient(provisionalCreds).use { client ->
        val response =
            client.loginWithXvc(
                email = resolved.email,
                password = resolved.password,
                deviceUuid = resolved.deviceUuid,
                deviceName = resolved.deviceName,
                forced = request.forced,
            )
        val credentials = buildCredentialsFromLoginResponse(provisionalCreds, response)
        val saved = if (request.save && credentials != null) {
            CredentialsStore.save(credentials)
            true
        } else {
            false
        }
        val restVerified = verifyRestLogin(credentials, request.verifyRest)
        val locoVerified = verifyLocoLogin(credentials, request.verifyLoco)
        respond(
            mapOf(
                "success" to ((response.statusOrNull() == 0L) && credentials != null),
                "status" to response.statusOrNull(),
                "usedCachedParams" to resolved.usedCachedParams,
                "saved" to saved,
                "credentials" to credentials,
                "restVerified" to restVerified,
                "locoVerified" to locoVerified,
                "response" to response,
            ),
        )
    }
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
            LocoClient(credentials).use {
                it.fullConnect()
                true
            }
        }.getOrNull()
    } else {
        null
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

private fun resolveLoginContext(
    email: String?,
    password: String?,
    deviceUuid: String?,
    deviceName: String?,
    useCachedParams: Boolean,
): ResolvedLoginContext {
    val needsCache =
        useCachedParams &&
            (email.isNullOrBlank() || password.isNullOrBlank() || deviceUuid.isNullOrBlank() || deviceName.isNullOrBlank())
    val cached = if (needsCache) KakaoCredentialExtractor.extractLoginParams() else null

    fun requireField(primary: String?, fallback: String?, field: String): String =
        primary?.takeIf { it.isNotBlank() }
            ?: fallback?.takeIf { it.isNotBlank() }
            ?: throw IllegalArgumentException("$field is required; provide it directly or populate Cache.db login.json")

    return ResolvedLoginContext(
        email = requireField(email, cached?.email, "email"),
        password = requireField(password, cached?.password, "password"),
        deviceUuid = requireField(deviceUuid, cached?.deviceUuid, "deviceUuid"),
        deviceName = requireField(deviceName, cached?.deviceName, "deviceName"),
        usedCachedParams = cached != null,
    )
}

private fun JsonObject.statusOrNull(): Long? =
    this["status"]?.jsonPrimitive?.longOrNull

private fun refreshExtractedCredentials(
    credentials: KakaoCredentials?,
    enabled: Boolean,
): RefreshedCredentialsResult {
    if (!enabled || credentials == null || credentials.refreshToken.isNullOrBlank()) {
        return RefreshedCredentialsResult(credentials = credentials)
    }

    return runCatching {
        KakaoRestClient(credentials).use { client ->
            val response = client.renewOAuth(credentials.refreshToken)
            val status = response.statusOrNull()
            if (status == 0L) {
                RefreshedCredentialsResult(
                    credentials =
                        credentials.withUpdatedTokens(
                            accessToken = response["access_token"]?.jsonPrimitive?.contentOrNull ?: credentials.accessToken(),
                            refreshToken = response["refresh_token"]?.jsonPrimitive?.contentOrNull ?: credentials.refreshToken,
                        ),
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

private data class ResolvedLoginContext(
    val email: String,
    val password: String,
    val deviceUuid: String,
    val deviceName: String,
    val usedCachedParams: Boolean,
)

private data class RefreshedCredentialsResult(
    val credentials: KakaoCredentials?,
    val refreshed: Boolean = false,
    val refreshStatus: Long? = null,
)

private data class ResolvedUploadFile(
    val path: Path,
    val fileName: String,
    val size: Long,
    val bytes: ByteArray,
)

private fun resolveUploadFile(filePath: String, fileNameOverride: String? = null): ResolvedUploadFile {
    val path = Path.of(filePath).toAbsolutePath().normalize()
    require(Files.exists(path)) { "filePath does not exist" }
    require(Files.isRegularFile(path)) { "filePath must point to a file" }
    val fileName = fileNameOverride?.takeIf { it.isNotBlank() } ?: path.fileName.toString()
    val bytes = Files.readAllBytes(path)
    return ResolvedUploadFile(
        path = path,
        fileName = fileName,
        size = bytes.size.toLong(),
        bytes = bytes,
    )
}

private fun inferImageContentType(fileName: String): String =
    when (fileName.substringAfterLast('.', "").lowercase()) {
        "png" -> "image/png"
        "gif" -> "image/gif"
        "webp" -> "image/webp"
        "bmp" -> "image/bmp"
        else -> "image/jpeg"
    }
