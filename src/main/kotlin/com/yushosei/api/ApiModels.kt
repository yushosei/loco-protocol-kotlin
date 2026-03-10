package com.yushosei.api

import com.yushosei.model.KakaoCredentials
import com.yushosei.model.Friend
import com.yushosei.model.OpenLinkAnonProfile
import com.yushosei.model.OpenProfilePostUpload
import com.yushosei.model.OpenProfileUpload
import com.yushosei.model.UploadedAttachment
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject

@Serializable
data class CredentialsExtractResponse(
    val saved: Boolean,
    val refreshed: Boolean = false,
    val refreshStatus: Long? = null,
    val restVerified: Boolean? = null,
    val selected: KakaoCredentials? = null,
    val candidates: List<KakaoCredentials> = emptyList(),
)

@Serializable
data class StoreCredentialsRequest(
    val credentials: KakaoCredentials,
)

@Serializable
data class XvcLoginRequest(
    val email: String? = null,
    val password: String? = null,
    val deviceUuid: String? = null,
    val deviceName: String? = null,
    val appVersion: String = "3.2.3.2698",
    val agent: String = "win32",
    val osVersion: String = "10.0",
    val language: String = "ko",
    val userAgent: String? = null,
    val aHeader: String? = null,
    val useCachedParams: Boolean = true,
    val verifyRest: Boolean = true,
    val verifyLoco: Boolean = false,
    val forced: Boolean = false,
    val save: Boolean = true,
)

@Serializable
data class PasscodeRequest(
    val email: String? = null,
    val password: String? = null,
    val deviceUuid: String? = null,
    val deviceName: String? = null,
    val appVersion: String = "3.2.3.2698",
    val agent: String = "win32",
    val osVersion: String = "10.0",
    val language: String = "ko",
    val userAgent: String? = null,
    val aHeader: String? = null,
    val useCachedParams: Boolean = true,
)

@Serializable
data class RegisterDeviceRequest(
    val passcode: String,
    val email: String? = null,
    val password: String? = null,
    val deviceUuid: String? = null,
    val deviceName: String? = null,
    val appVersion: String = "3.2.3.2698",
    val agent: String = "win32",
    val osVersion: String = "10.0",
    val language: String = "ko",
    val userAgent: String? = null,
    val aHeader: String? = null,
    val useCachedParams: Boolean = true,
    val permanent: Boolean = true,
    val verifyRest: Boolean = true,
    val verifyLoco: Boolean = false,
    val forced: Boolean = false,
    val save: Boolean = true,
)

@Serializable
data class RefreshTokenRequest(
    val refreshToken: String? = null,
    val verifyRest: Boolean = true,
    val save: Boolean = true,
)

@Serializable
data class RestAddFriendByPhoneRequest(
    val nickname: String,
    val phoneNumber: String,
    val countryIso: String = "KR",
    val countryCode: String = "82",
    val refreshDiff: Boolean = true,
)

@Serializable
data class RestFriendIdRequest(
    val userId: Long,
    val pa: String = "",
    val refreshDiff: Boolean = true,
)

@Serializable
data class RestFriendNicknameRequest(
    val userId: Long,
    val nickname: String,
    val refreshDiff: Boolean = true,
)

@Serializable
data class RestFriendIdsRequest(
    val userIds: List<Long>,
    val refreshDiff: Boolean = true,
)

@Serializable
data class RestFriendUuidRequest(
    val uuid: String,
)

@Serializable
data class RestUuidRequest(
    val uuid: String,
)

@Serializable
data class RestRedirectUrlRequest(
    val redirectUrl: String,
)

@Serializable
data class RestFriendListRequest(
    val types: List<String> = listOf("plus", "normal"),
    val eventTypes: List<String> = listOf("create"),
    val token: Long = 0L,
)

@Serializable
data class RestSettingsUpdateRequest(
    val settings: JsonObject = JsonObject(emptyMap()),
)

@Serializable
data class RestScrapPreviewRequest(
    val url: String,
)

@Serializable
data class RestAttachmentUploadRequest(
    val filePath: String,
    val kind: String = "photo",
    val fileName: String? = null,
    val contentType: String? = null,
)

@Serializable
data class RestOpenUploadRequest(
    val filePath: String,
    val fileName: String? = null,
    val contentType: String? = null,
)

@Serializable
data class RestOpenProfileBuildRequest(
    val nickname: String,
    val filePath: String,
    val fileName: String? = null,
    val contentType: String? = null,
)

@Serializable
data class RestFriendSearchResponse(
    val success: Boolean,
    val status: Long? = null,
    val source: String,
    val query: String,
    val matchCount: Int,
    val matches: List<Friend> = emptyList(),
    val response: JsonObject = JsonObject(emptyMap()),
)

@Serializable
data class RestAddFriendByPhoneResponse(
    val success: Boolean,
    val status: Long? = null,
    val diffStatus: Long? = null,
    val response: JsonObject = JsonObject(emptyMap()),
    val diff: JsonObject? = null,
)

@Serializable
data class RestFriendLookupResponse(
    val success: Boolean,
    val status: Long? = null,
    val source: String,
    val userId: Long,
    val friend: Friend? = null,
    val response: JsonObject = JsonObject(emptyMap()),
)

@Serializable
data class RestFriendActionResponse(
    val success: Boolean,
    val status: Long? = null,
    val diffStatus: Long? = null,
    val action: String,
    val userId: Long,
    val response: JsonObject = JsonObject(emptyMap()),
    val diff: JsonObject? = null,
)

@Serializable
data class RestFriendIdsActionResponse(
    val success: Boolean,
    val status: Long? = null,
    val diffStatus: Long? = null,
    val action: String,
    val userIds: List<Long>,
    val response: JsonObject = JsonObject(emptyMap()),
    val diff: JsonObject? = null,
)

@Serializable
data class RestFriendUuidLookupResponse(
    val success: Boolean,
    val status: Long? = null,
    val uuid: String,
    val response: JsonObject = JsonObject(emptyMap()),
)

@Serializable
data class RestFriendProfileResponse(
    val success: Boolean,
    val status: Long? = null,
    val userId: Long,
    val response: JsonObject = JsonObject(emptyMap()),
)

@Serializable
data class RestRawResponse(
    val success: Boolean,
    val status: Long? = null,
    val response: JsonObject = JsonObject(emptyMap()),
)

@Serializable
data class RestAttachmentUploadResponse(
    val success: Boolean,
    val kind: String,
    val fileName: String,
    val fileSize: Long,
    val result: UploadedAttachment? = null,
)

@Serializable
data class RestOpenLinkImageUploadResponse(
    val success: Boolean,
    val fileName: String,
    val fileSize: Long,
    val result: OpenProfileUpload? = null,
    val originalUrl: String? = null,
    val smallUrl: String? = null,
    val largeUrl: String? = null,
)

@Serializable
data class RestOpenLinkPostUploadResponse(
    val success: Boolean,
    val fileName: String,
    val fileSize: Long,
    val result: OpenProfilePostUpload? = null,
    val originalUrl: String? = null,
    val smallUrl: String? = null,
    val largeUrl: String? = null,
)

@Serializable
data class RestOpenProfileBuildResponse(
    val success: Boolean,
    val fileName: String,
    val fileSize: Long,
    val result: OpenLinkAnonProfile? = null,
    val originalUrl: String? = null,
    val smallUrl: String? = null,
    val largeUrl: String? = null,
)

@Serializable
data class RestWebLoginResponse(
    val success: Boolean,
    val status: Long? = null,
    val token: String? = null,
    val sessionUrl: String? = null,
    val response: JsonObject = JsonObject(emptyMap()),
)

@Serializable
data class RestUuidActionResponse(
    val success: Boolean,
    val status: Long? = null,
    val uuid: String,
    val response: JsonObject = JsonObject(emptyMap()),
)

@Serializable
data class LocoChatRequest(
    val chatId: Long,
)

@Serializable
data class LocoReadRequest(
    val chatId: Long,
    val cursor: Long? = null,
    val fetchAll: Boolean = false,
    val limit: Int = 50,
    val delayMs: Long = 0,
    val allowOpenChatUnsafe: Boolean = false,
)

@Serializable
data class LocoSendMessageRequest(
    val chatId: Long,
    val message: String,
    val allowOpenChatUnsafe: Boolean = false,
)

@Serializable
data class LocoWatchRequest(
    val durationMs: Long = 30_000,
    val idleTimeoutMs: Int = 1_000,
    val maxPackets: Int = 100,
)

@Serializable
data class LocoCommandRequest(
    val method: String,
    val body: JsonObject = JsonObject(emptyMap()),
    val fullConnect: Boolean = true,
)
