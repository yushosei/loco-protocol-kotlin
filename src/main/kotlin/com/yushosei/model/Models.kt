package com.yushosei.model

import kotlinx.serialization.Serializable

@Serializable
data class KakaoCredentials(
    val oauthToken: String,
    val userId: Long,
    val deviceUuid: String,
    val deviceName: String = "kakaotalk",
    val appVersion: String = "3.7.0",
    val userAgent: String = "",
    val aHeader: String = "",
    val refreshToken: String? = null,
    val authorizationHeader: String? = null,
) {
    fun authorizationSuffix(): String? =
        authorizationHeader
            ?.takeIf { it.isNotBlank() && it.contains('-') }
            ?.substringAfterLast('-')
            ?.takeIf { it.isNotBlank() }
            ?: deviceUuid.takeIf { it.isNotBlank() }

    fun accessToken(): String {
        val token = authorizationHeader?.takeIf { it.isNotBlank() } ?: oauthToken
        return when {
            deviceUuid.isNotBlank() && token.endsWith("-$deviceUuid") -> token.removeSuffix("-$deviceUuid")
            authorizationHeader != null && token.contains('-') -> token.substringBeforeLast('-')
            else -> token
        }
    }

    fun authorizationToken(): String =
        authorizationHeader?.takeIf { it.isNotBlank() }
            ?: if (deviceUuid.isBlank()) {
                accessToken()
            } else {
                "${accessToken()}-$deviceUuid"
            }

    fun withUpdatedTokens(
        accessToken: String,
        refreshToken: String? = this.refreshToken,
    ): KakaoCredentials {
        val suffix = authorizationSuffix()
        return copy(
            oauthToken = accessToken,
            refreshToken = refreshToken,
            authorizationHeader =
                suffix?.takeIf { it.isNotBlank() }?.let { "$accessToken-$it" }
                    ?: authorizationHeader,
        )
    }
}

@Serializable
data class CachedLoginParams(
    val email: String,
    val password: String,
    val deviceUuid: String,
    val deviceName: String,
    val xVc: String,
)

@Serializable
data class MyProfile(
    val nickname: String,
    val statusMessage: String,
    val accountId: Long,
    val email: String,
    val userId: Long,
    val profileImageUrl: String,
)

@Serializable
data class Friend(
    val userId: Long,
    val nickname: String,
    val friendNickname: String,
    val phoneNumber: String,
    val statusMessage: String,
    val favorite: Boolean,
    val hidden: Boolean,
)

@Serializable
data class ChatRoom(
    val chatId: Long,
    val kind: String,
    val title: String,
    val unreadCount: Long,
)

@Serializable
data class ChatMember(
    val userId: Long,
    val nickname: String,
    val friendNickname: String,
    val countryIso: String,
)

@Serializable
data class ChatMessage(
    val logId: Long,
    val authorId: Long,
    val messageType: Long,
    val message: String,
    val attachment: String,
    val sendAt: Long,
)

@Serializable
data class RestChatPage(
    val rooms: List<ChatRoom>,
    val nextCursor: Long?,
)

@Serializable
data class UploadedAttachment(
    val path: String,
    val size: Long,
    val host: String,
    val attachmentType: String,
    val fileName: String,
)

@Serializable
data class OpenProfileUpload(
    val accessKey: String,
)

@Serializable
data class OpenPostUploadInfoItem(
    val filename: String,
    val width: Int,
    val contentType: String,
    val length: Long,
    val height: Int,
)

@Serializable
data class OpenPostUploadInfo(
    val original: OpenPostUploadInfoItem,
    val small: OpenPostUploadInfoItem,
    val large: OpenPostUploadInfoItem,
)

@Serializable
data class OpenProfilePostUpload(
    val accessKey: String,
    val info: OpenPostUploadInfo,
)

@Serializable
data class OpenLinkAnonProfile(
    val nickname: String,
    val profilePath: String,
)

@Serializable
data class LocoServer(
    val host: String,
    val port: Int,
)

@Serializable
data class LocoCheckinResult(
    val server: LocoServer,
    val usedTls: Boolean,
    val secureProfile: String? = null,
    val bookingRevision: Int? = null,
    val raw: kotlinx.serialization.json.JsonObject,
)

@Serializable
data class LocoChatListing(
    val chatId: Long,
    val kind: String,
    val title: String,
    val hasUnread: Boolean,
    val activeMembers: Int? = null,
    val lastLogId: Long? = null,
    val lastSeenLogId: Long? = null,
)

@Serializable
data class LocoChatMember(
    val userId: Long,
    val nickname: String,
    val countryIso: String,
)

@Serializable
data class LocoChatMessage(
    val logId: Long,
    val authorId: Long,
    val authorNickname: String,
    val messageType: Int,
    val message: String,
    val attachment: String,
    val sendAt: Long,
)

@Serializable
data class LocoObservedPacket(
    val receivedAt: Long,
    val packetId: Int,
    val status: Long,
    val method: String,
    val body: kotlinx.serialization.json.JsonObject,
)
