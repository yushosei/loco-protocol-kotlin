package com.yushosei.auth

import com.dd.plist.NSArray
import com.dd.plist.NSData
import com.dd.plist.NSDictionary
import com.dd.plist.NSNumber
import com.dd.plist.NSObject
import com.dd.plist.NSString
import com.dd.plist.PropertyListParser
import com.yushosei.model.CachedLoginParams
import com.yushosei.model.KakaoCredentials
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.StandardCopyOption
import java.sql.DriverManager
import kotlin.io.path.exists

object KakaoCredentialExtractor {
    fun getCredentialCandidates(maxCandidates: Int = 8): List<KakaoCredentials> {
        if (isWindows()) {
            return KakaoWindowsSessionExtractor.getCredentialCandidates(maxCandidates)
        }
        return extractCandidatesFromCacheDb(300)
            .sortedWith(compareByDescending<ExtractedCredential> { it.priority }.thenByDescending { it.timestamp })
            .take(maxCandidates.coerceAtLeast(1))
            .map { it.credentials }
    }

    fun extractLoginParams(): CachedLoginParams? {
        if (isWindows()) {
            return null
        }
        val cacheDb = kakaoCacheDbPath()
        if (!cacheDb.exists()) {
            return null
        }
        val tempDir = Files.createTempDirectory("kakaotalk-cache")
        val tempDb = tempDir.resolve("Cache.db")
        copyCacheArtifacts(cacheDb, tempDb)

        DriverManager.getConnection("jdbc:sqlite:${tempDb.toAbsolutePath()}").use { connection ->
            connection.prepareStatement(
                """
                SELECT b.request_object
                FROM cfurl_cache_blob_data b
                JOIN cfurl_cache_response r ON b.entry_ID = r.entry_ID
                WHERE r.request_key LIKE '%login.json%'
                  AND b.request_object IS NOT NULL
                ORDER BY r.time_stamp DESC
                LIMIT 1
                """.trimIndent(),
            ).use { statement ->
                statement.executeQuery().use { resultSet ->
                    if (!resultSet.next()) {
                        return null
                    }
                    val requestObject = resultSet.getBytes(1) ?: return null
                    val plist = runCatching { PropertyListParser.parse(requestObject) }.getOrNull() ?: return null
                    return extractLoginParamsFromPlist(plist)
                }
            }
        }
    }

    private fun extractCandidatesFromCacheDb(maxRows: Int): List<ExtractedCredential> {
        val cacheDb = kakaoCacheDbPath()
        if (!cacheDb.exists()) {
            return emptyList()
        }

        val tempDir = Files.createTempDirectory("kakaotalk-cache")
        val tempDb = tempDir.resolve("Cache.db")
        copyCacheArtifacts(cacheDb, tempDb)

        val seenTokens = linkedSetOf<String>()
        val candidates = mutableListOf<ExtractedCredential>()

        DriverManager.getConnection("jdbc:sqlite:${tempDb.toAbsolutePath()}").use { connection ->
            connection.prepareStatement(
                """
                SELECT b.request_object, r.request_key, r.time_stamp
                FROM cfurl_cache_blob_data b
                JOIN cfurl_cache_response r ON b.entry_ID = r.entry_ID
                WHERE b.request_object IS NOT NULL
                  AND (r.request_key LIKE '%kakao.com%' OR r.request_key LIKE '%kakao%')
                ORDER BY r.time_stamp DESC
                LIMIT ?
                """.trimIndent(),
            ).use { statement ->
                statement.setInt(1, maxRows)
                statement.executeQuery().use { resultSet ->
                    while (resultSet.next()) {
                        val requestObject = resultSet.getBytes(1) ?: continue
                        val requestKey = resultSet.getString(2).orEmpty()
                        val timestamp = resultSet.getDouble(3)
                        val plist = runCatching { PropertyListParser.parse(requestObject) }.getOrNull() ?: continue
                        val headers = findHeadersMap(plist) ?: continue
                        val authToken = plistValueAsString(headers.objectForKey("Authorization")) ?: continue
                        if (!seenTokens.add(authToken)) {
                            continue
                        }

                        val userId = plistValueAsString(headers.objectForKey("talk-user-id"))?.toLongOrNull() ?: 0L
                        val userAgent = plistValueAsString(headers.objectForKey("User-Agent")).orEmpty()
                        val aHeader = plistValueAsString(headers.objectForKey("A")).orEmpty()
                        val appVersion = aHeader.split('/').getOrNull(1).orEmpty().ifBlank { "3.7.0" }
                        val deviceUuid = authToken.substringAfter('-', "")
                        val accessToken =
                            if (deviceUuid.isNotBlank() && authToken.endsWith("-$deviceUuid")) {
                                authToken.removeSuffix("-$deviceUuid")
                            } else {
                                authToken
                            }

                        candidates += ExtractedCredential(
                            credentials = KakaoCredentials(
                                oauthToken = accessToken,
                                userId = userId,
                                deviceUuid = deviceUuid,
                                appVersion = appVersion,
                                userAgent = userAgent,
                                aHeader = aHeader,
                            ),
                            timestamp = timestamp,
                            priority = urlPriority(requestKey),
                        )
                    }
                }
            }
        }

        return candidates
    }

    private fun extractLoginParamsFromPlist(plist: NSObject): CachedLoginParams? {
        val headers = findAnyHeadersMap(plist) ?: return null
        val xVc = plistValueAsString(headers.objectForKey("X-VC")).orEmpty()
        val rootArray = (plist as? NSDictionary)?.objectForKey("Array") as? NSArray ?: return null
        for (index in 0 until rootArray.count()) {
            val item = rootArray.objectAtIndex(index)
            if (item !is NSArray) {
                continue
            }
            val bytes = mutableListOf<Byte>()
            for (innerIndex in 0 until item.count()) {
                val chunk = item.objectAtIndex(innerIndex)
                if (chunk is NSData) {
                    chunk.bytes().forEach(bytes::add)
                }
            }
            if (bytes.isEmpty()) {
                continue
            }
            val body = ByteArray(bytes.size) { i -> bytes[i] }.toString(StandardCharsets.UTF_8)
            val params = parseUrlEncodedBody(body)
            val email = params["email"].orEmpty()
            if (email.isBlank()) {
                continue
            }
            return CachedLoginParams(
                email = email,
                password = params["password"].orEmpty(),
                deviceUuid = params["device_uuid"].orEmpty(),
                deviceName = params["device_name"].orEmpty(),
                xVc = xVc,
            )
        }
        return null
    }

    private fun findHeadersMap(plist: NSObject): NSDictionary? {
        val rootArray = (plist as? NSDictionary)?.objectForKey("Array") as? NSArray ?: return null
        for (index in 0 until rootArray.count()) {
            val item = rootArray.objectAtIndex(index)
            if (item is NSDictionary && item.objectForKey("Authorization") != null) {
                return item
            }
        }
        return null
    }

    private fun findAnyHeadersMap(plist: NSObject): NSDictionary? {
        val rootArray = (plist as? NSDictionary)?.objectForKey("Array") as? NSArray ?: return null
        for (index in 0 until rootArray.count()) {
            val item = rootArray.objectAtIndex(index)
            if (item is NSDictionary && item.objectForKey("Content-Type") != null) {
                return item
            }
        }
        return null
    }

    private fun plistValueAsString(value: NSObject?): String? = when (value) {
        is NSString -> value.toString()
        is NSNumber -> value.toString()
        else -> null
    }

    private fun parseUrlEncodedBody(body: String): Map<String, String> =
        body.split('&')
            .mapNotNull { part ->
                val pieces = part.split('=', limit = 2)
                if (pieces.size != 2) {
                    null
                } else {
                    pieces[0] to URLDecoder.decode(pieces[1], StandardCharsets.UTF_8)
                }
            }
            .toMap()

    private fun urlPriority(url: String): Int = when {
        url.contains("/mac/account/more_settings.json") -> 3
        url.contains("/messaging/chats") || url.contains("/mac/profile3/me.json") -> 2
        else -> 1
    }

    private fun copyCacheArtifacts(sourceDb: Path, targetDb: Path) {
        Files.copy(sourceDb, targetDb, StandardCopyOption.REPLACE_EXISTING)
        copyIfExists(Paths.get("${sourceDb.toAbsolutePath()}-wal"), Paths.get("${targetDb.toAbsolutePath()}-wal"))
        copyIfExists(Paths.get("${sourceDb.toAbsolutePath()}-shm"), Paths.get("${targetDb.toAbsolutePath()}-shm"))
    }

    private fun copyIfExists(source: Path, target: Path) {
        if (source.exists()) {
            Files.copy(source, target, StandardCopyOption.REPLACE_EXISTING)
        }
    }

    private fun kakaoCacheDbPath(): Path =
        Paths.get(
            System.getProperty("user.home"),
            "Library",
            "Containers",
            "com.kakao.KakaoTalkMac",
            "Data",
            "Library",
            "Caches",
            "Cache.db",
        )

    private fun isWindows(): Boolean =
        System.getProperty("os.name").contains("Windows", ignoreCase = true)

    private data class ExtractedCredential(
        val credentials: KakaoCredentials,
        val timestamp: Double,
        val priority: Int,
    )
}
