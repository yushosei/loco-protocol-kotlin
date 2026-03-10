package com.yushosei.auth

import com.yushosei.model.KakaoCredentials
import com.sun.jna.Memory
import com.sun.jna.Pointer
import com.sun.jna.platform.win32.Advapi32Util
import com.sun.jna.platform.win32.BaseTSD
import com.sun.jna.platform.win32.Kernel32
import com.sun.jna.platform.win32.WinNT
import com.sun.jna.platform.win32.WinReg
import com.sun.jna.ptr.IntByReference
import java.nio.charset.StandardCharsets
import java.util.Locale

object KakaoWindowsSessionExtractor {
    private const val DEVICE_INFO_KEY = "Software\\Kakao\\KakaoTalk\\DeviceInfo"
    private const val PROCESS_VM_READ = 0x0010
    private const val PROCESS_QUERY_INFORMATION = 0x0400
    private const val MEM_COMMIT = 0x1000
    private const val PAGE_GUARD = 0x0100
    private const val PAGE_NOACCESS = 0x0001
    private const val SCAN_CHUNK_SIZE = 1024 * 1024
    private const val SCAN_OVERLAP = 4096
    private const val DEFAULT_DEVICE_NAME = "KakaoTalk"
    private val requestLineRegex = Regex("""^(GET|POST)\s+([^\s]+)\s+HTTP/1\.[01]$""")
    private val userIdRegex = Regex(""""userId":([0-9]{3,20})""")
    private val refreshTokenRegex = Regex(""""refresh_token":"([^"]{16,160})"""")
    private val accountIdRegex = Regex(""""autoLoginAccountId":"([^"]+)"""")
    private val recipeRegex = Regex(""""recipe":"([0-9a-f]{16,160})"""")

    fun getCredentialCandidates(maxCandidates: Int = 8): List<KakaoCredentials> {
        if (!isWindows()) {
            return emptyList()
        }

        val deviceInfo = loadDeviceInfo()
        val candidates = linkedMapOf<String, WindowsSessionCandidate>()

        findKakaoTalkProcessIds().forEach { processId ->
            scanProcess(processId, deviceInfo).forEach { hit ->
                val candidate = hit.toCredentials(deviceInfo)
                val existing = candidates[hit.authorization]
                if (existing == null || hit.score > existing.score) {
                    candidates[hit.authorization] = WindowsSessionCandidate(candidate, hit.score)
                }
            }
        }

        return candidates.values
            .sortedByDescending { it.score }
            .take(maxCandidates.coerceAtLeast(1))
            .map { it.credentials }
    }

    internal fun parseSessionWindows(
        text: String,
        processId: Long = 0,
        deviceInfo: WindowsDeviceInfo? = null,
    ): List<WindowsSessionHit> {
        val sanitized = text.replace('\u0000', '\n')
        val candidates = linkedMapOf<String, WindowsSessionHit>()
        var cursor = sanitized.indexOf("Authorization:")

        while (cursor >= 0) {
            val start = (cursor - 1024).coerceAtLeast(0)
            val end = (cursor + 1536).coerceAtMost(sanitized.length)
            val window = sanitized.substring(start, end)
            parseWindow(window, processId, deviceInfo)?.let { hit ->
                val existing = candidates[hit.authorization]
                if (existing == null || hit.score > existing.score) {
                    candidates[hit.authorization] = hit
                }
            }
            cursor = sanitized.indexOf("Authorization:", cursor + "Authorization:".length)
        }

        return candidates.values.toList()
    }

    private fun parseWindow(
        window: String,
        processId: Long,
        deviceInfo: WindowsDeviceInfo?,
    ): WindowsSessionHit? {
        val headers = linkedMapOf<String, String>()
        var path = ""

        window.split(Regex("\\r?\\n")).forEach { rawLine ->
            val line = rawLine.filter { it == '\t' || it in ' '..'~' }.trim()
            if (line.isBlank()) {
                return@forEach
            }

            if (path.isBlank()) {
                requestLineRegex.matchEntire(line)?.let { match ->
                    path = match.groupValues[2]
                }
            }

            val separator = line.indexOf(':')
            if (separator <= 0) {
                return@forEach
            }
            val key = line.substring(0, separator).trim().lowercase(Locale.ROOT)
            val value = line.substring(separator + 1).trim()
            if (key.isNotBlank() && value.isNotBlank() && key !in headers) {
                headers[key] = value
            }
        }

        val authorization = headers["authorization"] ?: return null
        if (!isLikelyAuthorizationToken(authorization)) {
            return null
        }

        val aHeader = headers["a"] ?: return null
        val userAgent = headers["user-agent"] ?: return null
        val host = headers["host"].orEmpty()
        if (!isLikelyKakaoRequest(host, path) && !isLikelyHeaderOnlyHit(authorization, aHeader, userAgent, deviceInfo)) {
            return null
        }

        return WindowsSessionHit(
            authorization = authorization,
            aHeader = aHeader,
            userAgent = userAgent,
            path = path,
            host = host,
            processId = processId,
            userId = userIdRegex.find(window)?.groupValues?.getOrNull(1)?.toLongOrNull() ?: 0L,
            refreshToken = refreshTokenRegex.find(window)?.groupValues?.getOrNull(1),
            autoLoginAccountId = accountIdRegex.find(window)?.groupValues?.getOrNull(1),
            recipe = recipeRegex.find(window)?.groupValues?.getOrNull(1),
            score = scoreCandidate(authorization, aHeader, userAgent, host, path, deviceInfo),
        )
    }

    private fun scanProcess(processId: Long, deviceInfo: WindowsDeviceInfo?): List<WindowsSessionHit> {
        val handle =
            Kernel32.INSTANCE.OpenProcess(
                PROCESS_QUERY_INFORMATION or PROCESS_VM_READ,
                false,
                processId.toInt(),
            ) ?: return emptyList()

        val hits = linkedMapOf<String, WindowsSessionHit>()
        try {
            val memoryInfo = WinNT.MEMORY_BASIC_INFORMATION()
            var address = 0L

            while (true) {
                val result =
                    Kernel32.INSTANCE.VirtualQueryEx(
                        handle,
                        Pointer.createConstant(address),
                        memoryInfo,
                        BaseTSD.SIZE_T(memoryInfo.size().toLong()),
                    )
                if (result.toLong() == 0L) {
                    break
                }

                val baseAddress = Pointer.nativeValue(memoryInfo.baseAddress)
                val regionSize = memoryInfo.regionSize.toLong()
                if (shouldRead(memoryInfo, regionSize)) {
                    scanRegion(handle, processId, baseAddress, regionSize, deviceInfo, hits)
                }

                val nextAddress = baseAddress + regionSize
                if (nextAddress <= address) {
                    break
                }
                address = nextAddress
            }
        } finally {
            Kernel32.INSTANCE.CloseHandle(handle)
        }

        return hits.values.toList()
    }

    private fun scanRegion(
        handle: WinNT.HANDLE,
        processId: Long,
        baseAddress: Long,
        regionSize: Long,
        deviceInfo: WindowsDeviceInfo?,
        hits: MutableMap<String, WindowsSessionHit>,
    ) {
        var offset = 0L
        var carry = ByteArray(0)

        while (offset < regionSize) {
            val requested = minOf(SCAN_CHUNK_SIZE.toLong(), regionSize - offset).toInt()
            val buffer = Memory(requested.toLong())
            val bytesRead = IntByReference()
            val success =
                Kernel32.INSTANCE.ReadProcessMemory(
                    handle,
                    Pointer.createConstant(baseAddress + offset),
                    buffer,
                    requested,
                    bytesRead,
                )
            if (!success || bytesRead.value <= 0) {
                offset += requested
                carry = ByteArray(0)
                continue
            }

            val chunk = buffer.getByteArray(0, bytesRead.value)
            val combined = if (carry.isEmpty()) chunk else carry + chunk
            val text = combined.toString(StandardCharsets.ISO_8859_1)

            parseSessionWindows(text, processId, deviceInfo).forEach { hit ->
                val existing = hits[hit.authorization]
                if (existing == null || hit.score > existing.score) {
                    hits[hit.authorization] = hit
                }
            }

            val overlap = minOf(SCAN_OVERLAP, combined.size)
            carry = combined.copyOfRange(combined.size - overlap, combined.size)
            offset += bytesRead.value
        }
    }

    private fun shouldRead(memoryInfo: WinNT.MEMORY_BASIC_INFORMATION, regionSize: Long): Boolean {
        if (regionSize <= 0L) {
            return false
        }
        if (memoryInfo.state.toInt() != MEM_COMMIT) {
            return false
        }
        val protect = memoryInfo.protect.toInt()
        if (protect == 0 || (protect and PAGE_GUARD) != 0 || (protect and PAGE_NOACCESS) != 0) {
            return false
        }
        return true
    }

    private fun scoreCandidate(
        authorization: String,
        aHeader: String,
        userAgent: String,
        host: String,
        path: String,
        deviceInfo: WindowsDeviceInfo?,
    ): Int {
        var score = 0
        if (host.equals("katalk.kakao.com", ignoreCase = true)) {
            score += 60
        } else if (host.endsWith(".kakao.com", ignoreCase = true)) {
            score += 40
        }
        if (path.contains("/account/more_settings.json")) {
            score += 35
        }
        if (path.contains("/account/less_settings.json")) {
            score += 30
        }
        if (path.contains("/win32/")) {
            score += 20
        }
        if (aHeader.startsWith("win32/")) {
            score += 15
        }
        if (userAgent.startsWith("KT/")) {
            score += 10
        }
        if (!deviceInfo?.devId.isNullOrBlank() && authorization.contains(deviceInfo!!.devId)) {
            score += 40
        }
        return score
    }

    private fun isLikelyKakaoRequest(host: String, path: String): Boolean =
        host.endsWith("kakao.com", ignoreCase = true) ||
            path.contains("/win32/") ||
            path.contains("/mac/") ||
            path.contains("/android/")

    private fun isLikelyHeaderOnlyHit(
        authorization: String,
        aHeader: String,
        userAgent: String,
        deviceInfo: WindowsDeviceInfo?,
    ): Boolean =
        aHeader.startsWith("win32/") &&
            userAgent.startsWith("KT/") &&
            (!deviceInfo?.devId.isNullOrBlank() && authorization.contains(deviceInfo!!.devId))

    private fun isLikelyAuthorizationToken(token: String): Boolean {
        if (token.length < 48 || token.any { it.isWhitespace() }) {
            return false
        }
        val separator = token.lastIndexOf('-')
        if (separator <= 0 || separator == token.lastIndex) {
            return false
        }
        val accessToken = token.substring(0, separator)
        val suffix = token.substring(separator + 1)
        return accessToken.length >= 16 && suffix.length >= 32
    }

    private fun findKakaoTalkProcessIds(): List<Long> {
        return runCatching {
            ProcessBuilder("cmd", "/c", "tasklist /FI \"IMAGENAME eq KakaoTalk.exe\" /FO CSV /NH")
                .redirectErrorStream(true)
                .start()
                .inputStream
                .bufferedReader()
                .readLines()
                .mapNotNull { line ->
                    val columns = line.trim().trim('"').split("\",\"")
                    columns.getOrNull(1)?.replace(",", "")?.toLongOrNull()
                }.sortedDescending()
        }.getOrDefault(emptyList())
    }

    private fun loadDeviceInfo(): WindowsDeviceInfo? =
        runCatching {
            Advapi32Util.registryGetKeys(WinReg.HKEY_CURRENT_USER, DEVICE_INFO_KEY)
                .sortedDescending()
                .mapNotNull { subKey ->
                    val path = "$DEVICE_INFO_KEY\\$subKey"
                    val sysUuid = readRegistryString(path, "sys_uuid").orEmpty()
                    val devId = readRegistryString(path, "dev_id").orEmpty()
                    if (sysUuid.isBlank() && devId.isBlank()) {
                        null
                    } else {
                        WindowsDeviceInfo(
                            keyName = subKey,
                            sysUuid = sysUuid,
                            devId = devId,
                        )
                    }
                }.firstOrNull()
        }.getOrNull()

    private fun readRegistryString(path: String, value: String): String? =
        runCatching {
            Advapi32Util.registryGetStringValue(WinReg.HKEY_CURRENT_USER, path, value)
        }.getOrNull()

    private fun WindowsSessionHit.toCredentials(deviceInfo: WindowsDeviceInfo?): KakaoCredentials {
        val deviceUuid =
            deviceInfo?.sysUuid?.takeIf { it.isNotBlank() }
                ?: authorization.substringAfterLast('-', "")
        return KakaoCredentials(
            oauthToken = authorization.substringBeforeLast('-', authorization),
            userId = userId,
            deviceUuid = deviceUuid,
            deviceName = DEFAULT_DEVICE_NAME,
            appVersion = aHeader.substringAfter('/').substringBeforeLast('/').ifBlank { "25.10.1" },
            userAgent = userAgent,
            aHeader = aHeader,
            refreshToken = refreshToken,
            authorizationHeader = authorization,
        )
    }

    private fun isWindows(): Boolean =
        System.getProperty("os.name").contains("Windows", ignoreCase = true)

    internal data class WindowsDeviceInfo(
        val keyName: String,
        val sysUuid: String,
        val devId: String,
    )

    internal data class WindowsSessionHit(
        val authorization: String,
        val aHeader: String,
        val userAgent: String,
        val path: String,
        val host: String,
        val processId: Long,
        val userId: Long,
        val refreshToken: String?,
        val autoLoginAccountId: String?,
        val recipe: String?,
        val score: Int,
    )

    private data class WindowsSessionCandidate(
        val credentials: KakaoCredentials,
        val score: Int,
    )
}
