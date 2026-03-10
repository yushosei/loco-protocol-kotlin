package com.yushosei.loco

import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.KeyFactory
import java.security.PublicKey
import java.security.SecureRandom
import java.security.spec.RSAPublicKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class LocoEncryptor private constructor(
    private val secretKey: SecretKey,
    val profile: Profile,
) {
    enum class Profile(
        val handshakeKeyEncryptType: Int,
        val handshakeEncryptType: Int,
        val ivSize: Int,
    ) {
        NODE_KAKAO(
            handshakeKeyEncryptType = 12,
            handshakeEncryptType = 2,
            ivSize = 16,
        ),
        OPEN_KAKAO_GCM(
            handshakeKeyEncryptType = 16,
            handshakeEncryptType = 3,
            ivSize = 12,
        ),
    }

    fun buildHandshakePacket(): ByteArray {
        val encryptedKey = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding").apply {
            init(Cipher.ENCRYPT_MODE, rsaPublicKeyFor(profile))
        }.doFinal(secretKey.encoded)

        val buffer = ByteBuffer.allocate(12 + encryptedKey.size).order(ByteOrder.LITTLE_ENDIAN)
        buffer.putInt(encryptedKey.size)
        buffer.putInt(profile.handshakeKeyEncryptType)
        buffer.putInt(profile.handshakeEncryptType)
        buffer.put(encryptedKey)
        return buffer.array()
    }

    fun encrypt(plainBytes: ByteArray, ivOverride: ByteArray? = null): ByteArray {
        val iv = ivOverride?.copyOf() ?: ByteArray(profile.ivSize).also(secureRandom::nextBytes)
        require(iv.size == profile.ivSize) { "invalid iv size for ${profile.name}: expected ${profile.ivSize}, got ${iv.size}" }
        val encrypted = when (profile) {
            Profile.NODE_KAKAO -> {
                val cipher = Cipher.getInstance("AES/CFB/NoPadding")
                cipher.init(Cipher.ENCRYPT_MODE, secretKey, IvParameterSpec(iv))
                cipher.doFinal(plainBytes)
            }

            Profile.OPEN_KAKAO_GCM -> {
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(128, iv))
                cipher.doFinal(plainBytes)
            }
        }

        val frame = ByteBuffer.allocate(4 + iv.size + encrypted.size).order(ByteOrder.LITTLE_ENDIAN)
        frame.putInt(iv.size + encrypted.size)
        frame.put(iv)
        frame.put(encrypted)
        return frame.array()
    }

    fun decrypt(frameBytes: ByteArray): ByteArray {
        require(frameBytes.size >= profile.ivSize) { "frame too short" }
        val iv = frameBytes.copyOfRange(0, profile.ivSize)
        val payload = frameBytes.copyOfRange(profile.ivSize, frameBytes.size)
        return when (profile) {
            Profile.NODE_KAKAO -> {
                val cipher = Cipher.getInstance("AES/CFB/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, secretKey, IvParameterSpec(iv))
                cipher.doFinal(payload)
            }

            Profile.OPEN_KAKAO_GCM -> {
                require(payload.size >= 16) { "gcm payload too short" }
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, iv))
                cipher.doFinal(payload)
            }
        }
    }

    companion object {
        private const val OPEN_KAKAO_RSA_PUBLIC_KEY_DER_B64: String =
            "MIIBCAKCAQEAo7B26MRFhR8ZpnDCMarG20Lv0JcX0GBIpcxWkGzRqye53zf/1QF+fBOhQFtdHD5IeaakmdPGGKckcrC1DKXvHvbupwNp2UE/5mLY4rR5qfchQu5wzubCrRIEXVKyXEogSiiWjjfwumpJ7j7J8qx6ZRhBYPIvYsQ6QGfNjSpvE9m4KYqwAnY9I2ydGHnX/OW4+pEIgrIeFSR+DQokeRMI5RmDYUQC6foDBXxX6eF4scw5/mcojvxGGUXLyqEdH8wSPnULhh8NRH6+PBFfQRpC3JXdsh2kJ3SlvLHd9/pfEGKAEMdPNvMcQO/P4on9gbq6RKZVamwwEhBBS2Ajw/RjcQIBAw=="
        private const val NODE_KAKAO_RSA_PUBLIC_KEY_PEM: String =
            "-----BEGIN PUBLIC KEY-----\n" +
                "MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEApElgRBx+g7sniYFW7LE8ivrw\n" +
                "XShKTRFV8lXNItMXbN5QSC8vJ/cTSOTS619Xv5Zx7xXJIk4EKxtWesEGbgZpEUP2xQ+I\n" +
                "eH9oz0JxayEMvvD1nVNAWgpWE4pociEoArsK7qY3YwXb1CiDHo9hojLv7djbo3cwXvly\n" +
                "Mh4TUrX2RjCZPlVJxk/LVjzcl9ohJLkl3eoSrf0AE4kQ9mk3+raEhq5Dv+IDxKYX+fIy\n" +
                "tUWKmrQJusjtre9oVUX5sBOYZ0dzez/XapusEhUWImmB6mciVXfRXQ8IK4IH6vfNyxMS\n" +
                "OTfLEhRYN2SMLzplAYFiMV536tLS3VmG5GJRdkpDubqPeQIBAw==\n" +
                "-----END PUBLIC KEY-----"

        private val secureRandom = SecureRandom()
        private val openKakaoRsaPublicKey: PublicKey by lazy {
            parseDerRsaPublicKey(Base64.getDecoder().decode(OPEN_KAKAO_RSA_PUBLIC_KEY_DER_B64))
        }
        private val nodeKakaoRsaPublicKey: PublicKey by lazy { parsePemRsaPublicKey(NODE_KAKAO_RSA_PUBLIC_KEY_PEM) }

        fun create(profile: Profile = Profile.NODE_KAKAO, secretKeyBytes: ByteArray? = null): LocoEncryptor {
            val secretKey = secretKeyBytes?.let(::aesSecretKey) ?: generateSecretKey()
            return LocoEncryptor(secretKey, profile)
        }

        fun fromSecretKey(secretKeyBytes: ByteArray, profile: Profile = Profile.NODE_KAKAO): LocoEncryptor =
            LocoEncryptor(aesSecretKey(secretKeyBytes), profile)

        private fun generateSecretKey(): SecretKey {
            val generator = KeyGenerator.getInstance("AES")
            generator.init(128, secureRandom)
            return generator.generateKey()
        }

        private fun aesSecretKey(secretKeyBytes: ByteArray): SecretKey {
            require(secretKeyBytes.size == 16) { "LOCO AES secret must be 16 bytes" }
            return SecretKeySpec(secretKeyBytes.copyOf(), "AES")
        }

        private fun rsaPublicKeyFor(profile: Profile): PublicKey =
            when (profile) {
                Profile.NODE_KAKAO -> nodeKakaoRsaPublicKey
                Profile.OPEN_KAKAO_GCM -> openKakaoRsaPublicKey
            }

        private fun parsePemRsaPublicKey(pem: String): PublicKey {
            val der =
                Base64.getDecoder().decode(
                    pem.lineSequence()
                        .filterNot { it.startsWith("-----") }
                        .joinToString(""),
                )
            return KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(der))
        }

        private fun parseDerRsaPublicKey(derBytes: ByteArray): PublicKey {
            val (modulusBytes, exponentBytes) = parseDerSequenceOfTwoIntegers(derBytes)
            val keySpec = RSAPublicKeySpec(BigInteger(1, modulusBytes), BigInteger(1, exponentBytes))
            return KeyFactory.getInstance("RSA").generatePublic(keySpec)
        }

        private fun parseDerSequenceOfTwoIntegers(derBytes: ByteArray): Pair<ByteArray, ByteArray> {
            var cursor = 0
            require(derBytes[cursor++] == 0x30.toByte()) { "expected DER sequence" }
            cursor += derLength(derBytes, cursor).second

            require(derBytes[cursor++] == 0x02.toByte()) { "expected modulus integer" }
            val (modulusLength, modulusHeaderLength) = derLength(derBytes, cursor)
            cursor += modulusHeaderLength
            val modulus = derBytes.copyOfRange(cursor, cursor + modulusLength)
            cursor += modulusLength

            require(derBytes[cursor++] == 0x02.toByte()) { "expected exponent integer" }
            val (exponentLength, exponentHeaderLength) = derLength(derBytes, cursor)
            cursor += exponentHeaderLength
            val exponent = derBytes.copyOfRange(cursor, cursor + exponentLength)
            return modulus to exponent
        }

        private fun derLength(bytes: ByteArray, offset: Int): Pair<Int, Int> {
            val head = bytes[offset].toInt() and 0xFF
            if (head < 0x80) {
                return head to 1
            }
            val count = head and 0x7F
            var length = 0
            repeat(count) { index ->
                length = (length shl 8) or (bytes[offset + 1 + index].toInt() and 0xFF)
            }
            return length to (1 + count)
        }
    }
}
