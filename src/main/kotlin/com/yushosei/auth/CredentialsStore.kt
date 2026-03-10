package com.yushosei.auth

import com.yushosei.model.KakaoCredentials
import kotlinx.serialization.json.Json
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.Paths
import kotlin.io.path.exists
import kotlin.io.path.readText
import kotlin.io.path.writeText

object CredentialsStore {
    private val json = Json {
        prettyPrint = true
        ignoreUnknownKeys = true
        encodeDefaults = true
    }

    fun path(): Path =
        Paths.get(System.getProperty("user.home"), ".config", "kakaotalk", "credentials.json")

    fun load(): KakaoCredentials? {
        val path = path()
        if (!path.exists()) {
            return null
        }
        return json.decodeFromString(KakaoCredentials.serializer(), path.readText())
    }

    fun save(credentials: KakaoCredentials): Path {
        val path = path()
        Files.createDirectories(path.parent)
        path.writeText(json.encodeToString(KakaoCredentials.serializer(), credentials))
        return path
    }
}
