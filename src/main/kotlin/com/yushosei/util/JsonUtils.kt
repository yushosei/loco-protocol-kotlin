package com.yushosei.util

import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull

fun JsonElement.jsonString(key: String): String =
    jsonObject[key]?.jsonPrimitive?.contentOrNull.orEmpty()

fun JsonElement.jsonLong(key: String): Long =
    jsonObject[key]?.jsonPrimitive?.longOrNull
        ?: jsonObject[key]?.jsonPrimitive?.contentOrNull?.toLongOrNull()
        ?: 0L
