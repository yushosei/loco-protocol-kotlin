package com.yushosei.loco

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.longOrNull
import org.bson.BsonArray
import org.bson.BsonBinary
import org.bson.BsonBinaryReader
import org.bson.BsonBinaryWriter
import org.bson.BsonBoolean
import org.bson.BsonDateTime
import org.bson.BsonDocument
import org.bson.BsonDouble
import org.bson.BsonInt32
import org.bson.BsonInt64
import org.bson.BsonNull
import org.bson.BsonString
import org.bson.BsonValue
import org.bson.ByteBufNIO
import org.bson.codecs.BsonDocumentCodec
import org.bson.codecs.DecoderContext
import org.bson.codecs.EncoderContext
import org.bson.io.BasicOutputBuffer
import org.bson.io.ByteBufferBsonInput
import java.nio.ByteBuffer
import java.util.Base64

internal object BsonSupport {
    private val codec = BsonDocumentCodec()

    fun encode(document: BsonDocument): ByteArray {
        val output = BasicOutputBuffer()
        BsonBinaryWriter(output).use { writer ->
            codec.encode(writer, document, EncoderContext.builder().build())
        }
        return output.toByteArray()
    }

    fun decode(bytes: ByteArray): BsonDocument {
        val input = ByteBufferBsonInput(ByteBufNIO(ByteBuffer.wrap(bytes)))
        val reader = BsonBinaryReader(input)
        return reader.use {
            codec.decode(reader, DecoderContext.builder().build())
        }
    }

    fun toJson(document: BsonDocument): JsonObject =
        JsonObject(document.mapValues { (_, value) -> value.toJson() })

    fun fromJsonObject(document: JsonObject): BsonDocument =
        BsonDocument().apply {
            document.forEach { (key, value) -> append(key, value.toBson()) }
        }

    fun docOf(vararg pairs: Pair<String, BsonValue>): BsonDocument =
        BsonDocument().apply {
            pairs.forEach { (key, value) -> append(key, value) }
        }
}

internal fun BsonDocument.string(vararg keys: String): String =
    keys.asSequence().mapNotNull { key ->
        this[key]?.let { value ->
            when {
                value.isString -> value.asString().value
                value.isInt32 -> value.asInt32().value.toString()
                value.isInt64 -> value.asInt64().value.toString()
                else -> null
            }
        }
    }.firstOrNull().orEmpty()

internal fun BsonDocument.long(vararg keys: String): Long =
    keys.asSequence().mapNotNull { key ->
        this[key]?.let { value ->
            when {
                value.isInt64 -> value.asInt64().value
                value.isInt32 -> value.asInt32().value.toLong()
                value.isString -> value.asString().value.toLongOrNull()
                else -> null
            }
        }
    }.firstOrNull() ?: 0L

internal fun BsonDocument.int(vararg keys: String): Int =
    keys.asSequence().mapNotNull { key ->
        this[key]?.let { value ->
            when {
                value.isInt32 -> value.asInt32().value
                value.isInt64 -> value.asInt64().value.toInt()
                value.isString -> value.asString().value.toIntOrNull()
                else -> null
            }
        }
    }.firstOrNull() ?: 0

internal fun BsonDocument.bool(vararg keys: String): Boolean =
    keys.asSequence().mapNotNull { key ->
        this[key]?.let { value ->
            when {
                value.isBoolean -> value.asBoolean().value
                value.isString -> value.asString().value.toBooleanStrictOrNull()
                else -> null
            }
        }
    }.firstOrNull() ?: false

internal fun BsonDocument.array(key: String): List<BsonValue> =
    this[key]?.takeIf { it.isArray }?.asArray()?.values.orEmpty()

internal fun BsonValue.toJson(): JsonElement = when (this) {
    is BsonString -> JsonPrimitive(value)
    is BsonBoolean -> JsonPrimitive(value)
    is BsonInt32 -> JsonPrimitive(value)
    is BsonInt64 -> JsonPrimitive(value)
    is BsonDouble -> JsonPrimitive(value)
    is BsonDateTime -> JsonPrimitive(value)
    is BsonBinary -> JsonPrimitive(Base64.getEncoder().encodeToString(data))
    is BsonDocument -> BsonSupport.toJson(this)
    is BsonArray -> JsonArray(values.map(BsonValue::toJson))
    is BsonNull -> JsonNull
    else -> JsonPrimitive(toString())
}

internal fun BsonValue.asDocumentOrNull(): BsonDocument? = if (isDocument) asDocument() else null
internal fun BsonValue.asStringOrNull(): String? = if (isString) asString().value else null

internal fun JsonElement.toBson(): BsonValue = when (this) {
    JsonNull -> BsonNull.VALUE
    is JsonObject -> BsonSupport.fromJsonObject(this)
    is JsonArray -> BsonArray(map(JsonElement::toBson))
    is JsonPrimitive ->
        when {
            isString -> BsonString(content)
            booleanOrNull != null -> BsonBoolean(booleanOrNull!!)
            content.contains('.') || content.contains('e', ignoreCase = true) -> BsonDouble(doubleOrNull ?: content.toDouble())
            else -> {
                val numeric = longOrNull
                when {
                    numeric == null -> BsonString(content)
                    numeric in Int.MIN_VALUE..Int.MAX_VALUE -> BsonInt32(numeric.toInt())
                    else -> BsonInt64(numeric)
                }
            }
        }
}
