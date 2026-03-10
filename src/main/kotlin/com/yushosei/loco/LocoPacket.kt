package com.yushosei.loco

import org.bson.BsonDocument
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import java.util.concurrent.atomic.AtomicInteger

data class LocoPacket(
    val packetId: Int,
    val statusCode: Short,
    val method: String,
    val bodyType: Byte,
    val body: BsonDocument,
) {
    fun encode(): ByteArray {
        val bodyBytes = BsonSupport.encode(body)
        val buffer = ByteBuffer.allocate(HEADER_SIZE + bodyBytes.size).order(ByteOrder.LITTLE_ENDIAN)
        buffer.putInt(packetId)
        buffer.putShort(statusCode)
        val methodBytes = ByteArray(11)
        val source = method.toByteArray(StandardCharsets.US_ASCII)
        System.arraycopy(source, 0, methodBytes, 0, minOf(source.size, methodBytes.size))
        buffer.put(methodBytes)
        buffer.put(bodyType)
        buffer.putInt(bodyBytes.size)
        buffer.put(bodyBytes)
        return buffer.array()
    }

    fun status(): Long =
        if (body.containsKey("status")) body.long("status") else statusCode.toLong()

    companion object {
        const val HEADER_SIZE: Int = 22

        fun decode(bytes: ByteArray): LocoPacket {
            require(bytes.size >= HEADER_SIZE) { "packet too short" }
            val header = decodeHeader(bytes.copyOfRange(0, HEADER_SIZE))
            val bodyBytes = bytes.copyOfRange(HEADER_SIZE, HEADER_SIZE + header.bodyLength)
            val body = if (bodyBytes.isEmpty()) BsonDocument() else BsonSupport.decode(bodyBytes)
            return LocoPacket(
                packetId = header.packetId,
                statusCode = header.statusCode,
                method = header.method,
                bodyType = header.bodyType,
                body = body,
            )
        }

        fun decodeHeader(bytes: ByteArray): LocoHeader {
            require(bytes.size >= HEADER_SIZE) { "header too short" }
            val buffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
            val packetId = buffer.int
            val statusCode = buffer.short
            val methodBytes = ByteArray(11)
            buffer.get(methodBytes)
            val method = methodBytes.takeWhile { it != 0.toByte() }.toByteArray().toString(StandardCharsets.US_ASCII)
            val bodyType = buffer.get()
            val bodyLength = buffer.int
            return LocoHeader(packetId, statusCode, method, bodyType, bodyLength)
        }
    }
}

data class LocoHeader(
    val packetId: Int,
    val statusCode: Short,
    val method: String,
    val bodyType: Byte,
    val bodyLength: Int,
)

class PacketBuilder {
    constructor(initialId: Int = NODE_KAKAO_INITIAL_ID) {
        require(initialId in 0 until REQUEST_ID_MODULUS) { "initial packet id must be in [0, ${REQUEST_ID_MODULUS - 1}]" }
        nextId = AtomicInteger(initialId)
    }

    private val nextId: AtomicInteger

    fun build(method: String, body: BsonDocument = BsonDocument()): LocoPacket =
        LocoPacket(
            packetId = nextId.updateAndGet { current -> (current + 1) % REQUEST_ID_MODULUS },
            statusCode = 0,
            method = method,
            bodyType = 0,
            body = body,
        )

    companion object {
        private const val REQUEST_ID_MODULUS = 100000
        private const val NODE_KAKAO_INITIAL_ID = 1
    }
}
