package com.yushosei.logging

import com.yushosei.loco.BsonSupport
import com.yushosei.loco.LocoPacket
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
import java.util.concurrent.atomic.AtomicLong

@Serializable
enum class ProtocolLogDirection {
    TX,
    RX,
    SYSTEM,
}

@Serializable
enum class ProtocolLogType {
    PACKET,
    RAW,
    ERROR,
    SYSTEM,
}

@Serializable
data class ProtocolLogEntry(
    val id: Long,
    val timestamp: Long,
    val direction: ProtocolLogDirection,
    val type: ProtocolLogType,
    val transport: String? = null,
    val method: String? = null,
    val packetId: Int? = null,
    val status: Long? = null,
    val note: String? = null,
    val parsedBody: JsonObject? = null,
    val rawPreviewHex: String? = null,
    val rawLength: Int? = null,
    val truncated: Boolean = false,
)

object ProtocolLogStore {
    private const val maxHistorySize = 400
    private const val rawPreviewLimit = 256

    private val nextId = AtomicLong(1)
    private val lock = Any()
    private val history = ArrayDeque<ProtocolLogEntry>()
    private val events =
        MutableSharedFlow<ProtocolLogEntry>(
            replay = 0,
            extraBufferCapacity = 256,
            onBufferOverflow = BufferOverflow.DROP_OLDEST,
        )

    fun stream(): SharedFlow<ProtocolLogEntry> = events.asSharedFlow()

    fun snapshot(limit: Int = 200): List<ProtocolLogEntry> =
        synchronized(lock) {
            history.takeLast(limit.coerceAtLeast(1)).toList()
        }

    fun recordPacket(direction: ProtocolLogDirection, transport: String, packet: LocoPacket, note: String? = null) {
        publish(
            ProtocolLogEntry(
                id = nextId.getAndIncrement(),
                timestamp = System.currentTimeMillis(),
                direction = direction,
                type = ProtocolLogType.PACKET,
                transport = transport,
                method = packet.method,
                packetId = packet.packetId,
                status = packet.status(),
                note = note,
                parsedBody = BsonSupport.toJson(packet.body),
            ),
        )
    }

    fun recordRaw(direction: ProtocolLogDirection, transport: String, raw: ByteArray, note: String) {
        publish(
            ProtocolLogEntry(
                id = nextId.getAndIncrement(),
                timestamp = System.currentTimeMillis(),
                direction = direction,
                type = ProtocolLogType.RAW,
                transport = transport,
                note = note,
                rawPreviewHex = raw.toHexPreview(),
                rawLength = raw.size,
                truncated = raw.size > rawPreviewLimit,
            ),
        )
    }

    fun recordError(direction: ProtocolLogDirection, transport: String, raw: ByteArray, note: String) {
        publish(
            ProtocolLogEntry(
                id = nextId.getAndIncrement(),
                timestamp = System.currentTimeMillis(),
                direction = direction,
                type = ProtocolLogType.ERROR,
                transport = transport,
                note = note,
                rawPreviewHex = raw.toHexPreview(),
                rawLength = raw.size,
                truncated = raw.size > rawPreviewLimit,
            ),
        )
    }

    fun recordSystem(note: String, transport: String? = null) {
        publish(
            ProtocolLogEntry(
                id = nextId.getAndIncrement(),
                timestamp = System.currentTimeMillis(),
                direction = ProtocolLogDirection.SYSTEM,
                type = ProtocolLogType.SYSTEM,
                transport = transport,
                note = note,
            ),
        )
    }

    private fun publish(entry: ProtocolLogEntry) {
        synchronized(lock) {
            while (history.size >= maxHistorySize) {
                history.removeFirst()
            }
            history.addLast(entry)
        }
        events.tryEmit(entry)
    }

    private fun ByteArray.toHexPreview(): String {
        val preview = copyOf(minOf(size, rawPreviewLimit))
        return buildString(preview.size * 3) {
            preview.forEachIndexed { index, byte ->
                if (index > 0) {
                    append(' ')
                }
                append("%02x".format(byte.toInt() and 0xff))
            }
            if (size > rawPreviewLimit) {
                append(" ...")
            }
        }
    }
}
