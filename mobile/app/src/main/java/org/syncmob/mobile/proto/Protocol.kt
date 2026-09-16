package org.syncmob.mobile.proto

import org.json.JSONObject
import org.syncmob.mobile.security.Fingerprints
import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import java.util.Base64

/**
 * SyncMob wire protocol, version 1.
 *
 * Mirrors `desktop/src/proto.rs` exactly. Framing inside the Noise transport:
 *
 *     u32be ciphertextLength   (<= 65535)
 *     bytes ciphertext
 *
 * Decrypted plaintext:
 *
 *     u8    message type
 *     bytes payload (JSON for control messages, binary for FILE_CHUNK)
 */
object Proto {
    const val PROTOCOL_ID = "SyncMob/1"
    const val VERSION = 1

    const val DISCOVERY_PORT = 45820
    const val DEFAULT_TCP_PORT = 45821
    const val MULTICAST_GROUP = "239.255.79.20"

    const val MAX_FRAME = 65535
    const val MAX_PLAINTEXT = MAX_FRAME - 16
    const val CHUNK_SIZE = 32 * 1024
    const val MAX_CONTROL_JSON = 16 * 1024
    const val MAX_FILE_SIZE = 1L shl 40
    const val MAX_TEXT_CHARS = 4096
    const val MAX_NAME_CHARS = 64
    const val MAX_FILENAME_CHARS = 255

    const val BEACON_MAGIC = "SYNCMOB"
    const val MAX_BEACON_BYTES = 512

    const val TY_HELLO: Byte = 0x01
    const val TY_PING: Byte = 0x02
    const val TY_PONG: Byte = 0x03
    const val TY_PAIR_REQUEST: Byte = 0x10
    const val TY_PAIR_ACCEPT: Byte = 0x11
    const val TY_PAIR_REJECT: Byte = 0x12
    const val TY_TEXT: Byte = 0x20
    const val TY_TEXT_ACK: Byte = 0x21
    const val TY_FILE_OFFER: Byte = 0x30
    const val TY_FILE_ACCEPT: Byte = 0x31
    const val TY_FILE_REJECT: Byte = 0x32
    const val TY_FILE_CHUNK: Byte = 0x33
    const val TY_FILE_DONE: Byte = 0x34
    const val TY_FILE_ERROR: Byte = 0x35
    const val TY_FILE_CANCEL: Byte = 0x36

    /** Trim anything that came off the network before it reaches the UI. */
    fun clamp(s: String, max: Int): String {
        val cleaned = s.map { if (it.isISOControl()) ' ' else it }.joinToString("")
        return if (cleaned.length <= max) cleaned else cleaned.take(max) + "…"
    }
}

class ProtocolException(message: String) : Exception(message)

/** 128-bit transfer identifier. */
class TransferId(val bytes: ByteArray) {
    init {
        require(bytes.size == 16) { "transfer id must be 16 bytes" }
    }

    fun hex(): String = Fingerprints.hex(bytes)
    fun short(): String = hex().take(8)

    override fun equals(other: Any?): Boolean =
        other is TransferId && bytes.contentEquals(other.bytes)

    override fun hashCode(): Int = bytes.contentHashCode()
    override fun toString(): String = hex()

    companion object {
        private val rng = SecureRandom()
        fun random(): TransferId = TransferId(ByteArray(16).also { rng.nextBytes(it) })
        fun parse(s: String): TransferId? {
            val b = Fingerprints.unhex(s) ?: return null
            return if (b.size == 16) TransferId(b) else null
        }
    }
}

sealed class Message {
    data class Hello(val name: String, val version: Int, val platform: String) : Message()
    object Ping : Message()
    object Pong : Message()
    data class PairRequest(val name: String, val platform: String) : Message()
    object PairAccept : Message()
    data class PairReject(val reason: String) : Message()
    data class Text(val id: TransferId, val ts: Long, val text: String) : Message()
    data class TextAck(val id: TransferId) : Message()
    data class FileOffer(
        val id: TransferId,
        val name: String,
        val size: Long,
        val sha256: String,
        val mime: String = "",
    ) : Message()

    data class FileAccept(val id: TransferId) : Message()
    data class FileReject(val id: TransferId, val reason: String) : Message()
    data class FileChunk(val id: TransferId, val offset: Long, val data: ByteArray) : Message() {
        override fun equals(other: Any?): Boolean =
            other is FileChunk && id == other.id && offset == other.offset &&
                data.contentEquals(other.data)

        override fun hashCode(): Int =
            31 * (31 * id.hashCode() + offset.hashCode()) + data.contentHashCode()
    }

    data class FileDone(val id: TransferId, val sha256: String) : Message()
    data class FileError(val id: TransferId, val reason: String) : Message()
    data class FileCancel(val id: TransferId, val reason: String) : Message()

    val typeByte: Byte
        get() = when (this) {
            is Hello -> Proto.TY_HELLO
            Ping -> Proto.TY_PING
            Pong -> Proto.TY_PONG
            is PairRequest -> Proto.TY_PAIR_REQUEST
            PairAccept -> Proto.TY_PAIR_ACCEPT
            is PairReject -> Proto.TY_PAIR_REJECT
            is Text -> Proto.TY_TEXT
            is TextAck -> Proto.TY_TEXT_ACK
            is FileOffer -> Proto.TY_FILE_OFFER
            is FileAccept -> Proto.TY_FILE_ACCEPT
            is FileReject -> Proto.TY_FILE_REJECT
            is FileChunk -> Proto.TY_FILE_CHUNK
            is FileDone -> Proto.TY_FILE_DONE
            is FileError -> Proto.TY_FILE_ERROR
            is FileCancel -> Proto.TY_FILE_CANCEL
        }

    /**
     * Messages an unpaired peer is allowed to send. Everything else is dropped
     * and the connection closed — the mirror of the same rule on the desktop
     * side, enforced independently on each end.
     */
    fun allowedBeforePairing(): Boolean = when (this) {
        is Hello, Ping, Pong, is PairRequest, PairAccept, is PairReject -> true
        else -> false
    }

    fun encode(): ByteArray {
        val out = ByteArrayOutputStream(96)
        out.write(typeByte.toInt())
        when (this) {
            is Hello -> out.writeJson(
                JSONObject().put("name", name).put("version", version).put("platform", platform),
            )

            Ping, Pong, PairAccept -> {}
            is PairRequest -> out.writeJson(
                JSONObject().put("name", name).put("platform", platform),
            )

            is PairReject -> out.writeJson(JSONObject().put("reason", reason))
            is Text -> out.writeJson(
                JSONObject().put("id", id.hex()).put("ts", ts).put("text", text),
            )

            is TextAck -> out.writeJson(JSONObject().put("id", id.hex()))
            is FileOffer -> out.writeJson(
                JSONObject()
                    .put("id", id.hex())
                    .put("name", name)
                    .put("size", size)
                    .put("sha256", sha256)
                    .put("mime", mime),
            )

            is FileAccept -> out.writeJson(JSONObject().put("id", id.hex()))
            is FileReject -> out.writeJson(JSONObject().put("id", id.hex()).put("reason", reason))
            is FileError -> out.writeJson(JSONObject().put("id", id.hex()).put("reason", reason))
            is FileCancel -> out.writeJson(JSONObject().put("id", id.hex()).put("reason", reason))
            is FileDone -> out.writeJson(JSONObject().put("id", id.hex()).put("sha256", sha256))
            is FileChunk -> {
                out.write(id.bytes)
                for (i in 7 downTo 0) out.write(((offset ushr (i * 8)) and 0xFF).toInt())
                out.write(data)
            }
        }
        val bytes = out.toByteArray()
        if (bytes.size > Proto.MAX_PLAINTEXT) throw ProtocolException("message too large")
        return bytes
    }

    private fun ByteArrayOutputStream.writeJson(o: JSONObject) {
        write(o.toString().toByteArray(Charsets.UTF_8))
    }

    companion object {
        /**
         * Parse and validate one decrypted frame. Every bound checked here is a
         * bound the remote peer would otherwise control.
         */
        fun decode(buf: ByteArray): Message {
            if (buf.isEmpty()) throw ProtocolException("empty frame")
            val t = buf[0]
            val body = buf.copyOfRange(1, buf.size)

            if (t == Proto.TY_FILE_CHUNK) {
                if (body.size < 24) throw ProtocolException("short file chunk")
                val id = TransferId(body.copyOfRange(0, 16))
                var offset = 0L
                for (i in 16 until 24) offset = (offset shl 8) or (body[i].toLong() and 0xFF)
                if (offset < 0 || offset > Proto.MAX_FILE_SIZE) {
                    throw ProtocolException("bad chunk offset")
                }
                return FileChunk(id, offset, body.copyOfRange(24, body.size))
            }

            if (body.size > Proto.MAX_CONTROL_JSON) {
                throw ProtocolException("control frame too large")
            }
            val json = if (body.isEmpty()) {
                JSONObject()
            } else {
                try {
                    JSONObject(String(body, Charsets.UTF_8))
                } catch (e: Exception) {
                    throw ProtocolException("malformed json")
                }
            }

            fun id(): TransferId =
                TransferId.parse(json.optString("id")) ?: throw ProtocolException("bad transfer id")

            fun sha(): String {
                val s = json.optString("sha256")
                val hex = s.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' }
                if (s.length != 64 || !hex) throw ProtocolException("bad sha256")
                return s.lowercase()
            }

            return when (t) {
                Proto.TY_HELLO -> {
                    val name = json.optString("name")
                    if (name.length > Proto.MAX_NAME_CHARS) throw ProtocolException("name too long")
                    Hello(name, json.optInt("version", 1), json.optString("platform"))
                }

                Proto.TY_PING -> Ping
                Proto.TY_PONG -> Pong
                Proto.TY_PAIR_REQUEST -> {
                    val name = json.optString("name")
                    if (name.length > Proto.MAX_NAME_CHARS) throw ProtocolException("name too long")
                    PairRequest(name, json.optString("platform"))
                }

                Proto.TY_PAIR_ACCEPT -> PairAccept
                Proto.TY_PAIR_REJECT -> PairReject(json.optString("reason"))
                Proto.TY_TEXT -> {
                    val text = json.optString("text")
                    if (text.length > Proto.MAX_TEXT_CHARS) throw ProtocolException("text too long")
                    Text(id(), json.optLong("ts"), text)
                }

                Proto.TY_TEXT_ACK -> TextAck(id())
                Proto.TY_FILE_OFFER -> {
                    val name = json.optString("name")
                    if (name.length > Proto.MAX_FILENAME_CHARS) {
                        throw ProtocolException("file name too long")
                    }
                    val size = json.optLong("size", -1)
                    if (size < 0 || size > Proto.MAX_FILE_SIZE) throw ProtocolException("bad size")
                    FileOffer(id(), name, size, sha(), json.optString("mime"))
                }

                Proto.TY_FILE_ACCEPT -> FileAccept(id())
                Proto.TY_FILE_REJECT -> FileReject(id(), json.optString("reason"))
                Proto.TY_FILE_ERROR -> FileError(id(), json.optString("reason"))
                Proto.TY_FILE_CANCEL -> FileCancel(id(), json.optString("reason"))
                Proto.TY_FILE_DONE -> FileDone(id(), sha())
                else -> throw ProtocolException("unknown message type " + t.toInt())
            }
        }
    }
}

/**
 * UDP discovery beacon. Unauthenticated by design: it carries only public
 * information and never grants trust.
 */
class Beacon(
    val publicKey: ByteArray,
    val name: String,
    val port: Int,
    val platform: String,
) {
    fun encode(): ByteArray = JSONObject()
        .put("m", Proto.BEACON_MAGIC)
        .put("v", Proto.VERSION)
        .put("pk", Base64.getEncoder().encodeToString(publicKey))
        .put("name", Proto.clamp(name, 32))
        .put("port", port)
        .put("platform", platform)
        .toString()
        .toByteArray(Charsets.UTF_8)

    companion object {
        /** Returns null for anything malformed; never throws on network input. */
        fun parse(raw: ByteArray, length: Int): Beacon? {
            if (length <= 0 || length > Proto.MAX_BEACON_BYTES) return null
            return try {
                val o = JSONObject(String(raw, 0, length, Charsets.UTF_8))
                if (o.optString("m") != Proto.BEACON_MAGIC) return null
                if (o.optInt("v") != Proto.VERSION) return null
                val port = o.optInt("port")
                if (port <= 0 || port > 65535) return null
                val pk = Base64.getDecoder().decode(o.optString("pk"))
                if (pk.size != 32) return null
                Beacon(
                    publicKey = pk,
                    name = Proto.clamp(o.optString("name"), 32),
                    port = port,
                    platform = Proto.clamp(o.optString("platform"), 16),
                )
            } catch (e: Exception) {
                null
            }
        }
    }
}
