package org.syncmob.mobile.proto

import java.io.ByteArrayOutputStream
import java.util.Base64

/**
 * The `syncmob://pair?...` link encoded in the desktop QR code.
 *
 * It carries the desktop's public key out of band. A phone that scans it knows
 * which key to expect *before* connecting, so a machine-in-the-middle is
 * detected by the key check rather than by a human comparing digits.
 *
 * Parsing is strict on purpose: a truncated or malformed scan must fail, never
 * degrade into "connect to whatever answers and trust it".
 */
object PairingUri {
    private const val PREFIX = "syncmob://pair?"

    data class Target(
        val publicKey: ByteArray,
        val host: String,
        val port: Int,
        val name: String,
    ) {
        override fun equals(other: Any?) = other is Target &&
            publicKey.contentEquals(other.publicKey) && host == other.host && port == other.port

        override fun hashCode() = publicKey.contentHashCode() * 31 + port
    }

    fun parse(uri: String): Target? {
        if (!uri.startsWith(PREFIX)) return null
        var pk: ByteArray? = null
        var host: String? = null
        var port = Proto.DEFAULT_TCP_PORT
        var name = ""
        for (kv in uri.removePrefix(PREFIX).split('&')) {
            val idx = kv.indexOf('=')
            val k = if (idx < 0) kv else kv.substring(0, idx)
            val v = if (idx < 0) "" else kv.substring(idx + 1)
            when (k) {
                "pk" -> pk = runCatching { Base64.getUrlDecoder().decode(v) }.getOrNull()
                "host" -> host = v
                "port" -> port = v.toIntOrNull() ?: port
                "name" -> name = Proto.clamp(unescape(v), 64)
            }
        }
        val key = pk ?: return null
        if (key.size != 32) return null
        if (host.isNullOrBlank() || port <= 0 || port > 65535) return null
        return Target(key, host, port, name)
    }

    private fun unescape(s: String): String {
        val out = ByteArrayOutputStream()
        val b = s.toByteArray(Charsets.US_ASCII)
        var i = 0
        while (i < b.size) {
            if (b[i] == '%'.code.toByte() && i + 2 < b.size) {
                val v = s.substring(i + 1, i + 3).toIntOrNull(16)
                if (v != null) {
                    out.write(v)
                    i += 3
                    continue
                }
            }
            out.write(b[i].toInt())
            i++
        }
        return String(out.toByteArray(), Charsets.UTF_8)
    }
}
