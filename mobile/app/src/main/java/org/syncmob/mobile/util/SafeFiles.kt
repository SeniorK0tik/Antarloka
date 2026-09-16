package org.syncmob.mobile.util

import java.io.File
import java.io.InputStream
import java.security.MessageDigest

/**
 * Filesystem helpers whose correctness is a security property.
 *
 * Deliberately free of Android imports so it can be compiled and tested on a
 * plain JVM alongside the protocol and crypto code.
 */
object SafeFiles {
    /** Characters illegal in Windows file names, plus the path separators. */
    private val ILLEGAL = charArrayOf('<', '>', ':', '"', '/', '\\', '|', '?', '*')

    /** Device names reserved by Windows. */
    private val RESERVED = setOf(
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    )

    private const val MAX_NAME_LEN = 120

    /**
     * Turn a peer-supplied file name into something safe to create.
     *
     * Identical rules to `desktop/src/util.rs`: the remote side fully controls
     * this string, so directory traversal, absolute paths, alternate data
     * stream syntax, reserved device names, control characters and trailing
     * dots or spaces all have to go. Files sent from this phone keep working on
     * a Windows peer precisely because both ends apply the same rules.
     */
    fun sanitizeFilename(raw: String): String {
        // 1. Keep only the final path component, whatever separator was used.
        val base = raw.split('/', '\\').last().trim()

        // 2. Drop control characters and characters illegal on Windows.
        val cleanedBuilder = StringBuilder(base.length)
        for (c in base) {
            if (!c.isISOControl() && c !in ILLEGAL) cleanedBuilder.append(c)
        }

        // 3. Windows strips trailing dots and spaces, so strip them ourselves
        //    and validate the name that will actually exist.
        while (cleanedBuilder.isNotEmpty() &&
            (cleanedBuilder.last() == '.' || cleanedBuilder.last() == ' ')
        ) {
            cleanedBuilder.setLength(cleanedBuilder.length - 1)
        }
        val cleaned = cleanedBuilder.toString().trimStart()

        // 4. Refuse the special directory entries.
        if (cleaned.isEmpty() || cleaned == "." || cleaned == "..") return "received_file"

        // 5. Refuse reserved device names (with or without extension).
        val stem = cleaned.substringBefore('.').uppercase()
        if (stem in RESERVED) return "_$cleaned"

        // 6. Clamp the length, keeping the extension when possible.
        return truncateKeepingExtension(cleaned, MAX_NAME_LEN)
    }

    private fun truncateKeepingExtension(name: String, max: Int): String {
        if (name.length <= max) return name
        val dot = name.lastIndexOf('.')
        val hasExt = dot > 0 && name.length - dot <= 16
        val stem = if (hasExt) name.substring(0, dot) else name
        val ext = if (hasExt) name.substring(dot) else ""
        val budget = (max - ext.length).coerceAtLeast(0)
        val cut = minOf(budget, stem.length)
        if (cut == 0) return "received_file"
        return stem.substring(0, cut) + ext
    }

    /** A path inside [dir] that does not exist yet. Never overwrites. */
    fun uniqueFile(dir: File, name: String): File {
        dir.mkdirs()
        val candidate = File(dir, name)
        if (!candidate.exists()) return candidate
        val dot = name.lastIndexOf('.')
        val stem = if (dot > 0) name.substring(0, dot) else name
        val ext = if (dot > 0) name.substring(dot) else ""
        for (n in 1 until 10_000) {
            val c = File(dir, "$stem ($n)$ext")
            if (!c.exists()) return c
        }
        return File(dir, "$stem.${System.currentTimeMillis()}$ext")
    }

    fun humanBytes(n: Long): String {
        val units = arrayOf("Б", "КиБ", "МиБ", "ГиБ", "ТиБ")
        var v = n.toDouble()
        var i = 0
        while (v >= 1024.0 && i < units.size - 1) {
            v /= 1024.0
            i++
        }
        return if (i == 0) "$n ${units[0]}" else String.format("%.1f %s", v, units[i])
    }

    fun sha256(stream: InputStream): Pair<String, Long> {
        val digest = MessageDigest.getInstance("SHA-256")
        val buf = ByteArray(256 * 1024)
        var total = 0L
        stream.use {
            while (true) {
                val n = it.read(buf)
                if (n <= 0) break
                digest.update(buf, 0, n)
                total += n
            }
        }
        return hex(digest.digest()) to total
    }

    fun hex(b: ByteArray): String {
        val sb = StringBuilder(b.size * 2)
        for (x in b) sb.append(String.format("%02x", x))
        return sb.toString()
    }

    /**
     * Refuse to talk to anything that is not on the local network.
     *
     * SyncMob is a LAN tool; declining routable addresses means a hostile
     * beacon cannot steer the app at a host on the open internet.
     */
    fun isLanAddress(address: java.net.InetAddress): Boolean {
        if (address.isLoopbackAddress || address.isLinkLocalAddress ||
            address.isSiteLocalAddress || address.isAnyLocalAddress
        ) {
            return true
        }
        val b = address.address
        // 100.64.0.0/10, carrier grade NAT, used by some routers for guests.
        if (b.size == 4) {
            val o0 = b[0].toInt() and 0xFF
            val o1 = b[1].toInt() and 0xFF
            if (o0 == 100 && o1 in 64..127) return true
        }
        // fc00::/7 unique local addresses.
        if (b.size == 16 && (b[0].toInt() and 0xFE) == 0xFC) return true
        return false
    }
}
