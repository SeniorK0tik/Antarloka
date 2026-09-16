package org.syncmob.mobile

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.syncmob.mobile.util.SafeFiles
import java.net.InetAddress

/**
 * File names arrive from the network, so these rules are a security boundary,
 * not cosmetics. They mirror `desktop/src/util.rs` exactly, which is also why
 * a file sent from this phone keeps a usable name on a Windows peer.
 */
class SafeFilesTest {

    @Test
    fun traversal_is_stripped() {
        assertEquals("passwd", SafeFiles.sanitizeFilename("../../etc/passwd"))
        assertEquals("evil.dll", SafeFiles.sanitizeFilename("..\\..\\windows\\system32\\evil.dll"))
        assertEquals("path.txt", SafeFiles.sanitizeFilename("/absolute/path.txt"))
        assertEquals("received_file", SafeFiles.sanitizeFilename(".."))
        assertEquals("received_file", SafeFiles.sanitizeFilename("."))
        assertEquals("received_file", SafeFiles.sanitizeFilename(""))
    }

    @Test
    fun alternate_data_streams_and_illegal_chars_are_removed() {
        assertEquals("report.txt\$DATA", SafeFiles.sanitizeFilename("report.txt:\$DATA"))
        assertEquals("abcdef.txt", SafeFiles.sanitizeFilename("a<b>c|d?e*f.txt"))
        val withNul = "bad" + 0.toChar() + "name.txt"
        assertEquals("badname.txt", SafeFiles.sanitizeFilename(withNul))
    }

    @Test
    fun trailing_dots_and_spaces_are_removed() {
        // Windows silently strips these, which would turn "x.exe." into "x.exe"
        // after we had already decided the name looked harmless.
        assertEquals("payload.exe", SafeFiles.sanitizeFilename("payload.exe."))
        assertEquals("payload.exe", SafeFiles.sanitizeFilename("payload.exe   "))
    }

    @Test
    fun reserved_windows_names_are_escaped() {
        assertEquals("_CON", SafeFiles.sanitizeFilename("CON"))
        assertEquals("_nul.txt", SafeFiles.sanitizeFilename("nul.txt"))
        assertEquals("_com1.log", SafeFiles.sanitizeFilename("com1.log"))
    }

    @Test
    fun long_names_keep_their_extension() {
        val out = SafeFiles.sanitizeFilename("x".repeat(400) + ".tar.gz")
        assertTrue(out.length <= 120)
        assertTrue(out.endsWith(".gz"))
    }

    @Test
    fun ordinary_names_are_left_alone() {
        assertEquals("photo.jpg", SafeFiles.sanitizeFilename("photo.jpg"))
        assertEquals("otchet 2026.pdf", SafeFiles.sanitizeFilename("otchet 2026.pdf"))
    }

    @Test
    fun lan_filter_accepts_private_ranges_only() {
        assertTrue(SafeFiles.isLanAddress(InetAddress.getByName("192.168.1.5")))
        assertTrue(SafeFiles.isLanAddress(InetAddress.getByName("10.0.0.1")))
        assertTrue(SafeFiles.isLanAddress(InetAddress.getByName("172.16.9.9")))
        assertTrue(SafeFiles.isLanAddress(InetAddress.getByName("127.0.0.1")))
        assertTrue(SafeFiles.isLanAddress(InetAddress.getByName("100.70.0.1")))
        assertFalse(SafeFiles.isLanAddress(InetAddress.getByName("8.8.8.8")))
        assertFalse(SafeFiles.isLanAddress(InetAddress.getByName("172.32.0.1")))
    }

    @Test
    fun human_bytes_formats_sensibly() {
        assertTrue(SafeFiles.humanBytes(512).startsWith("512"))
        assertTrue(SafeFiles.humanBytes(1024).startsWith("1"))
        assertTrue(SafeFiles.humanBytes(5L * 1024 * 1024).contains("1024").not())
    }
}
