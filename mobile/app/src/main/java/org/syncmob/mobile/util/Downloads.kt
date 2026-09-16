package org.syncmob.mobile.util

import android.content.ContentValues
import android.content.Context
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import java.io.File

/**
 * Where a verified file ends up.
 *
 * On API 29+ this is the public Downloads collection through MediaStore, which
 * needs no storage permission. Below that, and whenever MediaStore refuses, it
 * falls back to the app's own external files directory, which also needs no
 * permission and is not world readable.
 */
object Downloads {
    private const val SUBDIR = "SyncMob"

    data class Saved(val displayName: String, val location: String, val uri: Uri?)

    fun publish(context: Context, source: File, name: String): Saved {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            runCatching { publishViaMediaStore(context, source, name) }
                .getOrNull()
                ?.let { return it }
        }
        return publishToAppDir(context, source, name)
    }

    private fun publishViaMediaStore(context: Context, source: File, name: String): Saved {
        val values = ContentValues().apply {
            put(MediaStore.Downloads.DISPLAY_NAME, name)
            put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS + "/" + SUBDIR)
            put(MediaStore.Downloads.IS_PENDING, 1)
        }
        val resolver = context.contentResolver
        val uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
            ?: throw IllegalStateException("MediaStore refused the insert")
        try {
            resolver.openOutputStream(uri).use { out ->
                requireNotNull(out) { "no output stream" }
                source.inputStream().use { it.copyTo(out, 256 * 1024) }
            }
            values.clear()
            values.put(MediaStore.Downloads.IS_PENDING, 0)
            resolver.update(uri, values, null, null)
        } catch (e: Exception) {
            resolver.delete(uri, null, null)
            throw e
        }
        source.delete()
        return Saved(name, "Загрузки/$SUBDIR", uri)
    }

    private fun publishToAppDir(context: Context, source: File, name: String): Saved {
        val dir = File(
            context.getExternalFilesDir(Environment.DIRECTORY_DOWNLOADS)
                ?: context.filesDir,
            "",
        )
        val dest = SafeFiles.uniqueFile(dir, name)
        source.copyTo(dest, overwrite = false)
        source.delete()
        return Saved(dest.name, dest.parentFile?.absolutePath ?: dest.absolutePath, null)
    }
}
