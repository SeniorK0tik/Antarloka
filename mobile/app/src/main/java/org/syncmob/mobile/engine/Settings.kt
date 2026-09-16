package org.syncmob.mobile.engine

import android.content.Context
import android.os.Build
import org.syncmob.mobile.proto.Proto

/** Non-secret, user-changeable settings. */
data class Settings(
    /** Name broadcast to the LAN. Visible to anyone on the network. */
    val deviceName: String,
    val tcpPort: Int,
    /** Announce our presence over UDP. */
    val discoveryEnabled: Boolean,
    /** Accept inbound connections at all. */
    val acceptIncoming: Boolean,
    /** Refuse addresses outside RFC1918 / link-local / unique-local ranges. */
    val lanOnly: Boolean,
    /** Allow pairing requests from unknown devices. */
    val allowNewPairings: Boolean,
    /** Refuse offers larger than this. 0 means no extra limit. */
    val maxFileSizeBytes: Long,
) {
    companion object {
        private const val PREFS = "syncmob_settings"

        fun load(context: Context): Settings {
            val p = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            return Settings(
                deviceName = Proto.clamp(
                    p.getString("device_name", null) ?: defaultName(),
                    32,
                ),
                tcpPort = p.getInt("tcp_port", Proto.DEFAULT_TCP_PORT),
                discoveryEnabled = p.getBoolean("discovery", true),
                acceptIncoming = p.getBoolean("accept_incoming", true),
                lanOnly = p.getBoolean("lan_only", true),
                allowNewPairings = p.getBoolean("allow_new_pairings", true),
                maxFileSizeBytes = p.getLong("max_file_size", 4L * 1024 * 1024 * 1024),
            )
        }

        fun save(context: Context, s: Settings) {
            context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
                .putString("device_name", s.deviceName)
                .putInt("tcp_port", s.tcpPort)
                .putBoolean("discovery", s.discoveryEnabled)
                .putBoolean("accept_incoming", s.acceptIncoming)
                .putBoolean("lan_only", s.lanOnly)
                .putBoolean("allow_new_pairings", s.allowNewPairings)
                .putLong("max_file_size", s.maxFileSizeBytes)
                .apply()
        }

        private fun defaultName(): String {
            val model = Build.MODEL?.trim().orEmpty()
            return if (model.isEmpty()) "Android" else Proto.clamp(model, 32)
        }
    }
}
