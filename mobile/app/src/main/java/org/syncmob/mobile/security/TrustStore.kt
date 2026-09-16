package org.syncmob.mobile.security

import org.json.JSONArray
import org.json.JSONObject
import org.syncmob.mobile.crypto.Identity
import org.syncmob.mobile.crypto.Noise
import org.syncmob.mobile.proto.Proto
import java.io.File
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Devices this phone has explicitly paired with.
 *
 * Membership here is the only thing that authorises a peer to send text or
 * files. The file is encrypted and authenticated with AES-256-GCM under a
 * subkey derived from the identity private key, so another app that somehow
 * reached the file cannot read the list — and cannot add an entry to it either,
 * which would otherwise be a silent way to grant itself access.
 */
class TrustStore private constructor(
    private val file: File,
    private val identity: Identity,
    private val devices: MutableMap<String, TrustedDevice>,
) {
    class Tampered(message: String, cause: Throwable? = null) : Exception(message, cause)

    fun list(): List<TrustedDevice> = synchronized(this) { devices.values.sortedBy { it.name } }

    fun size(): Int = synchronized(this) { devices.size }

    fun get(publicKey: ByteArray): TrustedDevice? = synchronized(this) {
        val d = devices[b64(publicKey)] ?: return null
        // Belt and braces: confirm the stored bytes really match, in constant
        // time, before this entry authorises anything.
        if (!Noise.constantTimeEquals(d.keyBytes(), publicKey)) null else d
    }

    /** True only for a device that was paired and is not blocked. */
    fun isAuthorised(publicKey: ByteArray): Boolean = get(publicKey)?.blocked == false

    fun byDeviceId(deviceId: String): TrustedDevice? =
        synchronized(this) { devices.values.firstOrNull { it.deviceId() == deviceId } }

    fun add(publicKey: ByteArray, name: String) {
        require(publicKey.size == 32) { "bad key length" }
        synchronized(this) {
            val key = b64(publicKey)
            val now = System.currentTimeMillis()
            val existing = devices[key]
            if (existing != null) {
                existing.name = Proto.clamp(name, 64)
                existing.lastSeenMs = now
                existing.blocked = false
            } else {
                if (devices.size >= MAX_DEVICES) throw IllegalStateException("trust store full")
                devices[key] = TrustedDevice(key, Proto.clamp(name, 64), now, now, false, false)
            }
        }
        save()
    }

    fun remove(publicKey: ByteArray) {
        synchronized(this) { devices.remove(b64(publicKey)) }
        save()
    }

    fun setAutoAccept(publicKey: ByteArray, on: Boolean) {
        synchronized(this) { devices[b64(publicKey)]?.autoAcceptFiles = on }
        save()
    }

    fun setBlocked(publicKey: ByteArray, blocked: Boolean) {
        synchronized(this) { devices[b64(publicKey)]?.blocked = blocked }
        save()
    }

    fun touch(publicKey: ByteArray, name: String) {
        synchronized(this) {
            val d = devices[b64(publicKey)] ?: return
            d.lastSeenMs = System.currentTimeMillis()
            if (name.isNotEmpty()) d.name = Proto.clamp(name, 64)
        }
        save()
    }

    fun save() {
        val array = JSONArray()
        synchronized(this) {
            for (d in devices.values) {
                array.put(
                    JSONObject()
                        .put("public_key", d.publicKey)
                        .put("name", d.name)
                        .put("added_at_ms", d.addedAtMs)
                        .put("last_seen_ms", d.lastSeenMs)
                        .put("auto_accept_files", d.autoAcceptFiles)
                        .put("blocked", d.blocked),
                )
            }
        }
        val plaintext = JSONObject().put("devices", array).toString().toByteArray(Charsets.UTF_8)

        val cipher = Cipher.getInstance(TRANSFORM)
        cipher.init(Cipher.ENCRYPT_MODE, aeadKey(), GCMParameterSpec(TAG_BITS, randomIv()))
        cipher.updateAAD(aad())
        val ct = cipher.doFinal(plaintext)

        val envelope = JSONObject()
            .put("version", FORMAT_VERSION)
            .put("nonce", Base64.getEncoder().encodeToString(cipher.iv))
            .put("ct", Base64.getEncoder().encodeToString(ct))
            .toString()

        // Write to a temporary file and rename, so a crash mid-write cannot
        // leave a half-written trust list behind.
        val tmp = File(file.parentFile, file.name + ".tmp")
        tmp.writeText(envelope)
        if (!tmp.renameTo(file)) {
            file.writeText(envelope)
            tmp.delete()
        }
    }

    private fun aeadKey() = SecretKeySpec(identity.deriveSubkey(SUBKEY_DOMAIN), "AES")

    private fun aad(): ByteArray = AAD_PREFIX + identity.publicKey

    private fun randomIv() = ByteArray(12).also { SecureRandom().nextBytes(it) }

    companion object {
        const val MAX_DEVICES = 256
        private const val SUBKEY_DOMAIN = "trust-store"
        private val AAD_PREFIX = "SyncMob/1 trust-store".toByteArray(Charsets.US_ASCII)
        private const val FORMAT_VERSION = 1
        private const val TRANSFORM = "AES/GCM/NoPadding"
        private const val TAG_BITS = 128

        private fun b64(key: ByteArray): String = Base64.getEncoder().encodeToString(key)

        /**
         * Load the store, or return an empty one if the file does not exist.
         *
         * A file that exists but fails authentication raises [Tampered] rather
         * than quietly starting fresh: silently clearing the trust list would
         * let an attacker downgrade a paired device back to "unknown".
         */
        fun load(file: File, identity: Identity): TrustStore {
            if (!file.exists()) {
                return TrustStore(file, identity, LinkedHashMap())
            }
            try {
                val envelope = JSONObject(file.readText())
                if (envelope.optInt("version") != FORMAT_VERSION) {
                    throw Tampered("unsupported trust store version")
                }
                val nonce = Base64.getDecoder().decode(envelope.getString("nonce"))
                val ct = Base64.getDecoder().decode(envelope.getString("ct"))
                if (nonce.size != 12) throw Tampered("bad nonce")

                val cipher = Cipher.getInstance(TRANSFORM)
                val key = SecretKeySpec(identity.deriveSubkey(SUBKEY_DOMAIN), "AES")
                cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, nonce))
                cipher.updateAAD(AAD_PREFIX + identity.publicKey)
                val plaintext = cipher.doFinal(ct)

                val devices = LinkedHashMap<String, TrustedDevice>()
                val array = JSONObject(String(plaintext, Charsets.UTF_8)).getJSONArray("devices")
                for (i in 0 until array.length()) {
                    val o = array.getJSONObject(i)
                    val d = TrustedDevice(
                        publicKey = o.getString("public_key"),
                        name = o.optString("name"),
                        addedAtMs = o.optLong("added_at_ms"),
                        lastSeenMs = o.optLong("last_seen_ms"),
                        autoAcceptFiles = o.optBoolean("auto_accept_files"),
                        blocked = o.optBoolean("blocked"),
                    )
                    // Drop anything that is not a well formed key.
                    if (d.keyBytes() != null) devices[d.publicKey] = d
                }
                return TrustStore(file, identity, devices)
            } catch (e: Tampered) {
                throw e
            } catch (e: Exception) {
                throw Tampered("Список доверенных устройств повреждён или был изменён", e)
            }
        }
    }
}

class TrustedDevice(
    /** Base64 of the 32 byte X25519 static public key. This is the identity. */
    val publicKey: String,
    /** Cosmetic only; refreshed on every connection, never an authorisation input. */
    var name: String,
    val addedAtMs: Long,
    var lastSeenMs: Long,
    var autoAcceptFiles: Boolean,
    var blocked: Boolean,
) {
    fun keyBytes(): ByteArray? = try {
        Base64.getDecoder().decode(publicKey).takeIf { it.size == 32 }
    } catch (e: Exception) {
        null
    }

    fun deviceId(): String = keyBytes()?.let { Fingerprints.deviceId(it) } ?: ""
    fun fingerprint(): String = keyBytes()?.let { Fingerprints.fingerprint(it) } ?: ""
}
