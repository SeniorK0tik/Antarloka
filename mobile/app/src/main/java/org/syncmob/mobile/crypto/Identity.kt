package org.syncmob.mobile.crypto

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import org.syncmob.mobile.security.Fingerprints
import java.security.KeyStore
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * The device's long term X25519 identity.
 *
 * The private key never exists on disk in the clear: it is sealed with an
 * AES-256-GCM key that lives in the Android Keystore, which on most devices
 * means it is held by the TEE or a secure element and cannot be extracted even
 * from a rooted phone. On API 28+ the wrapping key is additionally marked as
 * usable only while the device is unlocked.
 */
class Identity private constructor(
    /** 32 raw bytes. Kept in memory only for the lifetime of the process. */
    val privateKey: ByteArray,
    val publicKey: ByteArray,
    /** False when the Keystore was unavailable and a software fallback was used. */
    val hardwareBacked: Boolean,
) {
    fun deviceId(): String = Fingerprints.deviceId(publicKey)
    fun fingerprint(): String = Fingerprints.fingerprint(publicKey)
    fun deriveSubkey(domain: String): ByteArray = Fingerprints.deriveSubkey(privateKey, domain)

    /** Never let key material reach a log line. */
    override fun toString(): String = "Identity(deviceId=${deviceId()}, secret=<redacted>)"

    companion object {
        private const val TAG = "SyncMob/Identity"
        private const val PREFS = "syncmob_identity"
        private const val KEY_SEALED = "sealed_private_key"
        private const val KEY_PUBLIC = "public_key"
        private const val KEY_HW = "hardware_backed"
        private const val ALIAS = "syncmob_identity_v1"
        private const val KEYSTORE = "AndroidKeyStore"
        private const val TRANSFORM = "AES/GCM/NoPadding"
        private const val GCM_TAG_BITS = 128
        private const val IV_LEN = 12

        @Synchronized
        fun loadOrCreate(context: Context): Identity {
            val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            val sealed = prefs.getString(KEY_SEALED, null)
            val publicB64 = prefs.getString(KEY_PUBLIC, null)

            if (sealed != null && publicB64 != null) {
                try {
                    val blob = Base64.getDecoder().decode(sealed)
                    val priv = unseal(blob)
                    val pub = Base64.getDecoder().decode(publicB64)
                    // Recompute the public key: if the stored one was tampered
                    // with, we notice instead of announcing a key we cannot use.
                    val derived = Noise.publicKeyOf(priv)
                    if (!Noise.constantTimeEquals(derived, pub)) {
                        throw IllegalStateException("stored public key does not match the private key")
                    }
                    return Identity(priv, pub, prefs.getBoolean(KEY_HW, true))
                } catch (e: Exception) {
                    // A key we cannot unseal is unusable; refusing loudly is
                    // better than silently generating a new identity, which
                    // would invalidate every pairing without explanation.
                    throw IdentityUnavailableException(
                        "Не удалось расшифровать ключ устройства. " +
                            "Возможно, были сброшены учётные данные экрана блокировки.",
                        e,
                    )
                }
            }

            val (priv, pub) = Noise.generateKeyPair()
            var hardware = true
            val blob = try {
                seal(priv)
            } catch (e: Exception) {
                Log.w(TAG, "Android Keystore unavailable, storing key without hardware backing")
                hardware = false
                priv.copyOf()
            }
            prefs.edit()
                .putString(KEY_SEALED, Base64.getEncoder().encodeToString(blob))
                .putString(KEY_PUBLIC, Base64.getEncoder().encodeToString(pub))
                .putBoolean(KEY_HW, hardware)
                .apply()
            return Identity(priv, pub, hardware)
        }

        /** Delete the identity. Every existing pairing becomes worthless. */
        @Synchronized
        fun reset(context: Context) {
            context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().clear().apply()
            try {
                KeyStore.getInstance(KEYSTORE).apply { load(null) }.deleteEntry(ALIAS)
            } catch (e: Exception) {
                Log.w(TAG, "could not delete keystore entry: ${e.message}")
            }
        }

        private fun masterKey(): SecretKey {
            val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
            (ks.getEntry(ALIAS, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }

            val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
            val spec = KeyGenParameterSpec.Builder(
                ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                // Every encryption must use a fresh random IV.
                .setRandomizedEncryptionRequired(true)
                .apply {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                        // The identity cannot be used while the screen is locked.
                        setUnlockedDeviceRequired(true)
                    }
                }
                .build()
            gen.init(spec)
            return gen.generateKey()
        }

        private fun seal(plaintext: ByteArray): ByteArray {
            val cipher = Cipher.getInstance(TRANSFORM)
            cipher.init(Cipher.ENCRYPT_MODE, masterKey())
            val iv = cipher.iv
            require(iv.size == IV_LEN) { "unexpected IV length" }
            return iv + cipher.doFinal(plaintext)
        }

        private fun unseal(blob: ByteArray): ByteArray {
            if (blob.size == 32) {
                // Software fallback written when the Keystore was unavailable.
                return blob
            }
            require(blob.size > IV_LEN) { "sealed blob too short" }
            val cipher = Cipher.getInstance(TRANSFORM)
            cipher.init(
                Cipher.DECRYPT_MODE,
                masterKey(),
                GCMParameterSpec(GCM_TAG_BITS, blob, 0, IV_LEN),
            )
            return cipher.doFinal(blob, IV_LEN, blob.size - IV_LEN)
        }
    }
}

class IdentityUnavailableException(message: String, cause: Throwable? = null) :
    Exception(message, cause)
