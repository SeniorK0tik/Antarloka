package org.syncmob.mobile

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import org.syncmob.mobile.crypto.Identity
import org.syncmob.mobile.crypto.IdentityUnavailableException
import org.syncmob.mobile.engine.Engine
import org.syncmob.mobile.security.TrustStore

class SyncMobApp : Application() {
    override fun onCreate() {
        super.onCreate()
        val manager = getSystemService(NotificationManager::class.java)
        manager?.createNotificationChannel(
            NotificationChannel(
                CHANNEL_ID,
                getString(R.string.channel_name),
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = getString(R.string.channel_desc)
                setShowBadge(false)
            },
        )
    }

    companion object {
        const val CHANNEL_ID = "syncmob_running"
    }
}

/**
 * Single [Engine] shared by the activity and the foreground service.
 *
 * Creating it can fail in ways the user must see rather than have papered over:
 * a keystore entry that can no longer be decrypted (screen lock credentials
 * reset), or a trust store that failed its authentication check. Both surface
 * as [initError] instead of silently producing a fresh identity, which would
 * quietly invalidate every existing pairing.
 */
object EngineHolder {
    @Volatile
    private var engine: Engine? = null

    @Volatile
    var initError: String? = null
        private set

    @Synchronized
    fun getOrCreate(context: Context): Engine? {
        engine?.let { return it }
        return try {
            val identity = Identity.loadOrCreate(context.applicationContext)
            val e = Engine(context.applicationContext, identity)
            initError = null
            engine = e
            e
        } catch (e: IdentityUnavailableException) {
            initError = e.message
            null
        } catch (e: TrustStore.Tampered) {
            initError = e.message
            null
        } catch (e: Exception) {
            initError = "Не удалось запустить SyncMob: ${e.message}"
            null
        }
    }

    fun current(): Engine? = engine

    /** Wipe the identity and every pairing. Only from an explicit user action. */
    @Synchronized
    fun resetIdentity(context: Context) {
        engine?.stop()
        engine = null
        initError = null
        Identity.reset(context.applicationContext)
        java.io.File(context.applicationContext.filesDir, "trust.json").delete()
    }
}
