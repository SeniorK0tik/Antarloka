package org.syncmob.mobile.service

import android.app.Notification
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import org.syncmob.mobile.EngineHolder
import org.syncmob.mobile.R
import org.syncmob.mobile.SyncMobApp
import org.syncmob.mobile.ui.MainActivity

/**
 * Keeps the engine listening while the app is in the background.
 *
 * A foreground service is deliberate: a LAN receiver that silently accepts
 * connections with no visible indicator would be exactly the kind of thing a
 * user should not have running unknowingly. The notification is the "I am
 * reachable on this network" light, and stopping it stops the listener.
 */
class SyncMobService : Service() {

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            EngineHolder.current()?.stop()
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return START_NOT_STICKY
        }

        val engine = EngineHolder.getOrCreate(this)
        if (engine == null) {
            stopSelf()
            return START_NOT_STICKY
        }

        startForegroundCompat(engine.state.value.settings.deviceName)
        engine.start()
        return START_STICKY
    }

    private fun startForegroundCompat(deviceName: String) {
        val open = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val stop = PendingIntent.getService(
            this,
            1,
            Intent(this, SyncMobService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )

        val notification: Notification = NotificationCompat.Builder(this, SyncMobApp.CHANNEL_ID)
            .setContentTitle("SyncMob активен")
            .setContentText("Устройство «$deviceName» доступно в локальной сети")
            .setSmallIcon(R.drawable.ic_notification)
            .setOngoing(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setContentIntent(open)
            .addAction(0, "Остановить", stop)
            .build()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    override fun onDestroy() {
        EngineHolder.current()?.stop()
        super.onDestroy()
    }

    companion object {
        private const val NOTIFICATION_ID = 4821
        const val ACTION_STOP = "org.syncmob.mobile.STOP"

        fun start(context: Context) {
            val intent = Intent(context, SyncMobService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        fun stop(context: Context) {
            context.startService(
                Intent(context, SyncMobService::class.java).setAction(ACTION_STOP),
            )
        }
    }
}
