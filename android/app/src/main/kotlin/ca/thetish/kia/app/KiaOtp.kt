package ca.thetish.kia.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import ca.thetish.kia.core.R as CoreR

/**
 * The phone's side of Kia's 90-day device check.
 *
 * Every 90 days Kia stops trusting the server and every call answers "Kia needs
 * a code" until the owner types in the one Kia emails. Nothing on the phone can
 * skip that, but it should never again mean ssh and curl: anything that hits
 * the wall in the background - auto-lock, the widget - raises a notification,
 * and tapping it opens the app straight into the code dialog.
 */
object KiaOtp {

    /** Set on the intent that opens MainActivity, to open the code dialog. */
    const val EXTRA_OPEN = "ca.thetish.kia.OPEN_OTP"

    private const val CHANNEL = "kia-otp"
    private const val NOTIFICATION_ID = 7303

    /** Raises the notification if [otpRequired]; a no-op otherwise. */
    fun noticeIf(context: Context, otpRequired: Boolean) {
        if (otpRequired) notifyNeeded(context)
    }

    fun notifyNeeded(context: Context) {
        val manager = context.getSystemService(NotificationManager::class.java) ?: return
        manager.createNotificationChannel(
            NotificationChannel(CHANNEL, context.getString(R.string.otp_channel), NotificationManager.IMPORTANCE_HIGH),
        )

        val open = PendingIntent.getActivity(
            context,
            NOTIFICATION_ID,
            Intent(context, MainActivity::class.java)
                .putExtra(EXTRA_OPEN, true)
                .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        val notification: Notification = Notification.Builder(context, CHANNEL)
            .setSmallIcon(CoreR.drawable.ic_lock)
            .setContentTitle(context.getString(R.string.otp_title))
            .setContentText(context.getString(R.string.otp_notification_text))
            .setContentIntent(open)
            // Auto-lock retries every minute; one buzz is enough.
            .setOnlyAlertOnce(true)
            .setAutoCancel(true)
            .build()

        manager.notify(NOTIFICATION_ID, notification)
    }

    fun clear(context: Context) {
        context.getSystemService(NotificationManager::class.java)?.cancel(NOTIFICATION_ID)
    }
}
