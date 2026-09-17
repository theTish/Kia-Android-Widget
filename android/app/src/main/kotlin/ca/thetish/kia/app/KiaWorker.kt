package ca.thetish.kia.app

import android.content.Context
import android.os.SystemClock
import androidx.datastore.preferences.core.MutablePreferences
import androidx.glance.appwidget.GlanceAppWidgetManager
import androidx.glance.appwidget.state.updateAppWidgetState
import androidx.glance.appwidget.updateAll
import androidx.work.CoroutineWorker
import androidx.work.ExistingWorkPolicy
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import androidx.work.workDataOf
import java.util.concurrent.TimeUnit
import ca.thetish.kia.core.ApiResult
import ca.thetish.kia.core.BuildConfig
import ca.thetish.kia.core.KiaApi
import ca.thetish.kia.core.VehicleStatus
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Runs the actual API call for a widget tap.
 *
 * This is not done inside the ActionCallback because Glance dispatches those
 * through a BroadcastReceiver, and the system stops giving a receiver CPU after
 * roughly ten seconds. A cold car can take considerably longer than that to
 * answer a lock request, so the call would be killed part-way with the widget
 * still showing "Locking…" and no way to know whether the car got the message.
 * A worker survives that window.
 */
class KiaWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        val action = inputData.getString(KEY_ACTION) ?: return Result.failure()

        // The two bookkeeping actions make no network call, so they return
        // before any IO hop; refresh() does its own.
        when (action) {
            ACTION_DISARM -> { disarm(); return Result.success() }
            ACTION_STATUS -> { refresh(announce = true); return Result.success() }
        }

        val result = withContext(Dispatchers.IO) {
            when (action) {
                ACTION_LOCK -> KiaApi.lock()
                ACTION_UNLOCK -> KiaApi.unlock()
                ACTION_CLIMATE -> KiaApi.startClimate(BuildConfig.KIA_CLIMATE_PRESET)
                else -> null
            }
        } ?: return Result.failure()

        setState { prefs ->
            prefs[Keys.busy] = false
            prefs[Keys.message] = result.message
        }

        // A lock or unlock changes what the status line should say, so re-read it.
        if (result.ok) refresh(announce = false)

        return Result.success()
    }

    /**
     * Drops the unlock arming once its window has passed.
     *
     * Without this the widget keeps showing an amber "Confirm" forever, because
     * nothing redraws a widget on a timer. Tapping it after expiry only re-arms,
     * so the danger is cosmetic, but a safety control whose label is stale is
     * exactly the kind of thing that stops being trusted.
     */
    private suspend fun disarm() {
        var cleared = false
        setState(redraw = false) { prefs ->
            val armedUntil = prefs[Keys.armedUntil] ?: 0L
            // A newer tap may have re-armed since this was scheduled.
            if (armedUntil != 0L && SystemClock.elapsedRealtime() >= armedUntil) {
                prefs[Keys.armedUntil] = 0L
                cleared = true
            }
        }
        // Only push RemoteViews if something actually changed - otherwise this
        // is a wakeup and a full redraw of every instance for no visible effect.
        if (cleared) KiaWidget().updateAll(applicationContext)
    }

    private suspend fun refresh(announce: Boolean) {
        val result = withContext(Dispatchers.IO) { KiaApi.status() }
        val status = result.status

        setState { prefs ->
            prefs[Keys.busy] = false
            if (result.ok && status != null) {
                prefs.store(status)
                if (announce) prefs[Keys.message] = "Updated"
            } else if (announce) {
                prefs[Keys.message] = result.message
            }
        }
    }

    /**
     * Applies a state change to every instance of the widget and redraws.
     *
     * All instances share one car, so they all show the same thing. That also
     * sidesteps passing a GlanceId through WorkManager, which cannot carry one.
     */
    private suspend fun setState(redraw: Boolean = true, edit: (MutablePreferences) -> Unit) {
        val manager = GlanceAppWidgetManager(applicationContext)
        for (id in manager.getGlanceIds(KiaWidget::class.java)) {
            updateAppWidgetState(applicationContext, id, edit)
        }
        if (redraw) KiaWidget().updateAll(applicationContext)
    }

    private fun MutablePreferences.store(status: VehicleStatus) {
        status.batteryPercent?.let { this[Keys.battery] = it }
        status.range?.let { this[Keys.range] = it }
        this[Keys.charging] = status.isCharging

        // Removing the key is how "unknown" is stored: an absent preference
        // reads back as null, which must not render as "unlocked".
        val locked = status.isLocked
        if (locked == null) remove(Keys.locked) else this[Keys.locked] = locked
    }

    companion object {
        const val KEY_ACTION = "action"
        const val ACTION_LOCK = "lock"
        const val ACTION_UNLOCK = "unlock"
        const val ACTION_CLIMATE = "climate"
        const val ACTION_STATUS = "status"
        const val ACTION_DISARM = "disarm"

        private const val DISARM_WORK_NAME = "kia-widget-disarm"

        /**
         * Queues one action.
         *
         * Each action gets its own queue name. Sharing one name meant a later
         * tap REPLACEd - that is, cancelled - a command already talking to the
         * car: tap Unlock then Refresh and the unlock coroutine dies part-way,
         * so the widget never learns what happened and may paint a stale lock
         * state over a car that did unlock. Only a repeat of the SAME action
         * replaces its predecessor, which is what you want for a double tap.
         */
        fun enqueue(context: Context, action: String) {
            val request = OneTimeWorkRequestBuilder<KiaWorker>()
                .setInputData(workDataOf(KEY_ACTION to action))
                .build()

            WorkManager.getInstance(context)
                .enqueueUniqueWork("kia-widget-$action", ExistingWorkPolicy.REPLACE, request)
        }

        /**
         * Schedules the arming to lapse visually when it lapses in fact.
         *
         * Its own unique name, so an unrelated tap in the meantime cannot
         * replace it and strand the widget showing "Confirm".
         */
        fun enqueueDisarm(context: Context, delayMs: Long) {
            val request = OneTimeWorkRequestBuilder<KiaWorker>()
                .setInputData(workDataOf(KEY_ACTION to ACTION_DISARM))
                .setInitialDelay(delayMs, TimeUnit.MILLISECONDS)
                .build()

            WorkManager.getInstance(context)
                .enqueueUniqueWork(DISARM_WORK_NAME, ExistingWorkPolicy.REPLACE, request)
        }

        /** Drops a scheduled disarm once something else has cleared the arming. */
        fun cancelDisarm(context: Context) {
            WorkManager.getInstance(context).cancelUniqueWork(DISARM_WORK_NAME)
        }
    }
}
