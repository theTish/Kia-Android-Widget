package ca.thetish.kia.app

import android.Manifest
import android.annotation.SuppressLint
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.location.Location
import android.os.Build
import androidx.core.content.ContextCompat
import androidx.work.CoroutineWorker
import androidx.work.Constraints
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.ExistingWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import androidx.work.workDataOf
import ca.thetish.kia.core.CarPosition
import ca.thetish.kia.core.Geofence
import ca.thetish.kia.core.GeofenceDecision
import ca.thetish.kia.core.GeofenceEntry
import ca.thetish.kia.core.GeofenceLog
import ca.thetish.kia.core.GeofenceMode
import ca.thetish.kia.core.KiaApi
import ca.thetish.kia.core.KiaSettings
import ca.thetish.kia.core.PhoneFix
import ca.thetish.kia.core.VehicleStatus
import ca.thetish.kia.core.R as CoreR
import com.google.android.gms.location.GeofencingEvent
import com.google.android.gms.location.GeofencingRequest
import com.google.android.gms.location.LocationServices
import com.google.android.gms.location.Priority
import com.google.android.gms.location.Geofence as PlayGeofence
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import java.util.concurrent.TimeUnit
import kotlin.coroutines.resume

/**
 * Locking the car because you walked away from it.
 *
 * The original point of this whole project, and the last thing still handled by
 * a Tasker task comparing two GPS fixes to each other. This anchors to the
 * position the car itself reports instead, so it measures the thing that
 * actually matters - the gap between you and the car - rather than how far the
 * phone has travelled.
 *
 * The ring is registered with Play Services rather than polled, because the
 * alternative is a foreground service holding GPS all day to answer a question
 * whose answer is "no" ninety-nine times in a hundred. Play Services wakes us
 * on the way out and we do the expensive part - a status call and a fresh fix -
 * only then.
 *
 * Nothing here decides anything. [Geofence] does, in :core, where it can be
 * tested without a car; this file is the plumbing that feeds it and the switch
 * that decides whether its answer reaches the car.
 */
object Geofences {

    private const val FENCE_ID = "kia-car"
    private const val POLL_WORK = "kia-geofence-poll"
    private const val ACTION = "ca.thetish.kia.app.GEOFENCE"

    /**
     * How long Play Services may sit on an exit before telling us.
     *
     * Loose on purpose: a minute of latency costs nothing here - the dwell adds
     * another ninety seconds anyway - and a tighter setting buys that latency
     * with the radio.
     */
    private const val RESPONSIVENESS_MS = 60_000

    /**
     * How far the car's reported position has to shift to count as a new parking.
     *
     * The car's GPS wanders a few metres between reports without the car going
     * anywhere, and treating that as having moved would re-run the evaluation
     * every fifteen minutes all day.
     */
    private const val MOVED_METRES = 30.0

    private const val FENCE_PREFS = "kia_geofence_fence"

    /**
     * Points the ring at wherever the car last said it was.
     *
     * Called after any status the app or the widget fetches, so the fence
     * follows the car from one parking to the next without a job of its own.
     * A status with no location leaves the existing fence alone rather than
     * dropping it - the car omits its position far more often than it moves.
     */
    fun sync(context: Context, status: VehicleStatus?) {
        val app = context.applicationContext
        if (KiaSettings.geofenceMode(app) == GeofenceMode.OFF) {
            remove(app)
            return
        }

        if (!hasLocationPermission(app)) return
        schedulePolling(app)

        val lat = status?.latitude ?: return
        val lon = status.longitude ?: return
        register(app, lat, lon, KiaSettings.geofenceRadius(app), checkNow = moved(app, lat, lon))
    }

    /** Whether this position is a different parking from the one the ring is on. */
    private fun moved(context: Context, lat: Double, lon: Double): Boolean {
        val prefs = context.getSharedPreferences(FENCE_PREFS, Context.MODE_PRIVATE)
        if (!prefs.contains("lat")) return true
        return Geofence.distanceMetres(
            prefs.getFloat("lat", 0f).toDouble(),
            prefs.getFloat("lon", 0f).toDouble(),
            lat,
            lon,
        ) > MOVED_METRES
    }

    @SuppressLint("MissingPermission") // hasLocationPermission is checked by every caller
    private fun register(context: Context, lat: Double, lon: Double, radius: Int, checkNow: Boolean) {
        val fence = PlayGeofence.Builder()
            .setRequestId(FENCE_ID)
            .setCircularRegion(lat, lon, radius.toFloat())
            .setExpirationDuration(PlayGeofence.NEVER_EXPIRE)
            .setTransitionTypes(PlayGeofence.GEOFENCE_TRANSITION_EXIT)
            .setNotificationResponsiveness(RESPONSIVENESS_MS)
            .build()

        val request = GeofencingRequest.Builder()
            // Only a ring that has just moved gets an initial trigger. The car
            // reports where it parked some time after it parks, and the poll
            // only hears about it up to fifteen minutes after that - by which
            // time you have usually walked off. With no initial trigger the
            // ring lands around the car with you already outside it, and an
            // exit never comes: every parking you left promptly went unjudged.
            // Firing once for the new ring hands that walk to the evaluator,
            // which still wants an unlocked car and a served dwell before it
            // decides anything. A ring redrawn in the same place gets none, or
            // every poll while you are at work would be a fix and a status call.
            .setInitialTrigger(if (checkNow) GeofencingRequest.INITIAL_TRIGGER_EXIT else 0)
            .addGeofence(fence)
            .build()

        LocationServices.getGeofencingClient(context)
            .addGeofences(request, pendingIntent(context))
            // Remembered only once Play Services has the ring, so a failed
            // registration still gets its initial check on the next poll.
            .addOnSuccessListener {
                if (checkNow) {
                    context.getSharedPreferences(FENCE_PREFS, Context.MODE_PRIVATE).edit()
                        .putFloat("lat", lat.toFloat())
                        .putFloat("lon", lon.toFloat())
                        .apply()
                }
            }
    }

    fun remove(context: Context) {
        LocationServices.getGeofencingClient(context.applicationContext)
            .removeGeofences(listOf(FENCE_ID))
        // So switching back on judges wherever the car is then, not just future exits.
        context.applicationContext.getSharedPreferences(FENCE_PREFS, Context.MODE_PRIVATE)
            .edit().clear().apply()
        WorkManager.getInstance(context.applicationContext).cancelUniqueWork(POLL_WORK)
    }

    /**
     * Keeps asking the car where it is, so the ring can follow it.
     *
     * Without this the feature does not work at all, and the way it fails is
     * quiet: the fence sits wherever the car was the last time anything
     * fetched a status. Park somewhere new without opening the app and you are
     * already outside a ring drawn around this morning's parking space, so no
     * exit ever happens and nothing ever fires.
     *
     * Fifteen minutes is WorkManager's floor for periodic work, and it is also
     * about right - the cost of being late is that the car stays unlocked a
     * little longer, which is the situation this is trying to improve on, not
     * one it makes worse. The call goes through KiaWorker so the widget gets
     * the same reading rather than the app making two.
     */
    fun schedulePolling(context: Context) {
        val request = PeriodicWorkRequestBuilder<KiaWorker>(15, TimeUnit.MINUTES)
            .setInputData(workDataOf(KiaWorker.KEY_ACTION to KiaWorker.ACTION_STATUS))
            .setConstraints(
                Constraints.Builder()
                    .setRequiredNetworkType(NetworkType.CONNECTED)
                    .build()
            )
            .build()

        // KEEP, not REPLACE: replacing restarts the interval, so a screen that
        // calls this on every resume would mean it never actually runs.
        WorkManager.getInstance(context.applicationContext).enqueueUniquePeriodicWork(
            POLL_WORK,
            ExistingPeriodicWorkPolicy.KEEP,
            request,
        )
    }

    private fun pendingIntent(context: Context): PendingIntent {
        val intent = Intent(context, GeofenceReceiver::class.java).setAction(ACTION)
        // Mutable because Play Services fills in the transition details.
        return PendingIntent.getBroadcast(
            context,
            0,
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE,
        )
    }

    fun hasLocationPermission(context: Context): Boolean =
        ContextCompat.checkSelfPermission(context, Manifest.permission.ACCESS_FINE_LOCATION) ==
            PackageManager.PERMISSION_GRANTED

    /** Background location is the one that makes this work with the app closed. */
    fun hasBackgroundLocationPermission(context: Context): Boolean =
        Build.VERSION.SDK_INT < Build.VERSION_CODES.Q ||
            ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.ACCESS_BACKGROUND_LOCATION,
            ) == PackageManager.PERMISSION_GRANTED
}

/**
 * Play Services saying the phone has left the ring.
 *
 * Hands straight to a worker: a receiver gets about ten seconds of CPU and the
 * next step is a status call to a car that can take twenty-five.
 */
class GeofenceReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val event = GeofencingEvent.fromIntent(intent) ?: return
        if (event.hasError()) return
        if (event.geofenceTransition != PlayGeofence.GEOFENCE_TRANSITION_EXIT) return

        GeofenceWorker.enqueue(context, delaySeconds = 0)
    }
}

/**
 * Takes a fix, asks the car, and writes down what it decided.
 *
 * Runs twice per exit: once when Play Services reports it, and once more after
 * the dwell has had time to pass. That second run is the whole safeguard - the
 * first one only starts the clock, so a fix that wanders across the road and
 * back never gets as far as a lock command.
 */
class GeofenceWorker(context: Context, params: WorkerParameters) :
    CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        val app = applicationContext
        val mode = KiaSettings.geofenceMode(app)
        if (mode == GeofenceMode.OFF) return Result.success()
        if (!Geofences.hasLocationPermission(app)) {
            log(GeofenceEntry.OUTCOME_HOLD, "location permission not granted", acted = true)
            return Result.success()
        }

        val status = withContext(Dispatchers.IO) { KiaApi.status(KiaSettings.load(app)) }.status
        val fix = currentFix()

        val car = status?.let { s ->
            val lat = s.latitude
            val lon = s.longitude
            if (lat != null && lon != null) {
                CarPosition(lat, lon, positionReportedAt(s))
            } else {
                null
            }
        }

        val outcome = Geofence.evaluate(
            now = System.currentTimeMillis(),
            car = car,
            carIsLocked = status?.isLocked,
            fix = fix,
            state = GeofenceLog.loadState(app),
            radiusMetres = KiaSettings.geofenceRadius(app),
        )
        GeofenceLog.saveState(app, outcome.state)

        when (val decision = outcome.decision) {
            is GeofenceDecision.Hold ->
                log(GeofenceEntry.OUTCOME_HOLD, decision.reason, acted = false)

            is GeofenceDecision.Waiting -> {
                log(GeofenceEntry.OUTCOME_WAITING, decision.reason, acted = false)
                // Come back when the dwell is up and look again.
                enqueue(app, delaySeconds = Geofence.DEFAULT_DWELL_SECONDS)
            }

            is GeofenceDecision.Lock -> {
                val armed = mode == GeofenceMode.ARMED
                val sent = if (armed) {
                    withContext(Dispatchers.IO) { KiaApi.lock(KiaSettings.load(app)) }.ok
                } else {
                    false
                }
                log(
                    GeofenceEntry.OUTCOME_LOCK,
                    if (armed) {
                        if (sent) decision.reason else "${decision.reason} - lock failed"
                    } else {
                        "${decision.reason} (shadow: not sent)"
                    },
                    acted = sent,
                )
                if (sent) {
                    notifyLocked(decision.distanceMetres)
                    // The widget is now showing a car it thinks is unlocked.
                    KiaWorker.enqueue(app, KiaWorker.ACTION_STATUS)
                }
            }
        }

        return Result.success()
    }

    /**
     * When the car reported this position, which is what the latch keys on.
     *
     * The location's own timestamp, not the status's: the status one moves
     * every time Kia refreshes anything, so keying on it released the latch
     * without the car having gone anywhere, and let a position hours old pass
     * the age check as fresh.
     *
     * Falls back to now when /status gives no parseable time: a latch that
     * never releases would be worse than one that releases too often, since the
     * dwell still has to be served either way.
     */
    private fun positionReportedAt(status: VehicleStatus): Long =
        (status.locationUpdated ?: status.lastUpdated)
            ?.let { runCatching { java.time.OffsetDateTime.parse(it).toInstant().toEpochMilli() }
                .getOrNull() }
            ?: System.currentTimeMillis()

    @SuppressLint("MissingPermission") // checked in doWork before this is reached
    private suspend fun currentFix(): PhoneFix? = suspendCancellableCoroutine { cont ->
        val client = LocationServices.getFusedLocationProviderClient(applicationContext)
        client.getCurrentLocation(Priority.PRIORITY_HIGH_ACCURACY, null)
            .addOnSuccessListener { location: Location? ->
                cont.resume(
                    location?.let {
                        PhoneFix(it.latitude, it.longitude, it.accuracy, System.currentTimeMillis())
                    }
                )
            }
            .addOnFailureListener { cont.resume(null) }
    }

    private fun log(outcome: String, reason: String, acted: Boolean) {
        GeofenceLog.append(
            applicationContext,
            GeofenceEntry(System.currentTimeMillis(), outcome, reason, acted),
        )
    }

    /**
     * Says so when it locks the car.
     *
     * An app that operates a vehicle without telling you is not one you would
     * leave armed for long.
     */
    private fun notifyLocked(distanceMetres: Int) {
        val app = applicationContext
        val manager = app.getSystemService(NotificationManager::class.java) ?: return

        manager.createNotificationChannel(
            NotificationChannel(
                CHANNEL,
                app.getString(R.string.geofence_channel),
                NotificationManager.IMPORTANCE_DEFAULT,
            )
        )

        val open = PendingIntent.getActivity(
            app,
            0,
            Intent(app, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        val notification: Notification = Notification.Builder(app, CHANNEL)
            .setSmallIcon(CoreR.drawable.ic_lock)
            .setContentTitle(app.getString(R.string.geofence_locked_title))
            .setContentText(app.getString(R.string.geofence_locked_text, distanceMetres))
            .setContentIntent(open)
            .setAutoCancel(true)
            .build()

        runCatching { manager.notify(NOTIFICATION_ID, notification) }
    }

    companion object {
        private const val WORK_NAME = "kia-geofence"
        private const val CHANNEL = "kia-geofence"
        private const val NOTIFICATION_ID = 4201

        /**
         * Queues an evaluation.
         *
         * One unique name, REPLACE: a second exit while a dwell re-check is
         * pending should restart the reasoning, not race it.
         */
        fun enqueue(context: Context, delaySeconds: Int) {
            val request = OneTimeWorkRequestBuilder<GeofenceWorker>()
                .setInitialDelay(delaySeconds.toLong(), TimeUnit.SECONDS)
                .build()

            WorkManager.getInstance(context)
                .enqueueUniqueWork(WORK_NAME, ExistingWorkPolicy.REPLACE, request)
        }
    }
}
