package ca.thetish.kia.app

import android.Manifest
import android.annotation.SuppressLint
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.bluetooth.BluetoothDevice
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.location.Location
import android.os.Build
import androidx.core.content.ContextCompat
import androidx.work.CoroutineWorker
import androidx.work.ExistingWorkPolicy
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import ca.thetish.kia.core.Anchor
import ca.thetish.kia.core.Geofence
import ca.thetish.kia.core.GeofenceDecision
import ca.thetish.kia.core.GeofenceEntry
import ca.thetish.kia.core.GeofenceLog
import ca.thetish.kia.core.GeofenceMode
import ca.thetish.kia.core.GeofenceOutcome
import ca.thetish.kia.core.KiaApi
import ca.thetish.kia.core.KiaSettings
import ca.thetish.kia.core.PhoneFix
import ca.thetish.kia.core.VehicleStatus
import ca.thetish.kia.core.R as CoreR
import com.google.android.gms.location.LocationServices
import com.google.android.gms.location.Priority
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import java.util.concurrent.TimeUnit
import kotlin.coroutines.resume

/**
 * Locking the car because you walked away from it.
 *
 * The original point of this project, and the thing a Tasker task used to do
 * badly: it locked on Bluetooth disconnect after a bare `Wait 45 seconds`, with
 * no check that anybody had left, so it locked the keys and the phone inside
 * the car.
 *
 * The disconnect is still the trigger - it is the one moment the phone knows
 * something about the car rather than about a map - but it has been demoted
 * from the decision to the question. Two things come out of it:
 *
 *  - where the car is, taken from the phone's own fix while it is still sitting
 *    in the car. Kia's reported position is not used at all: it goes stale the
 *    moment the car is driven, with nothing in the payload to say so, and on
 *    2026-10-02 that put the phone "1842m" from a car it was inside.
 *  - a reason to start watching. While the car sits there unlocked, the phone
 *    is checked once a minute to see whether it has actually gone.
 *
 * Nothing here decides anything. [Geofence] does, in :core, where it can be
 * tested without a car; this file is the plumbing that feeds it and the switch
 * that decides whether its answer reaches the car.
 */
object Geofences {

    private const val WORK_NAME = "kia-geofence"
    private const val ANCHOR_WORK = "kia-anchor"

    /**
     * How often to look while the car sits there unlocked.
     *
     * A minute is short enough to catch the walk indoors and long enough that
     * nobody notices it on the battery. It also matches the dwell, so an
     * ordinary walk-away is two readings and done.
     */
    const val WATCH_INTERVAL_SECONDS = 60

    /**
     * How many of those to spend on one parking.
     *
     * Walking away takes a minute or two; half an hour covers unloading the
     * boot first, and stops well short of watching an unlocked car all evening.
     */
    const val WATCH_LIMIT = 30

    /** Starts a look. The receiver gets about ten seconds of CPU; a status call can take twenty-five. */
    fun check(context: Context, delaySeconds: Int = 0) {
        val request = OneTimeWorkRequestBuilder<GeofenceWorker>()
            .setInitialDelay(delaySeconds.toLong(), TimeUnit.SECONDS)
            .build()

        WorkManager.getInstance(context.applicationContext)
            .enqueueUniqueWork(WORK_NAME, ExistingWorkPolicy.REPLACE, request)
    }

    /** Back in the car, or switched off: nothing left to watch for. */
    fun stop(context: Context) {
        val app = context.applicationContext
        WorkManager.getInstance(app).cancelUniqueWork(WORK_NAME)
        GeofenceLog.clearAnchor(app)
    }

    internal fun anchorNow(context: Context) {
        WorkManager.getInstance(context.applicationContext).enqueueUniqueWork(
            ANCHOR_WORK,
            ExistingWorkPolicy.REPLACE,
            OneTimeWorkRequestBuilder<AnchorWorker>().build(),
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

    /** Reading which device disconnected needs this from Android 12. */
    fun hasBluetoothPermission(context: Context): Boolean =
        Build.VERSION.SDK_INT < Build.VERSION_CODES.S ||
            ContextCompat.checkSelfPermission(context, Manifest.permission.BLUETOOTH_CONNECT) ==
                PackageManager.PERMISSION_GRANTED
}

/**
 * The car's Bluetooth connecting and dropping.
 *
 * These two broadcasts are exempt from the background restrictions, so they
 * still arrive with the app closed - which is the only way any of this works.
 */
class CarBluetoothReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        val app = context.applicationContext
        if (KiaSettings.geofenceMode(app) == GeofenceMode.OFF) return

        val device: BluetoothDevice =
            intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE) ?: return
        if (!KiaSettings.isCarBluetooth(app, device.address)) return

        when (intent.action) {
            // Connected: you are in the car. Whatever the last parking was
            // still being watched for is over.
            BluetoothDevice.ACTION_ACL_CONNECTED -> Geofences.stop(app)

            // Dropped: the car has been switched off. Whether anybody got out
            // is what the next half hour is for.
            BluetoothDevice.ACTION_ACL_DISCONNECTED -> Geofences.anchorNow(app)
        }
    }
}

/**
 * Takes the fix that becomes the anchor, straight after the disconnect.
 *
 * Its own worker because the timing is the whole point: the phone is still in
 * the car for a few seconds after the Bluetooth drops, and that is the only
 * moment anything here can learn where the car is. What follows is ordinary
 * watching, which [GeofenceWorker] does.
 */
class AnchorWorker(context: Context, params: WorkerParameters) :
    CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        val app = applicationContext
        if (KiaSettings.geofenceMode(app) == GeofenceMode.OFF) return Result.success()
        if (!Geofences.hasLocationPermission(app)) {
            note(app, "location permission not granted")
            return Result.success()
        }

        val fix = currentFix(app)
        if (fix == null || fix.accuracyMetres > Geofence.MAX_ACCURACY_METRES) {
            // No anchor, so no decision for this parking. A guessed one is how
            // you lock a car somebody is still sitting in, and the log says so
            // rather than leaving a silent gap.
            note(
                app,
                fix?.let { "left the car on a fix accurate only to ${it.accuracyMetres.toInt()}m" }
                    ?: "left the car with no position fix",
            )
            return Result.success()
        }

        GeofenceLog.saveAnchor(
            app,
            Anchor(fix.latitude, fix.longitude, fix.accuracyMetres, System.currentTimeMillis()),
        )
        Geofences.check(app)
        return Result.success()
    }

    private fun note(app: Context, reason: String) {
        GeofenceLog.append(
            app,
            GeofenceEntry(System.currentTimeMillis(), GeofenceEntry.OUTCOME_HOLD, reason, false),
        )
    }
}

/**
 * Takes a fix, asks the car, and writes down what it decided.
 *
 * Runs once a minute while the car sits there unlocked, because the dwell wants
 * a second opinion: the first reading clear of the anchor only starts a clock,
 * so a fix that wanders across the road and back never gets as far as a lock.
 */
class GeofenceWorker(context: Context, params: WorkerParameters) :
    CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        val app = applicationContext
        val mode = KiaSettings.geofenceMode(app)
        if (mode == GeofenceMode.OFF) return Result.success()
        if (!Geofences.hasLocationPermission(app)) {
            log(GeofenceEntry.OUTCOME_HOLD, "location permission not granted", acted = false)
            return Result.success()
        }

        // No disconnect to measure from. Nothing to do and nothing to say: the
        // car has not been parked since this was switched on.
        val anchor = GeofenceLog.anchor(app) ?: return Result.success()

        var status = withContext(Dispatchers.IO) { KiaApi.status(KiaSettings.load(app)) }.status
        val fix = currentFix(app)

        val now = System.currentTimeMillis()
        GeofenceLog.recordCheck(app, now)

        val mayPoll = GeofenceLog.mayPollLive(app, anchor.atMillis, now)
        var outcome = evaluate(app, anchor, status, fix, allowRefresh = mayPoll)

        // Kia's cached answer was too old to decide on. Wake the car, and take
        // whatever it says as final - a second stale answer is refused rather
        // than chased.
        if (outcome.decision is GeofenceDecision.Refresh) {
            log(GeofenceEntry.OUTCOME_HOLD, outcome.decision.reason, acted = false)
            GeofenceLog.recordLivePoll(app, anchor.atMillis, now)
            status = withContext(Dispatchers.IO) { KiaApi.statusLive(KiaSettings.load(app)) }.status
            outcome = evaluate(app, anchor, status, fix, allowRefresh = false)
        }
        GeofenceLog.saveState(app, outcome.state)

        when (val decision = outcome.decision) {
            // Only reached when the live read came back stale too; the first
            // Refresh was logged and handled above.
            is GeofenceDecision.Refresh ->
                log(GeofenceEntry.OUTCOME_HOLD, decision.reason, acted = false)

            is GeofenceDecision.Hold ->
                log(GeofenceEntry.OUTCOME_HOLD, decision.reason, acted = false)

            is GeofenceDecision.Waiting ->
                log(GeofenceEntry.OUTCOME_WAITING, decision.reason, acted = false)

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

        watchAgain(app, anchor, status, outcome.decision)
        return Result.success()
    }

    /**
     * Comes back in a minute, while there is still a question to answer.
     *
     * It stops as soon as the answer cannot change: a decision made, the car
     * locked by anyone, or the car switched back on - each only as the car
     * reported it since the disconnect; see [Geofence.settles]. Otherwise a
     * count bounds it, so a car left unlocked all evening is watched for half
     * an hour and then left alone.
     */
    private fun watchAgain(
        app: Context,
        anchor: Anchor,
        status: VehicleStatus?,
        decision: GeofenceDecision,
    ) {
        if (decision is GeofenceDecision.Lock) return
        val readingAt = status?.lastUpdated?.let { parseTime(it) }
        if (Geofence.settles(anchor, status?.isLocked, status?.poweredOn, readingAt)) return

        val spent = GeofenceLog.chases(app, anchor.atMillis)
        if (spent >= Geofences.WATCH_LIMIT) return

        GeofenceLog.recordChase(app, anchor.atMillis, spent + 1)
        Geofences.check(app, delaySeconds = Geofences.WATCH_INTERVAL_SECONDS)
    }

    private fun evaluate(
        app: Context,
        anchor: Anchor,
        status: VehicleStatus?,
        fix: PhoneFix?,
        allowRefresh: Boolean,
    ): GeofenceOutcome = Geofence.evaluate(
        now = System.currentTimeMillis(),
        anchor = anchor,
        carIsLocked = status?.isLocked,
        carIsOn = status?.poweredOn,
        fix = fix,
        state = GeofenceLog.loadState(app),
        radiusMetres = KiaSettings.geofenceRadius(app),
        readingAt = status?.lastUpdated?.let { parseTime(it) },
        allowRefresh = allowRefresh,
    )

    /** One of /status's ISO timestamps, or null if it is not one. */
    private fun parseTime(iso: String): Long? = runCatching {
        java.time.OffsetDateTime.parse(iso).toInstant().toEpochMilli()
    }.getOrNull()

    private fun log(outcome: String, reason: String, acted: Boolean) {
        GeofenceLog.append(
            applicationContext,
            GeofenceEntry(System.currentTimeMillis(), outcome, reason, acted),
        )
    }

    /**
     * Says so when it locks the car.
     *
     * Not optional. Software that operates a car on its own has to leave a
     * trace a person will actually see, rather than one in a log they have to
     * go looking for.
     */
    private fun notifyLocked(distanceMetres: Int) {
        val app = applicationContext
        val manager = app.getSystemService(NotificationManager::class.java) ?: return

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            manager.createNotificationChannel(
                NotificationChannel(
                    CHANNEL,
                    app.getString(R.string.geofence_channel),
                    NotificationManager.IMPORTANCE_DEFAULT,
                )
            )
        }

        val open = PendingIntent.getActivity(
            app,
            0,
            Intent(app, GeofenceActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        val notification: Notification = Notification.Builder(app, CHANNEL)
            .setSmallIcon(CoreR.drawable.ic_lock)
            .setContentTitle(app.getString(R.string.geofence_locked_title))
            .setContentText(app.getString(R.string.geofence_locked_text, distanceMetres))
            .setContentIntent(open)
            .setAutoCancel(true)
            .build()

        manager.notify(NOTIFICATION_ID, notification)
    }

    private companion object {
        const val CHANNEL = "kia-geofence"
        const val NOTIFICATION_ID = 7301
    }
}

/**
 * One fix, as good as the phone can make it.
 *
 * getCurrentLocation rather than the last known one: a last known fix can be an
 * hour old and half a mile away, which is the exact mistake this feature exists
 * to stop making.
 */
@SuppressLint("MissingPermission") // every caller checks hasLocationPermission first
internal suspend fun currentFix(context: Context): PhoneFix? = suspendCancellableCoroutine { cont ->
    val client = LocationServices.getFusedLocationProviderClient(context)
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
