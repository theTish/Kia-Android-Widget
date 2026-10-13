package ca.thetish.kia.app

import android.Manifest
import android.annotation.SuppressLint
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.bluetooth.BluetoothDevice
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.location.Location
import android.net.wifi.WifiManager
import android.os.Build
import android.os.IBinder
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import ca.thetish.kia.core.Anchor
import ca.thetish.kia.core.Geofence
import ca.thetish.kia.core.GeofenceDecision
import ca.thetish.kia.core.GeofenceEntry
import ca.thetish.kia.core.GeofenceLog
import ca.thetish.kia.core.GeofenceMode
import ca.thetish.kia.core.GeofenceState
import ca.thetish.kia.core.KiaApi
import ca.thetish.kia.core.KiaSettings
import ca.thetish.kia.core.PhoneFix
import ca.thetish.kia.core.R as CoreR
import com.google.android.gms.location.LocationServices
import com.google.android.gms.location.Priority
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
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
 *  - a reason to start watching. Once a minute the phone checks whether it
 *    has actually gone, and when it has, the lock is sent. Kia is not asked
 *    whether the car is already locked: its cache still described the parking
 *    before for a while after the disconnect, and on 2026-10-09 that ended the
 *    watch before anybody had got out. Locking a locked car costs nothing.
 *
 * The watching happens in [WatchService], a foreground service, rather than in
 * scheduled work. Android held scheduled checks back while the phone sat in a
 * pocket, and locks landed ten to forty-five minutes after the walk away; a
 * foreground service is allowed to look on time. It lives at most
 * [Geofence.LOCK_DEADLINE_MS], so a lock is never sent later than that.
 *
 * Nothing here decides anything. [Geofence] does, in :core, where it can be
 * tested without a car; this file is the plumbing that feeds it and the switch
 * that decides whether its answer reaches the car.
 */
object Geofences {

    /**
     * How often to look after the car is switched off.
     *
     * Half the dwell, so the first reading clear of the ring comes at most
     * half a minute after you are, and the confirm a minute after that - all
     * inside [Geofence.LOCK_DEADLINE_MS]. A couple of minutes of GPS per
     * parking is not something the battery notices.
     */
    const val WATCH_INTERVAL_MS = 30_000L

    /** The car's Bluetooth dropped: start watching. */
    fun start(context: Context) {
        val app = context.applicationContext
        // A location service started without location permission is refused
        // by Android, and that refusal crashes the app.
        if (!hasLocationPermission(app)) {
            note(app, "location permission not granted")
            return
        }
        val intent = Intent(app, WatchService::class.java)
        try {
            ContextCompat.startForegroundService(app, intent)
        } catch (e: IllegalStateException) {
            // Android refuses some background starts. Say so rather than
            // leave a parking that silently went unwatched.
            note(app, "could not start watching: ${e.javaClass.simpleName}")
        }
    }

    /** Back in the car, or switched off: nothing left to watch for. */
    fun stop(context: Context) {
        val app = context.applicationContext
        app.stopService(Intent(app, WatchService::class.java))
        GeofenceLog.clearAnchor(app)
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

    /**
     * The Wi-Fi the phone is on now, or null if none or Android will not say.
     *
     * Android only names the network to an app with location permission and
     * location switched on, which this feature needs anyway.
     */
    @Suppress("DEPRECATION") // the replacement needs a network callback for a one-off question
    fun currentWifi(context: Context): String? {
        val wifi = context.applicationContext.getSystemService(WifiManager::class.java) ?: return null
        val ssid = runCatching { wifi.connectionInfo?.ssid }.getOrNull() ?: return null
        return ssid.removeSurrounding("\"").takeIf { it.isNotBlank() && it != WifiManager.UNKNOWN_SSID }
    }

    fun onHomeWifi(context: Context): Boolean {
        val home = KiaSettings.homeWifi(context) ?: return false
        return currentWifi(context) == home
    }

    internal fun note(app: Context, reason: String) {
        GeofenceLog.append(
            app,
            GeofenceEntry(System.currentTimeMillis(), GeofenceEntry.OUTCOME_HOLD, reason, false),
        )
    }
}

/**
 * The car's Bluetooth connecting and dropping.
 *
 * These two broadcasts are exempt from the background restrictions, so they
 * still arrive with the app closed - which is the only way any of this works.
 * Being Bluetooth broadcasts that need BLUETOOTH_CONNECT, they also let the app
 * start a foreground service from the background.
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
            // is what the next few minutes are for.
            BluetoothDevice.ACTION_ACL_DISCONNECTED -> Geofences.start(app)
        }
    }
}

/**
 * Watches one parking, for at most [Geofence.LOCK_DEADLINE_MS].
 *
 * Takes the anchor straight away - the phone is still in the car for a few
 * seconds after the Bluetooth drops, and that is the only moment anything here
 * can learn where the car is - then looks once a minute until the lock goes
 * out, the car reconnects, or the deadline passes. The "Watching" notification
 * is the price of looking on time, and is gone when it ends.
 */
class WatchService : Service() {

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var watch: Job? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        try {
            ServiceCompat.startForeground(
                this,
                WATCHING_ID,
                watchingNotification(),
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_LOCATION
                } else {
                    0
                },
            )
        } catch (e: RuntimeException) {
            // Refused, usually a permission taken away since the last parking.
            Geofences.note(applicationContext, "could not start watching: ${e.javaClass.simpleName}")
            stopSelf(startId)
            return START_NOT_STICKY
        }

        // A second disconnect is a new parking: start over from it.
        watch?.cancel()
        watch = scope.launch {
            try {
                if (anchor()) {
                    while (!look()) delay(Geofences.WATCH_INTERVAL_MS)
                }
            } finally {
                stopSelf(startId)
            }
        }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    /** Takes the fix that becomes the anchor. False if there is nothing to measure from. */
    private suspend fun anchor(): Boolean {
        val app = applicationContext
        if (KiaSettings.geofenceMode(app) == GeofenceMode.OFF) return false
        if (!Geofences.hasLocationPermission(app)) {
            Geofences.note(app, "location permission not granted")
            return false
        }

        val fix = currentFix(app)
        if (fix == null || fix.accuracyMetres > Geofence.MAX_ACCURACY_METRES) {
            // No anchor, so no decision for this parking. A guessed one is how
            // you lock a car somebody is still sitting in, and the log says so
            // rather than leaving a silent gap.
            Geofences.note(
                app,
                fix?.let { "left the car on a fix accurate only to ${it.accuracyMetres.toInt()}m" }
                    ?: "left the car with no position fix",
            )
            return false
        }

        GeofenceLog.saveAnchor(
            app,
            Anchor(
                fix.latitude,
                fix.longitude,
                fix.accuracyMetres,
                System.currentTimeMillis(),
                onHomeWifi = Geofences.onHomeWifi(app),
            ),
        )
        // A new parking starts with no dwell served. Left over from the last
        // one, a half-served dwell would let the first look lock straight away.
        GeofenceLog.saveState(app, GeofenceState())
        return true
    }

    /** One look. True when there is nothing left to watch for. */
    private suspend fun look(): Boolean {
        val app = applicationContext
        val mode = KiaSettings.geofenceMode(app)
        if (mode == GeofenceMode.OFF) return true
        val anchor = GeofenceLog.anchor(app) ?: return true

        val now = System.currentTimeMillis()
        GeofenceLog.recordCheck(app, now)

        if (Geofence.tooLate(anchor, now)) {
            Geofences.note(
                app,
                "gave up: ${(now - anchor.atMillis) / 1000}s after parking, past the " +
                    "${Geofence.LOCK_DEADLINE_MS / 1000}s limit",
            )
            GeofenceLog.clearAnchor(app)
            return true
        }

        val fix = currentFix(app)
        val before = GeofenceLog.loadState(app)
        val outcome = Geofence.evaluate(
            anchor = anchor,
            fix = fix,
            state = before,
            radiusMetres = KiaSettings.geofenceRadius(app),
            onHomeWifi = Geofences.onHomeWifi(app),
            now = now,
        )

        return when (val decision = outcome.decision) {
            is GeofenceDecision.Hold -> {
                GeofenceLog.saveState(app, outcome.state)
                log(GeofenceEntry.OUTCOME_HOLD, decision.reason, acted = false)
                false
            }

            is GeofenceDecision.Waiting -> {
                GeofenceLog.saveState(app, outcome.state)
                log(GeofenceEntry.OUTCOME_WAITING, decision.reason, acted = false)
                false
            }

            is GeofenceDecision.Lock -> {
                val armed = mode == GeofenceMode.ARMED
                val sent = if (armed) {
                    withContext(Dispatchers.IO) { KiaApi.lock(KiaSettings.load(app)) }.ok
                } else {
                    false
                }
                // A lock that did not go through has not settled anything:
                // keep the dwell already served and try again next minute.
                val done = sent || !armed
                GeofenceLog.saveState(app, if (done) outcome.state else before)
                log(
                    GeofenceEntry.OUTCOME_LOCK,
                    if (armed) {
                        if (sent) decision.reason else "${decision.reason} - lock failed, retrying"
                    } else {
                        "${decision.reason} (shadow: not sent)"
                    },
                    acted = sent,
                )
                if (sent) {
                    notifyLocked(decision.distanceMetres)
                    // The widget is still showing whatever the car was before.
                    KiaWorker.enqueue(app, KiaWorker.ACTION_STATUS)
                }
                done
            }
        }
    }

    private fun log(outcome: String, reason: String, acted: Boolean) {
        GeofenceLog.append(
            applicationContext,
            GeofenceEntry(System.currentTimeMillis(), outcome, reason, acted),
        )
    }

    private fun channel(id: String, name: Int, importance: Int) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            getSystemService(NotificationManager::class.java)
                ?.createNotificationChannel(NotificationChannel(id, getString(name), importance))
        }
    }

    private fun openApp(): PendingIntent = PendingIntent.getActivity(
        this,
        0,
        Intent(this, GeofenceActivity::class.java),
        PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
    )

    /** Quiet and short-lived: there only while a parking is being watched. */
    private fun watchingNotification(): Notification {
        channel(WATCHING_CHANNEL, R.string.geofence_watching_channel, NotificationManager.IMPORTANCE_LOW)
        return Notification.Builder(this, WATCHING_CHANNEL)
            .setSmallIcon(CoreR.drawable.ic_lock)
            .setContentTitle(getString(R.string.geofence_watching_title))
            .setContentIntent(openApp())
            .setOngoing(true)
            .build()
    }

    /**
     * Says so when it locks the car.
     *
     * Not optional. Software that operates a car on its own has to leave a
     * trace a person will actually see, rather than one in a log they have to
     * go looking for.
     */
    private fun notifyLocked(distanceMetres: Int) {
        val manager = getSystemService(NotificationManager::class.java) ?: return
        channel(CHANNEL, R.string.geofence_channel, NotificationManager.IMPORTANCE_DEFAULT)

        val notification: Notification = Notification.Builder(this, CHANNEL)
            .setSmallIcon(CoreR.drawable.ic_lock)
            .setContentTitle(getString(R.string.geofence_locked_title))
            .setContentText(getString(R.string.geofence_locked_text, distanceMetres))
            .setContentIntent(openApp())
            .setAutoCancel(true)
            .build()

        manager.notify(NOTIFICATION_ID, notification)
    }

    private companion object {
        const val CHANNEL = "kia-geofence"
        const val NOTIFICATION_ID = 7301
        const val WATCHING_CHANNEL = "kia-geofence-watching"
        const val WATCHING_ID = 7302
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
