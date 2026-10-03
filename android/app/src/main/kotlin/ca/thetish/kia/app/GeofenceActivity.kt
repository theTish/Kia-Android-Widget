package ca.thetish.kia.app

import android.Manifest
import android.app.Activity
import android.app.AlertDialog
import android.bluetooth.BluetoothManager
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.view.Gravity
import android.view.View
import android.widget.ImageButton
import android.widget.LinearLayout
import android.widget.TextView
import ca.thetish.kia.core.GeofenceEntry
import ca.thetish.kia.core.GeofenceLog
import ca.thetish.kia.core.GeofenceMode
import ca.thetish.kia.core.KiaSettings
import ca.thetish.kia.core.R as CoreR
import java.text.DateFormat
import java.util.Date

/**
 * The auto-lock switch, and the evidence for whether to move it.
 *
 * The log is most of this screen on purpose. Handing a piece of software the
 * ability to operate a car is not a decision to take on a description of how it
 * works; it is one to take after reading a fortnight of what it actually
 * decided, which is what Shadow is for.
 */
class GeofenceActivity : Activity() {

    private lateinit var modeNote: TextView
    private lateinit var checked: TextView
    private lateinit var warning: TextView
    private lateinit var radiusValue: TextView
    private lateinit var carDevice: TextView
    private lateinit var logContainer: LinearLayout
    private lateinit var empty: TextView

    private val modes = listOf(
        GeofenceMode.OFF to R.id.mode_off,
        GeofenceMode.SHADOW to R.id.mode_shadow,
        GeofenceMode.ARMED to R.id.mode_armed,
    )

    private val timestamps: DateFormat by lazy {
        android.text.format.DateFormat.getTimeFormat(this)
    }
    private val dates: DateFormat by lazy {
        android.text.format.DateFormat.getDateFormat(this)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_geofence)

        modeNote = findViewById(R.id.mode_note)
        checked = findViewById(R.id.checked)
        warning = findViewById(R.id.warning)
        radiusValue = findViewById(R.id.radius_value)
        carDevice = findViewById(R.id.car_device_value)
        findViewById<View>(R.id.car_device).setOnClickListener { chooseCarDevice() }
        logContainer = findViewById(R.id.log)
        empty = findViewById(R.id.empty)

        findViewById<ImageButton>(R.id.back).setOnClickListener { finish() }

        for ((mode, id) in modes) {
            findViewById<TextView>(id).setOnClickListener { choose(mode) }
        }

        findViewById<ImageButton>(R.id.radius_down).setOnClickListener { nudgeRadius(-25) }
        findViewById<ImageButton>(R.id.radius_up).setOnClickListener { nudgeRadius(+25) }

        findViewById<TextView>(R.id.clear).setOnClickListener {
            GeofenceLog.clear(this)
            renderLog()
        }
    }

    override fun onResume() {
        super.onResume()
        render()
    }

    // ── mode ──

    private fun choose(mode: GeofenceMode) {
        KiaSettings.saveGeofenceMode(this, mode)

        if (mode == GeofenceMode.OFF) {
            Geofences.stop(this)
        } else {
            requestWhatIsMissing()
        }
        render()
    }

    /**
     * Asks for what a dialog can actually grant.
     *
     * Not background location, deliberately. From Android 11 that permission
     * cannot be granted from a dialog at all: requestPermissions for it does
     * not prompt, it throws the user out into system Settings - and lands them
     * on the list of every app's location access rather than this one's, two
     * Back presses from where they were. Doing that unasked, immediately after
     * they granted the first one, reads as the app having lost its place.
     *
     * So the amber warning carries that trip instead, and only when tapped.
     */
    private fun requestWhatIsMissing() {
        if (!Geofences.hasLocationPermission(this)) {
            requestPermissions(
                arrayOf(
                    Manifest.permission.ACCESS_FINE_LOCATION,
                    Manifest.permission.ACCESS_COARSE_LOCATION,
                ),
                REQUEST_FOREGROUND,
            )
            return
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQUEST_NOTIFY)
        }
    }

    /** This app's own permission page - the nearest thing to a deep link Android offers. */
    private fun openAppSettings() {
        runCatching {
            startActivity(
                Intent(
                    Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
                    Uri.fromParts("package", packageName, null),
                )
            )
        }
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray,
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        // Foreground granted opens the door to asking for background; the rest
        // just redraws with whatever the answer was.
        if (requestCode == REQUEST_FOREGROUND) requestWhatIsMissing()
        render()
    }

    private fun nudgeRadius(delta: Int) {
        val current = KiaSettings.geofenceRadius(this)
        KiaSettings.saveGeofenceRadius(this, current + delta)
        render()
    }

    /**
     * Picks the car out of the phone's paired devices.
     *
     * A list of what is already paired rather than a scan: the car is paired,
     * scanning is a permission and a battery cost for a question already
     * answered, and a wrong choice here means the whole feature waits for a
     * disconnect that never comes.
     */
    private fun chooseCarDevice() {
        if (!Geofences.hasBluetoothPermission(this)) {
            requestPermissions(arrayOf(Manifest.permission.BLUETOOTH_CONNECT), REQUEST_BLUETOOTH)
            return
        }

        val adapter = getSystemService(BluetoothManager::class.java)?.adapter
        val paired = runCatching { adapter?.bondedDevices?.toList() }.getOrNull().orEmpty()
            .sortedBy { runCatching { it.name }.getOrNull() ?: it.address }

        if (paired.isEmpty()) {
            AlertDialog.Builder(this)
                .setMessage(R.string.geofence_car_device_empty)
                .setPositiveButton(android.R.string.ok, null)
                .show()
            return
        }

        val labels = paired.map { runCatching { it.name }.getOrNull() ?: it.address }.toTypedArray()
        val chosen = paired.indexOfFirst { KiaSettings.isCarBluetooth(this, it.address) }

        AlertDialog.Builder(this)
            .setTitle(R.string.geofence_car_device_pick)
            .setSingleChoiceItems(labels, chosen) { dialog, which ->
                val device = paired[which]
                KiaSettings.saveCarBluetooth(
                    this,
                    device.address,
                    runCatching { device.name }.getOrNull(),
                )
                dialog.dismiss()
                render()
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    // ── rendering ──

    private fun render() {
        val mode = KiaSettings.geofenceMode(this)

        for ((option, id) in modes) {
            val selected = option == mode
            findViewById<TextView>(id).apply {
                setBackgroundResource(
                    if (selected) R.drawable.segment_selected else R.drawable.segment_idle
                )
                setTextColor(getColor(if (selected) CoreR.color.text else CoreR.color.text_dim))
            }
        }

        modeNote.setText(
            when (mode) {
                GeofenceMode.OFF -> R.string.geofence_note_off
                GeofenceMode.SHADOW -> R.string.geofence_note_shadow
                GeofenceMode.ARMED -> R.string.geofence_note_armed
            }
        )
        modeNote.setTextColor(
            getColor(if (mode == GeofenceMode.ARMED) CoreR.color.armed else CoreR.color.text_dim)
        )

        radiusValue.text = getString(R.string.geofence_radius_value, KiaSettings.geofenceRadius(this))

        // Said separately from the log because they answer different questions:
        // the log says what it decided, this says that it is still asking.
        val at = GeofenceLog.checkedAt(this)
        checked.text = if (at == 0L) {
            getString(R.string.geofence_checked_never)
        } else {
            getString(R.string.geofence_checked, timestamps.format(Date(at)))
        }
        checked.visibility = if (mode == GeofenceMode.OFF) View.GONE else View.VISIBLE

        carDevice.text = KiaSettings.carBluetoothName(this)
            ?: KiaSettings.carBluetooth(this)
            ?: getString(R.string.geofence_car_device_none)

        renderWarning(mode)
        renderLog()
    }

    private fun renderWarning(mode: GeofenceMode) {
        val message = when {
            mode == GeofenceMode.OFF -> null
            // Named first: without it nothing ever triggers, so the other
            // warnings would be about a feature that cannot start anyway.
            KiaSettings.carBluetooth(this) == null -> getString(R.string.geofence_car_device_none)
            !Geofences.hasBluetoothPermission(this) -> getString(R.string.geofence_needs_bluetooth)
            !Geofences.hasLocationPermission(this) -> getString(R.string.geofence_needs_location)
            !Geofences.hasBackgroundLocationPermission(this) ->
                getString(R.string.geofence_needs_background)

            else -> null
        }
        warning.text = message.orEmpty()
        warning.visibility = if (message == null) View.GONE else View.VISIBLE

        // Only the background-location case has somewhere useful to go.
        val opensSettings = message != null && Geofences.hasLocationPermission(this)
        warning.isClickable = opensSettings
        warning.setOnClickListener(if (opensSettings) View.OnClickListener { openAppSettings() } else null)
    }

    private fun renderLog() {
        val entries = GeofenceLog.read(this)
        logContainer.removeAllViews()
        empty.visibility = if (entries.isEmpty()) View.VISIBLE else View.GONE
        logContainer.visibility = if (entries.isEmpty()) View.GONE else View.VISIBLE

        for ((index, entry) in entries.withIndex()) {
            if (index > 0) logContainer.addView(divider())
            logContainer.addView(row(entry))
        }
    }

    private fun divider(): View = View(this).apply {
        layoutParams = LinearLayout.LayoutParams(
            LinearLayout.LayoutParams.MATCH_PARENT,
            dp(1),
        )
        setBackgroundColor(getColor(CoreR.color.divider))
    }

    private fun row(entry: GeofenceEntry): View {
        val row = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT,
            )
            setPadding(0, dp(12), 0, dp(12))
        }

        val when_ = Date(entry.at)
        val header = TextView(this).apply {
            text = getString(
                R.string.geofence_entry_when,
                dates.format(when_),
                timestamps.format(when_),
            )
            setTextColor(getColor(CoreR.color.text_muted))
            textSize = 12f
        }

        val body = TextView(this).apply {
            // A bare "already locked" reads like a status line rather than a
            // decision, so holds say what they decided.
            text = if (entry.outcome == GeofenceEntry.OUTCOME_HOLD) {
                getString(R.string.geofence_entry_hold, entry.reason)
            } else {
                entry.reason
            }
            // Amber for anything that reached a lock decision - acted on or
            // not, those are the lines worth reading twice.
            setTextColor(
                getColor(if (entry.isLock) CoreR.color.armed else CoreR.color.text)
            )
            textSize = 15f
            gravity = Gravity.START
            setPadding(0, dp(2), 0, 0)
        }

        row.addView(header)
        row.addView(body)

        if (entry.acted) {
            row.addView(
                TextView(this).apply {
                    setText(R.string.geofence_entry_sent)
                    setTextColor(getColor(CoreR.color.accent))
                    textSize = 13f
                    setPadding(0, dp(2), 0, 0)
                }
            )
        }
        return row
    }

    private fun dp(value: Int): Int =
        (value * resources.displayMetrics.density).toInt()

    private companion object {
        const val REQUEST_FOREGROUND = 1
        const val REQUEST_NOTIFY = 3
        const val REQUEST_BLUETOOTH = 4
    }
}
