package ca.thetish.kia.app

import android.Manifest
import android.app.Activity
import android.os.Build
import android.os.Bundle
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
    private lateinit var warning: TextView
    private lateinit var radiusValue: TextView
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
        warning = findViewById(R.id.warning)
        radiusValue = findViewById(R.id.radius_value)
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
            Geofences.remove(this)
        } else {
            requestWhatIsMissing()
            startIfReady()
        }
        render()
    }

    /**
     * Gets the ring drawn now rather than whenever something next refreshes.
     *
     * Turning this on and seeing nothing happen for fifteen minutes would be
     * indistinguishable from it being broken, so one status is fetched
     * immediately; that call ends in Geofences.sync like every other.
     */
    private fun startIfReady() {
        if (KiaSettings.geofenceMode(this) == GeofenceMode.OFF) return
        if (!Geofences.hasLocationPermission(this)) return
        Geofences.schedulePolling(this)
        KiaWorker.enqueue(this, KiaWorker.ACTION_STATUS)
    }

    /**
     * Asks for location, foreground first.
     *
     * Android will not grant background location in the same breath as
     * foreground - and from Android 11 it will not grant it from a dialog at
     * all, only from Settings - so this asks for what it can and the screen
     * says plainly what is still missing.
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

        if (!Geofences.hasBackgroundLocationPermission(this)) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                requestPermissions(
                    arrayOf(Manifest.permission.ACCESS_BACKGROUND_LOCATION),
                    REQUEST_BACKGROUND,
                )
            }
            return
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQUEST_NOTIFY)
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
        startIfReady()
        render()
    }

    private fun nudgeRadius(delta: Int) {
        val current = KiaSettings.geofenceRadius(this)
        KiaSettings.saveGeofenceRadius(this, current + delta)
        render()
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

        renderWarning(mode)
        renderLog()
    }

    private fun renderWarning(mode: GeofenceMode) {
        val message = when {
            mode == GeofenceMode.OFF -> null
            !Geofences.hasLocationPermission(this) -> getString(R.string.geofence_needs_location)
            !Geofences.hasBackgroundLocationPermission(this) ->
                getString(R.string.geofence_needs_background)

            else -> null
        }
        warning.text = message.orEmpty()
        warning.visibility = if (message == null) View.GONE else View.VISIBLE
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
            text = entry.reason
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
        const val REQUEST_BACKGROUND = 2
        const val REQUEST_NOTIFY = 3
    }
}
