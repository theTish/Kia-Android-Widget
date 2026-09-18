package ca.thetish.kia.app

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.view.View
import android.widget.Button
import android.widget.TextView
import ca.thetish.kia.core.ApiResult
import ca.thetish.kia.core.KiaApi
import ca.thetish.kia.core.KiaSettings
import ca.thetish.kia.core.UnlockGuard
import ca.thetish.kia.core.VehicleStatus
import ca.thetish.kia.core.R as CoreR
import java.util.concurrent.Executors

/**
 * Phone controls, and where the detail lives.
 *
 * The widget is what gets used day to day; this screen exists for the long tail
 * /status returns that would be unreadable on a widget - tyre and fluid
 * warnings, service interval, charge limits, climate readback, where the car is.
 */
class MainActivity : Activity() {

    private val io = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())

    private lateinit var headline: TextView
    private lateinit var lockState: TextView
    private lateinit var status: TextView
    private lateinit var lockButton: Button
    private lateinit var unlockButton: Button
    private lateinit var climateButton: Button
    private lateinit var mapButton: Button

    private var latest: VehicleStatus? = null

    /** See UnlockGuard: first tap arms, second tap sends. */
    private var unlockArmedUntil = 0L

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        headline = findViewById(R.id.headline)
        lockState = findViewById(R.id.lock_state)
        status = findViewById(R.id.status)
        lockButton = findViewById(R.id.lock)
        unlockButton = findViewById(R.id.unlock)
        climateButton = findViewById(R.id.climate)
        mapButton = findViewById(R.id.map)

        lockButton.setOnClickListener { send("Locking") { KiaApi.lock(KiaSettings.load(this)) } }

        climateButton.setOnClickListener {
            send("Starting climate") { KiaApi.startClimate(KiaSettings.load(this)) }
        }

        unlockButton.setOnClickListener {
            val now = SystemClock.elapsedRealtime()
            if (UnlockGuard.shouldFire(now, unlockArmedUntil)) {
                unlockArmedUntil = 0L
                unlockButton.text = getString(R.string.unlock)
                send("Unlocking") { KiaApi.unlock(KiaSettings.load(this)) }
            } else {
                unlockArmedUntil = UnlockGuard.armUntil(now)
                unlockButton.text = getString(R.string.unlock_confirm)
                status.text = getString(R.string.unlock_prompt)
                main.postDelayed({
                    if (SystemClock.elapsedRealtime() >= unlockArmedUntil) {
                        unlockArmedUntil = 0L
                        unlockButton.text = getString(R.string.unlock)
                    }
                }, UnlockGuard.ARM_WINDOW_MS)
            }
        }

        findViewById<Button>(R.id.refresh).setOnClickListener { refresh() }

        findViewById<Button>(R.id.settings).setOnClickListener {
            startActivity(Intent(this, SettingsActivity::class.java))
        }

        mapButton.setOnClickListener {
            val s = latest ?: return@setOnClickListener
            val lat = s.latitude ?: return@setOnClickListener
            val lon = s.longitude ?: return@setOnClickListener
            // A q label so the pin is named rather than a bare point.
            val uri = Uri.parse("geo:$lat,$lon?q=$lat,$lon(EV6)")
            runCatching { startActivity(Intent(Intent.ACTION_VIEW, uri)) }
                .onFailure { status.text = getString(R.string.no_map_app) }
        }
    }

    override fun onResume() {
        super.onResume()
        if (!KiaSettings.isConfigured(this)) {
            status.text = getString(R.string.no_key)
            setButtonsEnabled(false)
            return
        }
        setButtonsEnabled(true)
        refresh()
    }

    private fun refresh() {
        status.text = getString(R.string.loading)
        io.execute {
            val outcome = KiaApi.status(KiaSettings.load(this))
            main.post {
                if (isDestroyed) return@post
                val s = outcome.status
                if (outcome.ok && s != null) {
                    latest = s
                    render(s)
                    status.text = getString(R.string.updated_at, shortTime(s.lastUpdated))
                } else {
                    status.text = getString(R.string.test_failed, outcome.message)
                }
            }
        }
    }

    private fun render(s: VehicleStatus) {
        headline.text = buildList {
            s.batteryPercent?.let { add("$it%") }
            s.range?.let { add("$it ${s.rangeUnit ?: "km"}") }
        }.joinToString("  ·  ").ifEmpty { getString(R.string.app_name) }

        lockState.text = when (s.isLocked) {
            true -> getString(R.string.locked_state)
            false -> getString(R.string.unlocked_state)
            null -> getString(R.string.lock_unknown)
        }
        // An unlocked car is the one state worth colouring.
        lockState.setTextColor(
            getColor(if (s.isLocked == false) CoreR.color.armed_text else CoreR.color.text_dim)
        )

        // Warnings first: anything needing attention should not sit below the
        // fold under charge limits.
        section(R.id.warnings_heading, R.id.warnings, buildList {
            addAll(s.warnings)
            if (s.openings.isNotEmpty()) add("Open: " + s.openings.joinToString(", "))
            if (s.engineRunning == true) add("Engine running")
        }.joinToString("\n"))

        section(R.id.charge_heading, R.id.charge, buildList {
            if (s.isCharging) {
                add("Charging" + (s.chargeRemainingText?.let { " - $it" } ?: ""))
                s.chargingEta?.let { add("Full at $it") }
            } else if (s.pluggedIn) {
                add("Plugged in" + (s.plugType?.let { " ($it)" } ?: "") + ", not charging")
            } else {
                add("Not plugged in")
            }
            if (s.chargeLimitAc != null && s.chargeLimitDc != null) {
                add("Limits: ${s.chargeLimitAc}% AC / ${s.chargeLimitDc}% DC")
            }
            s.battery12v?.let { add("12V battery: $it%") }
        }.joinToString("\n"))

        section(R.id.climate_heading, R.id.climate_info, buildList {
            add(if (s.climateOn == true) "Running" else "Off")
            s.setTemperature?.let { add("Set to $it°C") }
            if (s.defrostOn == true) add("Defrost on")
            if (s.steeringWheelHeaterOn == true) add("Steering wheel heater on")
            if (s.rearWindowHeaterOn == true) add("Rear window heater on")
        }.joinToString("\n"))

        section(R.id.car_heading, R.id.car, buildList {
            s.odometer?.let { add("Odometer: ${it.toInt()} ${s.odometerUnit ?: "km"}") }
            s.serviceDistanceToNext?.let { add("Next service at ${it.toInt()} km") }
            if (!s.windowsReported) add("Windows: not reported by this car")
        }.joinToString("\n"))

        mapButton.visibility = if (s.latitude != null) View.VISIBLE else View.GONE
    }

    /** Shows a section only when it has something to say. */
    private fun section(headingId: Int, bodyId: Int, text: String) {
        val visible = text.isNotBlank()
        findViewById<TextView>(headingId).visibility = if (visible) View.VISIBLE else View.GONE
        findViewById<TextView>(bodyId).apply {
            visibility = if (visible) View.VISIBLE else View.GONE
            this.text = text
        }
    }

    /** "2026-09-17T22:12:06+00:00" -> "22:12". A freshness hint, not a clock. */
    private fun shortTime(iso: String?): String =
        iso?.substringAfter('T')?.take(5) ?: "?"

    private fun send(label: String, call: () -> ApiResult) {
        setButtonsEnabled(false)
        status.text = getString(R.string.working, label)

        io.execute {
            val result = call()
            main.post {
                // The call can outlive the Activity by up to the request timeout.
                if (isDestroyed) return@post
                status.text = result.message
                setButtonsEnabled(true)
                if (result.ok) refresh()
            }
        }
    }

    private fun setButtonsEnabled(enabled: Boolean) {
        lockButton.isEnabled = enabled
        unlockButton.isEnabled = enabled
        climateButton.isEnabled = enabled
    }

    override fun onDestroy() {
        super.onDestroy()
        // shutdownNow interrupts a request still in flight; plain shutdown would
        // let it hold this Activity and its view tree for the full 45s timeout.
        io.shutdownNow()
        main.removeCallbacksAndMessages(null)
    }
}
