package ca.thetish.kia.app

import android.app.Activity
import android.content.Intent
import android.graphics.Typeface
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.text.SpannableStringBuilder
import android.text.Spanned
import android.text.style.ForegroundColorSpan
import android.text.style.StyleSpan
import android.view.View
import android.widget.ImageButton
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import ca.thetish.kia.core.ApiResult
import ca.thetish.kia.core.KiaApi
import ca.thetish.kia.core.KiaSettings
import ca.thetish.kia.core.UnlockGuard
import ca.thetish.kia.core.VehicleStatus
import ca.thetish.kia.core.R as CoreR
import java.text.DateFormat
import java.text.NumberFormat
import java.time.OffsetDateTime
import java.util.Date
import java.util.concurrent.Executors

/**
 * Phone controls, and where the detail lives.
 *
 * The widget is what gets used day to day; this screen exists for the long tail
 * /status returns that would be unreadable on a widget - tyre and fluid
 * warnings, service interval, charge limits, climate readback, where the car is.
 *
 * Everything the car did not report renders as an em dash or as "Not reported",
 * never as zero. The EV6 routinely answers with no EV data at all, and a 0%
 * battery over a car sitting on 75% is worse than no number.
 */
class MainActivity : Activity() {

    private val io = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())
    private val numbers: NumberFormat = NumberFormat.getIntegerInstance()

    /** The phone's own 12- or 24-hour preference, not ours to decide. */
    private val timeFormat: DateFormat by lazy { android.text.format.DateFormat.getTimeFormat(this) }

    private lateinit var status: TextView
    private lateinit var battery: TextView
    private lateinit var batteryUnit: TextView
    private lateinit var range: TextView
    private lateinit var batteryBar: BatteryBarView
    private lateinit var chargeState: TextView
    private lateinit var chargeLimit: TextView
    private lateinit var lockChipIcon: ImageView
    private lateinit var lockChipText: TextView
    private lateinit var hint: TextView

    private lateinit var lockButton: LinearLayout
    private lateinit var unlockButton: LinearLayout
    private lateinit var unlockIcon: ImageView
    private lateinit var unlockLabel: TextView
    private lateinit var climateButton: LinearLayout
    private lateinit var mapButton: LinearLayout

    private var latest: VehicleStatus? = null

    /** See UnlockGuard: first tap arms, second tap sends. */
    private var unlockArmedUntil = 0L

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        status = findViewById(R.id.status)
        battery = findViewById(R.id.battery)
        batteryUnit = findViewById(R.id.battery_unit)
        range = findViewById(R.id.range)
        batteryBar = findViewById(R.id.battery_bar)
        chargeState = findViewById(R.id.charge_state)
        chargeLimit = findViewById(R.id.charge_limit)
        lockChipIcon = findViewById(R.id.lock_chip_icon)
        lockChipText = findViewById(R.id.lock_chip_text)
        hint = findViewById(R.id.hint)

        lockButton = findViewById(R.id.lock)
        unlockButton = findViewById(R.id.unlock)
        unlockIcon = findViewById(R.id.unlock_icon)
        unlockLabel = findViewById(R.id.unlock_label)
        climateButton = findViewById(R.id.climate)
        mapButton = findViewById(R.id.map)

        lockButton.setOnClickListener { send(R.string.lock) { KiaApi.lock(KiaSettings.load(this)) } }

        climateButton.setOnClickListener {
            send(R.string.climate) { KiaApi.startClimate(KiaSettings.load(this)) }
        }

        unlockButton.setOnClickListener { onUnlockTapped() }

        findViewById<ImageButton>(R.id.refresh).setOnClickListener { refresh() }

        findViewById<ImageButton>(R.id.settings).setOnClickListener {
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

    // ── unlock ───────────────────────────────────────────────────────────────

    private fun onUnlockTapped() {
        val now = SystemClock.elapsedRealtime()

        if (UnlockGuard.shouldFire(now, unlockArmedUntil)) {
            disarm()
            send(R.string.unlock) { KiaApi.unlock(KiaSettings.load(this)) }
            return
        }

        unlockArmedUntil = UnlockGuard.armUntil(now)
        setUnlockArmed(true)
        hint.text = getString(R.string.unlock_prompt)

        main.postDelayed({
            // A second tap may have fired and re-disarmed in the meantime.
            if (SystemClock.elapsedRealtime() >= unlockArmedUntil) disarm()
        }, UnlockGuard.ARM_WINDOW_MS)
    }

    private fun disarm() {
        unlockArmedUntil = 0L
        setUnlockArmed(false)
        hint.text = ""
    }

    private fun setUnlockArmed(armed: Boolean) {
        unlockButton.setBackgroundResource(
            if (armed) R.drawable.control_armed else R.drawable.control_surface
        )
        val ink = getColor(if (armed) CoreR.color.armed_ink else CoreR.color.text)
        unlockIcon.setColorFilter(ink)
        unlockLabel.setTextColor(ink)
        unlockLabel.setText(if (armed) R.string.unlock_confirm else R.string.unlock)
    }

    // ── loading ──────────────────────────────────────────────────────────────

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

    private fun send(labelRes: Int, call: () -> ApiResult) {
        setButtonsEnabled(false)
        status.text = getString(R.string.working, getString(labelRes))

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
        val alpha = if (enabled) 1f else 0.5f
        lockButton.alpha = alpha
        unlockButton.alpha = alpha
        climateButton.alpha = alpha
    }

    // ── rendering ────────────────────────────────────────────────────────────

    private fun render(s: VehicleStatus) {
        renderCharge(s)
        renderLockChip(s)
        renderAttention(s)
        renderCards(s)

        mapButton.visibility = if (s.latitude != null) View.VISIBLE else View.GONE
    }

    private fun renderCharge(s: VehicleStatus) {
        battery.text = s.batteryPercent?.toString() ?: getString(R.string.no_value)
        batteryUnit.visibility = if (s.batteryPercent != null) View.VISIBLE else View.GONE

        range.text = if (s.range != null) {
            // The distance carries the weight; "range" is only the unit of
            // meaning, so it stays dim and light.
            val value = getString(R.string.range_value, s.range, s.rangeUnit ?: DEFAULT_UNIT)
            SpannableStringBuilder(value).apply {
                setSpan(ForegroundColorSpan(getColor(CoreR.color.text)), 0, length, SPAN)
                setSpan(StyleSpan(Typeface.BOLD), 0, length, SPAN)
                append(" ").append(getString(R.string.range_suffix))
            }
        } else {
            getString(R.string.range_unknown)
        }

        batteryBar.show(s.batteryPercent, s.chargeLimitAc)

        chargeState.text = when {
            s.isCharging -> s.chargeRemainingText
                ?.let { getString(R.string.charge_charging_left, it) }
                ?: getString(R.string.charge_charging)

            s.pluggedIn -> s.plugType
                ?.let { getString(R.string.charge_plugged_type, it) }
                ?: getString(R.string.charge_plugged)

            else -> getString(R.string.charge_unplugged)
        }
        // Charging is the one charge state worth colouring, and it matches the
        // bar directly above it.
        chargeState.setTextColor(
            getColor(if (s.isCharging) CoreR.color.accent else CoreR.color.text_dim)
        )

        chargeLimit.text = s.chargeLimitAc?.let { getString(R.string.charge_limit, it) } ?: ""
    }

    private fun renderLockChip(s: VehicleStatus) {
        val locked = s.isLocked
        lockChipText.setText(
            when (locked) {
                true -> R.string.locked_state
                false -> R.string.unlocked_state
                null -> R.string.lock_unknown
            }
        )
        lockChipIcon.setImageResource(
            if (locked == false) CoreR.drawable.ic_unlock else CoreR.drawable.ic_lock
        )
        // Amber, not red: an unlocked car is worth noticing, not an emergency.
        val tint = getColor(
            when (locked) {
                true -> CoreR.color.accent
                false -> CoreR.color.armed
                null -> CoreR.color.text_muted
            }
        )
        lockChipIcon.setColorFilter(tint)
        lockChipText.setTextColor(
            getColor(if (locked == null) CoreR.color.text_muted else CoreR.color.text)
        )
    }

    private fun renderAttention(s: VehicleStatus) {
        val lines = buildList {
            addAll(s.warnings)
            if (s.openings.isNotEmpty()) {
                add(getString(R.string.opening_list, s.openings.joinToString(", ")))
            }
            if (s.engineRunning == true) add(getString(R.string.engine_running))
        }

        findViewById<View>(R.id.attention_card).visibility =
            if (lines.isEmpty()) View.GONE else View.VISIBLE
        findViewById<TextView>(R.id.attention).text = lines.joinToString("\n")
    }

    private fun renderCards(s: VehicleStatus) {
        findViewById<TextView>(R.id.ac_limit).text = percentOrDash(s.chargeLimitAc)
        findViewById<TextView>(R.id.dc_limit).text = percentOrDash(s.chargeLimitDc)
        findViewById<TextView>(R.id.battery_12v).text = percentOrDash(s.battery12v)

        findViewById<TextView>(R.id.climate_value).text = s.setTemperature
            ?.let { getString(R.string.climate_temperature, trimDecimal(it)) }
            ?: getString(R.string.no_value)

        findViewById<TextView>(R.id.climate_sub).text = buildList {
            when (s.climateOn) {
                true -> add(getString(R.string.climate_running))
                false -> add(getString(R.string.climate_off))
                null -> {}
            }
            if (s.defrostOn == true) add(getString(R.string.climate_defrost))
            if (s.steeringWheelHeaterOn == true) add(getString(R.string.climate_wheel))
            if (s.rearWindowHeaterOn == true) add(getString(R.string.climate_rear))
            add(getString(R.string.climate_preset, KiaSettings.load(this@MainActivity).climatePreset))
        }.joinToString(" · ")

        renderService(s)

        findViewById<TextView>(R.id.odometer).text = s.odometer
            ?.let { getString(R.string.distance_value, numbers.format(it.toInt()), s.odometerUnit ?: DEFAULT_UNIT) }
            ?: getString(R.string.no_value)

        setRow(R.id.doors, s.doorsOpen.joinToString(", "), known = true)
        // The distinction matters: this EV6 never reports windows at all, and
        // "All shut" would be a claim the car never made.
        setRow(R.id.windows, s.windowsOpen.joinToString(", "), known = s.windowsReported)
    }

    /**
     * How far until the next service.
     *
     * The car does not report a distance: `distance_to_next` is the odometer
     * reading the service is booked against, and `distance_since_last` is the
     * reading of the last one. With the odometer at 33,379 and the next service
     * at 36,000, showing the raw field would promise another 36,000km of
     * motoring before anything needs doing - out by a factor of fourteen.
     */
    private fun renderService(s: VehicleStatus) {
        val value = findViewById<TextView>(R.id.service_value)
        val sub = findViewById<TextView>(R.id.service_sub)

        val dueAt = s.serviceDistanceToNext
        val odometer = s.odometer
        if (dueAt == null || odometer == null) {
            value.text = getString(R.string.no_value)
            sub.visibility = View.INVISIBLE
            return
        }

        sub.visibility = View.VISIBLE
        val remaining = (dueAt - odometer).toInt()
        if (remaining > 0) {
            value.text = numbers.format(remaining)
            value.setTextColor(getColor(CoreR.color.text))
            sub.setText(R.string.service_sub)
        } else {
            value.setText(R.string.service_due)
            value.setTextColor(getColor(CoreR.color.armed))
            sub.text = getString(R.string.service_overdue, numbers.format(-remaining))
        }
    }

    /** A row of openings: the list when something is open, "All shut" when not. */
    private fun setRow(id: Int, open: String, known: Boolean) {
        val view = findViewById<TextView>(id)
        when {
            !known -> {
                view.setText(R.string.not_reported)
                view.setTextColor(getColor(CoreR.color.text_muted))
            }

            open.isEmpty() -> {
                view.setText(R.string.all_shut)
                view.setTextColor(getColor(CoreR.color.text))
            }

            else -> {
                view.text = open
                view.setTextColor(getColor(CoreR.color.armed))
            }
        }
    }

    private fun percentOrDash(value: Int?): String =
        value?.let { getString(R.string.percent_value, it) } ?: getString(R.string.no_value)

    /** 21.0 -> "21", 21.5 -> "21.5". A whole number should not carry a ".0". */
    private fun trimDecimal(value: Double): String =
        if (value == value.toInt().toDouble()) value.toInt().toString() else value.toString()

    /**
     * "2026-09-17T22:12:06+00:00" -> "6:12 pm", in the phone's own time.
     *
     * The API answers in UTC. Printing its clock face verbatim, which is what
     * this used to do, made a reading from a minute ago look nine hours old -
     * the one thing this line exists to tell you.
     */
    private fun shortTime(iso: String?): String {
        if (iso == null) return "?"
        return runCatching {
            timeFormat.format(Date.from(OffsetDateTime.parse(iso).toInstant()))
        }.getOrElse {
            // Not every field the car fills in carries an offset. Better the
            // raw clock face than nothing at all.
            iso.substringAfter('T').take(5)
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        // shutdownNow interrupts a request still in flight; plain shutdown would
        // let it hold this Activity and its view tree for the full 45s timeout.
        io.shutdownNow()
        main.removeCallbacksAndMessages(null)
    }

    private companion object {
        const val DEFAULT_UNIT = "km"
        const val SPAN = Spanned.SPAN_EXCLUSIVE_EXCLUSIVE
    }
}
