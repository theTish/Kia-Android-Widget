package ca.thetish.kia.app

import android.app.Activity
import android.app.Dialog
import android.content.Intent
import android.graphics.Typeface
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.text.SpannableStringBuilder
import android.text.Spanned
import android.text.style.ForegroundColorSpan
import android.text.style.StyleSpan
import android.view.View
import android.view.WindowManager
import android.widget.ImageButton
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.core.net.toUri
import ca.thetish.kia.core.ApiResult
import ca.thetish.kia.core.ChargeLimits
import ca.thetish.kia.core.ClimateSettings
import ca.thetish.kia.core.ClimateSync
import ca.thetish.kia.core.KiaApi
import ca.thetish.kia.core.KiaSettings
import ca.thetish.kia.core.UnlockGuard
import ca.thetish.kia.core.VehicleStatus
import ca.thetish.kia.core.R as CoreR
import java.text.DateFormat
import java.text.NumberFormat
import java.time.DayOfWeek
import java.time.LocalTime
import java.time.OffsetDateTime
import java.time.format.DateTimeFormatter
import java.time.format.TextStyle
import java.util.Date
import java.util.Locale
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

        // Also on every open, not only when Climate settings change: it covers
        // a watch that was reinstalled, and a phone that updated from the
        // preset build and has never published. Unchanged is a no-op.
        ClimateSync.publish(this, KiaSettings.climate(this))

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

        findViewById<View>(R.id.climate_card).setOnClickListener {
            startActivity(Intent(this, ClimateActivity::class.java))
        }
        findViewById<View>(R.id.precondition_row).setOnClickListener { showSchedule() }
        findViewById<View>(R.id.ac_limit_cell).setOnClickListener { showChargeLimit(ac = true) }
        findViewById<View>(R.id.dc_limit_cell).setOnClickListener { showChargeLimit(ac = false) }

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
            val uri = "geo:$lat,$lon?q=$lat,$lon(EV6)".toUri()
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
        renderClimate(latest)
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

    /**
     * @param live read the car itself rather than Kia's cache. Wakes the modem,
     * so only after a command whose result the cache cannot yet know about.
     */
    private fun refresh(live: Boolean = false) {
        status.text = getString(R.string.loading)
        io.execute {
            val cfg = KiaSettings.load(this)
            val outcome = if (live) KiaApi.statusLive(cfg) else KiaApi.status(cfg)
            main.post {
                if (isDestroyed) return@post
                val s = outcome.status
                if (outcome.ok && s != null) {
                    latest = s
                    render(s)
                    status.text = getString(R.string.updated_at, shortTime(s.lastUpdated))
                    Geofences.sync(this, s)
                } else {
                    status.text = getString(R.string.test_failed, outcome.message)
                }
            }
        }
    }

    /**
     * @param onSuccess what to do once the car has taken the command. A plain
     * re-read by default; a caller whose change the cache will not show yet
     * can do better (see showChargeLimit). Declared before [call] so the
     * trailing-lambda call sites keep meaning the command.
     */
    private fun send(labelRes: Int, onSuccess: () -> Unit = { refresh() }, call: () -> ApiResult) {
        setButtonsEnabled(false)
        status.text = getString(R.string.working, getString(labelRes))

        io.execute {
            val result = call()
            main.post {
                // The call can outlive the Activity by up to the request timeout.
                if (isDestroyed) return@post
                status.text = result.message
                setButtonsEnabled(true)
                if (result.ok) onSuccess()
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
            s.isCharging -> chargingLine(s)

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

    /**
     * "Charging · 6.6 kW · 2h 10m left", with whichever halves the car gave.
     *
     * Both come from the same estimate of how long is left, so they appear and
     * vanish together in practice; they are handled separately anyway because a
     * line reading "Charging · left" would be worse than one reading "Charging".
     */
    private fun chargingLine(s: VehicleStatus): String {
        val power = s.chargingPowerText
        val left = s.chargeRemainingText
        return when {
            power != null && left != null ->
                getString(R.string.charge_charging_power_left, power, left)

            power != null -> getString(R.string.charge_charging_power, power)
            left != null -> getString(R.string.charge_charging_left, left)
            else -> getString(R.string.charge_charging)
        }
    }

    private fun renderAttention(s: VehicleStatus) {
        val lines = buildList {
            addAll(s.warnings)
            if (s.openings.isNotEmpty()) {
                add(getString(R.string.opening_list, s.openings.joinToString(", ")))
            }
            if (s.poweredOn == true) add(getString(R.string.car_on))
        }

        findViewById<View>(R.id.attention_card).visibility =
            if (lines.isEmpty()) View.GONE else View.VISIBLE
        findViewById<TextView>(R.id.attention).text = lines.joinToString("\n")
    }

    private fun renderCards(s: VehicleStatus) {
        findViewById<TextView>(R.id.ac_limit).text = percentOrDash(s.chargeLimitAc)
        findViewById<TextView>(R.id.dc_limit).text = percentOrDash(s.chargeLimitDc)
        findViewById<TextView>(R.id.battery_12v).text = percentOrDash(s.battery12v)

        renderClimate(s)
        renderPreconditioning(s)

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

    /**
     * What the Climate button will send, rather than what the car last said.
     *
     * The car's own readback was this card's figure until it turned out to be
     * "Lo" nearly all the time - the dial's position from whoever last sat in
     * the car, which predicts nothing. The one live fact worth keeping is
     * whether climate is running now, so that leads the line when it is.
     *
     * Called on resume as well as after a refresh, so coming back from the
     * Climate screen shows the change without waiting on the network.
     */
    private fun renderClimate(s: VehicleStatus?) {
        val settings = KiaSettings.climate(this)
        findViewById<TextView>(R.id.climate_value).text = getString(
            R.string.climate_temperature,
            ClimateSettings.formatTemperature(settings.temperature),
        )
        findViewById<TextView>(R.id.climate_sub).text = listOfNotNull(
            if (s?.climateOn == true) getString(R.string.climate_running) else null,
            ClimateSummary.describe(this, settings, withDuration = true, withTemperature = false),
        ).joinToString(" · ")
    }

    /**
     * On when the car will get itself ready - a departure timer or battery
     * warming - and Off only when it said enough to be sure: a battery that is
     * not warming says nothing about a departure timer. Anything less is "Not
     * reported" rather than a guess.
     */
    private fun renderPreconditioning(s: VehicleStatus) {
        val view = findViewById<TextView>(R.id.precondition)
        val departures = s.departures
        val battery = s.batteryPreconditioning
        val on = departures.orEmpty().any { it.enabled == true } || battery == true

        when {
            on -> {
                view.setText(R.string.state_on)
                view.setTextColor(getColor(CoreR.color.accent))
            }

            departures != null && battery != null -> {
                view.setText(R.string.state_off)
                view.setTextColor(getColor(CoreR.color.text))
            }

            else -> {
                view.setText(R.string.not_reported)
                view.setTextColor(getColor(CoreR.color.text_muted))
            }
        }
    }

    /**
     * Change one charge limit - the target state of charge for AC or for DC.
     *
     * A dialog with a stepper over the six values Kia accepts, opened from the
     * figure it changes. Only that one limit is sent; the API keeps the other
     * as the car has it.
     *
     * What happens after is the interesting part. The command returns a
     * transaction id, not a confirmation, and /status answers from Kia's
     * cache, which goes on reporting the old limit until the car checks in.
     * A plain re-read would therefore paint the old value straight back over
     * the one just chosen and look exactly like a failure. So the chosen value
     * is shown at once, and a LIVE read follows after a pause long enough for
     * the car to have applied it - whatever that read says is what the car
     * says, which is the rule on this screen.
     */
    private fun showChargeLimit(ac: Boolean) {
        val current = if (ac) latest?.chargeLimitAc else latest?.chargeLimitDc
        var value = ChargeLimits.snap(current ?: ChargeLimits.DEFAULT)

        val view = layoutInflater.inflate(R.layout.dialog_charge_limit, null)
        val figure = view.findViewById<TextView>(R.id.limit_value)
        view.findViewById<TextView>(R.id.limit_title)
            .setText(if (ac) R.string.charge_limit_title_ac else R.string.charge_limit_title_dc)

        fun show() {
            figure.text = getString(R.string.percent_value, value)
        }
        view.findViewById<View>(R.id.limit_down).setOnClickListener { value = ChargeLimits.down(value); show() }
        view.findViewById<View>(R.id.limit_up).setOnClickListener { value = ChargeLimits.up(value); show() }
        show()

        val dialog = Dialog(this)
        dialog.setContentView(view)
        dialog.window?.apply {
            setBackgroundDrawableResource(android.R.color.transparent)
            setLayout(
                (resources.displayMetrics.widthPixels * 0.9f).toInt(),
                WindowManager.LayoutParams.WRAP_CONTENT,
            )
        }
        view.findViewById<View>(R.id.limit_cancel).setOnClickListener { dialog.dismiss() }
        view.findViewById<View>(R.id.limit_set).setOnClickListener {
            dialog.dismiss()
            val chosen = value
            send(
                R.string.charge_limit_action,
                onSuccess = {
                    latest?.let { s ->
                        val shown = if (ac) s.copy(chargeLimitAc = chosen) else s.copy(chargeLimitDc = chosen)
                        latest = shown
                        render(shown)
                    }
                    main.postDelayed({ if (!isDestroyed) refresh(live = true) }, LIMIT_APPLY_DELAY_MS)
                },
            ) {
                val cfg = KiaSettings.load(this)
                if (ac) KiaApi.setChargeLimits(cfg, ac = chosen) else KiaApi.setChargeLimits(cfg, dc = chosen)
            }
        }
        dialog.show()
    }

    /**
     * The schedule behind the row, read-only.
     *
     * A dialog rather than a screen: it is two timers and a switch, and the
     * status it describes is already in hand here - a screen would have to be
     * handed it or fetch it again. Editing stays in Kia's own app; writing
     * timers back is a command to the car, and nothing on this phone needs to
     * own that.
     */
    private fun showSchedule() {
        val s = latest ?: return
        val view = layoutInflater.inflate(R.layout.dialog_precondition, null)
        val list = view.findViewById<LinearLayout>(R.id.precondition_list)

        val rows = s.departures.orEmpty().sortedBy { it.slot }.map { d ->
            Triple(getString(R.string.precondition_departure_n, d.slot), d.enabled, departureDetail(d))
        } + listOfNotNull(
            s.batteryPreconditioning?.let {
                Triple(
                    getString(R.string.precondition_battery),
                    it,
                    getString(R.string.precondition_battery_detail),
                )
            }
        )

        if (rows.isEmpty()) {
            view.findViewById<View>(R.id.precondition_none).visibility = View.VISIBLE
        }
        for ((index, row) in rows.withIndex()) {
            if (index > 0) list.addView(View(this).apply {
                layoutParams = LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, dp(1))
                setBackgroundColor(getColor(CoreR.color.divider))
            })
            list.addView(scheduleRow(row.first, row.second, row.third))
        }

        val dialog = Dialog(this)
        dialog.setContentView(view)
        dialog.window?.apply {
            setBackgroundDrawableResource(android.R.color.transparent)
            setLayout(
                (resources.displayMetrics.widthPixels * 0.9f).toInt(),
                WindowManager.LayoutParams.WRAP_CONTENT,
            )
        }
        view.findViewById<View>(R.id.precondition_close).setOnClickListener { dialog.dismiss() }
        dialog.show()
    }

    private fun scheduleRow(title: String, enabled: Boolean?, detail: String?): View {
        val row = layoutInflater.inflate(R.layout.row_precondition, null)
        row.findViewById<TextView>(R.id.title).text = title
        row.findViewById<TextView>(R.id.state).apply {
            when (enabled) {
                true -> {
                    setText(R.string.state_on)
                    setTextColor(getColor(CoreR.color.accent))
                }

                false -> {
                    setText(R.string.state_off)
                    setTextColor(getColor(CoreR.color.text_dim))
                }

                null -> {
                    setText(R.string.not_reported)
                    setTextColor(getColor(CoreR.color.text_muted))
                }
            }
        }
        row.findViewById<TextView>(R.id.detail).apply {
            text = detail
            visibility = if (detail.isNullOrEmpty()) View.GONE else View.VISIBLE
            // An off timer still shows what it is set to, but should not read
            // as though it will happen.
            setTextColor(getColor(if (enabled == true) CoreR.color.text_dim else CoreR.color.text_muted))
        }
        return row
    }

    /** "7:40 a.m. · weekdays" over "Climate 22°", in the phone's own 12/24-hour style. */
    private fun departureDetail(d: VehicleStatus.Departure): String {
        val time = d.time?.let {
            runCatching {
                LocalTime.parse(it).format(
                    DateTimeFormatter.ofPattern(
                        if (android.text.format.DateFormat.is24HourFormat(this)) "H:mm" else "h:mm a"
                    )
                )
            }.getOrNull()
        }
        val days = when (d.dayPattern) {
            VehicleStatus.Departure.Days.DAILY -> getString(R.string.days_daily)
            VehicleStatus.Departure.Days.WEEKDAYS -> getString(R.string.days_weekdays)
            VehicleStatus.Departure.Days.WEEKENDS -> getString(R.string.days_weekends)
            // Kia counts from Sunday = 0; java.time from Monday = 1.
            VehicleStatus.Departure.Days.OTHER -> d.days.orEmpty().joinToString(", ") {
                DayOfWeek.of(if (it == 0) 7 else it).getDisplayName(TextStyle.SHORT, Locale.getDefault())
            }

            null -> null
        }
        val climate = when (d.climateOn) {
            true -> getString(
                R.string.precondition_climate,
                d.climateTemperature?.let { t ->
                    if (t <= VehicleStatus.LO_CELSIUS) getString(R.string.climate_lo)
                    else getString(R.string.climate_temperature, trimDecimal(t))
                }.orEmpty(),
            ).trim()

            false -> getString(R.string.precondition_climate_off)
            null -> null
        }
        return listOfNotNull(
            listOfNotNull(time, days).joinToString(" · ").ifEmpty { null },
            climate,
        ).joinToString("\n")
    }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

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
        /** How long the car gets to apply a new limit before the live read that shows it. */
        const val LIMIT_APPLY_DELAY_MS = 10_000L
        const val SPAN = Spanned.SPAN_EXCLUSIVE_EXCLUSIVE
    }
}
