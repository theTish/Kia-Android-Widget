package ca.thetish.kia.app

import android.app.Activity
import android.os.Bundle
import android.widget.ImageButton
import android.widget.TextView
import ca.thetish.kia.core.ClimateSettings
import ca.thetish.kia.core.ClimateSync
import ca.thetish.kia.core.KiaSettings
import ca.thetish.kia.core.SeatHeat

/**
 * What the Climate button sends - from the app, the widget, anywhere on the phone.
 *
 * Its own screen rather than more rows on Settings: seven controls would push
 * the API fields and Save a long scroll apart, and these are changed with the
 * seasons while those are set once.
 *
 * Every change is saved as it is made, like the auto-lock radius, so there is
 * no Save button to forget and Back simply leaves.
 */
class ClimateActivity : Activity() {

    private lateinit var settings: ClimateSettings

    private lateinit var temperature: TextView
    private lateinit var duration: TextView
    private lateinit var summary: TextView

    private val seatOptions = SeatHeat.entries

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_climate)

        settings = KiaSettings.climate(this)

        temperature = findViewById(R.id.temperature_value)
        duration = findViewById(R.id.duration_value)
        summary = findViewById(R.id.climate_summary)

        findViewById<ImageButton>(R.id.back).setOnClickListener { finish() }

        findViewById<ImageButton>(R.id.temperature_down).setOnClickListener {
            update { copy(temperature = temperature - ClimateSettings.TEMPERATURE_STEP) }
        }
        findViewById<ImageButton>(R.id.temperature_up).setOnClickListener {
            update { copy(temperature = temperature + ClimateSettings.TEMPERATURE_STEP) }
        }
        findViewById<ImageButton>(R.id.duration_down).setOnClickListener {
            update { copy(durationMinutes = durationMinutes - ClimateSettings.DURATION_STEP) }
        }
        findViewById<ImageButton>(R.id.duration_up).setOnClickListener {
            update { copy(durationMinutes = durationMinutes + ClimateSettings.DURATION_STEP) }
        }

        toggle(R.id.defrost_off, R.id.defrost_on, settings.defrost) {
            update { copy(defrost = it) }
        }
        toggle(R.id.rear_heat_off, R.id.rear_heat_on, settings.rearHeat) {
            update { copy(rearHeat = it) }
        }
        toggle(R.id.wheel_off, R.id.wheel_on, settings.steeringWheel) {
            update { copy(steeringWheel = it) }
        }

        seats(
            listOf(R.id.driver_off, R.id.driver_low, R.id.driver_medium, R.id.driver_high),
            settings.driverSeat,
        ) { update { copy(driverSeat = it) } }
        seats(
            listOf(R.id.passenger_off, R.id.passenger_low, R.id.passenger_medium, R.id.passenger_high),
            settings.passengerSeat,
        ) { update { copy(passengerSeat = it) } }
        seats(
            listOf(R.id.rear_off, R.id.rear_low, R.id.rear_medium, R.id.rear_high),
            settings.rearSeats,
        ) { update { copy(rearSeats = it) } }

        render()
    }

    private fun toggle(offId: Int, onId: Int, current: Boolean, onChange: (Boolean) -> Unit) {
        Segments(this, listOf(false to offId, true to onId), onChange).select(current)
    }

    private fun seats(ids: List<Int>, current: SeatHeat, onChange: (SeatHeat) -> Unit) {
        Segments(this, seatOptions.zip(ids), onChange).select(current)
    }

    /** Applies a change, clamps it, saves it and redraws the parts that show numbers. */
    private fun update(change: ClimateSettings.() -> ClimateSettings) {
        settings = settings.change().normalized()
        KiaSettings.saveClimate(this, settings)
        ClimateSync.publish(this, settings)
        render()
    }

    private fun render() {
        temperature.text = getString(
            R.string.climate_temperature,
            ClimateSettings.formatTemperature(settings.temperature),
        )
        duration.text = getString(R.string.climate_minutes, settings.durationMinutes)

        // Dimmed rather than hidden at the ends, so the layout does not jump
        // and it is obvious why another tap does nothing.
        stepper(R.id.temperature_down, settings.temperature > ClimateSettings.MIN_TEMPERATURE)
        stepper(R.id.temperature_up, settings.temperature < ClimateSettings.MAX_TEMPERATURE)
        stepper(R.id.duration_down, settings.durationMinutes > ClimateSettings.MIN_DURATION)
        stepper(R.id.duration_up, settings.durationMinutes < ClimateSettings.MAX_DURATION)

        summary.text = getString(
            R.string.climate_sends,
            ClimateSummary.describe(this, settings, withDuration = true),
        )
    }

    private fun stepper(id: Int, enabled: Boolean) {
        findViewById<ImageButton>(id).apply {
            isEnabled = enabled
            alpha = if (enabled) 1f else 0.35f
        }
    }
}
