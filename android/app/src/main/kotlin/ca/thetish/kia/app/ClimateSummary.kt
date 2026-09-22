package ca.thetish.kia.app

import android.content.Context
import ca.thetish.kia.core.ClimateSettings
import ca.thetish.kia.core.SeatHeat

/**
 * One line saying what the Climate button will send, for places that have no
 * room for the controls themselves.
 *
 * Seats collapse to "seats high" when they all match, because that is the
 * common case and three near-identical phrases in a row read as noise.
 */
object ClimateSummary {

    fun describe(
        context: Context,
        settings: ClimateSettings,
        withDuration: Boolean,
        withTemperature: Boolean = true,
    ): String {
        val s = settings.normalized()
        val parts = mutableListOf<String>()
        if (withTemperature) parts += context.getString(
            R.string.climate_temperature,
            ClimateSettings.formatTemperature(s.temperature),
        )
        if (withDuration) parts += context.getString(R.string.climate_minutes, s.durationMinutes)
        if (s.defrost) parts += context.getString(R.string.climate_defrost)
        if (s.rearHeat) parts += context.getString(R.string.climate_rear)
        if (s.steeringWheel) parts += context.getString(R.string.climate_wheel)

        val seats = listOf(
            R.string.climate_seat_driver to s.driverSeat,
            R.string.climate_seat_passenger to s.passengerSeat,
            R.string.climate_seat_rear to s.rearSeats,
        )
        val levels = seats.map { it.second }.distinct()
        if (levels.size == 1 && levels.single() != SeatHeat.OFF) {
            parts += context.getString(R.string.climate_seats_all, level(context, levels.single()))
        } else {
            for ((label, heat) in seats) {
                if (heat != SeatHeat.OFF) parts += context.getString(label, level(context, heat))
            }
        }
        return parts.joinToString(" · ")
    }

    private fun level(context: Context, heat: SeatHeat): String = context.getString(
        when (heat) {
            SeatHeat.OFF -> R.string.seat_off
            SeatHeat.LOW -> R.string.seat_low
            SeatHeat.MEDIUM -> R.string.seat_medium
            SeatHeat.HIGH -> R.string.seat_high
        }
    ).lowercase()
}
