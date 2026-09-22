package ca.thetish.kia.core

/** How hard a seat heater runs. The level is the number the car's API takes. */
enum class SeatHeat(val level: Int) {
    OFF(0),
    LOW(1),
    MEDIUM(2),
    HIGH(3);

    companion object {
        fun fromLevel(level: Int): SeatHeat = entries.firstOrNull { it.level == level } ?: OFF
    }
}

/**
 * Exactly what the Climate button asks the car for.
 *
 * Replaces the three seasonal presets. A preset was a guess made on the
 * server about what "winter" means, and the only way to change it was to
 * redeploy the API; this is the answer to that question kept on the phone,
 * where the person pressing the button can change it.
 *
 * Every field is sent every time, including the ones that are off. The API
 * fills in anything missing with its own defaults - rear heating defaults to
 * on there - so leaving a field out would not mean "off", it would mean
 * "whatever the server thinks".
 */
data class ClimateSettings(
    val temperature: Double = DEFAULT_TEMPERATURE,
    val durationMinutes: Int = DEFAULT_DURATION,
    val defrost: Boolean = false,
    /** Rear window and mirror heating; `heating` in the API. */
    val rearHeat: Boolean = false,
    /**
     * On or off only. The API accepts 0-3, but the car treats any non-zero
     * level the same, so offering levels would be offering a choice that
     * does nothing.
     */
    val steeringWheel: Boolean = false,
    val driverSeat: SeatHeat = SeatHeat.OFF,
    val passengerSeat: SeatHeat = SeatHeat.OFF,
    /** Both rear seats together; nobody sets them separately from the front. */
    val rearSeats: SeatHeat = SeatHeat.OFF,
) {

    /**
     * Pulled back inside what the API accepts.
     *
     * Anything outside these bounds is answered with a 400, which from the
     * widget looks like the button being broken. Temperature is also snapped
     * to half degrees because that is the resolution the car works in: it is
     * sent as twice the value, truncated to an integer.
     */
    fun normalized(): ClimateSettings = copy(
        temperature = Math.round(temperature.coerceIn(MIN_TEMPERATURE, MAX_TEMPERATURE) * 2) / 2.0,
        durationMinutes = durationMinutes.coerceIn(MIN_DURATION, MAX_DURATION),
    )

    /**
     * The body for POST /start_climate.
     *
     * Written out by hand rather than with org.json: every value is a number
     * or a boolean, so there is nothing to escape, and this way the exact
     * bytes sent to the car can be checked in a plain unit test - Android's
     * JSONObject is only a stub off-device.
     */
    fun toJson(): String {
        val s = normalized()
        val fields = listOf(
            "set_temp" to formatTemperature(s.temperature),
            "duration" to s.durationMinutes.toString(),
            // Always true: this is the "start climate" call, and a request with
            // the HVAC itself off would only run the heaters.
            "climate" to "true",
            "defrost" to s.defrost.toString(),
            "heating" to (if (s.rearHeat) "1" else "0"),
            "steering_wheel" to (if (s.steeringWheel) "1" else "0"),
            "front_left_seat" to s.driverSeat.level.toString(),
            "front_right_seat" to s.passengerSeat.level.toString(),
            "rear_left_seat" to s.rearSeats.level.toString(),
            "rear_right_seat" to s.rearSeats.level.toString(),
        )
        return fields.joinToString(",", "{", "}") { (key, value) -> "\"$key\":$value" }
    }

    companion object {
        const val MIN_TEMPERATURE = 16.0
        const val MAX_TEMPERATURE = 30.0
        const val TEMPERATURE_STEP = 0.5
        const val DEFAULT_TEMPERATURE = 21.0

        const val MIN_DURATION = 5
        const val MAX_DURATION = 30
        const val DURATION_STEP = 5
        const val DEFAULT_DURATION = 10

        /** 21 degrees for ten minutes, nothing else: harmless in any season. */
        val DEFAULT = ClimateSettings()

        /**
         * What each of the old presets used to send, so nobody's button
         * changes behaviour the day they update.
         *
         * Mirrors CLIMATE_PRESETS in api/index.py. The server keeps its copy
         * for Tasker and anything else that still sends a preset name; this
         * one is only read to carry an old choice over, and for the watch
         * tile, which has no settings screen to choose on.
         */
        fun forPreset(name: String?): ClimateSettings? = when (name?.trim()?.lowercase()) {
            "winter" -> ClimateSettings(
                defrost = true,
                rearHeat = true,
                steeringWheel = true,
                driverSeat = SeatHeat.HIGH,
                passengerSeat = SeatHeat.HIGH,
            )
            "summer" -> DEFAULT
            // Defrost on for morning dew and frost, nothing else.
            "springfall" -> ClimateSettings(defrost = true)
            else -> null
        }

        /** 21 rather than 21.0, so a whole number reads as one wherever it is shown. */
        fun formatTemperature(value: Double): String =
            if (value % 1.0 == 0.0) value.toLong().toString() else value.toString()
    }
}
