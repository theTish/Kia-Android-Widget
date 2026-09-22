package ca.thetish.kia.core

import org.json.JSONObject

/**
 * Everything from /status that a client displays.
 *
 * Wider than the widget needs on purpose: the phone app is where the long tail
 * lives, because a widget showing tyre pressure warnings would be unreadable.
 *
 * Almost every field is nullable, and that is not defensive padding - the car
 * genuinely reports different subsets at different times. Windows come back
 * null on this EV6 always; EV battery and range go null whenever Kia's cached
 * view is stale. Anything unknown must render as unknown, never as zero or as
 * a cheerful default.
 *
 * Range is the awkward one: when it is not known it comes back as 0 rather than
 * as null. Seen on 2026-09-17, reading 0km beside a 73% battery, during a Kia
 * maintenance window - the rest of the payload carried last-known values while
 * range alone was zeroed, and a forced live poll returned the same 0 because it
 * went through the same unavailable upstream.
 *
 * So 0 maps to null here. Not because the car is shrugging - it is Kia being
 * down - but because "0 km" beside a three-quarters-full battery is a reading
 * nobody should act on, and an outage is exactly when a client should say it
 * does not know. A car genuinely out of charge has a battery percentage to say
 * so.
 */
data class VehicleStatus(
    // Charge
    val batteryPercent: Int?,
    val battery12v: Int?,
    val isCharging: Boolean,
    val pluggedIn: Boolean,
    val plugType: String?,
    val chargingEta: String?,
    val chargeRemainingText: String?,
    val chargeLimitAc: Int?,
    val chargeLimitDc: Int?,
    val batteryPreconditioning: Boolean?,

    // Distance
    val range: Int?,
    val rangeUnit: String?,
    val odometer: Double?,
    val odometerUnit: String?,

    // Security
    val isLocked: Boolean?,
    val engineRunning: Boolean?,
    /** Human names of any door or boot standing open, empty when all shut. */
    val doorsOpen: List<String>,
    /** Human names of any window standing open, empty when all shut. */
    val windowsOpen: List<String>,
    /** True only if the car actually reported window state; this EV6 never does. */
    val windowsReported: Boolean,

    // Climate
    val climateOn: Boolean?,
    val setTemperature: Double?,
    val defrostOn: Boolean?,
    val steeringWheelHeaterOn: Boolean?,
    val rearWindowHeaterOn: Boolean?,

    /**
     * The car's scheduled departures, or null when it did not say. Null and
     * empty differ on purpose: empty would be the car saying none are set.
     */
    val departures: List<Departure>?,

    // Care
    /** Human names of anything warning, empty when nothing is. */
    val warnings: List<String>,
    val serviceDistanceToNext: Double?,

    val latitude: Double?,
    val longitude: Double?,
    val lastUpdated: String?,
) {
    val hasEvData: Boolean get() = batteryPercent != null

    /**
     * Whether the climate target is the car's "Lo" rather than a temperature.
     *
     * The car sends its target as a hex step, and the library turns step 0
     * into 14.0 - the bottom of its table, below anything the EV6 lets you
     * pick. The car's own display calls that step "Lo", and showing "14°"
     * reads as a setting nobody made.
     */
    val climateTargetIsLo: Boolean
        get() = setTemperature?.let { it <= LO_CELSIUS } ?: false

    /** One scheduled departure. Days count as Kia does: 0 is Sunday. */
    data class Departure(
        val slot: Int,
        val enabled: Boolean?,
        /** 24-hour "07:30". */
        val time: String?,
        val days: List<Int>?,
        val climateOn: Boolean?,
        val climateTemperature: Double?,
    ) {
        enum class Days { DAILY, WEEKDAYS, WEEKENDS, OTHER }

        /** The common shapes a schedule takes, so a UI can say "weekdays". */
        val dayPattern: Days?
            get() = when (days?.toSet()) {
                null -> null
                (0..6).toSet() -> Days.DAILY
                (1..5).toSet() -> Days.WEEKDAYS
                setOf(0, 6) -> Days.WEEKENDS
                else -> Days.OTHER
            }
    }

    /**
     * Everything standing open, in one list.
     *
     * The two are kept apart above because the home screen lists doors and
     * windows on separate rows, and windows have their own "the car never says"
     * case; anywhere that just needs "is something open" wants them together.
     */
    val openings: List<String>
        get() = doorsOpen + windowsOpen.map { "$it window" }

    companion object {
        /** What the library decodes the car's "Lo" step to; see climateTargetIsLo. */
        const val LO_CELSIUS = 14.0

        private val OPENING_LABELS = mapOf(
            "front_left" to "front left",
            "front_right" to "front right",
            "back_left" to "rear left",
            "back_right" to "rear right",
            "trunk" to "boot",
            "hood" to "bonnet",
            "sunroof" to "sunroof",
        )

        private val WARNING_LABELS = mapOf(
            "tire_pressure_front_left" to "Tyre: front left",
            "tire_pressure_front_right" to "Tyre: front right",
            "tire_pressure_rear_left" to "Tyre: rear left",
            "tire_pressure_rear_right" to "Tyre: rear right",
            "washer_fluid_low" to "Washer fluid low",
            "brake_fluid_low" to "Brake fluid low",
        )

        fun parse(json: JSONObject): VehicleStatus {
            val range = json.optJSONObject("range")
            val odo = json.optJSONObject("odometer")
            val limits = json.optJSONObject("charge_limits")
            val climate = json.optJSONObject("climate")
            val warnings = json.optJSONObject("warnings")
            val service = json.optJSONObject("service")
            val location = json.optJSONObject("location")
            val doors = json.optJSONObject("doors")
            val windows = json.optJSONObject("windows")
            val precondition = json.optJSONObject("preconditioning")

            return VehicleStatus(
                batteryPercent = json.intOrNull("battery_percentage"),
                battery12v = json.intOrNull("battery_12v"),
                isCharging = json.optBoolean("is_charging", false),
                pluggedIn = json.optBoolean("plugged_in", false),
                plugType = json.stringOrNull("plug_type"),
                chargingEta = json.stringOrNull("charging_eta"),
                chargeRemainingText = json.stringOrNull("charging_duration_formatted"),
                chargeLimitAc = limits?.intOrNull("ac"),
                chargeLimitDc = limits?.intOrNull("dc"),
                batteryPreconditioning = precondition?.boolOrNull("battery")
                    ?: json.boolOrNull("battery_preconditioning"),

                range = range?.doubleOrNull("ev")?.toInt()?.takeIf { it > 0 },
                rangeUnit = range?.stringOrNull("unit"),
                odometer = odo?.doubleOrNull("value"),
                odometerUnit = odo?.stringOrNull("unit"),

                isLocked = json.boolOrNull("is_locked"),
                engineRunning = json.boolOrNull("engine_running"),
                doorsOpen = namesOfTrue(doors),
                windowsOpen = namesOfTrue(windows),
                windowsReported = windows?.keys()?.asSequence()
                    ?.any { !windows.isNull(it) } ?: false,

                climateOn = climate?.boolOrNull("air_control_on"),
                setTemperature = climate?.doubleOrNull("set_temperature"),
                defrostOn = climate?.boolOrNull("defrost_on"),
                steeringWheelHeaterOn = climate?.boolOrNull("steering_wheel_heater_on"),
                rearWindowHeaterOn = climate?.boolOrNull("rear_window_heater_on"),
                departures = precondition?.optJSONArray("departures")?.let { arr ->
                    (0 until arr.length()).mapNotNull { arr.optJSONObject(it) }.map { d ->
                        Departure(
                            slot = d.optInt("slot"),
                            enabled = d.boolOrNull("enabled"),
                            time = d.stringOrNull("time"),
                            days = d.optJSONArray("days")?.let { days ->
                                (0 until days.length()).map { days.optInt(it) }
                            },
                            climateOn = d.boolOrNull("climate_on"),
                            climateTemperature = d.doubleOrNull("climate_temperature"),
                        )
                    }
                },

                warnings = WARNING_LABELS.filter { (key, _) ->
                    warnings?.boolOrNull(key) == true
                }.values.toList(),
                serviceDistanceToNext = service?.doubleOrNull("distance_to_next"),

                latitude = location?.doubleOrNull("latitude"),
                longitude = location?.doubleOrNull("longitude"),
                lastUpdated = json.stringOrNull("last_updated_at"),
            )
        }

        private fun namesOfTrue(obj: JSONObject?): List<String> {
            if (obj == null) return emptyList()
            return obj.keys().asSequence()
                .filter { !obj.isNull(it) && obj.optBoolean(it) }
                .mapNotNull { OPENING_LABELS[it] }
                .toList()
        }

        // JSON null and absent both mean "unknown", so both come back as null
        // rather than as optInt's 0 or optBoolean's false.
        private fun JSONObject.intOrNull(key: String): Int? =
            if (isNull(key)) null else optInt(key)

        private fun JSONObject.doubleOrNull(key: String): Double? =
            if (isNull(key)) null else optDouble(key).takeIf { !it.isNaN() }

        private fun JSONObject.boolOrNull(key: String): Boolean? =
            if (isNull(key)) null else optBoolean(key)

        private fun JSONObject.stringOrNull(key: String): String? =
            if (isNull(key)) null else optString(key).takeIf { it.isNotBlank() }
    }
}
