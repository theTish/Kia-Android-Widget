package ca.thetish.kia.core

import android.content.Context

/**
 * Where to reach the API and how to authenticate.
 *
 * Passed into every KiaApi call rather than read from BuildConfig inside it,
 * because the two clients get it from different places: the phone reads what
 * the user typed into Settings, the watch tile has no practical way to be
 * configured so it keeps what was compiled in.
 */
data class KiaConfig(
    val baseUrl: String,
    val secret: String,
    val climate: ClimateSettings,
) {
    val isUsable: Boolean get() = secret.isNotBlank() && baseUrl.isNotBlank()

    companion object {
        /** Whatever local.properties supplied at build time. */
        fun fromBuildConfig() = KiaConfig(
            baseUrl = BuildConfig.KIA_BASE_URL.trimEnd('/'),
            secret = BuildConfig.KIA_SECRET,
            // The watch has nowhere to pick settings, so it sends what the old
            // preset name in local.properties used to mean. Unset or unknown
            // falls back to the plain default rather than failing the build.
            climate = ClimateSettings.forPreset(BuildConfig.KIA_CLIMATE_PRESET)
                ?: ClimateSettings.DEFAULT,
        )
    }
}

/**
 * The phone's on-device settings.
 *
 * SharedPreferences rather than DataStore on purpose: the widget's worker and
 * the Glance composable both need this synchronously, and DataStore's flow API
 * would mean either blocking on it anyway or restructuring both for no gain.
 *
 * Values fall back to the build-time ones, so a fresh install behaves exactly
 * as it did before Settings existed, and clearing a field restores that default
 * rather than breaking the app.
 */
object KiaSettings {

    private const val FILE = "kia_settings"
    private const val KEY_BASE_URL = "base_url"
    private const val KEY_SECRET = "secret"
    // Read only to carry an old choice over; see climate().
    private const val KEY_LEGACY_PRESET = "climate_preset"
    private const val KEY_CLIMATE_TEMP = "climate_temp"
    private const val KEY_CLIMATE_DURATION = "climate_duration"
    private const val KEY_CLIMATE_DEFROST = "climate_defrost"
    private const val KEY_CLIMATE_REAR_HEAT = "climate_rear_heat"
    private const val KEY_CLIMATE_WHEEL = "climate_wheel"
    private const val KEY_CLIMATE_DRIVER = "climate_driver_seat"
    private const val KEY_CLIMATE_PASSENGER = "climate_passenger_seat"
    private const val KEY_CLIMATE_REAR_SEATS = "climate_rear_seats"
    private const val KEY_WIDGET_BACKGROUND = "widget_background"
    private const val KEY_GEOFENCE_MODE = "geofence_mode"
    private const val KEY_GEOFENCE_RADIUS = "geofence_radius"

    /** Offered in the UI so switching hosts does not mean typing a URL. */
    val KNOWN_HOSTS = listOf(
        "https://kia.tishman.ca",
        "https://kia-android-widget.vercel.app",
    )

    /**
     * How the widget paints its card.
     *
     * Glass by default because it is the one that looks deliberate on a photo
     * wallpaper; solid exists because a busy wallpaper eats it, and nothing the
     * widget can do about that is worth the guess.
     */
    const val BACKGROUND_GLASS = "glass"
    const val BACKGROUND_SOLID = "solid"
    val BACKGROUNDS = listOf(BACKGROUND_GLASS, BACKGROUND_SOLID)

    fun load(context: Context): KiaConfig {
        val prefs = context.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE)
        val defaults = KiaConfig.fromBuildConfig()

        return KiaConfig(
            baseUrl = prefs.getString(KEY_BASE_URL, null)?.trim()?.trimEnd('/')
                ?.takeIf { it.isNotEmpty() } ?: defaults.baseUrl,
            secret = prefs.getString(KEY_SECRET, null)?.trim()
                ?.takeIf { it.isNotEmpty() } ?: defaults.secret,
            climate = climate(context),
        )
    }

    /**
     * What the Climate button sends.
     *
     * The first read after updating from the preset version seeds these from
     * whatever that preset used to send - the stored choice, or failing that
     * the build-time one, which is what a phone that never saved Settings was
     * sending - and writes them straight back. Doing it once and dropping the
     * old key means a later change to local.properties cannot quietly
     * override what was chosen here.
     */
    fun climate(context: Context): ClimateSettings {
        val prefs = context.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE)

        if (!prefs.contains(KEY_CLIMATE_TEMP)) {
            val seeded = ClimateSettings.forPreset(prefs.getString(KEY_LEGACY_PRESET, null))
                ?: KiaConfig.fromBuildConfig().climate
            saveClimate(context, seeded)
            return seeded.normalized()
        }

        val defaults = ClimateSettings.DEFAULT
        return ClimateSettings(
            temperature = prefs.getFloat(KEY_CLIMATE_TEMP, defaults.temperature.toFloat()).toDouble(),
            durationMinutes = prefs.getInt(KEY_CLIMATE_DURATION, defaults.durationMinutes),
            defrost = prefs.getBoolean(KEY_CLIMATE_DEFROST, defaults.defrost),
            rearHeat = prefs.getBoolean(KEY_CLIMATE_REAR_HEAT, defaults.rearHeat),
            steeringWheel = prefs.getBoolean(KEY_CLIMATE_WHEEL, defaults.steeringWheel),
            driverSeat = SeatHeat.fromLevel(prefs.getInt(KEY_CLIMATE_DRIVER, 0)),
            passengerSeat = SeatHeat.fromLevel(prefs.getInt(KEY_CLIMATE_PASSENGER, 0)),
            rearSeats = SeatHeat.fromLevel(prefs.getInt(KEY_CLIMATE_REAR_SEATS, 0)),
        ).normalized()
    }

    /**
     * Saved on every change rather than behind Settings' Save button, like the
     * auto-lock radius: each control is one tap, and losing seven of them to a
     * Back press would be worse than there being no undo.
     */
    fun saveClimate(context: Context, settings: ClimateSettings) {
        val s = settings.normalized()
        context.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE)
            .edit()
            // Half degrees are exact in a float, so nothing is lost here.
            .putFloat(KEY_CLIMATE_TEMP, s.temperature.toFloat())
            .putInt(KEY_CLIMATE_DURATION, s.durationMinutes)
            .putBoolean(KEY_CLIMATE_DEFROST, s.defrost)
            .putBoolean(KEY_CLIMATE_REAR_HEAT, s.rearHeat)
            .putBoolean(KEY_CLIMATE_WHEEL, s.steeringWheel)
            .putInt(KEY_CLIMATE_DRIVER, s.driverSeat.level)
            .putInt(KEY_CLIMATE_PASSENGER, s.passengerSeat.level)
            .putInt(KEY_CLIMATE_REAR_SEATS, s.rearSeats.level)
            .remove(KEY_LEGACY_PRESET)
            .apply()
    }

    /**
     * Whether the geofence is running, and what it may do when it fires.
     *
     * Off by default and deliberately not opt-out: it needs background location
     * and, at ARMED, it sends lock commands to a car on its own. Neither is
     * something to switch on for somebody.
     */
    fun geofenceMode(context: Context): GeofenceMode {
        val stored = context.applicationContext
            .getSharedPreferences(FILE, Context.MODE_PRIVATE)
            .getString(KEY_GEOFENCE_MODE, null)
        return GeofenceMode.entries.firstOrNull { it.name == stored } ?: GeofenceMode.OFF
    }

    fun saveGeofenceMode(context: Context, mode: GeofenceMode) {
        context.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE)
            .edit().putString(KEY_GEOFENCE_MODE, mode.name).apply()
    }

    /** How far from the car counts as having left it. */
    fun geofenceRadius(context: Context): Int =
        context.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE)
            .getInt(KEY_GEOFENCE_RADIUS, Geofence.DEFAULT_RADIUS_METRES)
            .coerceIn(MIN_RADIUS_METRES, MAX_RADIUS_METRES)

    fun saveGeofenceRadius(context: Context, metres: Int) {
        context.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE)
            .edit()
            .putInt(KEY_GEOFENCE_RADIUS, metres.coerceIn(MIN_RADIUS_METRES, MAX_RADIUS_METRES))
            .apply()
    }

    /**
     * Bounds on the ring.
     *
     * Below 75m a GPS fix good enough to pass the accuracy check can still
     * wander out of it while you sit in the car. Above 500m you have driven
     * somewhere, and a lock command is chasing a car that has moved.
     */
    const val MIN_RADIUS_METRES = 75
    const val MAX_RADIUS_METRES = 500

    /** Presentation, not connection, so it is read on its own rather than through KiaConfig. */
    fun widgetBackground(context: Context): String =
        context.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE)
            .getString(KEY_WIDGET_BACKGROUND, null)
            ?.takeIf { it in BACKGROUNDS }
            ?: BACKGROUND_GLASS

    fun save(
        context: Context,
        baseUrl: String,
        secret: String,
        widgetBackground: String,
    ) {
        context.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY_BASE_URL, baseUrl.trim().trimEnd('/'))
            .putString(KEY_SECRET, secret.trim())
            .putString(KEY_WIDGET_BACKGROUND, widgetBackground)
            .apply()
    }

    /** True once the user has saved anything, used to decide whether to prompt. */
    fun isConfigured(context: Context): Boolean =
        load(context).isUsable
}
