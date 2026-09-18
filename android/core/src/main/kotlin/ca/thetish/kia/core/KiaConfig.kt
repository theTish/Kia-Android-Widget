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
    val climatePreset: String,
) {
    val isUsable: Boolean get() = secret.isNotBlank() && baseUrl.isNotBlank()

    companion object {
        /** Whatever local.properties supplied at build time. */
        fun fromBuildConfig() = KiaConfig(
            baseUrl = BuildConfig.KIA_BASE_URL.trimEnd('/'),
            secret = BuildConfig.KIA_SECRET,
            climatePreset = BuildConfig.KIA_CLIMATE_PRESET,
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
    private const val KEY_PRESET = "climate_preset"
    private const val KEY_WIDGET_BACKGROUND = "widget_background"

    /** Offered in the UI so switching hosts does not mean typing a URL. */
    val KNOWN_HOSTS = listOf(
        "https://kia.tishman.ca",
        "https://kia-android-widget.vercel.app",
    )

    val PRESETS = listOf("winter", "summer", "springfall")

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
            climatePreset = prefs.getString(KEY_PRESET, null)?.trim()
                ?.takeIf { it.isNotEmpty() } ?: defaults.climatePreset,
        )
    }

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
        climatePreset: String,
        widgetBackground: String,
    ) {
        context.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY_BASE_URL, baseUrl.trim().trimEnd('/'))
            .putString(KEY_SECRET, secret.trim())
            .putString(KEY_PRESET, climatePreset.trim())
            .putString(KEY_WIDGET_BACKGROUND, widgetBackground)
            .apply()
    }

    /** True once the user has saved anything, used to decide whether to prompt. */
    fun isConfigured(context: Context): Boolean =
        load(context).isUsable
}
