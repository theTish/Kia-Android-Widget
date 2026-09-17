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

    /** Offered in the UI so switching hosts does not mean typing a URL. */
    val KNOWN_HOSTS = listOf(
        "https://kia.tishman.ca",
        "https://kia-android-widget.vercel.app",
    )

    val PRESETS = listOf("winter", "summer", "springfall")

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

    fun save(context: Context, baseUrl: String, secret: String, climatePreset: String) {
        context.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE)
            .edit()
            .putString(KEY_BASE_URL, baseUrl.trim().trimEnd('/'))
            .putString(KEY_SECRET, secret.trim())
            .putString(KEY_PRESET, climatePreset.trim())
            .apply()
    }

    /** True once the user has saved anything, used to decide whether to prompt. */
    fun isConfigured(context: Context): Boolean =
        load(context).isUsable
}
