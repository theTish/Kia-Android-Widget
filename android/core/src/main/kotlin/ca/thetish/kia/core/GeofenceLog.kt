package ca.thetish.kia.core

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

/** One decision, kept so it can be read back weeks later. */
data class GeofenceEntry(
    val at: Long,
    /** "hold", "waiting", "lock" - the decision's own name, lowercased. */
    val outcome: String,
    val reason: String,
    /** True only when the car was actually told to lock. */
    val acted: Boolean,
) {
    val isLock: Boolean get() = outcome == OUTCOME_LOCK

    companion object {
        const val OUTCOME_HOLD = "hold"
        const val OUTCOME_WAITING = "waiting"
        const val OUTCOME_LOCK = "lock"
    }
}

/**
 * What the geofence decided, and whether it did anything about it.
 *
 * This is the whole point of shadow mode. A geofence that locks your car is
 * only worth switching on once you have looked at a fortnight of what it would
 * have done and found nothing surprising in it - and "nothing surprising"
 * cannot be judged from memory, so every decision gets written down.
 *
 * SharedPreferences holding a JSON array rather than a database: it is a
 * hundred rows read all at once by one screen, and a Room dependency to store
 * them would be the heaviest thing in the app.
 */
object GeofenceLog {

    /** Roughly a month of ordinary use, and a few KB. */
    const val MAX_ENTRIES = 120

    private const val FILE = "kia_geofence_log"
    private const val KEY = "entries"

    /**
     * Records a decision, newest first.
     *
     * Holds included. This only runs when Play Services reports you leaving the
     * car, so there are a few a day rather than one a minute, and they are the
     * lines that matter most: dropping them left an exit from a locked car -
     * the ordinary case, and the correct answer - looking exactly like the
     * feature never having run at all.
     */
    fun append(context: Context, entry: GeofenceEntry) {
        val prefs = context.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE)
        val entries = read(context).toMutableList()
        entries.add(0, entry)
        while (entries.size > MAX_ENTRIES) entries.removeAt(entries.lastIndex)

        val array = JSONArray()
        for (e in entries) {
            array.put(
                JSONObject()
                    .put("at", e.at)
                    .put("outcome", e.outcome)
                    .put("reason", e.reason)
                    .put("acted", e.acted)
            )
        }
        prefs.edit().putString(KEY, array.toString()).apply()
    }

    fun read(context: Context): List<GeofenceEntry> {
        val raw = context.applicationContext
            .getSharedPreferences(FILE, Context.MODE_PRIVATE)
            .getString(KEY, null) ?: return emptyList()

        return runCatching {
            val array = JSONArray(raw)
            (0 until array.length()).map { i ->
                val o = array.getJSONObject(i)
                GeofenceEntry(
                    at = o.getLong("at"),
                    outcome = o.getString("outcome"),
                    reason = o.getString("reason"),
                    acted = o.optBoolean("acted", false),
                )
            }
        // A log that cannot be parsed is not worth crashing a car app over.
        }.getOrDefault(emptyList())
    }

    fun clear(context: Context) {
        context.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE)
            .edit().remove(KEY).apply()
    }

    /** The evaluator's state, kept beside the log because it has the same lifetime. */
    fun loadState(context: Context): GeofenceState {
        val prefs = context.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE)
        return GeofenceState(
            outsideSince = prefs.getLong("outside_since", 0L),
            actedOnCarReportedAt = prefs.getLong("acted_on", 0L),
        )
    }

    fun saveState(context: Context, state: GeofenceState) {
        context.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE)
            .edit()
            .putLong("outside_since", state.outsideSince)
            .putLong("acted_on", state.actedOnCarReportedAt)
            .apply()
    }
}
