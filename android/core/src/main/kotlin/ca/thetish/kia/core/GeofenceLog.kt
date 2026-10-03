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

    private const val KEY_POLLED_FOR = "live_polled_for"
    private const val KEY_POLLED_AT = "live_polled_at"
    private const val KEY_CHECKED_AT = "checked_at"
    private const val KEY_CHASING_FOR = "chasing_for"
    private const val KEY_CHASES = "chases"
    private const val KEY_ANCHOR_LAT = "anchor_lat"
    private const val KEY_ANCHOR_LON = "anchor_lon"
    private const val KEY_ANCHOR_ACCURACY = "anchor_accuracy"
    private const val KEY_ANCHOR_AT = "anchor_at"

    /** Long enough that crossing a ring repeatedly cannot wake the car repeatedly. */
    private const val MIN_LIVE_POLL_GAP_MS = 20 * 60 * 1000L

    private const val FILE = "kia_geofence_log"
    private const val KEY = "entries"

    /**
     * Records a decision, newest first.
     *
     * Holds included. They are the lines that matter most: dropping them left
     * getting out of a car that was already locked - the ordinary case, and the
     * correct answer - looking exactly like the
     * feature never having run at all.
     */
    /**
     * Whether a live poll is worth making now.
     *
     * One per parking, because the question it answers - is this car, parked
     * here, open - has one answer per parking, and a gap between polls so a
     * ring being crossed repeatedly cannot turn into a modem wake every few
     * minutes. Anything refused here simply holds, which is this feature's
     * default answer to everything.
     */
    fun mayPollLive(context: Context, anchorAt: Long, now: Long): Boolean {
        val prefs = context.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE)
        if (prefs.getLong(KEY_POLLED_FOR, 0L) == anchorAt) return false
        return now - prefs.getLong(KEY_POLLED_AT, 0L) >= MIN_LIVE_POLL_GAP_MS
    }

    fun recordLivePoll(context: Context, anchorAt: Long, now: Long) {
        context.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE)
            .edit()
            .putLong(KEY_POLLED_FOR, anchorAt)
            .putLong(KEY_POLLED_AT, now)
            .apply()
    }

    /**
     * Where the car was when its Bluetooth last dropped, or null if this phone
     * has not seen a disconnect since it was set up.
     *
     * Kept here rather than in settings because it is evidence, not a
     * preference: it belongs with the state the evaluator reads back.
     */
    fun anchor(context: Context): Anchor? {
        val prefs = context.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE)
        val at = prefs.getLong(KEY_ANCHOR_AT, 0L)
        if (at == 0L) return null
        return Anchor(
            latitude = Double.fromBits(prefs.getLong(KEY_ANCHOR_LAT, 0L)),
            longitude = Double.fromBits(prefs.getLong(KEY_ANCHOR_LON, 0L)),
            accuracyMetres = prefs.getFloat(KEY_ANCHOR_ACCURACY, 0f),
            atMillis = at,
        )
    }

    fun saveAnchor(context: Context, anchor: Anchor) {
        context.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE)
            .edit()
            // Stored as raw bits: SharedPreferences has no putDouble, and a
            // float would round a latitude to about a metre and a half.
            .putLong(KEY_ANCHOR_LAT, anchor.latitude.toRawBits())
            .putLong(KEY_ANCHOR_LON, anchor.longitude.toRawBits())
            .putFloat(KEY_ANCHOR_ACCURACY, anchor.accuracyMetres)
            .putLong(KEY_ANCHOR_AT, anchor.atMillis)
            .apply()
    }

    fun clearAnchor(context: Context) {
        context.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE)
            .edit()
            .remove(KEY_ANCHOR_LAT)
            .remove(KEY_ANCHOR_LON)
            .remove(KEY_ANCHOR_ACCURACY)
            .remove(KEY_ANCHOR_AT)
            .apply()
    }

    /**
     * How many close-together checks have already been spent on this parking.
     *
     * Counted per car position report, so a new parking starts again, and
     * capped by the caller: the point is to watch an unlocked car for the few
     * minutes in which somebody walks away from it, not to poll all evening.
     */
    fun chases(context: Context, anchorAt: Long): Int {
        val prefs = context.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE)
        if (prefs.getLong(KEY_CHASING_FOR, 0L) != anchorAt) return 0
        return prefs.getInt(KEY_CHASES, 0)
    }

    fun recordChase(context: Context, anchorAt: Long, count: Int) {
        context.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE)
            .edit()
            .putLong(KEY_CHASING_FOR, anchorAt)
            .putInt(KEY_CHASES, count)
            .apply()
    }

    /** When the evaluator last ran at all, whatever it decided. */
    fun checkedAt(context: Context): Long =
        context.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE)
            .getLong(KEY_CHECKED_AT, 0L)

    fun recordCheck(context: Context, now: Long) {
        context.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE)
            .edit().putLong(KEY_CHECKED_AT, now).apply()
    }

    fun append(context: Context, entry: GeofenceEntry) {
        val prefs = context.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE)
        val entries = read(context).toMutableList()

        // The same answer twice running is not news. Now that the evaluator
        // runs on every poll and not only on an exit, without this the log
        // would be a screen of "inside the ring" and the one line worth
        // reading would be off the bottom of it.
        entries.firstOrNull()?.let {
            if (it.outcome == entry.outcome && it.reason == entry.reason) return
        }

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
            awaySince = prefs.getLong("away_since", 0L),
            actedOnAnchorAt = prefs.getLong("acted_on", 0L),
        )
    }

    fun saveState(context: Context, state: GeofenceState) {
        context.applicationContext.getSharedPreferences(FILE, Context.MODE_PRIVATE)
            .edit()
            .putLong("away_since", state.awaySince)
            .putLong("acted_on", state.actedOnAnchorAt)
            .apply()
    }
}
