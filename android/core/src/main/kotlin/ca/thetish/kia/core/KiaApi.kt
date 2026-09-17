package ca.thetish.kia.core

import org.json.JSONObject
import java.io.BufferedReader
import java.net.HttpURLConnection
import java.net.URL

/** Outcome of one command, already reduced to something short enough for a watch face. */
data class ApiResult(val ok: Boolean, val message: String)

/**
 * The slice of /status worth putting on a widget.
 *
 * Every field is nullable because the car reports what it feels like reporting:
 * a value missing from the response is normal, not an error.
 */
data class VehicleStatus(
    val batteryPercent: Int?,
    val isCharging: Boolean,
    val pluggedIn: Boolean,
    val plugType: String?,
    val isLocked: Boolean?,
    val range: Int?,
    val rangeUnit: String?,
    val chargingEta: String?,
    val anyDoorOpen: Boolean?,
    val anyWindowOpen: Boolean?,
    val lastUpdated: String?,
)

/** A status read: the parsed state, or why it could not be read. */
data class StatusResult(val ok: Boolean, val message: String, val status: VehicleStatus?)

/**
 * Talks to the Flask API on Vercel.
 *
 * Deliberately uses HttpURLConnection rather than pulling in OkHttp: the whole
 * app makes four kinds of request and a smaller APK sideloads faster.
 */
object KiaApi {

    // The car can take a while to answer a command, so this is generous.
    private const val TIMEOUT_MS = 45_000

    fun lock(): ApiResult = command("/lock_car", null)

    fun unlock(): ApiResult = command("/unlock_car", null)

    fun startClimate(preset: String): ApiResult =
        command("/start_climate", """{"preset":"$preset"}""")

    /** Reads /status and parses the bits the widget shows. */
    fun status(): StatusResult {
        val (code, text, error) = request("/status", null)

        if (error != null) return StatusResult(false, error, null)
        if (code !in 200..299) {
            return StatusResult(false, field(text, "error") ?: "HTTP $code", null)
        }

        return try {
            val json = JSONObject(text)
            val range = json.optJSONObject("range")
            val doors = json.optJSONObject("doors")
            val windows = json.optJSONObject("windows")

            StatusResult(
                ok = true,
                message = "Updated",
                status = VehicleStatus(
                    batteryPercent = json.intOrNull("battery_percentage"),
                    isCharging = json.optBoolean("is_charging", false),
                    pluggedIn = json.optBoolean("plugged_in", false),
                    plugType = json.stringOrNull("plug_type"),
                    isLocked = json.boolOrNull("is_locked"),
                    range = range?.intOrNull("ev"),
                    rangeUnit = range?.stringOrNull("unit"),
                    chargingEta = json.stringOrNull("charging_eta"),
                    anyDoorOpen = doors?.anyTrue(),
                    anyWindowOpen = windows?.anyTrue(),
                    lastUpdated = json.stringOrNull("last_updated_at"),
                ),
            )
        } catch (e: Exception) {
            StatusResult(false, e.message?.takeIf { it.isNotBlank() } ?: "Bad response", null)
        }
    }

    private fun command(path: String, body: String?): ApiResult {
        val (code, text, error) = request(path, body)

        if (error != null) return ApiResult(false, error)

        return if (code in 200..299) {
            ApiResult(true, field(text, "status") ?: "Done")
        } else {
            // The API reports failures as {"error": "..."}; fall back to the code.
            ApiResult(false, field(text, "error") ?: "HTTP $code")
        }
    }

    /** One POST. Returns status code and body, or a human-readable failure. */
    private fun request(path: String, body: String?): Triple<Int, String, String?> {
        if (BuildConfig.KIA_SECRET.isEmpty()) {
            return Triple(0, "", "No key in build")
        }

        var conn: HttpURLConnection? = null
        return try {
            conn = (URL(BuildConfig.KIA_BASE_URL + path).openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                connectTimeout = TIMEOUT_MS
                readTimeout = TIMEOUT_MS
                doOutput = true
                setRequestProperty("Authorization", BuildConfig.KIA_SECRET)
                setRequestProperty("Accept", "application/json")
                setRequestProperty("Content-Type", "application/json")
            }

            conn.outputStream.use { it.write((body ?: "{}").toByteArray(Charsets.UTF_8)) }

            val code = conn.responseCode
            val stream = if (code in 200..299) conn.inputStream else conn.errorStream
            val text = stream?.bufferedReader()?.use(BufferedReader::readText).orEmpty()

            Triple(code, text, null)
        } catch (e: Exception) {
            Triple(0, "", e.message?.takeIf { it.isNotBlank() } ?: "Network error")
        } finally {
            conn?.disconnect()
        }
    }

    /** Pulls one string field out of a flat JSON object, for the command replies. */
    private fun field(json: String, key: String): String? =
        Regex("\"$key\"\\s*:\\s*\"([^\"]*)\"").find(json)?.groupValues?.get(1)

    // JSON null and absent both mean "unknown", so both come back as null here
    // rather than as optInt's 0 or optBoolean's false.
    private fun JSONObject.intOrNull(key: String): Int? =
        if (isNull(key)) null else optInt(key)

    private fun JSONObject.boolOrNull(key: String): Boolean? =
        if (isNull(key)) null else optBoolean(key)

    private fun JSONObject.stringOrNull(key: String): String? =
        if (isNull(key)) null else optString(key).takeIf { it.isNotBlank() }

    /** True if any member is true, null if every member is unknown. */
    private fun JSONObject.anyTrue(): Boolean? {
        var sawValue = false
        for (key in keys()) {
            if (isNull(key)) continue
            sawValue = true
            if (optBoolean(key)) return true
        }
        return if (sawValue) false else null
    }
}
