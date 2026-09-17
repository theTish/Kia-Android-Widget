package ca.thetish.kia.core

import org.json.JSONObject
import java.io.BufferedReader
import java.net.HttpURLConnection
import java.net.URL

/** Outcome of one command, already reduced to something short enough for a watch face. */
data class ApiResult(val ok: Boolean, val message: String)

/**
 * The slice of /status the clients actually render.
 *
 * Deliberately narrow: /status returns a great deal more (windows, warnings,
 * service intervals, climate readback), and this grows when something needs it
 * rather than carrying fields nothing reads.
 *
 * Every field is nullable because the car reports what it feels like reporting:
 * a value missing from the response is normal, not an error.
 */
data class VehicleStatus(
    val batteryPercent: Int?,
    val isCharging: Boolean,
    val isLocked: Boolean?,
    val range: Int?,
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

    private val Int.isOk get() = this in 200..299

    fun lock(cfg: KiaConfig): ApiResult = command(cfg, "/lock_car", null)

    fun unlock(cfg: KiaConfig): ApiResult = command(cfg, "/unlock_car", null)

    fun startClimate(cfg: KiaConfig): ApiResult =
        command(cfg, "/start_climate", JSONObject().put("preset", cfg.climatePreset).toString())

    /** Reads /status and parses the bits the clients show. */
    fun status(cfg: KiaConfig): StatusResult {
        val (code, text, error) = request(cfg, "/status", null)

        if (error != null) return StatusResult(false, error, null)
        if (!code.isOk) return StatusResult(false, field(text, "error") ?: "HTTP $code", null)

        return try {
            val json = JSONObject(text)
            StatusResult(
                ok = true,
                message = "Updated",
                status = VehicleStatus(
                    batteryPercent = json.intOrNull("battery_percentage"),
                    isCharging = json.optBoolean("is_charging", false),
                    isLocked = json.boolOrNull("is_locked"),
                    range = json.optJSONObject("range")?.intOrNull("ev"),
                ),
            )
        } catch (e: Exception) {
            StatusResult(false, e.message?.takeIf { it.isNotBlank() } ?: "Bad response", null)
        }
    }

    private fun command(cfg: KiaConfig, path: String, body: String?): ApiResult {
        val (code, text, error) = request(cfg, path, body)

        if (error != null) return ApiResult(false, error)

        return if (code.isOk) {
            ApiResult(true, field(text, "status") ?: "Done")
        } else {
            // The API reports failures as {"error": "..."}; fall back to the code.
            ApiResult(false, field(text, "error") ?: "HTTP $code")
        }
    }

    /** One POST. Returns status code and body, or a human-readable failure. */
    private fun request(cfg: KiaConfig, path: String, body: String?): Triple<Int, String, String?> {
        if (!cfg.isUsable) {
            return Triple(0, "", "No API key set")
        }

        return try {
            val conn = (URL(cfg.baseUrl + path).openConnection() as HttpURLConnection)
                .apply {
                    requestMethod = "POST"
                    connectTimeout = TIMEOUT_MS
                    readTimeout = TIMEOUT_MS
                    doOutput = true
                    setRequestProperty("Authorization", cfg.secret)
                    setRequestProperty("Accept", "application/json")
                    setRequestProperty("Content-Type", "application/json")
                }

            conn.outputStream.use { it.write((body ?: "{}").toByteArray(Charsets.UTF_8)) }

            val code = conn.responseCode
            val stream = if (code.isOk) conn.inputStream else conn.errorStream
            val text = stream?.bufferedReader()?.use(BufferedReader::readText).orEmpty()

            // No disconnect(): closing the streams above returns the socket to the
            // keep-alive pool. A command is nearly always followed by a /status to
            // the same host, and disconnecting makes that pay for a fresh TLS
            // handshake.
            Triple(code, text, null)
        } catch (e: Exception) {
            Triple(0, "", e.message?.takeIf { it.isNotBlank() } ?: "Network error")
        }
    }

    /** Pulls one string field out of a reply, for the command messages. */
    private fun field(json: String, key: String): String? =
        runCatching { JSONObject(json).stringOrNull(key) }.getOrNull()

    // JSON null and absent both mean "unknown", so both come back as null here
    // rather than as optInt's 0 or optBoolean's false.
    private fun JSONObject.intOrNull(key: String): Int? =
        if (isNull(key)) null else optInt(key)

    private fun JSONObject.boolOrNull(key: String): Boolean? =
        if (isNull(key)) null else optBoolean(key)

    private fun JSONObject.stringOrNull(key: String): String? =
        if (isNull(key)) null else optString(key).takeIf { it.isNotBlank() }
}
