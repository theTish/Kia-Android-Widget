package ca.thetish.kia.core

import org.json.JSONObject
import java.io.BufferedReader
import java.net.HttpURLConnection
import java.net.URL

/** Outcome of one command, already reduced to something short enough for a watch face. */
data class ApiResult(val ok: Boolean, val message: String)

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

    /**
     * Sends the chosen settings field by field rather than a preset name, so
     * the car gets exactly what was picked and the server has nothing to
     * interpret.
     */
    fun startClimate(cfg: KiaConfig): ApiResult =
        command(cfg, "/start_climate", cfg.climate.toJson())

    /**
     * Reads /status.
     *
     * Kia's cached view of the car sometimes answers with no EV data at all -
     * no battery, no range - while still reporting the 12V. When that happens
     * this retries once asking the API to poll the car directly, because a
     * status screen with no battery on it is useless.
     *
     * Only on the empty case: a forced poll wakes the car's modem, so it is not
     * something to do on every refresh.
     */
    fun status(cfg: KiaConfig): StatusResult {
        val first = statusOnce(cfg, force = false)
        if (first.ok && first.status?.batteryPercent == null) {
            val forced = statusOnce(cfg, force = true)
            if (forced.ok) return forced
        }
        return first
    }

    /**
     * Reads the car itself rather than Kia's cache.
     *
     * Wakes the modem, so it has one caller: the geofence, when it is about to
     * decide whether a car standing somewhere you have walked away from is
     * open, and the cached answer is too old to be that evidence.
     */
    fun statusLive(cfg: KiaConfig): StatusResult = statusOnce(cfg, force = true)

    private fun statusOnce(cfg: KiaConfig, force: Boolean): StatusResult {
        val body = if (force) JSONObject().put("force", true).toString() else null
        val (code, text, error) = request(cfg, "/status", body)

        if (error != null) return StatusResult(false, error, null)
        if (!code.isOk) return StatusResult(false, field(text, "error") ?: "HTTP $code", null)

        return try {
            StatusResult(ok = true, message = "Updated", status = VehicleStatus.parse(JSONObject(text)))
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

    private fun JSONObject.stringOrNull(key: String): String? =
        if (isNull(key)) null else optString(key).takeIf { it.isNotBlank() }
}
