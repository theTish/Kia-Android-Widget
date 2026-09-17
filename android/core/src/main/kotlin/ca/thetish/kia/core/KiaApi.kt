package ca.thetish.kia.core

import java.io.BufferedReader
import java.net.HttpURLConnection
import java.net.URL

/** Outcome of one call, already reduced to something short enough for a watch face. */
data class ApiResult(val ok: Boolean, val message: String)

/**
 * Talks to the Flask API on Vercel.
 *
 * Deliberately uses HttpURLConnection rather than pulling in OkHttp: the whole
 * app makes three kinds of request and a smaller APK sideloads faster.
 */
object KiaApi {

    private const val TIMEOUT_MS = 45_000

    fun lock(): ApiResult = post("/lock_car", null)

    fun unlock(): ApiResult = post("/unlock_car", null)

    fun startClimate(preset: String): ApiResult =
        post("/start_climate", """{"preset":"$preset"}""")

    private fun post(path: String, body: String?): ApiResult {
        if (BuildConfig.KIA_SECRET.isEmpty()) {
            return ApiResult(false, "No key in build")
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

            if (code in 200..299) {
                ApiResult(true, field(text, "status") ?: "Done")
            } else {
                // The API reports failures as {"error": "..."}; fall back to the code.
                ApiResult(false, field(text, "error") ?: "HTTP $code")
            }
        } catch (e: Exception) {
            ApiResult(false, e.message?.takeIf { it.isNotBlank() } ?: "Network error")
        } finally {
            conn?.disconnect()
        }
    }

    /** Pulls one string field out of a flat JSON object, so we skip a JSON dependency. */
    private fun field(json: String, key: String): String? =
        Regex("\"$key\"\\s*:\\s*\"([^\"]*)\"").find(json)?.groupValues?.get(1)
}
