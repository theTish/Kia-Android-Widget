package ca.thetish.kia.app

import android.app.Activity
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import android.widget.Button
import android.widget.TextView
import ca.thetish.kia.core.ApiResult
import ca.thetish.kia.core.BuildConfig
import ca.thetish.kia.core.KiaApi
import java.util.concurrent.Executors

/**
 * Phone controls for the EV6.
 *
 * Intentionally plain: an Activity, a background executor and three buttons.
 * The widget is what gets used day to day, so this screen exists to give the
 * long tail of car state somewhere to live and to make failures readable.
 */
class MainActivity : Activity() {

    private val io = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())

    private lateinit var status: TextView
    private lateinit var lockButton: Button
    private lateinit var unlockButton: Button
    private lateinit var climateButton: Button

    /**
     * Unlock is two taps. The first arms it, the second sends it. Leaving a car
     * unlocked by accident is worse than an extra tap, and the same guard is in
     * the watch tile.
     */
    private var unlockArmedUntil = 0L

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        status = findViewById(R.id.status)
        lockButton = findViewById(R.id.lock)
        unlockButton = findViewById(R.id.unlock)
        climateButton = findViewById(R.id.climate)

        lockButton.setOnClickListener { send("Locking") { KiaApi.lock() } }

        climateButton.setOnClickListener {
            send("Starting climate") { KiaApi.startClimate(BuildConfig.KIA_CLIMATE_PRESET) }
        }

        unlockButton.setOnClickListener {
            val now = SystemClock.elapsedRealtime()
            if (now < unlockArmedUntil) {
                unlockArmedUntil = 0L
                unlockButton.text = getString(R.string.unlock)
                send("Unlocking") { KiaApi.unlock() }
            } else {
                unlockArmedUntil = now + ARM_WINDOW_MS
                unlockButton.text = getString(R.string.unlock_confirm)
                status.text = getString(R.string.unlock_prompt)
                main.postDelayed({
                    if (SystemClock.elapsedRealtime() >= unlockArmedUntil) {
                        unlockArmedUntil = 0L
                        unlockButton.text = getString(R.string.unlock)
                    }
                }, ARM_WINDOW_MS)
            }
        }

        if (BuildConfig.KIA_SECRET.isEmpty()) {
            status.text = getString(R.string.no_key)
            setButtonsEnabled(false)
        }
    }

    private fun send(label: String, call: () -> ApiResult) {
        setButtonsEnabled(false)
        status.text = getString(R.string.working, label)

        io.execute {
            val result = call()
            main.post {
                status.text = result.message
                setButtonsEnabled(true)
            }
        }
    }

    private fun setButtonsEnabled(enabled: Boolean) {
        lockButton.isEnabled = enabled
        unlockButton.isEnabled = enabled
        climateButton.isEnabled = enabled
    }

    override fun onDestroy() {
        super.onDestroy()
        io.shutdown()
    }

    private companion object {
        const val ARM_WINDOW_MS = 10_000L
    }
}
