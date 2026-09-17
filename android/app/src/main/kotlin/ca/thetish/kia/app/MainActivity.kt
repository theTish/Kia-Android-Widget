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
import ca.thetish.kia.core.UnlockGuard
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

    /** See UnlockGuard: first tap arms, second tap sends. */
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
            if (UnlockGuard.shouldFire(now, unlockArmedUntil)) {
                unlockArmedUntil = 0L
                unlockButton.text = getString(R.string.unlock)
                send("Unlocking") { KiaApi.unlock() }
            } else {
                unlockArmedUntil = UnlockGuard.armUntil(now)
                unlockButton.text = getString(R.string.unlock_confirm)
                status.text = getString(R.string.unlock_prompt)
                main.postDelayed({
                    if (SystemClock.elapsedRealtime() >= unlockArmedUntil) {
                        unlockArmedUntil = 0L
                        unlockButton.text = getString(R.string.unlock)
                    }
                }, UnlockGuard.ARM_WINDOW_MS)
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
                // The call can outlive the Activity by up to the request timeout.
                if (isDestroyed) return@post
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
        // shutdownNow interrupts a request still in flight; plain shutdown would
        // let it hold this Activity and its view tree for the full 45s timeout.
        io.shutdownNow()
        main.removeCallbacksAndMessages(null)
    }

}
