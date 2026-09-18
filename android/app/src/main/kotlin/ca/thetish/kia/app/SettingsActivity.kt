package ca.thetish.kia.app

import android.app.Activity
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.widget.ArrayAdapter
import android.widget.AutoCompleteTextView
import android.widget.Button
import android.widget.EditText
import android.widget.Spinner
import android.widget.TextView
import android.widget.Toast
import ca.thetish.kia.core.KiaApi
import ca.thetish.kia.core.KiaConfig
import ca.thetish.kia.core.KiaSettings
import java.util.concurrent.Executors

/**
 * Where the API lives and how to authenticate to it.
 *
 * Exists mainly so the base URL is not compiled in. Switching between the
 * self-hosted box and the Vercel standby used to mean a rebuild and a
 * reinstall; now it is a dropdown, which matters precisely when the box is
 * down and you are standing next to the car.
 *
 * It also keeps the API key out of the APK for anyone who sets it here rather
 * than in local.properties - a compiled-in key can be read straight out of the
 * installed package.
 */
class SettingsActivity : Activity() {

    private val io = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())

    private lateinit var baseUrl: AutoCompleteTextView
    private lateinit var secret: EditText
    private lateinit var preset: Spinner
    private lateinit var result: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_settings)

        baseUrl = findViewById(R.id.base_url)
        secret = findViewById(R.id.secret)
        preset = findViewById(R.id.preset)
        result = findViewById(R.id.test_result)

        // The known hosts are suggestions, not a closed list - typing a new one
        // is the whole point if this ever moves again.
        baseUrl.setAdapter(
            ArrayAdapter(this, android.R.layout.simple_dropdown_item_1line, KiaSettings.KNOWN_HOSTS)
        )
        baseUrl.setOnClickListener { baseUrl.showDropDown() }

        // Own layouts for both states: the platform ones take their colour from
        // the theme and rendered invisible on this black background.
        preset.adapter = ArrayAdapter(this, R.layout.spinner_item, KiaSettings.PRESETS).apply {
            setDropDownViewResource(R.layout.spinner_item)
        }

        val current = KiaSettings.load(this)
        baseUrl.setText(current.baseUrl)
        secret.setText(current.secret)
        preset.setSelection(
            KiaSettings.PRESETS.indexOf(current.climatePreset).takeIf { it >= 0 } ?: 0
        )

        findViewById<Button>(R.id.test).setOnClickListener { test() }

        findViewById<Button>(R.id.save).setOnClickListener {
            KiaSettings.save(this, baseUrl.text.toString(), secret.text.toString(), selectedPreset())
            Toast.makeText(this, R.string.settings_saved, Toast.LENGTH_SHORT).show()
            finish()
        }
    }

    private fun selectedPreset(): String =
        preset.selectedItem?.toString() ?: KiaSettings.PRESETS.first()

    /**
     * Checks the entered values against the API before they are saved, so a
     * typo shows up here rather than as a failed lock in a car park.
     */
    private fun test() {
        val candidate = KiaConfig(
            baseUrl = baseUrl.text.toString().trim().trimEnd('/'),
            secret = secret.text.toString().trim(),
            climatePreset = selectedPreset(),
        )

        if (!candidate.isUsable) {
            result.text = getString(R.string.test_needs_values)
            return
        }

        result.text = getString(R.string.testing)
        io.execute {
            // Deliberately /status: it proves the URL, the key and the car all
            // work, and it changes nothing.
            val outcome = KiaApi.status(candidate)
            main.post {
                if (isDestroyed) return@post
                val status = outcome.status
                val battery = status?.batteryPercent
                result.text = when {
                    // Never invent a number: the car sometimes answers without
                    // any EV data at all, and "battery 0%" would read as a flat
                    // battery rather than as "not reported".
                    outcome.ok && battery != null -> getString(R.string.test_ok, battery)
                    outcome.ok -> getString(R.string.test_ok_no_data)
                    else -> getString(R.string.test_failed, outcome.message)
                }
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        io.shutdownNow()
        main.removeCallbacksAndMessages(null)
    }
}
