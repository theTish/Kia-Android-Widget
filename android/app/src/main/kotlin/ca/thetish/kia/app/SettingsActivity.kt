package ca.thetish.kia.app

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.view.View
import android.widget.ArrayAdapter
import android.widget.AutoCompleteTextView
import android.widget.EditText
import android.widget.ImageButton
import android.widget.ImageView
import android.widget.TextView
import android.widget.Toast
import androidx.glance.appwidget.updateAll
import ca.thetish.kia.core.GeofenceMode
import ca.thetish.kia.core.KiaApi
import ca.thetish.kia.core.KiaConfig
import ca.thetish.kia.core.KiaSettings
import ca.thetish.kia.core.R as CoreR
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
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
    private lateinit var reveal: ImageButton
    private lateinit var result: TextView
    private lateinit var resultIcon: ImageView

    private lateinit var presets: Segments
    private lateinit var backgrounds: Segments

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_settings)

        baseUrl = findViewById(R.id.base_url)
        secret = findViewById(R.id.secret)
        reveal = findViewById(R.id.reveal)
        result = findViewById(R.id.test_result)
        resultIcon = findViewById(R.id.test_icon)

        baseUrl.setAdapter(
            ArrayAdapter(this, android.R.layout.simple_dropdown_item_1line, KiaSettings.KNOWN_HOSTS)
        )
        baseUrl.setOnClickListener { baseUrl.showDropDown() }

        presets = Segments(
            KiaSettings.PRESETS.zip(
                listOf(R.id.preset_winter, R.id.preset_summer, R.id.preset_springfall)
            )
        )
        backgrounds = Segments(
            KiaSettings.BACKGROUNDS.zip(listOf(R.id.background_glass, R.id.background_solid))
        )

        val current = KiaSettings.load(this)
        baseUrl.setText(current.baseUrl)
        secret.setText(current.secret)
        presets.select(current.climatePreset)
        backgrounds.select(KiaSettings.widgetBackground(this))

        findViewById<View>(R.id.geofence).setOnClickListener {
            startActivity(Intent(this, GeofenceActivity::class.java))
        }

        reveal.setOnClickListener { toggleReveal() }
        findViewById<ImageButton>(R.id.back).setOnClickListener { finish() }
        findViewById<TextView>(R.id.test).setOnClickListener { test() }
        findViewById<TextView>(R.id.save).setOnClickListener { save() }
    }

    /**
     * A segmented control over a row of TextViews.
     *
     * Replaces the Spinner, which needed two custom layouts to stay visible on
     * black and still hid three options behind a tap. Three fixed choices fit
     * on one line, so show all three.
     */
    private inner class Segments(private val options: List<Pair<String, Int>>) {

        private var chosen: String = options.first().first

        init {
            for ((value, id) in options) {
                findViewById<TextView>(id).setOnClickListener { select(value) }
            }
        }

        val value: String get() = chosen

        fun select(value: String) {
            chosen = options.firstOrNull { it.first == value }?.first ?: options.first().first
            for ((option, id) in options) {
                val selected = option == chosen
                findViewById<TextView>(id).apply {
                    setBackgroundResource(
                        if (selected) R.drawable.segment_selected else R.drawable.segment_idle
                    )
                    setTextColor(getColor(if (selected) CoreR.color.text else CoreR.color.text_dim))
                    isSelected = selected
                }
            }
        }
    }

    private fun toggleReveal() {
        val hidden = secret.inputType and InputType.TYPE_TEXT_VARIATION_PASSWORD != 0
        // Reassigning inputType resets the selection, so put the caret back.
        val caret = secret.selectionEnd
        secret.inputType = InputType.TYPE_CLASS_TEXT or
            if (hidden) InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
            else InputType.TYPE_TEXT_VARIATION_PASSWORD
        secret.setSelection(caret.coerceIn(0, secret.text.length))
        reveal.setImageResource(if (hidden) CoreR.drawable.ic_eye_off else CoreR.drawable.ic_eye)
    }

    private fun entered() = KiaConfig(
        baseUrl = baseUrl.text.toString().trim().trimEnd('/'),
        secret = secret.text.toString().trim(),
        climatePreset = presets.value,
    )

    /**
     * Checks the entered values against the API before they are saved, so a
     * typo shows up here rather than as a failed lock in a car park.
     */
    private fun test() {
        val candidate = entered()

        if (!candidate.isUsable) {
            showResult(getString(R.string.test_needs_values), ok = false)
            return
        }

        showResult(getString(R.string.testing), ok = false)
        io.execute {
            // Deliberately /status: it proves the URL, the key and the car all
            // work, and it changes nothing.
            val outcome = KiaApi.status(candidate)
            main.post {
                if (isDestroyed) return@post
                val battery = outcome.status?.batteryPercent
                when {
                    // Never invent a number: the car sometimes answers without
                    // any EV data at all, and "battery 0%" would read as a flat
                    // battery rather than as "not reported".
                    outcome.ok && battery != null ->
                        showResult(getString(R.string.test_ok, battery), ok = true)

                    outcome.ok -> showResult(getString(R.string.test_ok_no_data), ok = true)

                    else -> showResult(
                        getString(R.string.test_failed, outcome.message),
                        ok = false,
                    )
                }
            }
        }
    }

    private fun showResult(text: String, ok: Boolean) {
        result.text = text
        result.setTextColor(getColor(if (ok) CoreR.color.accent else CoreR.color.text_dim))
        resultIcon.visibility = if (ok) View.VISIBLE else View.GONE
    }

    private fun save() {
        val entered = entered()
        KiaSettings.save(
            context = this,
            baseUrl = entered.baseUrl,
            secret = entered.secret,
            climatePreset = entered.climatePreset,
            widgetBackground = backgrounds.value,
        )

        // The widget reads its background at compose time, so a change here is
        // invisible until something redraws it - and nothing otherwise would
        // until the next tap. Hoisted out of the lambda so the coroutine holds
        // the application rather than this Activity.
        val app = applicationContext
        CoroutineScope(Dispatchers.Default).launch { KiaWidget().updateAll(app) }

        Toast.makeText(this, R.string.settings_saved, Toast.LENGTH_SHORT).show()
        finish()
    }

    override fun onResume() {
        super.onResume()
        // Read on the way back rather than at create: the mode is changed on
        // the screen this one launches.
        findViewById<TextView>(R.id.geofence_summary).setText(
            when (KiaSettings.geofenceMode(this)) {
                GeofenceMode.OFF -> R.string.geofence_summary_off
                GeofenceMode.SHADOW -> R.string.geofence_summary_shadow
                GeofenceMode.ARMED -> R.string.geofence_summary_armed
            }
        )
    }

    override fun onDestroy() {
        super.onDestroy()
        io.shutdownNow()
        main.removeCallbacksAndMessages(null)
    }
}
