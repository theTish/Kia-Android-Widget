package ca.thetish.kia.app

import android.content.Context
import android.os.SystemClock
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.booleanPreferencesKey
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.glance.GlanceId
import androidx.glance.GlanceModifier
import androidx.glance.action.Action
import androidx.glance.action.ActionParameters
import androidx.glance.action.clickable
import androidx.glance.appwidget.GlanceAppWidget
import androidx.glance.appwidget.GlanceAppWidgetReceiver
import androidx.glance.appwidget.action.ActionCallback
import androidx.glance.appwidget.action.actionRunCallback
import androidx.glance.appwidget.cornerRadius
import androidx.glance.appwidget.provideContent
import androidx.glance.appwidget.state.updateAppWidgetState
import androidx.glance.background
import androidx.glance.currentState
import androidx.glance.layout.Alignment
import androidx.glance.layout.Column
import androidx.glance.layout.Row
import androidx.glance.layout.Spacer
import androidx.glance.layout.fillMaxSize
import androidx.glance.layout.fillMaxWidth
import androidx.glance.layout.height
import androidx.glance.layout.padding
import androidx.glance.layout.width
import androidx.glance.text.FontWeight
import androidx.glance.text.Text
import androidx.glance.text.TextStyle
import androidx.glance.unit.ColorProvider

/** Matching the watch tile, so the two surfaces read as one product. */
private object Palette {
    val background = Color(0xFF101418)
    val lock = Color(0xFF2E7D32)
    val lockDim = Color(0xFF1F2A2F)
    val unlock = Color(0xFF37474F)
    val unlockDim = Color(0xFF1F2A2F)
    val armed = Color(0xFFB4560A)
    val armedText = Color(0xFFFFB74D)
    val climate = Color(0xFF1565C0)
    val climateDim = Color(0xFF10243A)
    val neutral = Color(0xFF263238)
    val text = Color(0xFFFFFFFF)
    val textDim = Color(0xFFB0BEC5)
}

/** Widget state. Survives reboots, which is why the arming window is stored too. */
internal object Keys {
    val message = stringPreferencesKey("message")
    val busy = booleanPreferencesKey("busy")
    val battery = intPreferencesKey("battery")
    val range = intPreferencesKey("range")
    val locked = booleanPreferencesKey("locked")
    val lockedKnown = booleanPreferencesKey("locked_known")
    val charging = booleanPreferencesKey("charging")
    val armedUntil = longPreferencesKey("armed_until")
}

/**
 * Home screen widget for the EV6.
 *
 * Mirrors the watch tile: a status line, Lock and Unlock side by side, Climate
 * below. Unlike the tile it also shows real car state, because a phone widget
 * is glanced at far more often than it is tapped.
 */
class KiaWidget : GlanceAppWidget() {

    override suspend fun provideGlance(context: Context, id: GlanceId) {
        provideContent { Content() }
    }

    @Composable
    private fun Content() {
        val prefs = currentState<Preferences>()

        val message = prefs[Keys.message] ?: "Tap Refresh"
        val busy = prefs[Keys.busy] ?: false
        val battery = prefs[Keys.battery]
        val range = prefs[Keys.range]
        // Two keys, because "unknown" and "unlocked" must not render the same.
        val locked = if (prefs[Keys.lockedKnown] == true) prefs[Keys.locked] else null
        val charging = prefs[Keys.charging] ?: false
        val armed = (prefs[Keys.armedUntil] ?: 0L) > SystemClock.elapsedRealtime()

        Column(
            modifier = GlanceModifier
                .fillMaxSize()
                .background(Palette.background)
                .cornerRadius(16.dp)
                .padding(12.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            StatusLine(battery, range, locked, charging)

            Spacer(GlanceModifier.height(4.dp))

            Text(
                text = if (armed) "Tap Unlock again to confirm" else message,
                style = TextStyle(
                    color = ColorProvider(if (armed) Palette.armedText else Palette.textDim),
                    fontSize = 12.sp,
                ),
            )

            Spacer(GlanceModifier.height(8.dp))

            Row(modifier = GlanceModifier.fillMaxWidth()) {
                Pill(
                    label = "Lock",
                    color = if (busy) Palette.lockDim else Palette.lock,
                    onClick = actionRunCallback<LockAction>(),
                    modifier = GlanceModifier.defaultWeight(),
                )
                Spacer(GlanceModifier.width(8.dp))
                Pill(
                    label = if (armed) "Confirm" else "Unlock",
                    color = when {
                        armed -> Palette.armed
                        busy -> Palette.unlockDim
                        else -> Palette.unlock
                    },
                    onClick = actionRunCallback<UnlockAction>(),
                    modifier = GlanceModifier.defaultWeight(),
                )
            }

            Spacer(GlanceModifier.height(8.dp))

            Row(modifier = GlanceModifier.fillMaxWidth()) {
                Pill(
                    label = "Climate",
                    color = if (busy) Palette.climateDim else Palette.climate,
                    onClick = actionRunCallback<ClimateAction>(),
                    modifier = GlanceModifier.defaultWeight(),
                )
                Spacer(GlanceModifier.width(8.dp))
                Pill(
                    label = "Refresh",
                    color = Palette.neutral,
                    onClick = actionRunCallback<RefreshAction>(),
                    modifier = GlanceModifier.defaultWeight(),
                )
            }
        }
    }

    @Composable
    private fun StatusLine(battery: Int?, range: Int?, locked: Boolean?, charging: Boolean) {
        val parts = buildList {
            if (battery != null) add(if (charging) "$battery% charging" else "$battery%")
            if (range != null) add("$range km")
            when (locked) {
                true -> add("Locked")
                false -> add("UNLOCKED")
                null -> {}
            }
        }

        Text(
            text = if (parts.isEmpty()) "EV6" else parts.joinToString("  ·  "),
            style = TextStyle(
                // An unlocked car is the one state worth colouring differently.
                color = ColorProvider(if (locked == false) Palette.armedText else Palette.text),
                fontSize = 16.sp,
                fontWeight = FontWeight.Medium,
            ),
        )
    }

    @Composable
    private fun Pill(label: String, color: Color, onClick: Action, modifier: GlanceModifier) {
        Column(
            modifier = modifier
                .height(48.dp)
                .background(color)
                .cornerRadius(24.dp)
                .clickable(onClick),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = label,
                style = TextStyle(
                    color = ColorProvider(Palette.text),
                    fontSize = 14.sp,
                    fontWeight = FontWeight.Medium,
                ),
            )
        }
    }
}

class KiaWidgetReceiver : GlanceAppWidgetReceiver() {
    override val glanceAppWidget: GlanceAppWidget = KiaWidget()
}

// ── Actions ──────────────────────────────────────────────────────────────────

/**
 * Unlock is two taps. The first arms it, the second sends it. Leaving a car
 * unlocked by accident is worse than an extra tap, and the same guard is in the
 * watch tile and the phone app.
 */
private const val ARM_WINDOW_MS = 10_000L

/**
 * Marks the widget busy and hands the call to KiaWorker.
 *
 * The work is deliberately not done here: see the note on KiaWorker about
 * BroadcastReceiver time limits.
 */
private suspend fun dispatch(context: Context, id: GlanceId, label: String, action: String) {
    updateAppWidgetState(context, id) { prefs ->
        prefs[Keys.busy] = true
        prefs[Keys.message] = "$label…"
        prefs[Keys.armedUntil] = 0L
    }
    KiaWidget().update(context, id)

    KiaWorker.enqueue(context, action)
}

class LockAction : ActionCallback {
    override suspend fun onAction(context: Context, glanceId: GlanceId, parameters: ActionParameters) =
        dispatch(context, glanceId, "Locking", KiaWorker.ACTION_LOCK)
}

class ClimateAction : ActionCallback {
    override suspend fun onAction(context: Context, glanceId: GlanceId, parameters: ActionParameters) =
        dispatch(context, glanceId, "Starting climate", KiaWorker.ACTION_CLIMATE)
}

class RefreshAction : ActionCallback {
    override suspend fun onAction(context: Context, glanceId: GlanceId, parameters: ActionParameters) =
        dispatch(context, glanceId, "Refreshing", KiaWorker.ACTION_STATUS)
}

class UnlockAction : ActionCallback {
    override suspend fun onAction(
        context: Context,
        glanceId: GlanceId,
        parameters: ActionParameters,
    ) {
        val now = SystemClock.elapsedRealtime()
        var armed = false

        updateAppWidgetState(context, glanceId) { prefs ->
            val armedUntil = prefs[Keys.armedUntil] ?: 0L
            if (now < armedUntil) {
                // Second tap inside the window: disarm and send it.
                prefs[Keys.armedUntil] = 0L
            } else {
                prefs[Keys.armedUntil] = now + ARM_WINDOW_MS
                armed = true
            }
        }

        if (armed) {
            KiaWidget().update(context, glanceId)
        } else {
            dispatch(context, glanceId, "Unlocking", KiaWorker.ACTION_UNLOCK)
        }
    }
}
