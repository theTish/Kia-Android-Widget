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
import ca.thetish.kia.core.KiaColors
import ca.thetish.kia.core.UnlockGuard

/** Local aliases for the shared tokens in :core, so the layout below stays readable. */
private object Palette {
    val background = Color(KiaColors.BACKGROUND)
    val lock = Color(KiaColors.LOCK)
    val lockDim = Color(KiaColors.LOCK_DIM)
    val unlock = Color(KiaColors.UNLOCK)
    val armed = Color(KiaColors.ARMED)
    val armedText = Color(KiaColors.ARMED_TEXT)
    val climate = Color(KiaColors.CLIMATE)
    val climateDim = Color(KiaColors.CLIMATE_DIM)
    val neutral = Color(KiaColors.NEUTRAL)
    val text = Color(KiaColors.TEXT)
    val textDim = Color(KiaColors.TEXT_DIM)
}

/** Widget state. Survives reboots, which is why the arming window is stored too. */
internal object Keys {
    val message = stringPreferencesKey("message")
    val busy = booleanPreferencesKey("busy")
    val battery = intPreferencesKey("battery")
    val range = intPreferencesKey("range")
    // Absent means "unknown", which must not render as "unlocked".
    val locked = booleanPreferencesKey("locked")
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
        val locked = prefs[Keys.locked]
        val charging = prefs[Keys.charging] ?: false
        val armed = UnlockGuard.shouldFire(SystemClock.elapsedRealtime(), prefs[Keys.armedUntil] ?: 0L)

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
                        busy -> Palette.lockDim
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

    // The arming is cleared above, so a disarm job scheduled by an earlier tap
    // would wake the device ten seconds later only to change nothing.
    KiaWorker.cancelDisarm(context)
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
        var justArmed = false

        updateAppWidgetState(context, glanceId) { prefs ->
            if (UnlockGuard.shouldFire(now, prefs[Keys.armedUntil] ?: 0L)) {
                // Second tap inside the window: disarm and send it.
                prefs[Keys.armedUntil] = 0L
            } else {
                prefs[Keys.armedUntil] = UnlockGuard.armUntil(now)
                justArmed = true
            }
        }

        if (justArmed) {
            KiaWidget().update(context, glanceId)
            // Make the amber "Confirm" lapse on screen when the window lapses.
            KiaWorker.enqueueDisarm(context, UnlockGuard.ARM_WINDOW_MS)
        } else {
            dispatch(context, glanceId, "Unlocking", KiaWorker.ACTION_UNLOCK)
        }
    }
}
