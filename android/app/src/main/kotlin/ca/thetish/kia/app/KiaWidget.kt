package ca.thetish.kia.app

import android.content.Context
import android.graphics.Bitmap
import androidx.core.graphics.createBitmap
import android.graphics.Canvas
import android.graphics.RectF
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
import androidx.glance.LocalSize
import androidx.glance.ColorFilter
import androidx.glance.Image
import androidx.glance.ImageProvider
import androidx.glance.action.Action
import androidx.glance.action.ActionParameters
import androidx.glance.action.clickable
import androidx.glance.appwidget.GlanceAppWidget
import androidx.glance.appwidget.GlanceAppWidgetReceiver
import androidx.glance.appwidget.SizeMode
import androidx.glance.appwidget.action.ActionCallback
import androidx.glance.appwidget.action.actionRunCallback
import androidx.glance.appwidget.provideContent
import androidx.glance.appwidget.state.updateAppWidgetState
import androidx.glance.background
import androidx.glance.currentState
import androidx.glance.layout.Alignment
import androidx.glance.layout.Box
import androidx.glance.layout.Column
import androidx.glance.layout.ContentScale
import androidx.glance.layout.Row
import androidx.glance.layout.RowScope
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
import ca.thetish.kia.core.BatteryBar
import ca.thetish.kia.core.KiaColors
import ca.thetish.kia.core.KiaSettings
import ca.thetish.kia.core.UnlockGuard
import ca.thetish.kia.core.R as CoreR

/**
 * The widget's two skins.
 *
 * Glass is the default and is where the odd colours live: a widget cannot read
 * the wallpaper, so everything secondary is white at a percentage rather than a
 * grey, and that is what lets the same card sit on a dark photo and a light one.
 * Solid drops all of that for opaque values.
 */
private class Skin(glass: Boolean) {
    val background = if (glass) R.drawable.widget_bg_glass else R.drawable.widget_bg_solid
    val button = if (glass) R.drawable.widget_button_glass else R.drawable.widget_button_solid
    val text = Color(KiaColors.TEXT)
    val dim = if (glass) Color(0xCCFFFFFF) else Color(KiaColors.TEXT_DIM)
    val muted = if (glass) Color(0x80FFFFFF) else Color(KiaColors.TEXT_MUTED)
    val track = if (glass) 0x33FFFFFF.toInt() else KiaColors.TRACK.toInt()
    val tick = if (glass) 0xD9FFFFFF.toInt() else KiaColors.TEXT.toInt()
    val accent = Color(KiaColors.ACCENT)
    val armed = Color(KiaColors.ARMED)
    val armedInk = Color(KiaColors.ARMED_INK)
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
    // Distinct from charging: a car plugged in but not drawing is the state
    // worth knowing about, because it is usually a charger that did not start.
    val pluggedIn = booleanPreferencesKey("plugged_in")
    val chargeRemaining = stringPreferencesKey("charge_remaining")
    val chargeLimitAc = intPreferencesKey("charge_limit_ac")
    val armedUntil = longPreferencesKey("armed_until")
}

/**
 * Home screen widget for the EV6.
 *
 * The car, the charge and the four things worth doing without opening anything.
 * Every control is icon-only and neutral, including Lock: on a home screen the
 * widget is competing with app icons, and one accent-filled button would read as
 * the thing to press rather than as one of four equals.
 */
class KiaWidget : GlanceAppWidget() {

    // Exact, so LocalSize reports the size the host actually gave us. Under the
    // default SizeMode it reports the provider's declared minimum, and the car
    // is sized as a share of the width - which would then be a share of a
    // number that has nothing to do with the widget on the screen.
    override val sizeMode = SizeMode.Exact

    override suspend fun provideGlance(context: Context, id: GlanceId) {
        // Read outside the composition: a SharedPreferences hit per recomposition
        // would be pointless, and this cannot change while the widget is drawing.
        val glass = KiaSettings.widgetBackground(context) == KiaSettings.BACKGROUND_GLASS
        provideContent { Content(Skin(glass)) }
    }

    @Composable
    private fun Content(skin: Skin) {
        val prefs = currentState<Preferences>()

        val battery = prefs[Keys.battery]
        val range = prefs[Keys.range]
        val locked = prefs[Keys.locked]
        val charging = prefs[Keys.charging] ?: false
        val pluggedIn = prefs[Keys.pluggedIn] ?: false
        val message = prefs[Keys.message] ?: ""
        val busy = prefs[Keys.busy] ?: false
        val armed = UnlockGuard.shouldFire(
            SystemClock.elapsedRealtime(),
            prefs[Keys.armedUntil] ?: 0L,
        )

        Column(
            modifier = GlanceModifier
                .fillMaxSize()
                .background(ImageProvider(skin.background), ContentScale.FillBounds)
                .padding(14.dp),
        ) {
            // The row takes the slack, so the controls stay on the bottom edge
            // however tall the host has made the widget.
            Row(
                modifier = GlanceModifier.fillMaxWidth().defaultWeight(),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                val carWidth = carWidth(LocalSize.current.width.value)
                Image(
                    provider = ImageProvider(CoreR.drawable.ev6_gt),
                    contentDescription = null,
                    contentScale = ContentScale.Fit,
                    modifier = GlanceModifier
                        .width(carWidth.dp)
                        .height((carWidth * CAR_ASPECT).dp),
                )

                Spacer(GlanceModifier.width(12.dp))

                Column(modifier = GlanceModifier.defaultWeight()) {
                    Headline(skin, battery, charging, pluggedIn)
                    Spacer(GlanceModifier.height(2.dp))
                    Summary(skin, range, locked)
                    StatusLine(
                        skin = skin,
                        prefs = prefs,
                        armed = armed,
                        charging = charging,
                        pluggedIn = pluggedIn,
                        message = message,
                        noData = battery == null && range == null && locked == null,
                        // On a short widget the charge state gives up its line
                        // rather than push the bar off the bottom. An armed
                        // unlock or a command in flight never does: those are
                        // the line telling you what the widget is about to do.
                        essentialOnly = LocalSize.current.height.value < COMPACT_HEIGHT,
                    )
                    Spacer(GlanceModifier.height(5.dp))
                    Image(
                        provider = ImageProvider(
                            batteryBar(battery, prefs[Keys.chargeLimitAc], skin)
                        ),
                        contentDescription = null,
                        contentScale = ContentScale.FillBounds,
                        modifier = GlanceModifier.fillMaxWidth().height(BAR_VIEW_HEIGHT.dp),
                    )
                }
            }

            Spacer(GlanceModifier.height(10.dp))

            Row(modifier = GlanceModifier.fillMaxWidth()) {
                // While a command is in flight every control greys out. The row
                // stays tappable - RemoteViews cannot really disable a click -
                // but it should not look ready when it is not.
                val ink = if (busy) skin.muted else skin.text

                IconButton(skin, CoreR.drawable.ic_lock, actionRunCallback<LockAction>(), tint = ink)
                Spacer(GlanceModifier.width(6.dp))
                IconButton(
                    skin = skin,
                    icon = CoreR.drawable.ic_unlock,
                    onClick = actionRunCallback<UnlockAction>(),
                    // The one place the widget breaks its own no-colour rule:
                    // an armed unlock has to be unmistakable before the second tap.
                    background = if (armed) R.drawable.widget_button_armed else skin.button,
                    tint = if (armed) skin.armedInk else ink,
                )
                Spacer(GlanceModifier.width(6.dp))
                IconButton(skin, CoreR.drawable.ic_climate, actionRunCallback<ClimateAction>(), tint = ink)
                Spacer(GlanceModifier.width(6.dp))
                IconButton(skin, CoreR.drawable.ic_refresh, actionRunCallback<RefreshAction>(), tint = ink)
            }
        }
    }

    /** The percentage, with the charge state as an icon beside it. */
    @Composable
    private fun Headline(skin: Skin, battery: Int?, charging: Boolean, pluggedIn: Boolean) {
        Row(verticalAlignment = Alignment.Bottom) {
            Text(
                text = battery?.toString() ?: "—",
                style = TextStyle(
                    color = ColorProvider(skin.text),
                    fontSize = 28.sp,
                    fontWeight = FontWeight.Bold,
                ),
            )
            if (battery != null) {
                Text(
                    text = "%",
                    style = TextStyle(
                        color = ColorProvider(skin.dim),
                        fontSize = 16.sp,
                        fontWeight = FontWeight.Bold,
                    ),
                )
            }

            val icon = when {
                charging -> CoreR.drawable.ic_bolt
                pluggedIn -> CoreR.drawable.ic_plug
                else -> null
            }
            if (icon != null) {
                Spacer(GlanceModifier.width(6.dp))
                Image(
                    provider = ImageProvider(icon),
                    contentDescription = null,
                    colorFilter = ColorFilter.tint(
                        ColorProvider(if (charging) skin.accent else skin.text)
                    ),
                    modifier = GlanceModifier.width(18.dp).height(18.dp),
                )
            }
        }
    }

    /** Range and lock state, the two things worth a glance from across a room. */
    @Composable
    private fun Summary(skin: Skin, range: Int?, locked: Boolean?) {
        Row {
            if (range != null) {
                Text(
                    text = "$range km",
                    maxLines = 1,
                    style = TextStyle(
                        color = ColorProvider(skin.text),
                        fontSize = 13.sp,
                        fontWeight = FontWeight.Medium,
                    ),
                )
                Text(
                    text = " · ",
                    style = TextStyle(color = ColorProvider(skin.dim), fontSize = 13.sp),
                )
            }
            Text(
                text = when (locked) {
                    true -> "Locked"
                    false -> "Unlocked"
                    null -> "Lock unknown"
                },
                maxLines = 1,
                style = TextStyle(
                    color = ColorProvider(if (locked == false) skin.armed else skin.dim),
                    fontSize = 13.sp,
                    fontWeight = if (locked == false) FontWeight.Bold else FontWeight.Normal,
                ),
            )
        }
    }

    /**
     * The one optional line: whatever is most worth saying right now.
     *
     * An armed unlock outranks everything, then anything an action has to
     * report, then the charge state. When none of those apply the line is
     * omitted entirely rather than left blank, so the card closes up.
     */
    @Composable
    private fun StatusLine(
        skin: Skin,
        prefs: Preferences,
        armed: Boolean,
        charging: Boolean,
        pluggedIn: Boolean,
        message: String,
        noData: Boolean,
        essentialOnly: Boolean,
    ) {
        val (text, color) = when {
            armed -> "Tap Unlock again to confirm" to skin.armed
            message.isNotEmpty() -> message to skin.dim
            essentialOnly -> return
            charging -> {
                val left = prefs[Keys.chargeRemaining]
                (if (left != null) "Charging · $left left" else "Charging") to skin.accent
            }

            pluggedIn -> "Plugged in · not charging" to skin.text
            // A widget that has never been refreshed has nothing else to offer,
            // and four unlabelled icons do not say "start here".
            noData -> "Tap Refresh" to skin.dim
            else -> return
        }

        Spacer(GlanceModifier.height(2.dp))
        Text(
            text = text,
            maxLines = 1,
            style = TextStyle(
                color = ColorProvider(color),
                fontSize = 12.sp,
                fontWeight = FontWeight.Medium,
            ),
        )
    }

    @Composable
    private fun RowScope.IconButton(
        skin: Skin,
        icon: Int,
        onClick: Action,
        background: Int = skin.button,
        tint: Color = skin.text,
    ) {
        Box(
            modifier = GlanceModifier
                .defaultWeight()
                .height(48.dp)
                .background(ImageProvider(background), ContentScale.FillBounds)
                .clickable(onClick),
            contentAlignment = Alignment.Center,
        ) {
            Image(
                provider = ImageProvider(icon),
                contentDescription = null,
                colorFilter = ColorFilter.tint(ColorProvider(tint)),
                modifier = GlanceModifier.width(20.dp).height(20.dp),
            )
        }
    }

    private companion object {
        // 875x429 source, so the height follows from the width.
        const val CAR_ASPECT = 429f / 875f

        /**
         * How much of the card the car may take.
         *
         * A fixed width does not survive resizing: at 150dp on a 257dp-wide
         * widget the right-hand column is left with 63dp, and "412 km · Locked"
         * wraps onto three lines. A share of the width keeps the two in
         * proportion, with a floor so the car stays recognisable and a ceiling
         * so it stops growing once the text has all the room it needs.
         */
        fun carWidth(widthDp: Float): Float = (widthDp * 0.38f).coerceIn(84f, 168f)

        // The bar is rendered at a fixed pixel size and stretched to fit,
        // because Glance has no fractional weights to express "78% of a row".
        /**
         * Below this the card cannot hold every line at once.
         *
         * The provider declares a matching minResizeHeight, so a launcher will
         * not normally hand us less; this is what happens if one does anyway.
         */
        const val COMPACT_HEIGHT = 152f

        const val BAR_BITMAP_WIDTH = 400
        const val BAR_BITMAP_BAR_HEIGHT = 8f
        const val BAR_VIEW_HEIGHT = 8

        fun batteryBar(percent: Int?, limitPercent: Int?, skin: Skin): Bitmap {
            val overhang = BAR_BITMAP_BAR_HEIGHT * BatteryBar.TICK_OVERHANG
            val height = (BAR_BITMAP_BAR_HEIGHT + overhang * 2).toInt()
            val bitmap = createBitmap(BAR_BITMAP_WIDTH, height)

            BatteryBar().draw(
                canvas = Canvas(bitmap),
                bar = RectF(
                    0f,
                    overhang,
                    BAR_BITMAP_WIDTH.toFloat(),
                    overhang + BAR_BITMAP_BAR_HEIGHT,
                ),
                percent = percent,
                limitPercent = limitPercent,
                fillColor = KiaColors.ACCENT.toInt(),
                trackColor = skin.track,
                tickColor = skin.tick,
            )

            return bitmap
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
            // Make the amber state lapse on screen when the window lapses.
            KiaWorker.enqueueDisarm(context, UnlockGuard.ARM_WINDOW_MS)
        } else {
            dispatch(context, glanceId, "Unlocking", KiaWorker.ACTION_UNLOCK)
        }
    }
}
