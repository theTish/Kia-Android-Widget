package ca.thetish.kiatile

import android.os.SystemClock
import androidx.concurrent.futures.ResolvableFuture
import ca.thetish.kia.core.ApiResult
import ca.thetish.kia.core.KiaApi
import ca.thetish.kia.core.KiaColors
import ca.thetish.kia.core.KiaConfig
import ca.thetish.kia.core.UnlockGuard
import ca.thetish.kia.core.VehicleStatus
import ca.thetish.kia.core.R as CoreR
import androidx.wear.protolayout.ActionBuilders
import androidx.wear.protolayout.ColorBuilders.argb
import androidx.wear.protolayout.DimensionBuilders.degrees
import androidx.wear.protolayout.DimensionBuilders.dp
import androidx.wear.protolayout.DimensionBuilders.expand
import androidx.wear.protolayout.DimensionBuilders.sp
import androidx.wear.protolayout.LayoutElementBuilders
import androidx.wear.protolayout.ModifiersBuilders
import androidx.wear.protolayout.ResourceBuilders
import androidx.wear.protolayout.TimelineBuilders
import androidx.wear.tiles.RequestBuilders
import androidx.wear.tiles.TileBuilders
import androidx.wear.tiles.TileService
import com.google.common.util.concurrent.ListenableFuture
import java.util.concurrent.Executors

/**
 * Mutable bits shared between a tap and the background call it starts.
 *
 * The action state is deliberately not persisted: a cold start should come up
 * neutral rather than resurrecting a half finished action or, worse, a stale
 * unlock arming. The car's own state is cached in the same place for the same
 * reason - it is a read, not a promise, and a tile that comes up claiming a
 * charge level from yesterday is worse than one that comes up blank.
 */
private object TileState {
    /**
     * What the last tap is doing or did, shown once and then dropped.
     *
     * Consumed by the render rather than cleared on a timer, because nothing
     * redraws a tile on a schedule: left in place it would still be announcing
     * "Locked" the next morning, in the slot where the lock state belongs.
     */
    @Volatile
    var message: String? = null

    @Volatile
    var busy: Boolean = false

    /** Unlock is armed until this moment, on the elapsed-realtime clock. */
    @Volatile
    var armedUntil: Long = 0L

    @Volatile
    var status: VehicleStatus? = null

    /** When [status] last came back, on the elapsed-realtime clock. 0 means never. */
    @Volatile
    var fetchedAt: Long = 0L

    /** When one was last tried, successful or not, so a dead API is not hammered. */
    @Volatile
    var attemptedAt: Long = 0L

    @Volatile
    var fetching: Boolean = false
}

/**
 * The EV6 on the wrist.
 *
 * Laid out for a round face, and that constraint is what shapes it. The design
 * this follows puts the charge on the bezel as an arc, the car above the
 * figures, and the controls along the bottom - but its sizes are drawn at watch
 * *pixels*, roughly twice the dp a 40mm watch actually offers. Reproducing them
 * literally would put a 148dp car on a 192dp screen and leave the controls
 * hanging off the glass.
 *
 * So the composition is the design's and the numbers are not: see the geometry
 * note on the companion for what each one has to clear. The visible departure
 * is Climate, which is a third circle in the button row rather than a labelled
 * pill underneath - a pill's bottom corners fall outside the bezel at any width
 * wide enough to hold the word.
 */
class KiaTileService : TileService() {

    private val worker = Executors.newSingleThreadExecutor()

    override fun onTileRequest(
        requestParams: RequestBuilders.TileRequest
    ): ListenableFuture<TileBuilders.Tile> {
        handleTap(requestParams.currentState.lastClickableId)
        refreshIfStale()

        val tile = TileBuilders.Tile.Builder()
            .setResourcesVersion(RESOURCES_VERSION)
            .setTileTimeline(TimelineBuilders.Timeline.fromLayoutElement(buildLayout()))
            .build()

        return ResolvableFuture.create<TileBuilders.Tile>().apply { set(tile) }
    }

    override fun onTileResourcesRequest(
        requestParams: RequestBuilders.ResourcesRequest
    ): ListenableFuture<ResourceBuilders.Resources> {
        val resources = ResourceBuilders.Resources.Builder()
            .setVersion(RESOURCES_VERSION)
            .addIdToImageMapping(IMG_CAR, drawable(CoreR.drawable.ev6_gt))
            .addIdToImageMapping(IMG_LOCK, drawable(CoreR.drawable.ic_lock))
            .addIdToImageMapping(IMG_UNLOCK, drawable(CoreR.drawable.ic_unlock))
            .addIdToImageMapping(IMG_CLIMATE, drawable(CoreR.drawable.ic_climate))
            .build()

        return ResolvableFuture.create<ResourceBuilders.Resources>().apply { set(resources) }
    }

    override fun onDestroy() {
        worker.shutdown()
        super.onDestroy()
    }

    private fun drawable(resId: Int): ResourceBuilders.ImageResource =
        ResourceBuilders.ImageResource.Builder()
            .setAndroidResourceByResId(
                ResourceBuilders.AndroidImageResourceByResId.Builder()
                    .setResourceId(resId)
                    .build()
            )
            .build()

    // ── interaction ──

    private fun handleTap(clickableId: String) {
        if (clickableId.isEmpty() || TileState.busy) return

        when (clickableId) {
            ID_LOCK -> {
                TileState.armedUntil = 0L
                send("Locking") { KiaApi.lock(CONFIG) }
            }

            ID_CLIMATE -> {
                TileState.armedUntil = 0L
                send("Climate") { KiaApi.startClimate(CONFIG) }
            }

            // Unlock is the one action here you cannot take back in a car park,
            // and a watch screen is easy to brush against. Make it deliberate.
            ID_UNLOCK -> {
                val now = SystemClock.elapsedRealtime()
                if (UnlockGuard.shouldFire(now, TileState.armedUntil)) {
                    TileState.armedUntil = 0L
                    send("Unlocking") { KiaApi.unlock(CONFIG) }
                } else {
                    TileState.armedUntil = UnlockGuard.armUntil(now)
                    TileState.message = "Tap again to unlock"
                }
            }
        }
    }

    private fun send(label: String, call: () -> ApiResult) {
        TileState.busy = true
        TileState.message = "$label…"

        // Captured outside the lambda: referencing applicationContext inside it
        // would capture this Service and hold it for the length of the call.
        val ctx = applicationContext
        worker.execute {
            val result = call()
            TileState.message = result.message.take(28)
            TileState.busy = false
            // A lock or unlock changes what the tile should be saying.
            if (result.ok) fetch()
            getUpdater(ctx).requestUpdate(KiaTileService::class.java)
        }
    }

    /**
     * Reads the car, but only when what we have is old enough to be wrong.
     *
     * The tile cannot wait for this: the system gives onTileRequest a few
     * seconds and a cold API takes twenty. So it draws whatever it has, fetches
     * behind it, and asks for a redraw when the answer lands - which is also why
     * first paint after a cold start shows dashes rather than numbers.
     */
    private fun refreshIfStale() {
        if (TileState.fetching || TileState.busy) return

        val now = SystemClock.elapsedRealtime()
        // Two floors, because a failure and a success mean different things: a
        // good reading is worth five minutes, a failed call is worth half a
        // minute before trying again, and neither should turn opening the tile
        // into a request per glance.
        if (TileState.attemptedAt != 0L && now - TileState.attemptedAt < RETRY_FLOOR_MS) return
        if (TileState.fetchedAt != 0L && now - TileState.fetchedAt < STATUS_MAX_AGE_MS) return

        TileState.fetching = true
        val ctx = applicationContext
        worker.execute {
            fetch()
            getUpdater(ctx).requestUpdate(KiaTileService::class.java)
        }
    }

    private fun fetch() {
        try {
            TileState.attemptedAt = SystemClock.elapsedRealtime()
            val outcome = KiaApi.status(CONFIG)
            if (outcome.ok && outcome.status != null) {
                TileState.status = outcome.status
                TileState.fetchedAt = SystemClock.elapsedRealtime()
            }
        } finally {
            // In a finally so a throw cannot wedge the tile into never fetching
            // again for the life of the process.
            TileState.fetching = false
        }
    }

    // ── layout ──

    private fun buildLayout(): LayoutElementBuilders.LayoutElement {
        val armed = UnlockGuard.shouldFire(SystemClock.elapsedRealtime(), TileState.armedUntil)
        val status = TileState.status
        val message = TileState.message.also { TileState.message = null }

        val stack = LayoutElementBuilders.Column.Builder()
            .setHorizontalAlignment(LayoutElementBuilders.HORIZONTAL_ALIGN_CENTER)
            .addContent(car())
            .addContent(vGap(2f))
            .addContent(figures(status))
            .addContent(subtitle(status, armed, message))
            .addContent(vGap(8f))
            .addContent(
                LayoutElementBuilders.Row.Builder()
                    .setVerticalAlignment(LayoutElementBuilders.VERTICAL_ALIGN_CENTER)
                    .addContent(
                        // Lock recedes while unlock is armed, so exactly one
                        // target is live.
                        circleButton(
                            image = IMG_LOCK,
                            id = ID_LOCK,
                            background = if (armed) COLOR_SURFACE_2 else COLOR_ACCENT,
                            content = if (armed) COLOR_TEXT_MUTED else COLOR_ACCENT_INK,
                            outlined = armed,
                            ring = false,
                        )
                    )
                    .addContent(hGap(CIRCLE_GAP))
                    .addContent(
                        circleButton(
                            image = IMG_UNLOCK,
                            id = ID_UNLOCK,
                            background = if (armed) COLOR_ARMED else COLOR_SURFACE_2,
                            content = if (armed) COLOR_ARMED_INK else COLOR_TEXT,
                            outlined = !armed,
                            ring = armed,
                        )
                    )
                    .addContent(hGap(CIRCLE_GAP))
                    .addContent(
                        circleButton(
                            image = IMG_CLIMATE,
                            id = ID_CLIMATE,
                            background = COLOR_SURFACE_2,
                            content = if (armed) COLOR_TEXT_MUTED else COLOR_TEXT,
                            outlined = true,
                            ring = false,
                        )
                    )
                    .build()
            )
            .build()

        // Centring in an expanding Box is what keeps the layout inside the
        // bezel on both watch sizes, rather than fixed top padding. The arcs go
        // in the same Box so they take the full face rather than the stack's
        // width.
        return LayoutElementBuilders.Box.Builder()
            .setWidth(expand())
            .setHeight(expand())
            .setVerticalAlignment(LayoutElementBuilders.VERTICAL_ALIGN_CENTER)
            .setHorizontalAlignment(LayoutElementBuilders.HORIZONTAL_ALIGN_CENTER)
            .addContent(arc(360f, COLOR_TRACK))
            .apply {
                // No arc at all when the car has not reported a charge: an empty
                // track is honest, a zero-length accent arc is not.
                status?.batteryPercent?.let {
                    addContent(arc(it.coerceIn(0, 100) * 3.6f, COLOR_ACCENT))
                }
            }
            .addContent(stack)
            .build()
    }

    /** The charge, on the bezel, where it costs no vertical room at all. */
    private fun arc(sweep: Float, color: Int): LayoutElementBuilders.LayoutElement =
        LayoutElementBuilders.Arc.Builder()
            .setAnchorAngle(degrees(0f))
            .setAnchorType(LayoutElementBuilders.ARC_ANCHOR_START)
            .addContent(
                LayoutElementBuilders.ArcLine.Builder()
                    // A full circle drawn as 360 can close on itself oddly;
                    // a hair under is indistinguishable and safe.
                    .setLength(degrees(minOf(sweep, 359.9f)))
                    .setThickness(dp(ARC_THICKNESS))
                    .setColor(argb(color))
                    .build()
            )
            .build()

    private fun car(): LayoutElementBuilders.LayoutElement =
        LayoutElementBuilders.Image.Builder()
            .setResourceId(IMG_CAR)
            .setWidth(dp(CAR_WIDTH))
            .setHeight(dp(CAR_HEIGHT))
            .setContentScaleMode(LayoutElementBuilders.CONTENT_SCALE_MODE_FIT)
            .build()

    /** "78% · 412 km", with the charge carrying the weight. */
    private fun figures(status: VehicleStatus?): LayoutElementBuilders.LayoutElement {
        val row = LayoutElementBuilders.Row.Builder()
            .setVerticalAlignment(LayoutElementBuilders.VERTICAL_ALIGN_BOTTOM)
            .addContent(
                label(
                    text = status?.batteryPercent?.let { "$it%" } ?: "—",
                    size = 22f,
                    color = COLOR_TEXT,
                    weight = LayoutElementBuilders.FONT_WEIGHT_BOLD,
                )
            )

        status?.range?.let {
            row.addContent(label(" · $it ${status.rangeUnit ?: "km"}", 13f, COLOR_TEXT_DIM))
        }

        return row.build()
    }

    /**
     * One line under the figures: whatever an action has to say, or the lock
     * state when nothing is happening.
     *
     * They share a slot because there is no room for two, and because they are
     * never both urgent - the moment you have tapped something, what the car was
     * a moment ago stops being the point.
     */
    private fun subtitle(
        status: VehicleStatus?,
        armed: Boolean,
        message: String?,
    ): LayoutElementBuilders.LayoutElement {
        if (message != null) {
            return label(message, 11f, if (armed) COLOR_ARMED else COLOR_TEXT_DIM)
        }

        val locked = status?.isLocked
        return label(
            text = when (locked) {
                true -> "Locked"
                false -> "Unlocked"
                null -> "Lock unknown"
            },
            size = 11f,
            color = if (locked == false) COLOR_ARMED else COLOR_TEXT_DIM,
        )
    }

    private fun vGap(height: Float): LayoutElementBuilders.LayoutElement =
        LayoutElementBuilders.Spacer.Builder().setHeight(dp(height)).build()

    private fun hGap(width: Float): LayoutElementBuilders.LayoutElement =
        LayoutElementBuilders.Spacer.Builder().setWidth(dp(width)).build()

    private fun icon(image: String, size: Float, tint: Int): LayoutElementBuilders.LayoutElement =
        LayoutElementBuilders.Image.Builder()
            .setResourceId(image)
            .setWidth(dp(size))
            .setHeight(dp(size))
            .setColorFilter(
                LayoutElementBuilders.ColorFilter.Builder()
                    .setTint(argb(tint))
                    .build()
            )
            .build()

    private fun label(
        text: String,
        size: Float,
        color: Int,
        weight: Int = LayoutElementBuilders.FONT_WEIGHT_NORMAL,
    ): LayoutElementBuilders.LayoutElement =
        LayoutElementBuilders.Text.Builder()
            .setText(text)
            .setMaxLines(1)
            .setFontStyle(
                LayoutElementBuilders.FontStyle.Builder()
                    .setSize(sp(size))
                    .setWeight(weight)
                    .setColor(argb(color))
                    .build()
            )
            .build()

    private fun circleButton(
        image: String,
        id: String,
        background: Int,
        content: Int,
        outlined: Boolean,
        ring: Boolean,
    ): LayoutElementBuilders.LayoutElement {
        val modifiers = ModifiersBuilders.Modifiers.Builder()
            .setBackground(
                ModifiersBuilders.Background.Builder()
                    .setColor(argb(background))
                    .setCorner(
                        ModifiersBuilders.Corner.Builder()
                            .setRadius(dp(CIRCLE_SIZE / 2f))
                            .build()
                    )
                    .build()
            )
            .setClickable(
                ModifiersBuilders.Clickable.Builder()
                    .setId(id)
                    .setOnClick(ActionBuilders.LoadAction.Builder().build())
                    .build()
            )

        // Colour alone would not read in sunlight, so armed also gets an
        // outline; the unarmed buttons get a hairline so they have an edge
        // against black.
        if (ring || outlined) {
            modifiers.setBorder(
                ModifiersBuilders.Border.Builder()
                    .setWidth(dp(if (ring) 3f else 1f))
                    .setColor(argb(if (ring) COLOR_ARMED_RING else COLOR_LINE))
                    .build()
            )
        }

        return LayoutElementBuilders.Box.Builder()
            .setWidth(dp(CIRCLE_SIZE))
            .setHeight(dp(CIRCLE_SIZE))
            .setModifiers(modifiers.build())
            .addContent(icon(image, ICON_SIZE, content))
            .build()
    }

    private companion object {
        // The watch is a separate device with its own storage, so the phone's
        // Settings screen cannot reach it. Build-time config it is - see
        // local.properties.example. Changing hosts means rebuilding the tile.
        val CONFIG = KiaConfig.fromBuildConfig()

        // Bumped whenever the drawables change, so the tile refetches them.
        const val RESOURCES_VERSION = "3"

        /** How stale a reading may be before the tile goes and asks again. */
        const val STATUS_MAX_AGE_MS = 5 * 60 * 1000L

        /** The shortest gap between two attempts, whatever the last one did. */
        const val RETRY_FLOOR_MS = 30 * 1000L

        const val IMG_CAR = "img_car"
        const val IMG_LOCK = "img_lock"
        const val IMG_UNLOCK = "img_unlock"
        const val IMG_CLIMATE = "img_climate"

        const val ID_LOCK = "lock"
        const val ID_UNLOCK = "unlock"
        const val ID_CLIMATE = "climate"

        // Geometry, against a 40mm watch: 192dp across, so 96dp of radius, and
        // call it 95dp once the arc has taken its 6dp off the edge.
        //
        // The stack is 41 + 2 + 26 + 14 + 8 + 48 = 139dp tall, centred, so
        // nothing is further than 70dp above or below the middle. The two
        // constraints that actually bite:
        //
        //  - the car, 84dp wide with its top edge 70dp up, needs
        //    sqrt(42² + 70²) = 82dp of radius;
        //  - the outer circles, 48dp across with their centres 54dp out and
        //    45dp down, reach sqrt(54² + 45²) + 24 = 95dp.
        //
        // The second is the one with no slack left, which is why Climate is a
        // circle in that row and not a pill below it: a pill wide enough to
        // read "Climate" puts its bottom corners past 105dp.
        const val CAR_WIDTH = 84f
        const val CAR_HEIGHT = 41f
        const val CIRCLE_SIZE = 48f
        const val CIRCLE_GAP = 6f
        const val ICON_SIZE = 22f
        const val ARC_THICKNESS = 6f

        // Shared with the phone app and widget via :core, so the surfaces match.
        val COLOR_ACCENT = KiaColors.ACCENT.toInt()
        val COLOR_ACCENT_INK = KiaColors.ACCENT_INK.toInt()
        val COLOR_ARMED = KiaColors.ARMED.toInt()
        val COLOR_ARMED_INK = KiaColors.ARMED_INK.toInt()
        val COLOR_ARMED_RING = KiaColors.ARMED.toInt()
        val COLOR_SURFACE_2 = KiaColors.SURFACE_2.toInt()
        val COLOR_LINE = KiaColors.LINE.toInt()
        val COLOR_TRACK = KiaColors.TRACK.toInt()
        val COLOR_TEXT = KiaColors.TEXT.toInt()
        val COLOR_TEXT_DIM = KiaColors.TEXT_DIM.toInt()
        val COLOR_TEXT_MUTED = KiaColors.TEXT_MUTED.toInt()
    }
}
