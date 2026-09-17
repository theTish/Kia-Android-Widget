package ca.thetish.kiatile

import android.os.SystemClock
import androidx.concurrent.futures.ResolvableFuture
import ca.thetish.kia.core.ApiResult
import ca.thetish.kia.core.BuildConfig
import ca.thetish.kia.core.KiaApi
import ca.thetish.kia.core.R as CoreR
import ca.thetish.kia.core.KiaColors
import ca.thetish.kia.core.UnlockGuard
import androidx.wear.protolayout.ActionBuilders
import androidx.wear.protolayout.ColorBuilders.argb
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
 * Deliberately not persisted: a cold start should come up neutral rather than
 * resurrecting a half finished action or, worse, a stale unlock arming.
 */
private object TileState {
    @Volatile
    var message: String = "Ready"

    @Volatile
    var busy: Boolean = false

    /** Unlock is armed until this moment, on the elapsed-realtime clock. */
    @Volatile
    var armedUntil: Long = 0L
}

/**
 * Layout is built for a round face. Lock and Unlock sit either side of the
 * centre line where the bezel is widest; Climate takes the bottom as a pill.
 * The whole stack is 140dp tall and centre-aligned, which keeps every target
 * inside the glass on a 40mm watch as well as a 44mm one.
 */
class KiaTileService : TileService() {

    private val worker = Executors.newSingleThreadExecutor()

    override fun onTileRequest(
        requestParams: RequestBuilders.TileRequest
    ): ListenableFuture<TileBuilders.Tile> {
        handleTap(requestParams.currentState.lastClickableId)

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
                send("Locking") { KiaApi.lock() }
            }

            ID_CLIMATE -> {
                TileState.armedUntil = 0L
                send("Climate") { KiaApi.startClimate(BuildConfig.KIA_CLIMATE_PRESET) }
            }

            // Unlock is the one action here you cannot take back in a car park,
            // and a watch screen is easy to brush against. Make it deliberate.
            ID_UNLOCK -> {
                val now = SystemClock.elapsedRealtime()
                if (UnlockGuard.shouldFire(now, TileState.armedUntil)) {
                    TileState.armedUntil = 0L
                    send("Unlocking") { KiaApi.unlock() }
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
            getUpdater(ctx).requestUpdate(KiaTileService::class.java)
        }
    }

    // ── layout ──

    private fun buildLayout(): LayoutElementBuilders.LayoutElement {
        val armed = UnlockGuard.shouldFire(SystemClock.elapsedRealtime(), TileState.armedUntil)

        val stack = LayoutElementBuilders.Column.Builder()
            .setHorizontalAlignment(LayoutElementBuilders.HORIZONTAL_ALIGN_CENTER)
            .addContent(status(armed))
            .addContent(vGap(8f))
            .addContent(
                LayoutElementBuilders.Row.Builder()
                    .setVerticalAlignment(LayoutElementBuilders.VERTICAL_ALIGN_CENTER)
                    .addContent(
                        // Lock recedes while unlock is armed, so exactly one target is live.
                        circleButton(
                            label = "Lock",
                            image = IMG_LOCK,
                            id = ID_LOCK,
                            background = if (armed) COLOR_LOCK_DIM else COLOR_LOCK,
                            content = if (armed) COLOR_TEXT_MUTED else COLOR_TEXT,
                            ring = false
                        )
                    )
                    .addContent(hGap(20f))
                    .addContent(
                        circleButton(
                            label = if (armed) "Confirm" else "Unlock",
                            image = IMG_UNLOCK,
                            id = ID_UNLOCK,
                            background = if (armed) COLOR_ARMED else COLOR_UNLOCK,
                            content = COLOR_TEXT,
                            ring = armed
                        )
                    )
                    .build()
            )
            .addContent(vGap(14f))
            .addContent(
                pillButton(
                    label = "Climate",
                    image = IMG_CLIMATE,
                    id = ID_CLIMATE,
                    background = if (armed) COLOR_CLIMATE_DIM else COLOR_CLIMATE,
                    content = if (armed) COLOR_TEXT_MUTED else COLOR_TEXT
                )
            )
            .build()

        // Centring in an expanding Box is what keeps the layout inside the
        // bezel on both watch sizes, rather than fixed top padding.
        return LayoutElementBuilders.Box.Builder()
            .setWidth(expand())
            .setHeight(expand())
            .setVerticalAlignment(LayoutElementBuilders.VERTICAL_ALIGN_CENTER)
            .setHorizontalAlignment(LayoutElementBuilders.HORIZONTAL_ALIGN_CENTER)
            .addContent(stack)
            .build()
    }

    private fun status(armed: Boolean): LayoutElementBuilders.LayoutElement =
        LayoutElementBuilders.Text.Builder()
            .setText(TileState.message)
            .setMaxLines(1)
            .setFontStyle(
                LayoutElementBuilders.FontStyle.Builder()
                    .setSize(sp(12f))
                    .setColor(argb(if (armed) COLOR_ARMED_TEXT else COLOR_TEXT_DIM))
                    .build()
            )
            .build()

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

    private fun label(text: String, size: Float, color: Int): LayoutElementBuilders.LayoutElement =
        LayoutElementBuilders.Text.Builder()
            .setText(text)
            .setMaxLines(1)
            .setFontStyle(
                LayoutElementBuilders.FontStyle.Builder()
                    .setSize(sp(size))
                    .setColor(argb(color))
                    .build()
            )
            .build()

    private fun tapModifiers(
        id: String,
        background: Int,
        cornerRadius: Float,
        ring: Boolean
    ): ModifiersBuilders.Modifiers {
        val builder = ModifiersBuilders.Modifiers.Builder()
            .setBackground(
                ModifiersBuilders.Background.Builder()
                    .setColor(argb(background))
                    .setCorner(
                        ModifiersBuilders.Corner.Builder()
                            .setRadius(dp(cornerRadius))
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

        // Colour alone would not read in sunlight, so armed also gets an outline.
        if (ring) {
            builder.setBorder(
                ModifiersBuilders.Border.Builder()
                    .setWidth(dp(3f))
                    .setColor(argb(COLOR_ARMED_TEXT))
                    .build()
            )
        }

        return builder.build()
    }

    private fun circleButton(
        label: String,
        image: String,
        id: String,
        background: Int,
        content: Int,
        ring: Boolean
    ): LayoutElementBuilders.LayoutElement =
        LayoutElementBuilders.Box.Builder()
            .setWidth(dp(CIRCLE_SIZE))
            .setHeight(dp(CIRCLE_SIZE))
            .setModifiers(tapModifiers(id, background, CIRCLE_SIZE / 2f, ring))
            .addContent(
                LayoutElementBuilders.Column.Builder()
                    .setHorizontalAlignment(LayoutElementBuilders.HORIZONTAL_ALIGN_CENTER)
                    .addContent(icon(image, 22f, content))
                    .addContent(vGap(2f))
                    .addContent(label(label, 11f, content))
                    .build()
            )
            .build()

    private fun pillButton(
        label: String,
        image: String,
        id: String,
        background: Int,
        content: Int
    ): LayoutElementBuilders.LayoutElement =
        LayoutElementBuilders.Box.Builder()
            .setWidth(dp(PILL_WIDTH))
            .setHeight(dp(PILL_HEIGHT))
            .setModifiers(tapModifiers(id, background, PILL_HEIGHT / 2f, ring = false))
            .addContent(
                LayoutElementBuilders.Row.Builder()
                    .setVerticalAlignment(LayoutElementBuilders.VERTICAL_ALIGN_CENTER)
                    .addContent(icon(image, 20f, content))
                    .addContent(hGap(8f))
                    .addContent(label(label, 14f, content))
                    .build()
            )
            .build()

    private companion object {
        // Bumped whenever the drawables change, so the tile refetches them.
        const val RESOURCES_VERSION = "2"

        const val IMG_LOCK = "img_lock"
        const val IMG_UNLOCK = "img_unlock"
        const val IMG_CLIMATE = "img_climate"

        const val ID_LOCK = "lock"
        const val ID_UNLOCK = "unlock"
        const val ID_CLIMATE = "climate"

        // 62dp clears the 48dp touch-target floor with room to spare, and two
        // of them plus a 20dp gap is 144dp across, inside the 173dp the
        // narrower watch offers at that height.
        //
        // The pill is 48dp to meet Android's minimum touch target. That makes
        // the stack 148dp tall, so the pill's furthest point (its bottom
        // corner arc) reaches 89dp from centre — clear of the 99dp radius on
        // a 40mm watch, never mind the 112dp on a 44mm one.
        const val CIRCLE_SIZE = 62f
        const val PILL_WIDTH = 130f
        const val PILL_HEIGHT = 48f

        // Shared with the phone app and widget via :core, so the surfaces match.
        val COLOR_LOCK = KiaColors.LOCK.toInt()
        val COLOR_LOCK_DIM = KiaColors.LOCK_DIM.toInt()
        val COLOR_UNLOCK = KiaColors.UNLOCK.toInt()
        val COLOR_ARMED = KiaColors.ARMED.toInt()
        val COLOR_ARMED_TEXT = KiaColors.ARMED_TEXT.toInt()
        val COLOR_CLIMATE = KiaColors.CLIMATE.toInt()
        val COLOR_CLIMATE_DIM = KiaColors.CLIMATE_DIM.toInt()
        val COLOR_TEXT = KiaColors.TEXT.toInt()
        val COLOR_TEXT_DIM = KiaColors.TEXT_DIM.toInt()
        val COLOR_TEXT_MUTED = KiaColors.TEXT_MUTED.toInt()
    }
}
