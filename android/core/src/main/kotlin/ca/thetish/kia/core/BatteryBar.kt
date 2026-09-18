package ca.thetish.kia.core

import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.RectF

/**
 * The charge bar, drawn once and used at both sizes.
 *
 * The phone draws it 10dp tall inside a custom View and the widget draws it 4dp
 * tall into a bitmap, because Glance has no fractional weights and so cannot
 * express "78% of this row" in a layout. Same geometry either way, which is the
 * point: the tick that marks the charge limit has to sit at the same fraction
 * on both, or the two surfaces disagree about where the car stops charging.
 *
 * A class rather than an object because it keeps its Paint and its scratch
 * rectangles: one of its two callers is View.onDraw, where allocating is a
 * frame-time cost for no reason. Each caller keeps its own instance, so none of
 * that state is shared across threads.
 */
class BatteryBar {

    private val paint = Paint(Paint.ANTI_ALIAS_FLAG)
    private val scratch = RectF()

    /**
     * Paints the track, the fill and the limit tick into [bar].
     *
     * [bar] is the bar itself, not the canvas: the tick deliberately overhangs
     * it by [TICK_OVERHANG] top and bottom, so callers must leave that much
     * room or the overhang is clipped away.
     *
     * [percent] and [limitPercent] are 0-100. A null limit omits the tick,
     * which is the honest rendering when the car has not reported one.
     */
    fun draw(
        canvas: Canvas,
        bar: RectF,
        percent: Int?,
        limitPercent: Int?,
        fillColor: Int,
        trackColor: Int,
        tickColor: Int,
    ) {
        if (bar.width() <= 0f || bar.height() <= 0f) return

        val radius = bar.height() / 2f

        paint.color = trackColor
        canvas.drawRoundRect(bar, radius, radius, paint)

        // An unknown charge leaves the track empty rather than drawing zero:
        // a bar pinned to the left reads as a flat battery.
        if (percent != null) {
            val fill = bar.width() * percent.coerceIn(0, 100) / 100f
            if (fill > 0f) {
                paint.color = fillColor
                scratch.set(bar.left, bar.top, bar.left + fill, bar.bottom)
                canvas.drawRoundRect(scratch, radius, radius, paint)
            }
        }

        if (limitPercent != null) {
            val overhang = bar.height() * TICK_OVERHANG
            val thickness = maxOf(2f, bar.height() * 0.2f)
            val centre = bar.left + bar.width() * limitPercent.coerceIn(0, 100) / 100f
            val left = centre.coerceIn(bar.left, bar.right - thickness)

            paint.color = tickColor
            scratch.set(left, bar.top - overhang, left + thickness, bar.bottom + overhang)
            canvas.drawRoundRect(scratch, thickness / 2f, thickness / 2f, paint)
        }
    }

    companion object {
        /** How far the limit tick stands out of the bar, as a share of bar height. */
        const val TICK_OVERHANG = 0.4f
    }
}
