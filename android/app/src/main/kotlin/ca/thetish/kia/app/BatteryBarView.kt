package ca.thetish.kia.app

import android.content.Context
import android.graphics.Canvas
import android.graphics.RectF
import android.util.AttributeSet
import android.view.View
import ca.thetish.kia.core.BatteryBar
import ca.thetish.kia.core.R as CoreR

/**
 * The charge bar on the home screen.
 *
 * A View rather than a stack of weighted LinearLayouts because the limit tick
 * has to overhang the bar, and a weighted layout can only place things inside
 * it. The drawing itself lives in :core so the widget's version cannot drift.
 */
class BatteryBarView @JvmOverloads constructor(
    context: Context,
    attrs: AttributeSet? = null,
) : View(context, attrs) {

    private var percent: Int? = null
    private var limitPercent: Int? = null

    // Both held rather than made per frame: onDraw runs on every scroll tick.
    private val bar = BatteryBar()
    private val bounds = RectF()

    private val fill = context.getColor(CoreR.color.accent)
    private val track = context.getColor(CoreR.color.track)
    private val tick = context.getColor(CoreR.color.text)

    /** Both nullable: neither an unknown charge nor an unknown limit is zero. */
    fun show(percent: Int?, limitPercent: Int?) {
        if (percent == this.percent && limitPercent == this.limitPercent) return
        this.percent = percent
        this.limitPercent = limitPercent
        invalidate()
    }

    override fun onDraw(canvas: Canvas) {
        val barHeight = BAR_HEIGHT_DP * resources.displayMetrics.density
        // Centred, which is what leaves the tick its overhang at both ends.
        val top = (height - barHeight) / 2f

        bounds.set(0f, top, width.toFloat(), top + barHeight)
        bar.draw(
            canvas = canvas,
            bar = bounds,
            percent = percent,
            limitPercent = limitPercent,
            fillColor = fill,
            trackColor = track,
            tickColor = tick,
        )
    }

    private companion object {
        const val BAR_HEIGHT_DP = 10f
    }
}
