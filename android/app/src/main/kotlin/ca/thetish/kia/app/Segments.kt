package ca.thetish.kia.app

import android.app.Activity
import android.widget.TextView
import ca.thetish.kia.core.R as CoreR

/**
 * A segmented control over a row of TextViews.
 *
 * Replaces the Spinner, which needed two custom layouts to stay visible on
 * black and still hid its options behind a tap. A handful of fixed choices
 * fit on one line, so show them all.
 *
 * Shared between Settings and Climate so both draw the selected state the
 * same way; [onChange] fires only on a tap, not on the initial [select].
 */
class Segments<T>(
    private val activity: Activity,
    private val options: List<Pair<T, Int>>,
    private val onChange: (T) -> Unit = {},
) {

    private var chosen: T = options.first().first

    init {
        for ((value, id) in options) {
            activity.findViewById<TextView>(id).setOnClickListener {
                select(value)
                onChange(value)
            }
        }
    }

    val value: T get() = chosen

    fun select(value: T) {
        chosen = options.firstOrNull { it.first == value }?.first ?: options.first().first
        for ((option, id) in options) {
            val selected = option == chosen
            activity.findViewById<TextView>(id).apply {
                setBackgroundResource(
                    if (selected) R.drawable.segment_selected else R.drawable.segment_idle
                )
                setTextColor(
                    activity.getColor(if (selected) CoreR.color.text else CoreR.color.text_dim)
                )
                isSelected = selected
            }
        }
    }
}
