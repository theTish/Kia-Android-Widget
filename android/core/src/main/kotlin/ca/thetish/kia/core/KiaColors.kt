package ca.thetish.kia.core

/**
 * The one set of colour tokens, so the watch and the phone genuinely match.
 *
 * These were previously three hard-coded copies — a Glance palette, a set of
 * tile constants and an app colors.xml — and they had already drifted: the
 * backgrounds disagreed and the tile carried a token the others lacked.
 *
 * Values are ARGB Longs because the two Kotlin consumers want different types:
 * Glance takes `Color(...)`, ProtoLayout takes an Int. `core/res/values/colors.xml`
 * mirrors these for XML layouts and must be kept in step.
 */
object KiaColors {
    const val BACKGROUND = 0xFF101418L
    const val LOCK = 0xFF2E7D32L
    const val LOCK_DIM = 0xFF1F2A2FL
    const val UNLOCK = 0xFF37474FL
    const val ARMED = 0xFFB4560AL
    const val ARMED_TEXT = 0xFFFFB74DL
    const val CLIMATE = 0xFF1565C0L
    const val CLIMATE_DIM = 0xFF10243AL
    const val NEUTRAL = 0xFF263238L
    const val TEXT = 0xFFFFFFFFL
    const val TEXT_DIM = 0xFFB0BEC5L
    const val TEXT_MUTED = 0xFF6D7B82L
}
