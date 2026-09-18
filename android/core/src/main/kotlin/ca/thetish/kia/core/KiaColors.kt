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

    // Surfaces. Black is the page; the greys are cards stacked on it, and they
    // are close together on purpose - the design separates them with 1px lines
    // rather than with contrast, which is what keeps the car the brightest
    // thing on the screen.
    const val BACKGROUND = 0xFF000000L
    const val SURFACE = 0xFF111417L
    const val SURFACE_2 = 0xFF15191CL
    const val CARD = 0xFF0B0D0FL
    const val LINE = 0xFF262B30L
    const val DIVIDER = 0xFF22272BL
    const val TRACK = 0xFF1A1E22L

    // Text. Three steps, and the third matters: "not reported" has to look
    // different from a real value, or an unknown reads as a measurement.
    const val TEXT = 0xFFF3F5F0L
    const val TEXT_DIM = 0xFFA3ABB0L
    const val TEXT_MUTED = 0xFF7C858BL

    // GT lime, sampled from the drive-mode button on the steering wheel - which
    // is why it is this exact value and not a tidier one. Reserved for charge
    // and for the one primary action on a screen; spending it on anything else
    // is what would make it stop meaning "go". Flat fill, never a gradient: the
    // glow under the car on the home screen is a light effect, not a fill.
    const val ACCENT = 0xFFCEDE27L
    const val ACCENT_INK = 0xFF0B0D05L

    // Amber is only ever "this needs your attention": an armed unlock, a
    // warning light, a door left open.
    const val ARMED = 0xFFFFB547L
    const val ARMED_INK = 0xFF1A1204L
    const val ARMED_BG = 0xFF211808L
    const val ARMED_LINE = 0xFF4A340FL
}
