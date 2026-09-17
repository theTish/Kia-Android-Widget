package ca.thetish.kia.core

/**
 * The two-tap unlock rule, in one place.
 *
 * Leaving a car unlocked by accident is worse than an extra tap, so every
 * surface arms on the first tap and only sends on the second. Each surface
 * stores `armedUntil` differently — the tile keeps it in memory on purpose so a
 * cold start comes up disarmed, the phone app in a field, the widget in
 * DataStore — but the window and the decision must not drift between them,
 * which is what this object prevents.
 */
object UnlockGuard {

    /** How long an armed unlock stays armed. */
    const val ARM_WINDOW_MS = 10_000L

    /** True when a tap at [now] should send the unlock rather than arm it. */
    fun shouldFire(now: Long, armedUntil: Long): Boolean = now < armedUntil

    /** The deadline to store when a tap arms the guard. */
    fun armUntil(now: Long): Long = now + ARM_WINDOW_MS
}
