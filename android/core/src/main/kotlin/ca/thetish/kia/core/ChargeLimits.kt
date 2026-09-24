package ca.thetish.kia.core

/**
 * The values Kia accepts for a charge limit, and how a picker moves between them.
 *
 * The car takes a target state of charge per plug type - one for AC, one for
 * DC - as a whole number from 50 to 100 in steps of 10. The API refuses anything
 * else with a 400, so the picker only ever offers these six values rather than
 * letting a slider land on 85 and bounce.
 *
 * Nothing here talks to the car: it is the rule, kept where it can be tested.
 */
object ChargeLimits {
    const val MIN = 50
    const val MAX = 100
    const val STEP = 10

    /** What the picker starts on when the car has not reported a limit. */
    const val DEFAULT = 80

    val STEPS: List<Int> = (MIN..MAX step STEP).toList()

    fun isValid(value: Int): Boolean = value in STEPS

    /** The nearest step strictly above [value], or [MAX] once there is none. */
    fun up(value: Int): Int = STEPS.firstOrNull { it > value } ?: MAX

    /** The nearest step strictly below [value], or [MIN] once there is none. */
    fun down(value: Int): Int = STEPS.lastOrNull { it < value } ?: MIN

    /**
     * The nearest value the car would accept.
     *
     * The status read can carry whatever Kia stored, and a limit set from the
     * car's own screen or an older app might not sit on a step. The picker
     * opens on this rather than on the raw figure, so what it shows is always
     * something Set can send. (up/down never skip a step from an off-step
     * value either - 85 goes to 90, not 100 - so the two agree.)
     */
    fun snap(value: Int): Int {
        val rounded = ((value + STEP / 2) / STEP) * STEP
        return rounded.coerceIn(MIN, MAX)
    }
}
