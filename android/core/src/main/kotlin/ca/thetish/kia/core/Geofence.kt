package ca.thetish.kia.core

import kotlin.math.asin
import kotlin.math.cos
import kotlin.math.min
import kotlin.math.sin
import kotlin.math.sqrt

/** Where the car said it was, and when it said so. */
data class CarPosition(
    val latitude: Double,
    val longitude: Double,
    /** Wall-clock millis, from /status - not the elapsed-realtime clock. */
    val reportedAt: Long,
)

/** One position fix from the phone. */
data class PhoneFix(
    val latitude: Double,
    val longitude: Double,
    val accuracyMetres: Float,
    val atMillis: Long,
)

/** What the feature is allowed to do. */
enum class GeofenceMode {
    /** Not running at all. */
    OFF,

    /** Decides and records, never touches the car. The default, and where it stays until its log is boring. */
    SHADOW,

    /** Decides, records, and sends the lock. */
    ARMED,
}

/**
 * What the evaluator concluded, and why.
 *
 * The reason is not decoration: in shadow mode it is the entire product. A log
 * saying "would have locked" tells you nothing about whether to trust it, and a
 * log saying "held: fix accurate only to 380m" tells you everything.
 */
sealed interface GeofenceDecision {
    val reason: String

    /** Nothing to do, and here is what ruled it out. */
    data class Hold(override val reason: String) : GeofenceDecision

    /** Outside the ring, but not for long enough yet. */
    data class Waiting(override val reason: String) : GeofenceDecision

    /** Walked away from an unlocked car. */
    data class Lock(override val reason: String, val distanceMetres: Int) : GeofenceDecision

    /**
     * Outside the ring, but the lock reading is too old to act on.
     *
     * The caller is expected to ask the car itself and evaluate again. Kia
     * serves a cached view that can be hours behind: on 2026-09-22 it reported
     * a locked car two minutes before the owner locked it by hand, and this
     * logged "already locked" about a car standing open.
     */
    data class Refresh(override val reason: String) : GeofenceDecision
}

/**
 * What has to be remembered between one evaluation and the next.
 *
 * Kept out of the evaluator so it can stay a pure function: the caller persists
 * this and hands it back.
 */
data class GeofenceState(
    /** When the phone was first seen outside the ring. 0 when it is inside. */
    val outsideSince: Long = 0L,

    /**
     * The car position a lock has already been decided for.
     *
     * Without this the evaluator re-fires on every fix for as long as you are
     * away from the car, which in shadow mode is a log full of noise and in
     * armed mode is a lock command every couple of minutes all day.
     */
    val actedOnCarReportedAt: Long = 0L,
)

/** A decision and the state to carry forward. */
data class GeofenceOutcome(val decision: GeofenceDecision, val state: GeofenceState)

/**
 * Should the car be locked, given where it is and where you are?
 *
 * The rule this replaces is a Tasker task that takes two GPS fixes 45 seconds
 * apart and compares them to the phone's own last position. That works, but it
 * is measuring the wrong thing: it knows you have moved, not that you have
 * moved away from the car. Anchoring to the position the car itself reports
 * means it behaves the same whether the car is on the drive or at the far end
 * of a car park you walked across.
 *
 * Every rule here exists to refuse rather than to fire. Locking a car nobody
 * has left is a nuisance; failing to lock one is what the owner was already
 * doing by hand. So an unknown reads as "do nothing" everywhere, and the
 * decision needs a known-unlocked car, a position the car reported recently, a
 * fix good enough to believe, and distance that holds up over time.
 */
object Geofence {

    /**
     * How far you have to get from the car.
     *
     * 150m is past the other side of a supermarket car park but well inside
     * "walked to the shop", which is the distance at which forgetting matters.
     */
    const val DEFAULT_RADIUS_METRES = 150

    /**
     * How long you have to stay out there.
     *
     * The Tasker rule used 45 seconds and rarely misfired, so this is not a
     * number that needs to be brave. It is the difference between walking away
     * and a GPS fix wandering off across the road for one sample.
     */
    const val DEFAULT_DWELL_SECONDS = 90

    /**
     * The worst fix worth believing.
     *
     * A network fix in a city can be accurate to 500m, which is to say it can
     * put you three ring-widths away without your having moved. Those get
     * thrown out rather than averaged in.
     */
    const val MAX_ACCURACY_METRES = 60f

    /**
     * How stale the car's own position may be.
     *
     * Past this it is a record of where the car was, not where it is, and the
     * distance being measured is meaningless. Six hours covers a working day
     * parked up without covering an overnight where the car may have moved
     * without this app hearing about it.
     */
    const val MAX_CAR_POSITION_AGE_MS = 6 * 60 * 60 * 1000L

    /**
     * How old the lock reading may be before it is worth waking the car for.
     *
     * Kia answers /status from a cache the car refreshes when it feels like
     * it, so "locked" can mean "was locked when the car last checked in".
     * Five minutes is short enough that a reading this recent can only have
     * come from the drive that just ended or a poll made for this decision.
     */
    const val MAX_READING_AGE_MS = 5 * 60 * 1000L

    /**
     * How long after the car parked a live poll is worth its cost.
     *
     * A forced poll wakes the car's modem and takes a little 12V, so it is not
     * something to do every quarter of an hour all day while the car sits at
     * work. Walking away from a car you have just parked happens within
     * minutes of it reporting that position; past three quarters of an hour,
     * an old reading is refused instead.
     */
    const val REFRESH_WINDOW_MS = 45 * 60 * 1000L

    /**
     * @param readingAt when the car reported the state this lock reading came
     *   from, or null if it did not say.
     * @param allowRefresh false once a live poll has already been made for
     *   this decision, so a car that answers with a stale reading anyway is
     *   refused rather than polled in a loop.
     */
    fun evaluate(
        now: Long,
        car: CarPosition?,
        carIsLocked: Boolean?,
        fix: PhoneFix?,
        state: GeofenceState,
        radiusMetres: Int = DEFAULT_RADIUS_METRES,
        dwellSeconds: Int = DEFAULT_DWELL_SECONDS,
        readingAt: Long? = null,
        allowRefresh: Boolean = false,
    ): GeofenceOutcome {
        // ── Reasons to do nothing at all ──

        if (car == null) return hold(state, "the car has not reported a position")

        val carAge = now - car.reportedAt
        if (carAge > MAX_CAR_POSITION_AGE_MS) {
            return hold(state, "the car's position is ${hours(carAge)} old")
        }

        if (fix == null) return hold(state, "no position fix")
        if (fix.accuracyMetres > MAX_ACCURACY_METRES) {
            return hold(state, "fix accurate only to ${fix.accuracyMetres.toInt()}m")
        }

        // ── Distance ──

        val distance = distanceMetres(car.latitude, car.longitude, fix.latitude, fix.longitude)
        val metres = distance.toInt()

        if (distance <= radiusMetres) {
            return hold(state.inside(), "${metres}m from the car, inside the ${radiusMetres}m ring")
        }

        // Already decided for this reading of the car's position. Waiting for
        // the car to report a new one is what makes the latch release itself:
        // the next drive gives a new timestamp.
        if (state.actedOnCarReportedAt == car.reportedAt) {
            return GeofenceOutcome(
                GeofenceDecision.Hold("already decided for this parking"),
                state,
            )
        }

        // ── Is the car even open? ──
        //
        // Asked here rather than first because it is the expensive question:
        // the answer that matters is a live one, and there is no point waking
        // a car to learn the lock state of one you are standing next to.

        // An unknown lock state is not an unlocked one. This is the single most
        // important refusal here: it is what stops a failed /status from
        // looking like an open car.
        if (carIsLocked == null) return hold(state, "lock state unknown")

        val readingAge = readingAt?.let { now - it }
        if (readingAge == null || readingAge > MAX_READING_AGE_MS) {
            val age = readingAge?.let { ago(it) } ?: "of unknown age"
            return if (allowRefresh && carAge <= REFRESH_WINDOW_MS) {
                GeofenceOutcome(
                    GeofenceDecision.Refresh("the lock reading is $age - asking the car"),
                    state,
                )
            } else {
                hold(state, "the lock reading is $age")
            }
        }

        // Locked resets the dwell: the walk this clock was timing ended with
        // the car shut, so the next one starts from scratch.
        if (carIsLocked) return hold(state.inside(), "already locked")

        // ── Outside, and it counts ──

        val outsideSince = if (state.outsideSince == 0L) fix.atMillis else state.outsideSince
        val outsideFor = fix.atMillis - outsideSince
        val dwellMs = dwellSeconds * 1000L

        if (outsideFor < dwellMs) {
            return GeofenceOutcome(
                GeofenceDecision.Waiting(
                    "${metres}m away, ${outsideFor / 1000}s of ${dwellSeconds}s"
                ),
                state.copy(outsideSince = outsideSince),
            )
        }

        return GeofenceOutcome(
            GeofenceDecision.Lock(
                reason = "${metres}m away for ${outsideFor / 1000}s, car unlocked",
                distanceMetres = metres,
            ),
            GeofenceState(outsideSince = 0L, actedOnCarReportedAt = car.reportedAt),
        )
    }

    /**
     * Great-circle distance in metres.
     *
     * Haversine on a sphere. At the scale this works over - a few hundred
     * metres - the error against a proper ellipsoid is centimetres, and the
     * ring is 150m wide.
     */
    fun distanceMetres(lat1: Double, lon1: Double, lat2: Double, lon2: Double): Double {
        val dLat = Math.toRadians(lat2 - lat1)
        val dLon = Math.toRadians(lon2 - lon1)
        val a = sin(dLat / 2) * sin(dLat / 2) +
            cos(Math.toRadians(lat1)) * cos(Math.toRadians(lat2)) *
            sin(dLon / 2) * sin(dLon / 2)
        return 2 * EARTH_RADIUS_METRES * asin(min(1.0, sqrt(a)))
    }

    private fun hold(state: GeofenceState, reason: String) =
        GeofenceOutcome(GeofenceDecision.Hold(reason), state)

    /** Back within the ring: the dwell timer starts again from scratch next time. */
    private fun GeofenceState.inside() = copy(outsideSince = 0L)

    /** "12m old", "2h old" - the age of a reading, in the largest unit that reads plainly. */
    private fun ago(millis: Long): String = "${hours(millis)} old"

    private fun hours(millis: Long): String {
        val h = millis / (60 * 60 * 1000L)
        return if (h >= 1) "${h}h" else "${millis / (60 * 1000L)}m"
    }

    private const val EARTH_RADIUS_METRES = 6_371_008.8
}
