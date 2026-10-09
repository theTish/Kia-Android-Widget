package ca.thetish.kia.core

import kotlin.math.asin
import kotlin.math.cos
import kotlin.math.min
import kotlin.math.sin
import kotlin.math.sqrt

/**
 * Where the car is, taken from the phone at the moment it stopped being in it.
 *
 * The phone's own fix when the car's Bluetooth dropped. At that instant the
 * phone is inside the car, so this is the car's position measured by the only
 * instrument on hand that is both accurate and current.
 *
 * It replaces the position Kia reports, which is neither. The car reports where
 * it is when it parks and then goes quiet, and nothing in the payload says that
 * figure is stale - which on 2026-10-02 put the phone "1842m" from a car it was
 * sitting inside, and locked it.
 */
data class Anchor(
    val latitude: Double,
    val longitude: Double,
    /** How well the fix that produced it was placed. */
    val accuracyMetres: Float,
    /** Wall-clock millis of the disconnect. */
    val atMillis: Long,
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

    /** Away from the car, but not for long enough yet. */
    data class Waiting(override val reason: String) : GeofenceDecision

    /** Walked away from the car. Whether it was already locked is not asked: locking a locked car does nothing. */
    data class Lock(override val reason: String, val distanceMetres: Int) : GeofenceDecision
}

/**
 * What has to be remembered between one evaluation and the next.
 *
 * Kept out of the evaluator so it can stay a pure function: the caller persists
 * this and hands it back.
 */
data class GeofenceState(
    /** When the phone was first seen clear of the anchor. 0 when it is not. */
    val awaySince: Long = 0L,

    /**
     * The anchor a lock has already been decided for.
     *
     * Without this the evaluator re-fires on every fix for as long as you are
     * away from the car, which in shadow mode is a log full of noise and in
     * armed mode is a lock command every couple of minutes all day. The next
     * drive produces a new disconnect, and with it a new anchor.
     */
    val actedOnAnchorAt: Long = 0L,
)

/** A decision and the state to carry forward. */
data class GeofenceOutcome(val decision: GeofenceDecision, val state: GeofenceState)

/**
 * Should the car be locked, given that you have got out of it?
 *
 * This replaces a Tasker task that locked on Bluetooth disconnect after a bare
 * `Wait 45 seconds`, with no check that anybody had left - so it locked the
 * keys and the phone inside the car. That incident is why this project exists,
 * and why the disconnect here is only the question, never the answer.
 *
 * The disconnect says the car has been switched off. What follows says whether
 * anyone actually left it: the phone has to move clear of where it was sitting
 * when the music stopped, by more than its own fix could be wrong by, and still
 * be clear a minute later.
 *
 * Every rule exists to refuse rather than to fire. Locking a car nobody has
 * left is a nuisance at best and a lockout at worst; failing to lock one is
 * what the owner was already doing by hand. So an unknown reads as "do nothing"
 * everywhere.
 */
object Geofence {

    /**
     * How far from the car counts as having left it.
     *
     * Small, because the anchor is trustworthy now. The case this was written
     * for is a car on the drive and its owner indoors, thirty metres away; a
     * ring wide enough to cover a GPS wobble would never see it. What makes a
     * ring this small safe is the margin rule below, not the number itself.
     */
    const val DEFAULT_RADIUS_METRES = 50

    /**
     * How long you have to stay out there.
     *
     * The Tasker rule waited forty-five seconds and then locked whatever had
     * happened. This waits for a second opinion instead: the first reading past
     * the ring starts a clock, and the lock needs the phone still clear when it
     * runs out. A minute is two separate readings, which is the point of it,
     * and it covers getting out to open a gate and getting back in.
     */
    const val DEFAULT_DWELL_SECONDS = 60

    /**
     * The worst fix worth reasoning about at all.
     *
     * A network fix in a city can be accurate to 500m, which is to say it can
     * put you three ring-widths away without your having moved. Whether a given
     * fix is good enough for a given ring is decided by the margin test at the
     * distance check; this is only the outer limit.
     */
    const val MAX_ACCURACY_METRES = 60f

    /**
     * A backstop, not a rule about walking.
     *
     * With the anchor coming from the phone, distance is normally beyond doubt.
     * The one way it can lie is a Bluetooth session that drops mid-drive: the
     * anchor lands on the road and the gap grows at thirty metres a second. The
     * car being on refuses that case first, and this catches it if Kia's idea
     * of "on" is stale too.
     */
    const val MAX_PLAUSIBLE_METRES = 2_000

    /**
     * @param anchor where the car was when its Bluetooth dropped, or null if
     *   this phone has not seen a disconnect to measure from.
     * @param carIsOn whether Kia says the car is running, or null if unknown.
     * @param readingAt when the car reported that, or null if it did not say.
     *   Only a reading from after the disconnect is believed.
     */
    fun evaluate(
        now: Long,
        anchor: Anchor?,
        carIsOn: Boolean? = null,
        fix: PhoneFix?,
        state: GeofenceState,
        radiusMetres: Int = DEFAULT_RADIUS_METRES,
        dwellSeconds: Int = DEFAULT_DWELL_SECONDS,
        readingAt: Long? = null,
    ): GeofenceOutcome {
        // ── Is there a question to answer? ──

        if (anchor == null) return hold(state, "no disconnect to measure from")

        // Whether the reading describes this parking at all. Kia's cache still
        // holds the drive, or the parking before it, for a while after the
        // Bluetooth drops, and what it says is about then, not now.
        val thisParking = readingAt != null && readingAt >= anchor.atMillis

        // A car that is running is a car somebody is using, or one deliberately
        // left warming up. Either way it is not one to lock behind them, and
        // this is the cheapest refusal available: no fix, no distance, no call.
        // An "on" from before the disconnect is the drive that just ended, not
        // the car now, and is ignored.
        if (carIsOn == true && thisParking) return hold(state.beside(), "the car is on")

        if (fix == null) return hold(state, "no position fix")
        if (fix.accuracyMetres > MAX_ACCURACY_METRES) {
            return hold(state, "fix accurate only to ${fix.accuracyMetres.toInt()}m")
        }

        // ── How far from the car ──

        val distance = distanceMetres(anchor.latitude, anchor.longitude, fix.latitude, fix.longitude)
        val metres = distance.toInt()

        // Clear of the ring by more than the fix could be wrong by. A phone 40m
        // from the car on a fix accurate to 30m has told you nothing: it is
        // equally consistent with sitting in the driver's seat. Written as a
        // margin rather than a floor on the ring so that a small ring - a car
        // on the drive, its owner indoors - is safe to ask for.
        val clear = distance - fix.accuracyMetres - anchor.accuracyMetres
        if (clear <= radiusMetres) {
            val reason = if (distance <= radiusMetres) {
                "${metres}m from the car, inside the ${radiusMetres}m ring"
            } else {
                "${metres}m from the car, give or take ${fix.accuracyMetres.toInt()}m - " +
                    "not clear of the ${radiusMetres}m ring"
            }
            return hold(state.beside(), reason)
        }

        if (distance > MAX_PLAUSIBLE_METRES) {
            return hold(state, "${metres}m from the car, further than getting out explains")
        }

        // Already decided for this disconnect. The next drive ends in another
        // one, which is what releases the latch.
        if (state.actedOnAnchorAt == anchor.atMillis) {
            return GeofenceOutcome(GeofenceDecision.Hold("already decided for this parking"), state)
        }

        // ── Away, and it counts ──

        val awaySince = if (state.awaySince == 0L) fix.atMillis else state.awaySince
        val awayFor = fix.atMillis - awaySince
        val dwellMs = dwellSeconds * 1000L

        if (awayFor < dwellMs) {
            return GeofenceOutcome(
                GeofenceDecision.Waiting("${metres}m away, ${awayFor / 1000}s of ${dwellSeconds}s"),
                state.copy(awaySince = awaySince),
            )
        }

        return GeofenceOutcome(
            GeofenceDecision.Lock(
                reason = "${metres}m away for ${awayFor / 1000}s",
                distanceMetres = metres,
            ),
            GeofenceState(awaySince = 0L, actedOnAnchorAt = anchor.atMillis),
        )
    }

    /**
     * Whether a reading ends the watch: the car switched back on since its
     * Bluetooth dropped, so somebody is using it.
     *
     * Only a reading from after the disconnect counts. Straight after it Kia's
     * cache is still the drive, or the parking before it; taking that at its
     * word stopped the watch on its first look, before anybody had got out.
     */
    fun settles(anchor: Anchor, carIsOn: Boolean?, readingAt: Long?): Boolean =
        carIsOn == true && readingAt != null && readingAt >= anchor.atMillis

    /**
     * Great-circle distance in metres.
     *
     * Haversine on a sphere. At the scale this works over - a few hundred
     * metres - the error against a proper ellipsoid is centimetres.
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

    /** Still at the car: the dwell starts again from scratch next time. */
    private fun GeofenceState.beside() = copy(awaySince = 0L)

    private const val EARTH_RADIUS_METRES = 6_371_008.8
}
