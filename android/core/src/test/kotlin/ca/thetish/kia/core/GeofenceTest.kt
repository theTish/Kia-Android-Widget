package ca.thetish.kia.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The geofence can send a lock command to a real car on its own, so its rules
 * are worth more scrutiny than the rest of this project put together.
 *
 * Most of what follows tests a refusal. That is the point: the failure that
 * matters is not "did not lock", which is the status quo the owner already
 * lives with, but "locked a car somebody was still sitting in".
 */
class GeofenceTest {

    private val now = 1_700_000_000_000L

    // Two points about 1.2km apart, and one 60m away, near Ottawa.
    private val carLat = 45.4215
    private val carLon = -75.6972

    private fun car(reportedAt: Long = now) = CarPosition(carLat, carLon, reportedAt)

    private fun fixAt(
        metresNorth: Double,
        accuracy: Float = 10f,
        at: Long = now,
    ) = PhoneFix(carLat + metresNorth / 111_320.0, carLon, accuracy, at)

    private fun evaluate(
        car: CarPosition? = car(),
        locked: Boolean? = false,
        fix: PhoneFix? = fixAt(400.0),
        state: GeofenceState = GeofenceState(),
        at: Long = now,
        // A reading as fresh as the evaluation unless a test says otherwise:
        // the age rules have their own cases below.
        readingAt: Long? = at,
        allowRefresh: Boolean = false,
    ) = Geofence.evaluate(
        now = at,
        car = car,
        carIsLocked = locked,
        fix = fix,
        state = state,
        readingAt = readingAt,
        allowRefresh = allowRefresh,
    )

    // ── distance ──

    @Test
    fun `haversine is right to within a metre over a few hundred metres`() {
        val d = Geofence.distanceMetres(carLat, carLon, carLat + 400 / 111_320.0, carLon)
        assertEquals(400.0, d, 1.0)
    }

    @Test
    fun `distance to itself is zero`() {
        assertEquals(0.0, Geofence.distanceMetres(carLat, carLon, carLat, carLon), 0.001)
    }

    // ── refusals ──

    @Test
    fun `holds when the car has never reported a position`() {
        val out = evaluate(car = null)
        assertTrue(out.decision is GeofenceDecision.Hold)
        assertTrue(out.decision.reason.contains("not reported"))
    }

    @Test
    fun `holds when the car's position is too old to mean anything`() {
        val stale = now - Geofence.MAX_CAR_POSITION_AGE_MS - 1
        val out = evaluate(car = car(reportedAt = stale))
        assertTrue(out.decision is GeofenceDecision.Hold)
        assertTrue(out.decision.reason.contains("old"))
    }

    /** The one that matters most: a failed /status must not read as an open car. */
    @Test
    fun `holds when the lock state is unknown`() {
        val out = evaluate(locked = null)
        assertTrue(out.decision is GeofenceDecision.Hold)
        assertEquals("lock state unknown", out.decision.reason)
    }

    @Test
    fun `holds when the car is already locked`() {
        val out = evaluate(locked = true)
        assertTrue(out.decision is GeofenceDecision.Hold)
        assertEquals("already locked", out.decision.reason)
    }

    @Test
    fun `holds when there is no fix`() {
        assertTrue(evaluate(fix = null).decision is GeofenceDecision.Hold)
    }

    @Test
    fun `holds when the fix is too vague to place you`() {
        val out = evaluate(fix = fixAt(400.0, accuracy = Geofence.MAX_ACCURACY_METRES + 1))
        assertTrue(out.decision is GeofenceDecision.Hold)
        assertTrue(out.decision.reason.contains("accurate only to"))
    }

    /**
     * A 500m-accurate network fix can put you three ring-widths from a car you
     * are sitting in. Distance is not consulted at all until the fix is good.
     */
    @Test
    fun `a vague fix is refused even when it reads as far away`() {
        val out = evaluate(fix = fixAt(5_000.0, accuracy = 500f))
        assertTrue(out.decision is GeofenceDecision.Hold)
        assertTrue(out.decision.reason.contains("accurate only to"))
    }

    @Test
    fun `holds while inside the ring`() {
        val out = evaluate(fix = fixAt(60.0))
        assertTrue(out.decision is GeofenceDecision.Hold)
        assertTrue(out.decision.reason.contains("inside"))
    }

    // ── the dwell ──

    @Test
    fun `first fix outside only starts the clock`() {
        val out = evaluate()
        assertTrue(out.decision is GeofenceDecision.Waiting)
        assertEquals(now, out.state.outsideSince)
    }

    @Test
    fun `still waiting part way through the dwell`() {
        val started = GeofenceState(outsideSince = now)
        val later = now + (Geofence.DEFAULT_DWELL_SECONDS - 1) * 1000L
        val out = evaluate(fix = fixAt(400.0, at = later), state = started, at = later)
        assertTrue(out.decision is GeofenceDecision.Waiting)
    }

    @Test
    fun `locks once the dwell has passed`() {
        val started = GeofenceState(outsideSince = now)
        val later = now + Geofence.DEFAULT_DWELL_SECONDS * 1000L
        val out = evaluate(fix = fixAt(400.0, at = later), state = started, at = later)

        val decision = out.decision
        assertTrue(decision is GeofenceDecision.Lock)
        assertEquals(400.0, (decision as GeofenceDecision.Lock).distanceMetres.toDouble(), 3.0)
    }

    /**
     * Walking out and back must not bank the time. Otherwise a lap of a car
     * park adds up to a dwell you never actually served.
     */
    @Test
    fun `coming back inside resets the clock`() {
        val started = GeofenceState(outsideSince = now)
        val back = evaluate(fix = fixAt(10.0), state = started)
        assertEquals(0L, back.state.outsideSince)

        val out = evaluate(fix = fixAt(400.0), state = back.state)
        assertTrue(out.decision is GeofenceDecision.Waiting)
    }

    @Test
    fun `being locked also resets the clock`() {
        val out = evaluate(locked = true, state = GeofenceState(outsideSince = now))
        assertEquals(0L, out.state.outsideSince)
    }

    // ── the latch ──

    @Test
    fun `does not decide twice for the same parking`() {
        val started = GeofenceState(outsideSince = now)
        val later = now + Geofence.DEFAULT_DWELL_SECONDS * 1000L
        val first = evaluate(fix = fixAt(400.0, at = later), state = started, at = later)
        assertTrue(first.decision is GeofenceDecision.Lock)

        // Same car position, still away, an hour later.
        val muchLater = later + 60 * 60 * 1000L
        val second = evaluate(
            fix = fixAt(400.0, at = muchLater),
            state = first.state,
            at = muchLater,
        )
        assertTrue(second.decision is GeofenceDecision.Hold)
        assertTrue(second.decision.reason.contains("already decided"))
    }

    /** A new parking is a new position report, and the latch lets go. */
    @Test
    fun `decides again once the car has reported from somewhere new`() {
        val latched = GeofenceState(outsideSince = 0L, actedOnCarReportedAt = now - 1000)
        val out = evaluate(car = car(reportedAt = now), state = latched)
        assertTrue(out.decision is GeofenceDecision.Waiting)
    }

    // ── the whole sequence ──

    @Test
    fun `a park and walk away, fix by fix`() {
        var state = GeofenceState()
        val step = 30_000L
        var t = now

        // Sitting in the car, unlocked.
        var out = Geofence.evaluate(t, car(), false, fixAt(5.0, at = t), state, readingAt = t)
        assertTrue(out.decision is GeofenceDecision.Hold)
        state = out.state

        // Out of the car and walking.
        val distances = listOf(180.0, 260.0, 340.0, 520.0)
        val seen = mutableListOf<GeofenceDecision>()
        for (d in distances) {
            t += step
            out = Geofence.evaluate(t, car(), false, fixAt(d, at = t), state, readingAt = t)
            state = out.state
            seen += out.decision
        }

        // Three fixes of waiting at 30s apart, then the 90s dwell is served.
        assertTrue(seen.take(3).all { it is GeofenceDecision.Waiting })
        assertTrue(seen.last() is GeofenceDecision.Lock)
    }

    // ── how old the lock reading is ──

    @Test
    fun `asks the car when the reading is too old to act on`() {
        val decision = evaluate(
            readingAt = now - 40 * 60 * 1000L,
            allowRefresh = true,
        ).decision
        assertTrue(decision is GeofenceDecision.Refresh)
        assertTrue(decision.reason.contains("40m old"))
    }

    @Test
    fun `refuses rather than asks when the car parked long ago`() {
        // Beyond the refresh window: an old reading about a car that has sat
        // there for hours is not a walk-away in progress.
        val parkedAt = now - 3 * 60 * 60 * 1000L
        val decision = evaluate(
            car = car(reportedAt = parkedAt),
            readingAt = parkedAt,
            allowRefresh = true,
        ).decision
        assertTrue(decision is GeofenceDecision.Hold)
        assertTrue(decision.reason.contains("3h old"))
    }

    @Test
    fun `refuses when the live reading comes back stale too`() {
        val decision = evaluate(
            readingAt = now - 40 * 60 * 1000L,
            allowRefresh = false,
        ).decision
        assertTrue(decision is GeofenceDecision.Hold)
    }

    @Test
    fun `refuses a reading with no timestamp at all`() {
        val decision = evaluate(readingAt = null).decision
        assertTrue(decision is GeofenceDecision.Hold)
        assertTrue(decision.reason.contains("unknown age"))
    }

    @Test
    fun `a stale reading standing next to the car is not worth a poll`() {
        // The lock question is only asked once you are outside the ring, so
        // this holds on distance without waking anything.
        val decision = evaluate(
            fix = fixAt(20.0),
            readingAt = now - 40 * 60 * 1000L,
            allowRefresh = true,
        ).decision
        assertTrue(decision is GeofenceDecision.Hold)
        assertTrue(decision.reason.contains("ring"))
    }
}
