package ca.thetish.kia.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The evaluator can send a lock command to a real car on its own, so its rules
 * are worth more scrutiny than the rest of this project put together.
 *
 * Most of what follows tests a refusal. That is the point: the failure that
 * matters is not "did not lock", which is the status quo the owner already
 * lives with, but "locked a car somebody was still sitting in" - which is what
 * the Tasker task this replaces actually did, keys and phone included.
 */
class GeofenceTest {

    private val now = 1_700_000_000_000L

    // The car, as the phone measured it when the Bluetooth dropped.
    private val carLat = 45.4215
    private val carLon = -75.6972

    private fun anchor(at: Long = now - 60_000L, accuracy: Float = 5f) =
        Anchor(carLat, carLon, accuracy, at)

    private fun fixAt(
        metresNorth: Double,
        accuracy: Float = 10f,
        at: Long = now,
    ) = PhoneFix(carLat + metresNorth / 111_320.0, carLon, accuracy, at)

    private fun evaluate(
        anchor: Anchor? = anchor(),
        locked: Boolean? = false,
        on: Boolean? = false,
        fix: PhoneFix? = fixAt(400.0),
        state: GeofenceState = GeofenceState(),
        at: Long = now,
        // A reading as fresh as the evaluation unless a test says otherwise:
        // the age rules have their own cases below.
        readingAt: Long? = at,
        allowRefresh: Boolean = false,
        radius: Int = Geofence.DEFAULT_RADIUS_METRES,
    ) = Geofence.evaluate(
        now = at,
        anchor = anchor,
        carIsLocked = locked,
        carIsOn = on,
        fix = fix,
        state = state,
        radiusMetres = radius,
        readingAt = readingAt,
        allowRefresh = allowRefresh,
    )

    // ── distance ──

    @Test
    fun `haversine is right to within a metre over a few hundred metres`() {
        val metres = Geofence.distanceMetres(carLat, carLon, carLat + 400 / 111_320.0, carLon)
        assertEquals(400.0, metres, 1.0)
    }

    @Test
    fun `distance to itself is zero`() {
        assertEquals(0.0, Geofence.distanceMetres(carLat, carLon, carLat, carLon), 0.001)
    }

    // ── nothing to measure from ──

    @Test
    fun `holds when there has been no disconnect`() {
        // A phone that has not been in the car since this was switched on knows
        // nothing about where the car is, and Kia's answer is not used.
        val decision = evaluate(anchor = null).decision
        assertTrue(decision is GeofenceDecision.Hold)
        assertEquals("no disconnect to measure from", decision.reason)
    }

    // ── the car says it is in use ──

    @Test
    fun `holds while the car is running`() {
        val decision = evaluate(on = true, fix = fixAt(4000.0)).decision
        assertTrue(decision is GeofenceDecision.Hold)
        assertEquals("the car is on", decision.reason)
    }

    @Test
    fun `running beats every other reason to fire`() {
        // Dwell served, well away, unlocked, fresh reading: everything this
        // needs to lock, except that somebody has the car running.
        val outcome = evaluate(on = true, state = GeofenceState(awaySince = now - 10 * 60 * 1000L))
        assertTrue(outcome.decision is GeofenceDecision.Hold)
        assertEquals(0L, outcome.state.awaySince)
    }

    // ── the fix ──

    @Test
    fun `holds when there is no fix`() {
        assertTrue(evaluate(fix = null).decision is GeofenceDecision.Hold)
    }

    @Test
    fun `holds when the fix is too vague to place you`() {
        val decision = evaluate(fix = fixAt(400.0, accuracy = 120f)).decision
        assertTrue(decision is GeofenceDecision.Hold)
        assertTrue(decision.reason.contains("120m"))
    }

    @Test
    fun `a vague fix is refused even when it reads as far away`() {
        val decision = evaluate(fix = fixAt(5_000.0, accuracy = 400f)).decision
        assertTrue(decision is GeofenceDecision.Hold)
    }

    // ── the margin: clear of the ring by more than the fix could be wrong by ──

    @Test
    fun `holds beside the car`() {
        val decision = evaluate(fix = fixAt(10.0)).decision
        assertTrue(decision is GeofenceDecision.Hold)
        assertTrue(decision.reason.contains("inside the 50m ring"))
    }

    @Test
    fun `a vague fix just outside a small ring decides nothing`() {
        // 40m away on a fix accurate to 30m is consistent with sitting in the
        // driver's seat, whatever the arithmetic says.
        val decision = evaluate(fix = fixAt(40.0, accuracy = 30f), radius = 25).decision
        assertTrue(decision is GeofenceDecision.Hold)
        assertTrue(decision.reason.contains("not clear of the 25m ring"))
    }

    @Test
    fun `a confident fix outside a small ring does count`() {
        // Indoors, forty-five metres from a car on the drive: the case a small
        // ring exists for.
        val later = now + Geofence.DEFAULT_DWELL_SECONDS * 1000L
        val decision = evaluate(
            fix = fixAt(45.0, accuracy = 5f, at = later),
            state = GeofenceState(awaySince = now),
            at = later,
            readingAt = later,
            radius = 25,
        ).decision
        assertTrue(decision is GeofenceDecision.Lock)
    }

    @Test
    fun `a sloppy anchor widens the margin too`() {
        // The anchor carries its own error: a fix taken through a windscreen is
        // not a surveyed point, and both uncertainties sit in the same gap.
        val decision = evaluate(
            anchor = anchor(accuracy = 45f),
            fix = fixAt(80.0, accuracy = 10f),
            radius = 25,
        ).decision
        assertTrue(decision is GeofenceDecision.Hold)
    }

    // ── a distance getting out does not explain ──

    @Test
    fun `refuses a gap larger than getting out explains`() {
        // A Bluetooth session that drops mid-drive anchors on the road, and the
        // gap then grows at thirty metres a second.
        val decision = evaluate(
            fix = fixAt(5_000.0, at = now + 10 * 60 * 1000L),
            state = GeofenceState(awaySince = now),
        ).decision
        assertTrue(decision is GeofenceDecision.Hold)
        assertTrue(decision.reason.contains("further than getting out explains"))
    }

    // ── the lock state ──

    @Test
    fun `holds when the lock state is unknown`() {
        val decision = evaluate(locked = null).decision
        assertTrue(decision is GeofenceDecision.Hold)
        assertEquals("lock state unknown", decision.reason)
    }

    @Test
    fun `holds when the car is already locked`() {
        val decision = evaluate(locked = true).decision
        assertTrue(decision is GeofenceDecision.Hold)
        assertEquals("already locked", decision.reason)
    }

    @Test
    fun `being locked resets the clock`() {
        val out = evaluate(locked = true, state = GeofenceState(awaySince = now))
        assertEquals(0L, out.state.awaySince)
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
    fun `a stale reading beside the car is not worth a poll`() {
        // The lock question is only asked once you are clear of the car, so
        // this holds on distance without waking anything.
        val decision = evaluate(
            fix = fixAt(10.0),
            readingAt = now - 40 * 60 * 1000L,
            allowRefresh = true,
        ).decision
        assertTrue(decision is GeofenceDecision.Hold)
        assertTrue(decision.reason.contains("ring"))
    }

    // ── the dwell ──

    @Test
    fun `first reading away only starts the clock`() {
        val out = evaluate()
        assertTrue(out.decision is GeofenceDecision.Waiting)
        assertEquals(now, out.state.awaySince)
    }

    @Test
    fun `still waiting part way through the dwell`() {
        val half = now + (Geofence.DEFAULT_DWELL_SECONDS / 2) * 1000L
        val out = evaluate(
            fix = fixAt(400.0, at = half),
            state = GeofenceState(awaySince = now),
            at = half,
        )
        assertTrue(out.decision is GeofenceDecision.Waiting)
    }

    @Test
    fun `locks once the dwell has passed`() {
        val later = now + Geofence.DEFAULT_DWELL_SECONDS * 1000L
        val out = evaluate(
            fix = fixAt(400.0, at = later),
            state = GeofenceState(awaySince = now),
            at = later,
            readingAt = later,
        )
        val decision = out.decision
        assertTrue(decision is GeofenceDecision.Lock)
        // Truncated metres: 400m of latitude lands a hair short on a sphere.
        assertEquals(400.0, (decision as GeofenceDecision.Lock).distanceMetres.toDouble(), 2.0)
        assertEquals(0L, out.state.awaySince)
    }

    @Test
    fun `coming back to the car resets the clock`() {
        val back = evaluate(fix = fixAt(10.0), state = GeofenceState(awaySince = now))
        assertEquals(0L, back.state.awaySince)

        val out = evaluate(fix = fixAt(400.0), state = back.state)
        assertTrue(out.decision is GeofenceDecision.Waiting)
    }

    // ── the latch ──

    @Test
    fun `does not decide twice for the same parking`() {
        val later = now + Geofence.DEFAULT_DWELL_SECONDS * 1000L
        val first = evaluate(
            fix = fixAt(400.0, at = later),
            state = GeofenceState(awaySince = now),
            at = later,
            readingAt = later,
        )
        assertTrue(first.decision is GeofenceDecision.Lock)

        val second = evaluate(
            fix = fixAt(420.0, at = later + 60_000L),
            state = first.state,
            at = later + 60_000L,
            readingAt = later + 60_000L,
        )
        assertTrue(second.decision is GeofenceDecision.Hold)
        assertEquals("already decided for this parking", second.decision.reason)
    }

    @Test
    fun `decides again after the next drive`() {
        val later = now + Geofence.DEFAULT_DWELL_SECONDS * 1000L
        val latched = GeofenceState(awaySince = now, actedOnAnchorAt = now - 60_000L)

        // A new disconnect is a new anchor, and the latch is keyed to the old one.
        val out = evaluate(
            anchor = anchor(at = later),
            fix = fixAt(400.0, at = later),
            state = latched,
            at = later,
            readingAt = later,
        )
        assertTrue(out.decision is GeofenceDecision.Lock)
    }

    // ── the whole thing, reading by reading ──

    @Test
    fun `park, get out, walk away`() {
        val parked = anchor(at = now)
        var state = GeofenceState()
        var t = now
        val step = 30_000L

        // Still in the car when the Bluetooth drops.
        var out = Geofence.evaluate(
            t, parked, false, false, fixAt(3.0, at = t), state, readingAt = t,
        )
        assertTrue(out.decision is GeofenceDecision.Hold)
        state = out.state

        // Out and walking.
        val seen = mutableListOf<GeofenceDecision>()
        for (d in listOf(90.0, 160.0, 240.0)) {
            t += step
            out = Geofence.evaluate(
                t, parked, false, false, fixAt(d, at = t), state, readingAt = t,
            )
            state = out.state
            seen += out.decision
        }

        // Two readings of waiting at 30s apart, then the 60s dwell is served.
        assertTrue(seen.take(2).all { it is GeofenceDecision.Waiting })
        assertTrue(seen.last() is GeofenceDecision.Lock)
    }

    @Test
    fun `the phone left in the car locks nothing`() {
        // 2026-10-02, and the Tasker incident before it: the phone stayed with
        // the car. Nothing can tell that from the owner staying with it either,
        // so the car is left unlocked - the safe half of the mistake.
        val parked = anchor(at = now)
        var state = GeofenceState()
        var t = now

        repeat(5) {
            t += 60_000L
            val out = Geofence.evaluate(
                t, parked, false, false, fixAt(2.0, at = t), state, readingAt = t,
            )
            state = out.state
            assertTrue(out.decision is GeofenceDecision.Hold)
        }
    }
}
