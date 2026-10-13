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
        fix: PhoneFix? = fixAt(400.0),
        state: GeofenceState = GeofenceState(),
        radius: Int = Geofence.DEFAULT_RADIUS_METRES,
    ) = Geofence.evaluate(
        now = now,
        anchor = anchor,
        fix = fix,
        state = state,
        radiusMetres = radius,
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
        )
        assertTrue(out.decision is GeofenceDecision.Waiting)
    }

    @Test
    fun `locks once the dwell has passed`() {
        val later = now + Geofence.DEFAULT_DWELL_SECONDS * 1000L
        val out = evaluate(
            fix = fixAt(400.0, at = later),
            state = GeofenceState(awaySince = now),
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
        )
        assertTrue(first.decision is GeofenceDecision.Lock)

        val second = evaluate(
            fix = fixAt(420.0, at = later + 60_000L),
            state = first.state,
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
            t, parked, fixAt(3.0, at = t), state,
        )
        assertTrue(out.decision is GeofenceDecision.Hold)
        state = out.state

        // Out and walking.
        val seen = mutableListOf<GeofenceDecision>()
        for (d in listOf(90.0, 160.0, 240.0)) {
            t += step
            out = Geofence.evaluate(
                t, parked, fixAt(d, at = t), state,
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
                t, parked, fixAt(2.0, at = t), state,
            )
            state = out.state
            assertTrue(out.decision is GeofenceDecision.Hold)
        }
    }

    @Test
    fun `a car left unlocked on 2026-10-09 gets locked`() {
        // Parked at 08:36 and left open on purpose. Kia's cache still had the
        // parking before as locked, the old watcher believed it on its first
        // look, and nothing was ever sent. Kia's view is no longer an input:
        // getting clear of the car and staying clear is the whole question.
        val parked = anchor(at = now, accuracy = 10f)
        var state = GeofenceState()
        var t = now
        val seen = mutableListOf<GeofenceDecision>()

        for (d in listOf(0.0, 0.0, 60.0, 140.0, 220.0)) {
            val out = Geofence.evaluate(t, parked, fixAt(d, accuracy = 8f, at = t), state, radiusMetres = 25)
            state = out.state
            seen += out.decision
            t += 60_000L
        }

        // Beside the car twice, out of the ring, then still out a minute on.
        assertTrue(seen.take(2).all { it is GeofenceDecision.Hold })
        assertTrue(seen[2] is GeofenceDecision.Waiting)
        assertTrue(seen[3] is GeofenceDecision.Lock)
        assertEquals("already decided for this parking", seen[4].reason)
    }

    // ── home ──

    private val home = Home(carLat, carLon)

    @Test
    fun `at home the car locks after five minutes however close the phone is`() {
        // 2026-10-12, 20:21: parked on the drive, phone indoors 13-15m away on
        // a fix good to about ten. The ring can never clear; time does instead.
        val parked = anchor(at = now)
        val later = now + Geofence.HOME_DELAY_MS
        val out = Geofence.evaluate(later, parked, fixAt(14.0, at = later), GeofenceState(), radiusMetres = 25, home = home)
        val decision = out.decision
        assertTrue(decision is GeofenceDecision.Lock)
        assertTrue((decision as GeofenceDecision.Lock).atHome)
        assertEquals(parked.atMillis, out.state.actedOnAnchorAt)
    }

    @Test
    fun `at home nothing locks before the five minutes are up`() {
        val parked = anchor(at = now)
        val soon = now + Geofence.HOME_DELAY_MS - 1
        val decision = Geofence.evaluate(soon, parked, fixAt(14.0, at = soon), GeofenceState(), radiusMetres = 25, home = home).decision
        assertTrue(decision is GeofenceDecision.Hold)
    }

    @Test
    fun `at home a missing fix does not stop the lock`() {
        val parked = anchor(at = now)
        val later = now + Geofence.HOME_DELAY_MS
        val decision = Geofence.evaluate(later, parked, null, GeofenceState(), home = home).decision
        assertTrue(decision is GeofenceDecision.Lock)
    }

    @Test
    fun `parked away from home keeps the walk-away rule`() {
        val parked = anchor(at = now)
        val later = now + Geofence.HOME_DELAY_MS
        val elsewhere = Home(carLat + 500 / 111_320.0, carLon)
        val decision = Geofence.evaluate(later, parked, fixAt(14.0, at = later), GeofenceState(), radiusMetres = 25, home = elsewhere).decision
        assertTrue(decision is GeofenceDecision.Hold)
    }

    @Test
    fun `at home it locks once per parking`() {
        val parked = anchor(at = now)
        val later = now + Geofence.HOME_DELAY_MS
        val latched = GeofenceState(actedOnAnchorAt = parked.atMillis)
        val decision = Geofence.evaluate(later, parked, fixAt(14.0, at = later), latched, radiusMetres = 25, home = home).decision
        assertTrue(decision is GeofenceDecision.Hold)
    }
}
