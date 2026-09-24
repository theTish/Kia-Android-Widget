package ca.thetish.kia.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ChargeLimitsTest {

    @Test
    fun `the six values the car accepts, and nothing between`() {
        assertEquals(listOf(50, 60, 70, 80, 90, 100), ChargeLimits.STEPS)
        for (v in ChargeLimits.STEPS) assertTrue("$v", ChargeLimits.isValid(v))
        for (v in listOf(0, 40, 45, 55, 85, 95, 110)) assertFalse("$v", ChargeLimits.isValid(v))
    }

    @Test
    fun `stepping stops at the ends rather than leaving the range`() {
        assertEquals(90, ChargeLimits.up(80))
        assertEquals(100, ChargeLimits.up(100))
        assertEquals(70, ChargeLimits.down(80))
        assertEquals(50, ChargeLimits.down(50))
    }

    @Test
    fun `a limit the car reports off-step is pulled onto a step before it is moved`() {
        // 85 came from somewhere else; + must give 90, not 95 and not 100.
        assertEquals(90, ChargeLimits.snap(85))
        assertEquals(90, ChargeLimits.up(85))
        assertEquals(80, ChargeLimits.down(85))
        assertEquals(80, ChargeLimits.snap(84))
        assertEquals(50, ChargeLimits.snap(20))
        assertEquals(100, ChargeLimits.snap(130))
    }
}
