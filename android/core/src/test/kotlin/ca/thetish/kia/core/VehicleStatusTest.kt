package ca.thetish.kia.core

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pre-conditioning is the part of /status most likely to be missing, because
 * the library decodes no schedule for Canada. Missing has to stay missing:
 * a card claiming "off" for a car that never answered would be worse than
 * saying nothing.
 */
class VehicleStatusTest {

    private fun parse(json: String) = VehicleStatus.parse(JSONObject(json))

    @Test
    fun `no preconditioning block leaves departures unknown`() {
        val s = parse("""{"battery_preconditioning": false}""")
        assertNull(s.departures)
        assertEquals(false, s.batteryPreconditioning)
    }

    @Test
    fun `null departures stay unknown rather than empty`() {
        val s = parse("""{"preconditioning": {"battery": true, "departures": null}}""")
        assertNull(s.departures)
        assertEquals(true, s.batteryPreconditioning)
    }

    @Test
    fun `departures parse with their schedule and climate`() {
        val s = parse(
            """{"preconditioning": {"battery": false, "departures": [
                {"slot": 1, "enabled": true, "time": "07:30", "days": [1,2,3,4,5],
                 "climate_on": true, "climate_temperature": 21.0, "defrost": false},
                {"slot": 2, "enabled": false, "time": null, "days": [0,6],
                 "climate_on": null, "climate_temperature": null, "defrost": null}
            ]}}"""
        )
        val (one, two) = s.departures!!
        assertEquals(true, one.enabled)
        assertEquals("07:30", one.time)
        assertEquals(VehicleStatus.Departure.Days.WEEKDAYS, one.dayPattern)
        assertEquals(21.0, one.climateTemperature!!, 0.0)
        assertEquals(false, two.enabled)
        assertNull(two.time)
        assertNull(two.climateOn)
        assertEquals(VehicleStatus.Departure.Days.WEEKENDS, two.dayPattern)
    }

    @Test
    fun `the libraries bottom step reads as Lo`() {
        // Seen live on 2026-09-21: set_temperature 14.0 with climate off.
        assertTrue(parse("""{"climate": {"set_temperature": 14.0}}""").climateTargetIsLo)
        assertFalse(parse("""{"climate": {"set_temperature": 21.0}}""").climateTargetIsLo)
        assertFalse(parse("""{"climate": {"set_temperature": null}}""").climateTargetIsLo)
    }

    @Test
    fun `charging power reads as a round figure`() {
        assertEquals(
            "6.6 kW",
            parse("""{"estimated_charging_power_kw": 6.6}""").chargingPowerText,
        )
        // A whole number should not carry a ".0" on a widget line.
        assertEquals(
            "7 kW",
            parse("""{"estimated_charging_power_kw": 7.0}""").chargingPowerText,
        )
    }

    @Test
    fun `no charging power when the car is not charging`() {
        // The API sends null rather than 0, but a 0 would be just as useless.
        assertNull(parse("{}").chargingPowerText)
        assertNull(parse("""{"estimated_charging_power_kw": 0}""").chargingPowerText)
    }
}
