package ca.thetish.kia.core

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ClimateSettingsTest {

    @Test
    fun `default sends every field, heaters explicitly off`() {
        assertEquals(
            "{\"set_temp\":21,\"duration\":10,\"climate\":true,\"defrost\":false," +
                "\"heating\":0,\"steering_wheel\":0,\"front_left_seat\":0," +
                "\"front_right_seat\":0,\"rear_left_seat\":0,\"rear_right_seat\":0}",
            ClimateSettings.DEFAULT.toJson(),
        )
    }

    @Test
    fun `chosen values are sent as chosen`() {
        val settings = ClimateSettings(
            temperature = 22.5,
            durationMinutes = 20,
            defrost = true,
            rearHeat = true,
            steeringWheel = true,
            driverSeat = SeatHeat.HIGH,
            passengerSeat = SeatHeat.LOW,
            rearSeats = SeatHeat.MEDIUM,
        )
        assertEquals(
            "{\"set_temp\":22.5,\"duration\":20,\"climate\":true,\"defrost\":true," +
                "\"heating\":1,\"steering_wheel\":1,\"front_left_seat\":3," +
                "\"front_right_seat\":1,\"rear_left_seat\":2,\"rear_right_seat\":2}",
            settings.toJson(),
        )
    }

    @Test
    fun `out of range values are pulled back inside what the API accepts`() {
        val hot = ClimateSettings(temperature = 35.0, durationMinutes = 60).normalized()
        assertEquals(30.0, hot.temperature, 0.0)
        assertEquals(30, hot.durationMinutes)

        val cold = ClimateSettings(temperature = 10.0, durationMinutes = 1).normalized()
        assertEquals(16.0, cold.temperature, 0.0)
        assertEquals(5, cold.durationMinutes)
    }

    @Test
    fun `temperature snaps to the half degrees the car works in`() {
        assertEquals(21.5, ClimateSettings(temperature = 21.4).normalized().temperature, 0.0)
        assertEquals(21.0, ClimateSettings(temperature = 21.2).normalized().temperature, 0.0)
    }

    @Test
    fun `old presets carry over as what they used to send`() {
        val winter = ClimateSettings.forPreset("winter")!!
        assertEquals(21.0, winter.temperature, 0.0)
        assertEquals(true, winter.defrost)
        assertEquals(true, winter.rearHeat)
        assertEquals(true, winter.steeringWheel)
        assertEquals(SeatHeat.HIGH, winter.driverSeat)
        assertEquals(SeatHeat.HIGH, winter.passengerSeat)
        assertEquals(SeatHeat.OFF, winter.rearSeats)

        assertEquals(ClimateSettings.DEFAULT, ClimateSettings.forPreset("Summer"))
        assertEquals(ClimateSettings(defrost = true), ClimateSettings.forPreset(" springfall "))
    }

    @Test
    fun `unknown or missing preset has nothing to carry over`() {
        assertNull(ClimateSettings.forPreset("autumn"))
        assertNull(ClimateSettings.forPreset(""))
        assertNull(ClimateSettings.forPreset(null))
    }

    @Test
    fun `seat levels outside the scale read as off`() {
        assertEquals(SeatHeat.HIGH, SeatHeat.fromLevel(3))
        assertEquals(SeatHeat.OFF, SeatHeat.fromLevel(7))
    }
}
