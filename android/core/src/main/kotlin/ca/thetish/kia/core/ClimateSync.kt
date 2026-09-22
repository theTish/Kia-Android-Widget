package ca.thetish.kia.core

import android.content.Context
import android.net.Uri
import com.google.android.gms.tasks.Tasks
import com.google.android.gms.wearable.DataMap
import com.google.android.gms.wearable.DataMapItem
import com.google.android.gms.wearable.PutDataMapRequest
import com.google.android.gms.wearable.Wearable
import java.util.concurrent.TimeUnit

/**
 * Carries the phone's climate choice to the watch.
 *
 * The watch has no screen to choose on, and before this it sent whatever
 * preset was compiled into it - which quietly disagreed with the phone the
 * moment anyone changed a setting there. Now the phone publishes one Data
 * Layer item and the watch reads it back at the moment Climate is pressed.
 *
 * Read on demand rather than through a WearableListenerService: Play Services
 * replicates the item to the watch's own store whenever the two are in range,
 * so reading it locally already gets the latest the watch has been told, and
 * there is one less component to go stale or miss a change it was asleep for.
 *
 * The Data Layer only connects apps with the same package name and signing
 * key on both ends, which is why the tile's applicationId is the phone's.
 */
object ClimateSync {

    private const val PATH = "/climate"

    private const val TEMPERATURE = "temperature"
    private const val DURATION = "duration"
    private const val DEFROST = "defrost"
    private const val REAR_HEAT = "rear_heat"
    private const val WHEEL = "steering_wheel"
    private const val DRIVER = "driver_seat"
    private const val PASSENGER = "passenger_seat"
    private const val REAR_SEATS = "rear_seats"

    /**
     * Phone side. Fire and forget: a watch that is out of range picks the item
     * up when it reconnects, and an unchanged item is a no-op, so this is
     * cheap to call on every change and again whenever the app opens.
     */
    fun publish(context: Context, settings: ClimateSettings) {
        val s = settings.normalized()
        val request = PutDataMapRequest.create(PATH).apply {
            dataMap.putDouble(TEMPERATURE, s.temperature)
            dataMap.putInt(DURATION, s.durationMinutes)
            dataMap.putBoolean(DEFROST, s.defrost)
            dataMap.putBoolean(REAR_HEAT, s.rearHeat)
            dataMap.putBoolean(WHEEL, s.steeringWheel)
            dataMap.putInt(DRIVER, s.driverSeat.level)
            dataMap.putInt(PASSENGER, s.passengerSeat.level)
            dataMap.putInt(REAR_SEATS, s.rearSeats.level)
        }.asPutDataRequest().setUrgent()

        runCatching {
            Wearable.getDataClient(context.applicationContext).putDataItem(request)
        }
    }

    /**
     * Watch side. Blocks, so call it off the main thread. Null when the phone
     * has never published anything - an older phone build, or a watch that
     * has not been in range since - and the caller keeps what it had.
     */
    fun pull(context: Context): ClimateSettings? = runCatching {
        val uri = Uri.Builder().scheme("wear").path(PATH).build()
        val items = Tasks.await(
            Wearable.getDataClient(context.applicationContext).getDataItems(uri),
            PULL_TIMEOUT_SECONDS,
            TimeUnit.SECONDS,
        )
        try {
            items.firstOrNull()?.let { decode(DataMapItem.fromDataItem(it).dataMap) }
        } finally {
            items.release()
        }
    }.getOrNull()

    private fun decode(map: DataMap): ClimateSettings? {
        if (!map.containsKey(TEMPERATURE)) return null
        return ClimateSettings(
            temperature = map.getDouble(TEMPERATURE),
            durationMinutes = map.getInt(DURATION, ClimateSettings.DEFAULT_DURATION),
            defrost = map.getBoolean(DEFROST),
            rearHeat = map.getBoolean(REAR_HEAT),
            steeringWheel = map.getBoolean(WHEEL),
            driverSeat = SeatHeat.fromLevel(map.getInt(DRIVER)),
            passengerSeat = SeatHeat.fromLevel(map.getInt(PASSENGER)),
            rearSeats = SeatHeat.fromLevel(map.getInt(REAR_SEATS)),
        ).normalized()
    }

    /** The store is local, so this only bites if Play Services is wedged. */
    private const val PULL_TIMEOUT_SECONDS = 3L
}
