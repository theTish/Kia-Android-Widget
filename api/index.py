import os
from flask import Flask, request, jsonify
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from hyundai_kia_connect_api import KiaUvoApiCA
from hyundai_kia_connect_api.vehicle_manager import VehicleManager

app = Flask(__name__)

USERNAME = os.environ.get("KIA_USERNAME")
PASSWORD = os.environ.get("KIA_PASSWORD")
PIN = os.environ.get("KIA_PIN")
SECRET_KEY = os.environ.get("SECRET_KEY")

vehicle_manager = VehicleManager(
    KiaUvoApiCA(
        username=USERNAME,
        password=PASSWORD,
        pin=PIN,
        region="CA",
        brand="KIA"
    )
)

VEHICLE_ID = None

def get_vehicle():
    global VEHICLE_ID
    vehicle_manager.update_all_vehicles_with_cached_state()
    if VEHICLE_ID is None:
        VEHICLE_ID = vehicle_manager.get_all_vehicle_ids()[0]
    return vehicle_manager.get_vehicle(VEHICLE_ID)

@app.route("/status", methods=["POST"])
def vehicle_status():
    if request.headers.get("Authorization") != SECRET_KEY:
        return jsonify({"error": "Unauthorized"}), 403

    try:
        vehicle = get_vehicle()

        # Charge limits
        charge_limits = {}
        try:
            raw = vehicle_manager.api._get_charge_limits(vehicle_manager.token, vehicle)
            charge_limits = raw[0] if isinstance(raw, list) else raw
        except Exception as e:
            print(f"⚠️ Failed to get charge limits: {e}")

        # Plug type
        try:
            plug_type = int(vehicle.ev_battery_is_plugged_in)
        except (ValueError, TypeError):
            plug_type = 0

        # Charge limit fallbacks
        ac_limit = int(charge_limits.get("ev_charge_limits_ac", 100))
        dc_limit = int(charge_limits.get("ev_charge_limits_dc", 100))
        target_limit = dc_limit if plug_type == 1 else ac_limit

        # Raw values
        dur = vehicle.ev_estimated_current_charge_duration or 0
        pct = vehicle.ev_battery_percentage or 0

        # Estimated charging power
        estimated_kw = None
        if plug_type in [1, 2] and dur > 0 and target_limit > pct:
            battery_capacity_kwh = 77.4
            fraction = (target_limit - pct) / 100
            estimated_kw = round((battery_capacity_kwh * fraction) / (dur / 60), 1)

        # Actual charging power
        actual_kw = None
        try:
            current = float(vehicle.ev_charging_current)
            voltage = float(vehicle.ev_charging_voltage)
            actual_kw = round((current * voltage) / 1000, 1)
        except Exception as e:
            print(f"⚠️ Couldn't compute actual power: {e}")

        # ETA formatting
        eta_time = eta_duration = None
        if plug_type and dur > 0:
            now = datetime.now(ZoneInfo("America/Toronto"))
            eta_dt = now + timedelta(minutes=dur)
            eta_time = eta_dt.strftime("%-I:%M %p")
            h, m = divmod(dur, 60)
            eta_duration = f"{h}h {m}m remaining"

        # Final response
        return jsonify({
            "battery_percentage": int(pct),
            "battery_12v": int(vehicle.car_battery_percentage),
            "charge_duration": int(dur),
            "charging_eta": eta_time,
            "charging_duration_formatted": eta_duration,
            "estimated_charging_power_kw": estimated_kw,
            "actual_charging_power_kw": actual_kw,
            "target_charge_limit": target_limit,
            "is_charging": bool(vehicle.ev_battery_is_charging),
            "plugged_in": bool(plug_type > 0),
            "is_locked": bool(vehicle.is_locked),
            "engine_running": bool(vehicle.engine_is_running),
            "doors": {
                "front_left": bool(int(vehicle.front_left_door_is_open)),
                "front_right": bool(int(vehicle.front_right_door_is_open)),
                "back_left": bool(int(vehicle.back_left_door_is_open)),
                "back_right": bool(int(vehicle.back_right_door_is_open)),
                "trunk": bool(vehicle.trunk_is_open),
                "hood": bool(vehicle.hood_is_open)
            }
        }), 200

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500
