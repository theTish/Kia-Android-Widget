import os
from flask import Flask, request, jsonify
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from hyundai_kia_connect_api.HyundaiBlueLink import HyundaiBlueLink

# ── Setup ─────────────────────────────────────────────────────────────
app = Flask(__name__)
SECRET_KEY = os.environ.get("SECRET_KEY")
KIA_USERNAME = os.environ.get("KIA_USERNAME")
KIA_PASSWORD = os.environ.get("KIA_PASSWORD")
KIA_PIN = os.environ.get("KIA_PIN")

# ── Initialize API client ─────────────────────────────────────────────
api = HyundaiBlueLink(username=KIA_USERNAME, password=KIA_PASSWORD, pin=KIA_PIN, brand="KIA", region="CA")
api.login()
vehicles = api.get_vehicles()
vehicle = vehicles[0]

# ── Endpoint ──────────────────────────────────────────────────────────
@app.route('/status', methods=['POST'])
def vehicle_status():
    if request.headers.get("Authorization") != SECRET_KEY:
        return jsonify({"error": "Unauthorized"}), 403

    try:
        vehicle_status = api.get_vehicle_status(vehicle)

        pct = vehicle_status.ev_battery_percentage
        dur = vehicle_status.ev_estimated_current_charge_duration
        plugged_in = bool(vehicle_status.ev_battery_is_plugged_in)
        charging = bool(vehicle_status.ev_battery_is_charging)
        limit = 100  # Default charge target

        # ── Estimate charging power ─────────────────────────────
        estimated_kw = None
        if charging and dur > 0 and pct < limit:
            battery_capacity_kwh = 77.4
            fraction = (limit - pct) / 100
            estimated_kw = round((battery_capacity_kwh * fraction) / (dur / 60), 1)

        actual_kw = None
        try:
            current = float(vehicle_status.ev_charging_current)
            voltage = float(vehicle_status.ev_charging_voltage)
            actual_kw = round((current * voltage) / 1000, 1)
        except Exception:
            pass

        # ── ETA Calculation ─────────────────────────────────────
        eta_time = eta_duration = None
        if charging and dur > 0:
            now = datetime.now(ZoneInfo("America/Toronto"))
            eta_dt = now + timedelta(minutes=dur)
            eta_time = eta_dt.strftime("%-I:%M %p")
            h, m = divmod(dur, 60)
            eta_duration = f"{h}h {m}m remaining"

        # ── Response ────────────────────────────────────────────
        return jsonify({
            "battery_percentage": int(pct),
            "battery_12v": int(vehicle_status.car_battery_percentage),
            "charge_duration": int(dur),
            "charging_eta": eta_time,
            "charging_duration_formatted": eta_duration,
            "estimated_charging_power_kw": estimated_kw,
            "actual_charging_power_kw": actual_kw,
            "target_charge_limit": limit,
            "is_charging": charging,
            "plugged_in": plugged_in,
            "is_locked": bool(vehicle_status.is_locked),
            "engine_running": bool(vehicle_status.engine_is_running),
            "doors": {
                "front_left": bool(int(vehicle_status.front_left_door_is_open)),
                "front_right": bool(int(vehicle_status.front_right_door_is_open)),
                "back_left": bool(int(vehicle_status.back_left_door_is_open)),
                "back_right": bool(int(vehicle_status.back_right_door_is_open)),
                "trunk": bool(vehicle_status.trunk_is_open),
                "hood": bool(vehicle_status.hood_is_open)
            }
        }), 200

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500
