import os
from flask import Flask, request, jsonify
from hyundai_kia_connect_api import VehicleManager

app = Flask(__name__)

USERNAME = os.getenv("KIA_USERNAME")
PASSWORD = os.getenv("KIA_PASSWORD")
PIN = os.getenv("KIA_PIN")
SECRET_KEY = os.getenv("SECRET_KEY")

vehicle_manager = VehicleManager(
    region=2,  # North America
    brand=1,   # KIA
    username=USERNAME,
    password=PASSWORD,
    pin=str(PIN)
)

@app.route("/", methods=["GET"])
def root():
    return jsonify({"status": "API is running"}), 200

@app.route("/status", methods=["POST"])
def status():
    if request.headers.get("Authorization") != SECRET_KEY:
        return jsonify({"error": "Unauthorized"}), 403

    try:
        vehicle_manager.update_all_vehicles_with_cached_state()
        vehicle = vehicle_manager.get_first_vehicle()
        data = getattr(vehicle, "_vehicle_data", {})
        ev_status = data.get("vehicleStatus", {}).get("evStatus", {})

        return jsonify({
            "battery_percentage": ev_status.get("batteryLevel", "unknown"),
            "is_charging": ev_status.get("charging", False),
            "plugged_in": ev_status.get("plugged", False),
            "estimated_charging_power_kw": ev_status.get("estimatedChargingPow", None),
            "charge_duration": ev_status.get("remainTime2", None),
            "charging_eta": ev_status.get("chargingEndTime", None),
            "target_charge_limit": ev_status.get("targetSOCLevel", None),
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500
