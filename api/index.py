import os
from flask import Flask, request, jsonify
from hyundai_kia_connect_api.KiaUvoApiCA import KiaUvoApiCA
from hyundai_kia_connect_api.const import Brand, Region

app = Flask(__name__)

USERNAME = os.getenv("KIA_USERNAME")
PASSWORD = os.getenv("KIA_PASSWORD")
PIN = os.getenv("KIA_PIN")
SECRET_KEY = os.getenv("SECRET_KEY")

client = KiaUvoApiCA(username=USERNAME, password=PASSWORD, pin=PIN, region=Region.CA, brand=Brand.KIA)

@app.route("/status", methods=["POST"])
def status():
    if request.headers.get("Authorization") != SECRET_KEY:
        return jsonify({"error": "Unauthorized"}), 403

    try:
        vehicle_list = client.get_vehicles()
        vehicle = vehicle_list[0]

        status = client.get_cached_vehicle_status(vehicle)

        battery = status.get("battery", {})
        charging = status.get("charging", {})

        return jsonify({
            "battery_percentage": battery.get("batteryLevel", "unknown"),
            "is_charging": charging.get("isCharging", False),
            "plugged_in": charging.get("isPluggedIn", False),
            "estimated_charging_power_kw": charging.get("estimatedChargingPower", None),
            "charge_duration": charging.get("chargeTimeRemaining", None),
            "charging_eta": charging.get("chargingEndTime", None),
            "target_charge_limit": charging.get("targetSOCLevel", 100)
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500
