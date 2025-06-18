import os
from flask import Flask, request, jsonify
from hyundai_kia_connect_api.HyundaiBlueLink import HyundaiBlueLink
from hyundai_kia_connect_api.const import Brand, Region
from hyundai_kia_connect_api.exceptions import AuthenticationError
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

app = Flask(__name__)

# Get credentials from environment variables
USERNAME = os.environ.get('KIA_USERNAME')
PASSWORD = os.environ.get('KIA_PASSWORD')
PIN = os.environ.get('KIA_PIN')

if USERNAME is None or PASSWORD is None or PIN is None:
    raise ValueError("Missing credentials! Check your environment variables.")

# Initialize HyundaiBlueLink API for Kia using Region.US
vehicle_manager = HyundaiBlueLink(
    username=USERNAME,
    password=PASSWORD,
    pin=str(PIN),
    region=Region.US,  # Try Region.KR if US doesn't return full data
    brand=Brand.KIA,
    language="en"
)

# Refresh the token and update vehicle states
try:
    print("Attempting to authenticate and refresh token...")
    vehicle_manager.check_and_refresh_token()
    print("Token refreshed successfully.")
    print("Updating vehicle states...")
    vehicle_manager.update_all_vehicles_with_cached_state()
    print(f"Connected! Found {len(vehicle_manager.vehicles)} vehicle(s).")
except AuthenticationError as e:
    print(f"Failed to authenticate: {e}")
    exit(1)
except Exception as e:
    print(f"Unexpected error during initialization: {e}")
    exit(1)

# Secret key for security
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("Missing SECRET_KEY environment variable.")

# VEHICLE_ID setup
VEHICLE_ID = os.environ.get("VEHICLE_ID")
if not VEHICLE_ID:
    if not vehicle_manager.vehicles:
        raise ValueError("No vehicles found in the account. Please ensure your Kia account has at least one vehicle.")
    VEHICLE_ID = next(iter(vehicle_manager.vehicles.keys()))
    print(f"No VEHICLE_ID provided. Using the first vehicle found: {VEHICLE_ID}")

@app.before_request
def log_request_info():
    print(f"Incoming request: {request.method} {request.url}")

@app.route('/', methods=['GET'])
def root():
    return jsonify({"status": "Welcome to the Kia Vehicle Control API (Bluelink version)"}), 200

@app.route('/status', methods=['POST'])
def vehicle_status():
    print("Received request to /status")

    if request.headers.get("Authorization") != SECRET_KEY:
        return jsonify({"error": "Unauthorized"}), 403

    try:
        vehicle_manager.update_all_vehicles_with_cached_state()
        vehicle = vehicle_manager.get_vehicle(VEHICLE_ID)
        status = vehicle_manager.get_cached_vehicle_status(vehicle)
        ev_status = status.get("vehicleStatus", {}).get("evStatus", {})

        dur = ev_status.get("remainTime2", {}).get("value") or 0
        pct = ev_status.get("batteryCharge", {}).get("value") or 0
        actual_kw = ev_status.get("chargingPower")
        estimated_kw = ev_status.get("estimatedChargingPow")

        # Format ETA if duration is available
        eta_time = eta_duration = None
        if dur > 0:
            now = datetime.now(ZoneInfo("America/Toronto"))
            eta_dt = now + timedelta(minutes=dur)
            eta_time = eta_dt.strftime("%-I:%M %p")
            h, m = divmod(dur, 60)
            eta_duration = f"{h}h {m}m remaining"

        resp = {
            "battery_percentage": int(pct),
            "charge_duration": int(dur),
            "charging_eta": eta_time,
            "charging_duration_formatted": eta_duration,
            "actual_charging_power_kw": actual_kw,
            "estimated_charging_power_kw": estimated_kw,
            "is_charging": bool(ev_status.get("batteryChargeStatus")),
            "plugged_in": bool(ev_status.get("plugged")),
            "doors": {},
        }

        return jsonify(resp), 200

    except Exception as e:
        import traceback
        print(f"❌ Error in /status: {e}")
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    print("Starting Kia Vehicle Control API (Bluelink version)...")
    app.run(host="0.0.0.0", port=8080)
