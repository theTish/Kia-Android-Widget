
import os
from flask import Flask, request, jsonify
from hyundai_kia_connect_api import VehicleManager, ClimateRequestOptions
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

# Initialize Vehicle Manager
vehicle_manager = VehicleManager(
    region=2,  # North America region
    brand=1,   # KIA brand
    username=USERNAME,
    password=PASSWORD,
    pin=str(PIN)
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

# Secret key for security - moved to environment variables
SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("Missing SECRET_KEY environment variable.")

# Dynamically fetch the first vehicle ID if VEHICLE_ID is not set
VEHICLE_ID = os.environ.get("VEHICLE_ID")
if not VEHICLE_ID:
    if not vehicle_manager.vehicles:
        raise ValueError("No vehicles found in the account. Please ensure your Kia account has at least one vehicle.")
    # Fetch the first vehicle ID
    VEHICLE_ID = next(iter(vehicle_manager.vehicles.keys()))
    print(f"No VEHICLE_ID provided. Using the first vehicle found: {VEHICLE_ID}")

# Log incoming requests
@app.before_request
def log_request_info():
    print(f"Incoming request: {request.method} {request.url}")

# Root endpoint
@app.route('/', methods=['GET'])
def root():
    return jsonify({"status": "Welcome to the Kia Vehicle Control API"}), 200

# List vehicles endpoint
@app.route('/list_vehicles', methods=['GET'])
def list_vehicles():
    print("Received request to /list_vehicles")

    if request.headers.get("Authorization") != SECRET_KEY:
        print("Unauthorized request: Missing or incorrect Authorization header")
        return jsonify({"error": "Unauthorized"}), 403

    try:
        print("Refreshing vehicle states...")
        vehicle_manager.update_all_vehicles_with_cached_state()

        vehicles = vehicle_manager.vehicles
        print(f"Vehicles data: {vehicles}")  # Log the vehicles data

        if not vehicles:
            print("No vehicles found in the account")
            return jsonify({"error": "No vehicles found"}), 404

        # Iterate over the dictionary values (Vehicle objects)
        vehicle_list = [
            {
                "name": v.name,
                "id": v.id,
                "model": v.model,
                "year": v.year
            }
            for v in vehicles.values()  # Use .values() to get the Vehicle objects
        ]

        if not vehicle_list:
            print("No valid vehicles found in the account")
            return jsonify({"error": "No valid vehicles found"}), 404

        print(f"Returning vehicle list: {vehicle_list}")
        return jsonify({"status": "Success", "vehicles": vehicle_list}), 200
    except Exception as e:
        print(f"Error in /list_vehicles: {e}")
        return jsonify({"error": str(e)}), 500

#Vehicle Status Endpoint
@app.route('/status', methods=['POST'])
def vehicle_status():
    print("Received request to /status")

    if request.headers.get("Authorization") != SECRET_KEY:
        return jsonify({"error": "Unauthorized"}), 403

    try:
        # ── Refresh vehicle state ──
        vehicle_manager.update_all_vehicles_with_cached_state()
        vehicle = vehicle_manager.get_vehicle(VEHICLE_ID)

        # ── Grab raw charge limits from the API ──
        charge_limits = {}
        try:
            raw = vehicle_manager.api._get_charge_limits(vehicle_manager.token, vehicle)
            charge_limits = raw[0] if isinstance(raw, list) else raw
            print("⚙️ Charge limits raw:", charge_limits)
        except Exception as e:
            print(f"❌ Failed to get charge limits: {e}")

        # ── Determine plug type ──
        try:
            plug_type = int(vehicle.ev_battery_is_plugged_in)
        except (ValueError, TypeError):
            plug_type = 0
        print(f"🔌 Plugged in raw: {vehicle.ev_battery_is_plugged_in} → {plug_type}")

        # ── Parse dynamic AC/DC limits (fallback to 100) ──
        try:
            ac_limit = int(charge_limits.get("ev_charge_limits_ac", 100))
        except (ValueError, TypeError):
            ac_limit = 100
        try:
            dc_limit = int(charge_limits.get("ev_charge_limits_dc", 100))
        except (ValueError, TypeError):
            dc_limit = 100

        # ── Choose the right limit ──
        if plug_type == 1:         # DC
            target_limit = dc_limit
        elif plug_type == 2:       # AC
            target_limit = ac_limit
        else:
            target_limit = ac_limit  # default if unplugged
        print(f"🎯 Using target charge limit: {target_limit}%")

        # ── Rest of your calculations ──
        dur = vehicle.ev_estimated_current_charge_duration
        pct = vehicle.ev_battery_percentage

        # Estimated power (kW) from battery % math
        estimated_kw = None
        if plug_type in [1, 2] and dur > 0 and target_limit > pct:
            battery_capacity_kwh = 77.4
            fraction = (target_limit - pct) / 100
            estimated_kw = round((battery_capacity_kwh * fraction) / (dur / 60), 1)
        print(f"⚡ Estimated power (calculated): {estimated_kw} kW")

        # Actual power from current & voltage
        actual_kw = None
        try:
            current = float(vehicle.ev_charging_current)
            voltage = float(vehicle.ev_charging_voltage)
            actual_kw = round((current * voltage) / 1000, 1)
            print(f"⚡ Actual power (calculated): {actual_kw} kW")
        except Exception as e:
            print(f"❌ Couldn’t compute actual power: {e}")

        # ── Pull raw values from evStatus (if available) ──
        try:
            raw_status = vehicle_manager.api._get_cached_vehicle_status(vehicle_manager.token, vehicle)
            ev_status = raw_status.get("vehicleStatus", {}).get("evStatus", {})
        except Exception as e:
            print(f"❌ Could not fetch evStatus: {e}")
            ev_status = {}
        
        api_charging_power = ev_status.get("chargingPower")
        api_estimated_power = ev_status.get("estimatedChargingPow")
        
        print(f"⚙️ API chargingPower: {api_charging_power}, estimatedChargingPow: {api_estimated_power}")
        
        # Fallback logic if actual_kw is missing
        actual_kw = actual_kw or api_charging_power
        estimated_kw = estimated_kw or api_estimated_power

        # ETA in Toronto time
        eta_time = eta_duration = None
        if plug_type and dur > 0:
            now = datetime.now(ZoneInfo("America/Toronto"))
            eta_dt = now + timedelta(minutes=dur)
            eta_time = eta_dt.strftime("%-I:%M %p")
            h, m = divmod(dur, 60)
            eta_duration = f"{h}h {m}m remaining"

        # Build response
        resp = {
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
        }

        return jsonify(resp), 200

    except Exception as e:
        import traceback
        print(f"❌ Error in /status: {e}")
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

# Unlock car endpoint
@app.route('/unlock_car', methods=['POST'])
def unlock_car():
    print("Received request to /unlock_car")

    if request.headers.get("Authorization") != SECRET_KEY:
        print("Unauthorized request: Missing or incorrect Authorization header")
        return jsonify({"error": "Unauthorized"}), 403

    try:
        print("Refreshing vehicle states...")
        vehicle_manager.update_all_vehicles_with_cached_state()

        # Unlock the vehicle using the VehicleManager's unlock method
        result = vehicle_manager.unlock(VEHICLE_ID)
        print(f"Unlock result: {result}")

        return jsonify({"status": "Car unlocked", "result": result}), 200
    except Exception as e:
        print(f"Error in /unlock_car: {e}")
        return jsonify({"error": str(e)}), 500

# Lock car endpoint
@app.route('/lock_car', methods=['POST'])
def lock_car():
    print("Received request to /lock_car")

    if request.headers.get("Authorization") != SECRET_KEY:
        print("Unauthorized request: Missing or incorrect Authorization header")
        return jsonify({"error": "Unauthorized"}), 403

    try:
        print("Refreshing vehicle states...")
        vehicle_manager.update_all_vehicles_with_cached_state()

        # Lock the vehicle using the VehicleManager's lock method
        result = vehicle_manager.lock(VEHICLE_ID)
        print(f"Lock result: {result}")

        return jsonify({"status": "Car locked", "result": result}), 200
    except Exception as e:
        print(f"Error in /lock_car: {e}")
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    print("Starting Kia Vehicle Control API...")
    app.run(host="0.0.0.0", port=8080)

@app.route('/lock_status', methods=['GET'])
def lock_status():
    print("Received request to /lock_status")

    if request.headers.get("Authorization") != SECRET_KEY:
        print("Unauthorized request: Missing or incorrect Authorization header")
        return jsonify({"error": "Unauthorized"}), 403

    try:
        vehicle_manager.update_all_vehicles_with_cached_state()

        vehicle = next(iter(vehicle_manager.vehicles.values()))
        is_locked = vehicle.is_locked  # This should be a boolean (True/False)

        print(f"Lock status: {'Locked' if is_locked else 'Unlocked'}")
        return jsonify({"is_locked": is_locked}), 200

    except Exception as e:
        print(f"Error in /lock_status: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/debug_vehicle', methods=['POST'])
def debug_vehicle():
    print("Received request to /debug_vehicle")

    if request.headers.get("Authorization") != SECRET_KEY:
        return jsonify({"error": "Unauthorized"}), 403

    try:
        vehicle_manager.update_all_vehicles_with_cached_state()
        vehicle = vehicle_manager.get_vehicle(VEHICLE_ID)

        # ✅ Access the raw private vehicle data
        raw_data = getattr(vehicle, "_vehicle_data", {})
        ev_status = raw_data.get("vehicleStatus", {}).get("evStatus", {})

        print("🔍 Found evStatus keys:", list(ev_status.keys()))

        return jsonify({
            "ev_status_raw": ev_status,
            "keys": list(ev_status.keys()),
        }), 200

    except Exception as e:
        import traceback
        print(f"❌ Error in /debug_vehicle: {e}")
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500

