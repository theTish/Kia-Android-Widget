
import os
import logging
from functools import wraps
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from flask import Flask, request, jsonify
from hyundai_kia_connect_api import VehicleManager, ClimateRequestOptions
from hyundai_kia_connect_api.exceptions import AuthenticationError

# ── Constants ──
REGION_NORTH_AMERICA = 2
BRAND_KIA = 1
DEFAULT_BATTERY_CAPACITY_KWH = 77.4
CACHE_TTL_SECONDS = 30
MAX_REQUESTS_PER_MINUTE = 60

# ── Flask App Setup ──
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", os.urandom(24).hex())
app.config['JSON_SORT_KEYS'] = False

# ── Logging Configuration ──
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# ── Environment Variables ──
USERNAME = os.environ.get('KIA_USERNAME')
PASSWORD = os.environ.get('KIA_PASSWORD')
PIN = os.environ.get('KIA_PIN')  # Keep as string to preserve leading zeros
SECRET_KEY = os.environ.get("SECRET_KEY")
BATTERY_CAPACITY_KWH = float(os.environ.get("BATTERY_CAPACITY_KWH") or DEFAULT_BATTERY_CAPACITY_KWH)

if USERNAME is None or PASSWORD is None or PIN is None:
    raise ValueError("Missing credentials! Check KIA_USERNAME, KIA_PASSWORD, and KIA_PIN environment variables.")

if not SECRET_KEY:
    raise ValueError("Missing SECRET_KEY environment variable.")

# Debug: Log PIN length (not the actual PIN for security)
logger.info(f"KIA_PIN length: {len(PIN)} characters")

# ── Initialize Vehicle Manager ──
vehicle_manager = VehicleManager(
    region=REGION_NORTH_AMERICA,
    brand=BRAND_KIA,
    username=USERNAME,
    password=PASSWORD,
    pin=PIN  # Already a string from environment
)

# ── Authenticate and Initialize ──
try:
    logger.info("Attempting to authenticate and refresh token...")
    vehicle_manager.check_and_refresh_token()
    logger.info("Token refreshed successfully.")
    logger.info("Updating vehicle states...")
    vehicle_manager.update_all_vehicles_with_cached_state()
    logger.info(f"Connected! Found {len(vehicle_manager.vehicles)} vehicle(s).")
except AuthenticationError as e:
    logger.error(f"Failed to authenticate: {e}")
    exit(1)
except Exception as e:
    logger.error(f"Unexpected error during initialization: {e}")
    exit(1)

# ── Dynamically fetch VEHICLE_ID ──
VEHICLE_ID = os.environ.get("VEHICLE_ID")
if not VEHICLE_ID:
    if not vehicle_manager.vehicles:
        raise ValueError("No vehicles found in the account. Please ensure your Kia account has at least one vehicle.")
    VEHICLE_ID = next(iter(vehicle_manager.vehicles.keys()))
    logger.info(f"No VEHICLE_ID provided. Using the first vehicle found: {VEHICLE_ID}")

# ── Cache Management ──
vehicle_state_cache = {
    "last_update": None,
    "data": None
}

def get_cached_vehicle_state():
    """Get vehicle state with caching."""
    now = datetime.now()
    if (vehicle_state_cache["last_update"] is None or
        (now - vehicle_state_cache["last_update"]).total_seconds() > CACHE_TTL_SECONDS):
        logger.info("Cache expired or empty, refreshing vehicle states...")
        vehicle_manager.update_all_vehicles_with_cached_state()
        vehicle_state_cache["last_update"] = now
    return vehicle_manager.get_vehicle(VEHICLE_ID)

# ── Rate Limiting (Simple implementation) ──
rate_limit_store = {}

def check_rate_limit(client_id: str, max_requests: int = MAX_REQUESTS_PER_MINUTE) -> bool:
    """Simple rate limiting check."""
    now = datetime.now()
    minute_ago = now - timedelta(minutes=1)

    # Clean old entries
    rate_limit_store[client_id] = [
        ts for ts in rate_limit_store.get(client_id, []) if ts > minute_ago
    ]

    # Check limit
    if len(rate_limit_store.get(client_id, [])) >= max_requests:
        return False

    # Add current request
    if client_id not in rate_limit_store:
        rate_limit_store[client_id] = []
    rate_limit_store[client_id].append(now)

    return True

# ── Token Refresh Helper ──
def refresh_token_if_needed():
    """Refresh token if needed."""
    try:
        vehicle_manager.check_and_refresh_token()
    except Exception as e:
        logger.warning(f"Token refresh check failed: {e}")

# ── Authorization Decorator ──
def require_auth(f):
    """Decorator to require authorization header."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization")
        if auth_header != SECRET_KEY:
            logger.warning(f"Unauthorized request to {request.path} from {request.remote_addr}")
            return jsonify({"error": "Unauthorized"}), 403

        # Rate limiting
        client_id = request.remote_addr
        if not check_rate_limit(client_id):
            logger.warning(f"Rate limit exceeded for {client_id}")
            return jsonify({"error": "Rate limit exceeded. Please try again later."}), 429

        return f(*args, **kwargs)
    return decorated

# ── Request Logging ──
@app.before_request
def log_request_info():
    logger.info(f"Incoming request: {request.method} {request.url} from {request.remote_addr}")

# ── Health Check Endpoint ──
@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint for monitoring."""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now(ZoneInfo("America/Toronto")).isoformat(),
        "vehicles_count": len(vehicle_manager.vehicles)
    }), 200

# ── Root Endpoint ──
@app.route('/', methods=['GET'])
def root():
    """Root endpoint."""
    return jsonify({"status": "Welcome to the Kia Vehicle Control API"}), 200

# ── List Vehicles Endpoint ──
@app.route('/list_vehicles', methods=['GET'])
@require_auth
def list_vehicles():
    """List all vehicles in the account."""
    logger.info("Received request to /list_vehicles")

    try:
        refresh_token_if_needed()
        vehicle = get_cached_vehicle_state()
        vehicles = vehicle_manager.vehicles

        if not vehicles:
            logger.warning("No vehicles found in the account")
            return jsonify({"error": "No vehicles found"}), 404

        vehicle_list = [
            {
                "name": v.name,
                "id": v.id,
                "model": v.model,
                "year": v.year
            }
            for v in vehicles.values()
        ]

        if not vehicle_list:
            logger.warning("No valid vehicles found in the account")
            return jsonify({"error": "No valid vehicles found"}), 404

        logger.info(f"Returning vehicle list: {vehicle_list}")
        return jsonify({"status": "Success", "vehicles": vehicle_list}), 200
    except Exception as e:
        logger.error(f"Error in /list_vehicles: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

# ── Vehicle Status Endpoint ──
@app.route('/status', methods=['POST'])
@require_auth
def vehicle_status():
    """Get current vehicle status."""
    logger.info("Received request to /status")

    try:
        refresh_token_if_needed()
        vehicle = get_cached_vehicle_state()

        # ── Grab raw charge limits from the API ──
        charge_limits = {}
        try:
            raw = vehicle_manager.api._get_charge_limits(vehicle_manager.token, vehicle)
            charge_limits = raw[0] if isinstance(raw, list) else raw
            logger.info(f"Charge limits raw: {charge_limits}")
        except Exception as e:
            logger.error(f"Failed to get charge limits: {e}")

        # ── Determine plug type ──
        try:
            plug_type = int(vehicle.ev_battery_is_plugged_in)
        except (ValueError, TypeError):
            plug_type = 0
        logger.info(f"Plugged in raw: {vehicle.ev_battery_is_plugged_in} → {plug_type}")

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
        logger.info(f"Using target charge limit: {target_limit}%")

        # ── Rest of calculations ──
        dur = vehicle.ev_estimated_current_charge_duration
        pct = vehicle.ev_battery_percentage

        # Estimated power (kW) from battery % math
        estimated_kw = None
        if plug_type in [1, 2] and dur > 0 and target_limit > pct:
            fraction = (target_limit - pct) / 100
            estimated_kw = round((BATTERY_CAPACITY_KWH * fraction) / (dur / 60), 1)
        logger.info(f"Estimated power (calculated): {estimated_kw} kW")

        # Actual power from current & voltage
        actual_kw = None
        try:
            current = float(vehicle.ev_charging_current)
            voltage = float(vehicle.ev_charging_voltage)
            actual_kw = round((current * voltage) / 1000, 1)
            logger.info(f"Actual power (calculated): {actual_kw} kW")
        except Exception as e:
            logger.error(f"Couldn't compute actual power: {e}")

        # ── Pull raw values from evStatus (if available) ──
        try:
            raw_status = vehicle_manager.api._get_cached_vehicle_status(vehicle_manager.token, vehicle)
            ev_status = raw_status.get("vehicleStatus", {}).get("evStatus", {})
        except Exception as e:
            logger.error(f"Could not fetch evStatus: {e}")
            ev_status = {}

        api_charging_power = ev_status.get("chargingPower")
        api_estimated_power = ev_status.get("estimatedChargingPow")

        logger.info(f"API chargingPower: {api_charging_power}, estimatedChargingPow: {api_estimated_power}")

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
        logger.error(f"Error in /status: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

# ── Lock Status Endpoint ──
@app.route('/lock_status', methods=['GET'])
@require_auth
def lock_status():
    """Get vehicle lock status."""
    logger.info("Received request to /lock_status")

    try:
        refresh_token_if_needed()
        vehicle = get_cached_vehicle_state()
        is_locked = vehicle.is_locked

        logger.info(f"Lock status: {'Locked' if is_locked else 'Unlocked'}")
        return jsonify({"is_locked": is_locked}), 200

    except Exception as e:
        logger.error(f"Error in /lock_status: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

# ── Unlock Car Endpoint ──
@app.route('/unlock_car', methods=['POST'])
@require_auth
def unlock_car():
    """Unlock the vehicle."""
    logger.info("Received request to /unlock_car")

    try:
        refresh_token_if_needed()
        vehicle_manager.update_all_vehicles_with_cached_state()

        result = vehicle_manager.unlock(VEHICLE_ID)
        logger.info(f"Unlock result: {result}")

        return jsonify({"status": "Car unlocked", "result": result}), 200
    except Exception as e:
        logger.error(f"Error in /unlock_car: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

# ── Lock Car Endpoint ──
@app.route('/lock_car', methods=['POST'])
@require_auth
def lock_car():
    """Lock the vehicle."""
    logger.info("Received request to /lock_car")

    try:
        refresh_token_if_needed()
        vehicle_manager.update_all_vehicles_with_cached_state()

        result = vehicle_manager.lock(VEHICLE_ID)
        logger.info(f"Lock result: {result}")

        return jsonify({"status": "Car locked", "result": result}), 200
    except Exception as e:
        logger.error(f"Error in /lock_car: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

# ── Start Climate Endpoint ──
@app.route('/start_climate', methods=['POST'])
@require_auth
def start_climate():
    """Start climate control."""
    logger.info("Received request to /start_climate")

    try:
        refresh_token_if_needed()
        vehicle_manager.update_all_vehicles_with_cached_state()

        data = request.get_json() or {}
        logger.info(f"Incoming payload: {data}")

        # ── Input Validation ──
        try:
            set_temp = float(data.get("set_temp", 21))
            if not 16 <= set_temp <= 30:  # Reasonable temperature range
                return jsonify({"error": "Temperature must be between 16-30°C"}), 400
        except (ValueError, TypeError):
            return jsonify({"error": "Invalid temperature value"}), 400

        try:
            duration = int(data.get("duration", 10))
            if not 5 <= duration <= 30:  # Reasonable duration range
                return jsonify({"error": "Duration must be between 5-30 minutes"}), 400
        except (ValueError, TypeError):
            return jsonify({"error": "Invalid duration value"}), 400

        # Validate seat heating levels (0-3)
        for seat in ["front_left_seat", "front_right_seat", "rear_left_seat", "rear_right_seat"]:
            try:
                level = int(data.get(seat, 0))
                if not 0 <= level <= 3:
                    return jsonify({"error": f"{seat} must be between 0-3"}), 400
            except (ValueError, TypeError):
                return jsonify({"error": f"Invalid {seat} value"}), 400

        # Validate steering wheel heating (0-3)
        try:
            steering = int(data.get("steering_wheel", 0))
            if not 0 <= steering <= 3:
                return jsonify({"error": "steering_wheel must be between 0-3"}), 400
        except (ValueError, TypeError):
            return jsonify({"error": "Invalid steering_wheel value"}), 400

        # Create ClimateRequestOptions object
        climate_options = ClimateRequestOptions(
            climate=bool(data.get("climate", True)),
            set_temp=set_temp,
            defrost=bool(data.get("defrost", False)),
            heating=int(data.get("heating", 1)),
            duration=duration,
            front_left_seat=int(data.get("front_left_seat", 0)),
            front_right_seat=int(data.get("front_right_seat", 0)),
            rear_left_seat=int(data.get("rear_left_seat", 0)),
            rear_right_seat=int(data.get("rear_right_seat", 0)),
            steering_wheel=steering
        )

        result = vehicle_manager.start_climate(VEHICLE_ID, climate_options)
        logger.info(f"Start climate result: {result}")

        return jsonify({"status": "Climate started", "result": result}), 200
    except Exception as e:
        logger.error(f"Error in /start_climate: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

# ── Stop Climate Endpoint ──
@app.route('/stop_climate', methods=['POST'])
@require_auth
def stop_climate():
    """Stop climate control."""
    logger.info("Received request to /stop_climate")

    try:
        refresh_token_if_needed()
        vehicle_manager.update_all_vehicles_with_cached_state()

        result = vehicle_manager.stop_climate(VEHICLE_ID)
        logger.info(f"Stop climate result: {result}")

        return jsonify({"status": "Climate stopped", "result": result}), 200
    except Exception as e:
        logger.error(f"Error in /stop_climate: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

# ── Debug Vehicle Endpoint ──
@app.route('/debug_vehicle', methods=['POST'])
@require_auth
def debug_vehicle():
    """Debug endpoint to view raw vehicle data."""
    logger.info("Received request to /debug_vehicle")

    try:
        refresh_token_if_needed()
        vehicle_manager.update_all_vehicles_with_cached_state()
        vehicle = vehicle_manager.get_vehicle(VEHICLE_ID)

        # Access the raw private vehicle data
        raw_data = getattr(vehicle, "_vehicle_data", {})
        ev_status = raw_data.get("vehicleStatus", {}).get("evStatus", {})

        logger.info(f"Found evStatus keys: {list(ev_status.keys())}")

        return jsonify({
            "ev_status_raw": ev_status,
            "keys": list(ev_status.keys()),
        }), 200

    except Exception as e:
        logger.error(f"Error in /debug_vehicle: {e}", exc_info=True)
        return jsonify({"error": str(e)}), 500

# ── Error Handlers ──
@app.errorhandler(404)
def not_found(e):
    """Handle 404 errors."""
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def internal_error(e):
    """Handle 500 errors."""
    logger.error(f"Internal server error: {e}", exc_info=True)
    return jsonify({"error": "Internal server error"}), 500

# ── Main Entry Point ──
if __name__ == "__main__":
    logger.info("Starting Kia Vehicle Control API...")
    app.run(host="0.0.0.0", port=8080, debug=False)
