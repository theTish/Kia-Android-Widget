import os
import logging
from functools import wraps
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from flask import Flask, request, jsonify

# ── Constants ──
# Region codes: 1=Europe, 2=Canada, 3=USA, 4=China, 5=Australia
DEFAULT_REGION = 2  # Canada
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
REGION = int(os.environ.get("KIA_REGION") or DEFAULT_REGION)

# Debug: Log PIN length (not the actual PIN for security)
if PIN:
    logger.info(f"KIA_PIN length: {len(PIN)} characters")

# ── Global state ──
vehicle_manager = None
VEHICLE_ID = None
vehicle_state_cache = {
    "last_update": None,
    "data": None
}
rate_limit_store = {}

def init_vehicle_manager():
    """Initialize vehicle manager lazily on first request using HyundaiBlueLink (working June version)."""
    global vehicle_manager, VEHICLE_ID

    # If already initialized, return success
    if vehicle_manager is not None and VEHICLE_ID is not None:
        return True

    # Check credentials first
    if USERNAME is None or PASSWORD is None or PIN is None:
        logger.error("Missing credentials! Check KIA_USERNAME, KIA_PASSWORD, and KIA_PIN environment variables.")
        return False

    if not SECRET_KEY:
        logger.error("Missing SECRET_KEY environment variable.")
        return False

    try:
        # Initialize using HyundaiBlueLink like the working June version
        if vehicle_manager is None:
            from hyundai_kia_connect_api.HyundaiBlueLink import HyundaiBlueLink

            logger.info("Initializing HyundaiBlueLink API for Kia Canada...")
            logger.info(f"Using PIN with length: {len(PIN)} characters")

            vehicle_manager = HyundaiBlueLink(
                username=USERNAME,
                password=PASSWORD,
                pin=PIN,
                brand="KIA",
                region="CA"  # Canada region as string
            )

            logger.info("Attempting to login...")
            vehicle_manager.login()
            logger.info("Login successful.")

            logger.info("Getting vehicles...")
            vehicles = vehicle_manager.get_vehicles()
            logger.info(f"Found {len(vehicles)} vehicle(s).")

            if not vehicles:
                logger.error("No vehicles found in the account.")
                return False

            # Store first vehicle
            VEHICLE_ID = vehicles[0]
            logger.info(f"Using vehicle: {VEHICLE_ID}")

        return True
    except Exception as e:
        logger.error(f"Failed to initialize vehicle manager: {e}")
        import traceback
        traceback.print_exc()
        return False

def get_cached_vehicle_state():
    """Get vehicle state with caching using HyundaiBlueLink API."""
    if vehicle_manager is None:
        raise RuntimeError("Vehicle manager not initialized")

    if VEHICLE_ID is None:
        raise RuntimeError("VEHICLE_ID not set")

    now = datetime.now()
    if (vehicle_state_cache["last_update"] is None or
        (now - vehicle_state_cache["last_update"]).total_seconds() > CACHE_TTL_SECONDS):
        logger.info("Cache expired or empty, refreshing vehicle status...")
        vehicle_state_cache["data"] = vehicle_manager.get_vehicle_status(VEHICLE_ID)
        vehicle_state_cache["last_update"] = now

    return vehicle_state_cache["data"]

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

def refresh_token_if_needed():
    """Refresh token if needed - HyundaiBlueLink handles this internally."""
    # HyundaiBlueLink API handles token refresh internally
    pass

def require_auth(f):
    """Decorator to require authorization header."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not init_vehicle_manager():
            return jsonify({"error": "Service initialization failed"}), 503

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
    initialized = init_vehicle_manager()

    response = {
        "status": "healthy" if initialized else "degraded",
        "timestamp": datetime.now(ZoneInfo("America/Toronto")).isoformat(),
        "vehicle_manager_initialized": vehicle_manager is not None,
        "vehicle_id_set": VEHICLE_ID is not None,
        "vehicle_id": str(VEHICLE_ID) if VEHICLE_ID else "not set"
    }

    return jsonify(response), 200 if initialized else 503

# ── Root Endpoint ──
@app.route('/', methods=['GET'])
def root():
    """Root endpoint."""
    return jsonify({"status": "Welcome to the Kia Vehicle Control API"}), 200

# ── Diagnostic Endpoint ──
@app.route('/diagnostics', methods=['GET'])
def diagnostics():
    """Diagnostic endpoint to check environment configuration (no auth required)."""
    region_names = {1: "Europe", 2: "Canada", 3: "USA", 4: "China", 5: "Australia"}

    # Check credential format issues
    credential_warnings = []
    if USERNAME and ('@' not in USERNAME):
        credential_warnings.append("KIA_USERNAME should be an email address")

    pin_length = len(PIN) if PIN else 0
    if PIN and pin_length != 4:
        credential_warnings.append(f"KIA_PIN should be 4 digits, got length: {pin_length}")

    # Add info about PIN length to help debug
    pin_info = {
        "length": pin_length,
        "starts_with_zero": PIN.startswith('0') if PIN else False
    }

    return jsonify({
        "env_vars_set": {
            "KIA_USERNAME": USERNAME is not None and USERNAME != "",
            "KIA_PASSWORD": PASSWORD is not None and PASSWORD != "",
            "KIA_PIN": PIN is not None and PIN != "",
            "SECRET_KEY": SECRET_KEY is not None and SECRET_KEY != "",
            "VEHICLE_ID": os.environ.get("VEHICLE_ID", "") != "",
            "BATTERY_CAPACITY_KWH": os.environ.get("BATTERY_CAPACITY_KWH", "") != "",
            "KIA_REGION": os.environ.get("KIA_REGION", "") != ""
        },
        "configuration": {
            "region_code": REGION,
            "region_name": region_names.get(REGION, "Unknown"),
            "battery_capacity_kwh": BATTERY_CAPACITY_KWH,
            "brand": BRAND_KIA
        },
        "pin_info": pin_info,
        "global_state": {
            "vehicle_manager_initialized": vehicle_manager is not None,
            "vehicle_id_set": VEHICLE_ID is not None,
            "vehicle_id_value": VEHICLE_ID if VEHICLE_ID else None
        },
        "warnings": credential_warnings if credential_warnings else None
    }), 200

# ── List Vehicles Endpoint ──
@app.route('/list_vehicles', methods=['GET'])
@require_auth
def list_vehicles():
    """List all vehicles in the account."""
    logger.info("Received request to /list_vehicles")

    try:
        vehicles = vehicle_manager.get_vehicles()

        if not vehicles:
            logger.warning("No vehicles found in the account")
            return jsonify({"error": "No vehicles found"}), 404

        # HyundaiBlueLink returns vehicle objects
        vehicle_list = [{"id": str(v)} for v in vehicles]

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
        vehicle_status = get_cached_vehicle_state()

        pct = vehicle_status.ev_battery_percentage
        dur = vehicle_status.ev_estimated_current_charge_duration
        plugged_in = bool(vehicle_status.ev_battery_is_plugged_in)
        charging = bool(vehicle_status.ev_battery_is_charging)
        limit = 100  # Default charge target

        # ── Estimate charging power ──
        estimated_kw = None
        if charging and dur > 0 and pct < limit:
            fraction = (limit - pct) / 100
            estimated_kw = round((BATTERY_CAPACITY_KWH * fraction) / (dur / 60), 1)

        actual_kw = None
        try:
            current = float(vehicle_status.ev_charging_current)
            voltage = float(vehicle_status.ev_charging_voltage)
            actual_kw = round((current * voltage) / 1000, 1)
        except Exception:
            pass

        # ── ETA Calculation ──
        eta_time = eta_duration = None
        if charging and dur > 0:
            now = datetime.now(ZoneInfo("America/Toronto"))
            eta_dt = now + timedelta(minutes=dur)
            eta_time = eta_dt.strftime("%-I:%M %p")
            h, m = divmod(dur, 60)
            eta_duration = f"{h}h {m}m remaining"

        # ── Response ──
        resp = {
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
        }

        return jsonify(resp), 200

    except Exception as e:
        import traceback
        logger.error(f"Error in /status: {e}")
        traceback.print_exc()
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
        result = vehicle_manager.unlock(VEHICLE_ID)
        logger.info(f"Unlock result: {result}")

        return jsonify({"status": "Car unlocked", "result": str(result)}), 200
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
        result = vehicle_manager.lock(VEHICLE_ID)
        logger.info(f"Lock result: {result}")

        return jsonify({"status": "Car locked", "result": str(result)}), 200
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
        from hyundai_kia_connect_api import ClimateRequestOptions

        data = request.get_json() or {}
        logger.info(f"Incoming payload: {data}")

        # ── Input Validation ──
        try:
            set_temp = float(data.get("set_temp", 21))
            if not 16 <= set_temp <= 30:
                return jsonify({"error": "Temperature must be between 16-30°C"}), 400
        except (ValueError, TypeError):
            return jsonify({"error": "Invalid temperature value"}), 400

        try:
            duration = int(data.get("duration", 10))
            if not 5 <= duration <= 30:
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
        result = vehicle_manager.stop_climate(VEHICLE_ID)
        logger.info(f"Stop climate result: {result}")

        return jsonify({"status": "Climate stopped", "result": str(result)}), 200
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
        vehicle_status = get_cached_vehicle_state()

        # Try to get raw data if available
        raw_data = getattr(vehicle_status, "_vehicle_data", {})

        return jsonify({
            "vehicle_status": str(vehicle_status),
            "raw_data": raw_data,
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

# ── Vercel Entry Point ──
# This is required for Vercel to properly handle the Flask app
if __name__ != "__main__":
    # When running in Vercel, this will be imported
    pass
