import os
import copy
import logging
from functools import wraps
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from flask import Flask, request, jsonify

# NOTE: Custom DNS patching removed - the hyundai_kia_connect_api library v3.52.1+
# handles Cloudflare/IPv4 issues internally with its own socket patching
# NOTE: v4.0+ adds OTP/2FA support required as of 2026 by Kia Canada

# ── Constants ──
REGION_CODES = {
    1: "Europe",
    2: "Canada",
    3: "USA",
    4: "China",
    5: "Australia",
}
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

def _trimmed_env(name: str):
    raw = os.environ.get(name)
    if raw is None:
        return None

    trimmed = raw.strip()
    if trimmed != raw:
        logger.warning(f"{name} contained surrounding whitespace. Trimming it before use.")

    return trimmed or None


# ── Environment Variables ──
USERNAME = _trimmed_env('KIA_USERNAME')
PASSWORD = _trimmed_env('KIA_PASSWORD')
PIN = _trimmed_env('KIA_PIN')  # Keep as string to preserve leading zeros
SECRET_KEY = _trimmed_env("SECRET_KEY")
BATTERY_CAPACITY_KWH = float(os.environ.get("BATTERY_CAPACITY_KWH") or DEFAULT_BATTERY_CAPACITY_KWH)
region_env_raw = os.environ.get("KIA_REGION")
region_env = region_env_raw.strip() if region_env_raw else None
if region_env:
    try:
        REGION = int(region_env)
        if REGION not in REGION_CODES:
            raise ValueError
    except ValueError:
        raise ValueError(
            f"Invalid KIA_REGION '{region_env_raw}'. Valid options are: {sorted(REGION_CODES.keys())}"
        )
else:
    REGION = DEFAULT_REGION

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

# ── OTP/2FA Support ──
# State tracking for OTP authentication process
otp_state = {
    "required": False,
    "sent": False,
    "verified": False,
    "error": None,
    "otp_request": None,  # Stores OTP data from initial login
    "xid": None,  # Transaction ID from error response
    "otpkey": None  # OTP key from error response
}

def manual_canada_send_otp(api, method="email"):
    """
    Manually send OTP for Canada region using correct MFA flow.

    Based on PR #1033: https://github.com/Hyundai-Kia-Connect/hyundai_kia_connect_api/pull/1033

    Flow:
    1. Login (error 7110) → get transactionId
    2. /mfa/selverifmeth → get userInfoUuid, mfaApiCode
    3. /mfa/sendotp → send OTP, get otpKey
    """
    import requests

    # Step 1: Ensure we have xid from initial login
    if not otp_state.get("xid"):
        logger.info("No xid, triggering login to get error 7110...")
        try:
            login_url = "https://kiaconnect.ca/tods/api/v2/login"
            login_data = {
                "userId": os.environ.get("KIA_EMAIL"),
                "password": os.environ.get("KIA_PASSWORD")
            }
            login_response = requests.post(login_url, json=login_data, headers=api.API_HEADERS, timeout=10)

            if login_response.status_code == 200:
                response_json = login_response.json()
                error_code = response_json.get("error", {}).get("errorCode")

                if error_code == "7110":
                    xid = login_response.headers.get("transactionId")
                    if xid:
                        otp_state["xid"] = xid
                        logger.info(f"Got xid from login: {xid}")
                    else:
                        raise Exception("Error 7110 but no transactionId")
                else:
                    raise Exception(f"Expected error 7110 but got: {error_code}")
            else:
                raise Exception(f"Login failed: {login_response.status_code}")
        except Exception as e:
            raise Exception(f"Failed to get xid: {e}")

    # Step 2: Select verification method to get userInfoUuid
    logger.info("Step 2: Calling /mfa/selverifmeth to get userInfoUuid...")
    selverif_url = "https://kiaconnect.ca/tods/api/mfa/selverifmeth"
    headers = api.API_HEADERS.copy()

    selverif_data = {
        "mfaApiCode": "0107",  # Always "0107" for Canada per PR #1033
        "userAccount": os.environ.get("KIA_EMAIL")
    }

    selverif_response = requests.post(selverif_url, json=selverif_data, headers=headers, timeout=10)
    logger.info(f"selverifmeth response: {selverif_response.status_code}")
    logger.info(f"Response: {selverif_response.text[:500]}")

    if selverif_response.status_code != 200:
        raise Exception(f"selverifmeth failed: {selverif_response.status_code} - {selverif_response.text[:500]}")

    selverif_result = selverif_response.json()
    user_info_uuid = selverif_result.get("userInfoUuid")
    user_account_list = selverif_result.get("userAccount")  # List of email addresses

    if not user_info_uuid:
        raise Exception(f"Missing userInfoUuid in response: {selverif_result}")

    logger.info(f"Got userInfoUuid: {user_info_uuid[:10]}...")
    logger.info(f"Available accounts: {user_account_list}")
    otp_state["userInfoUuid"] = user_info_uuid
    otp_state["mfaApiCode"] = "0107"  # Store for later steps

    # Step 3: Send OTP
    logger.info(f"Step 3: Sending OTP via {method} to /mfa/sendotp...")
    sendotp_url = "https://kiaconnect.ca/tods/api/mfa/sendotp"

    sendotp_data = {
        "otpMethod": "E" if method == "email" else "S",  # E=email, S=SMS
        "mfaApiCode": "0107",
        "userAccount": os.environ.get("KIA_EMAIL"),
        "userPhone": "",  # Empty for email
        "userInfoUuid": user_info_uuid
    }

    sendotp_response = requests.post(sendotp_url, json=sendotp_data, headers=headers, timeout=10)
    logger.info(f"sendotp response: {sendotp_response.status_code}")
    logger.info(f"Response: {sendotp_response.text[:500]}")

    if sendotp_response.status_code != 200:
        raise Exception(f"sendotp failed: {sendotp_response.status_code} - {sendotp_response.text[:500]}")

    sendotp_result = sendotp_response.json()
    otp_key = sendotp_result.get("otpKey")

    if not otp_key:
        raise Exception(f"Missing otpKey in response: {sendotp_result}")

    logger.info(f"OTP sent! otpKey: {otp_key[:10]}...")
    otp_state["otpKey"] = otp_key

    return sendotp_result

def manual_canada_verify_otp(api, otp_code):
    """
    Manually verify OTP for Canada region using correct MFA flow.

    Flow:
    4. /mfa/validateotp → validate code, get otpValidationKey
    5. /mfa/genmfatkn → generate tokens (sid, rmtoken)

    Returns (sid, rmtoken) tuple on success.
    """
    import requests

    if not otp_state.get("otpKey"):
        raise Exception("Missing otpKey. Call /otp/send first.")

    headers = api.API_HEADERS.copy()

    # Step 4: Validate OTP code
    logger.info("Step 4: Validating OTP code with /mfa/validateotp...")
    validateotp_url = "https://kiaconnect.ca/tods/api/mfa/validateotp"

    validateotp_data = {
        "otpKey": otp_state["otpKey"],
        "otpValue": otp_code
    }

    validateotp_response = requests.post(validateotp_url, json=validateotp_data, headers=headers, timeout=10)
    logger.info(f"validateotp response: {validateotp_response.status_code}")
    logger.info(f"Response: {validateotp_response.text[:500]}")

    if validateotp_response.status_code != 200:
        raise Exception(f"validateotp failed: {validateotp_response.status_code} - {validateotp_response.text[:500]}")

    validateotp_result = validateotp_response.json()
    otp_validation_key = validateotp_result.get("otpValidationKey")

    if not otp_validation_key:
        raise Exception(f"Missing otpValidationKey in response: {validateotp_result}")

    logger.info(f"OTP validated! otpValidationKey: {otp_validation_key[:10]}...")

    # Step 5: Generate MFA tokens
    logger.info("Step 5: Generating tokens with /mfa/genmfatkn...")
    genmfatkn_url = "https://kiaconnect.ca/tods/api/mfa/genmfatkn"

    genmfatkn_data = {
        "otpValidationKey": otp_validation_key,
        "mfaYn": "Y",  # Y = remember device for 90 days
        "mfaApiCode": otp_state.get("mfaApiCode")
    }

    genmfatkn_response = requests.post(genmfatkn_url, json=genmfatkn_data, headers=headers, timeout=10)
    logger.info(f"genmfatkn response: {genmfatkn_response.status_code}")
    logger.info(f"Response headers: {dict(genmfatkn_response.headers)}")
    logger.info(f"Response: {genmfatkn_response.text[:500]}")

    if genmfatkn_response.status_code != 200:
        raise Exception(f"genmfatkn failed: {genmfatkn_response.status_code} - {genmfatkn_response.text[:500]}")

    # Extract tokens from response headers
    sid = genmfatkn_response.headers.get("sid")
    rmtoken = genmfatkn_response.headers.get("rmtoken")

    if not sid or not rmtoken:
        raise Exception(f"Missing sid/rmtoken in headers: {dict(genmfatkn_response.headers)}")

    logger.info("Successfully generated tokens!")
    return sid, rmtoken

def init_vehicle_manager():
    """Initialize vehicle manager lazily on first request."""
    global vehicle_manager, VEHICLE_ID

    # If already initialized, return success
    if vehicle_manager is not None and VEHICLE_ID is not None:
        return True

    # If vehicle_manager exists but VEHICLE_ID is None, force re-initialization
    if vehicle_manager is not None and VEHICLE_ID is None:
        logger.warning("Vehicle manager exists but VEHICLE_ID is None. Forcing re-initialization...")
        vehicle_manager = None

    # Check credentials first
    if USERNAME is None or PASSWORD is None or PIN is None:
        logger.error("Missing credentials! Check KIA_USERNAME, KIA_PASSWORD, and KIA_PIN environment variables.")
        return False

    if not SECRET_KEY:
        logger.error("Missing SECRET_KEY environment variable.")
        return False

    try:
        # Initialize using VehicleManager exactly like working main.py
        if vehicle_manager is None:
            from hyundai_kia_connect_api import VehicleManager
            from hyundai_kia_connect_api.exceptions import AuthenticationError
            from hyundai_kia_connect_api.ApiImpl import OTPRequest, OTP_NOTIFY_TYPE
            import hyundai_kia_connect_api

            # Log library version for debugging
            lib_version = getattr(hyundai_kia_connect_api, '__version__', 'unknown')
            logger.info(f"hyundai_kia_connect_api version: {lib_version}")

            logger.info(
                f"Initializing Vehicle Manager (Region: {REGION} ({REGION_CODES.get(REGION, 'Unknown')}), "
                f"Brand: {BRAND_KIA})..."
            )
            logger.info(f"Using PIN with length: {len(PIN)} characters")

            vehicle_manager = VehicleManager(
                region=REGION,
                brand=BRAND_KIA,
                username=USERNAME,
                password=PASSWORD,
                pin=str(PIN)
                # NOTE: otp_handler is NOT a constructor parameter in v4.4.0
                # OTP is handled via send_otp() and verify_otp() methods
            )

            logger.info("Attempting to authenticate...")

            # Try to authenticate - login() returns either Token or OTPRequest
            try:
                login_result = vehicle_manager.login()

                # Check if OTP is required
                if isinstance(login_result, OTPRequest):
                    logger.warning("OTP/2FA required for authentication")
                    logger.info(f"OTP methods available - Email: {login_result.has_email}, SMS: {login_result.has_sms}")
                    if login_result.email:
                        logger.info(f"OTP can be sent to email: {login_result.email}")
                    if login_result.sms:
                        logger.info(f"OTP can be sent to SMS: {login_result.sms}")

                    # Store the OTPRequest for later use
                    otp_state["required"] = True
                    otp_state["verified"] = False
                    otp_state["otp_request"] = login_result
                    otp_state["error"] = "OTP required - call POST /otp/send to start authentication"

                    logger.info("VehicleManager initialized but authentication pending OTP verification")
                    return True

                # Login successful without OTP
                logger.info("Authentication successful (no OTP required)")
                otp_state["required"] = False
                otp_state["verified"] = True
                otp_state["otp_request"] = None

            except Exception as auth_error:
                logger.error(f"Authentication error: {auth_error}")

                # For other errors, log but try to continue
                logger.error(f"Authentication error (will retry on next request): {auth_error}")
                otp_state["error"] = str(auth_error)

                # Still try to diagnose
                logger.info("Attempting direct API call to diagnose...")
                try:
                    import copy
                    import uuid
                    import base64
                    import requests

                    api = vehicle_manager.api
                    test_url = api.API_URL + "v2/login"

                    # Mirror the same headers the library sends to avoid validation errors
                    test_headers = copy.deepcopy(getattr(api, "API_HEADERS", {}))
                    test_headers.pop("accessToken", None)

                    # Generate Deviceid like the library does (required for Canada since July 2025)
                    base_device_id = "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.102 Mobile Safari/537.36"
                    unique_device_id = f"{base_device_id}+{str(uuid.uuid4())}"
                    test_headers["Deviceid"] = base64.b64encode(unique_device_id.encode()).decode()

                    # Add User-Agent header (the library sends this but API_HEADERS may not include it)
                    test_headers["User-Agent"] = base_device_id
                    # Use CWP instead of SPA for login (library uses CWP)
                    test_headers["from"] = "CWP"

                    test_data = {"loginId": USERNAME, "password": PASSWORD}

                    # Log headers (excluding secrets) to verify Deviceid is present
                    safe_headers = {k: (v[:20] + "..." if k == "Deviceid" else v)
                                   for k, v in test_headers.items()
                                   if k.lower() != "client_secret"}
                    logger.info(f"Direct API test - Headers with Deviceid: {safe_headers}")

                    test_response = requests.post(test_url, json=test_data, headers=test_headers, timeout=10)
                    logger.info(
                        "Direct API test - Status: %s | URL: %s",
                        test_response.status_code,
                        test_url,
                    )
                    logger.info(f"Direct API test - Response headers: {dict(test_response.headers)}")
                    logger.info(f"Direct API test - Body (first 500 chars): {test_response.text[:500]}")

                    # Check for error 7110 (OTP required) and extract OTP context
                    response_json = test_response.json()
                    error_code = response_json.get("error", {}).get("errorCode")

                    if error_code == "7110":
                        logger.warning("Error 7110 detected - OTP/2FA required")

                        # Extract OTP context from response headers
                        xid = test_response.headers.get("transactionId")
                        status_header = test_response.headers.get("status")

                        if xid and status_header == "7110":
                            otp_state["xid"] = xid
                            otp_state["required"] = True
                            otp_state["verified"] = False
                            logger.info(f"OTP context extracted - xid: {xid}, status: {status_header}")
                            logger.info("Will use manual Canada OTP flow (otpkey not needed)")
                        else:
                            logger.warning("Error 7110 but missing OTP context in headers")

                except Exception as test_error:
                    logger.error(f"Direct API test failed: {test_error}")

                # Don't fail initialization - allow OTP flow to complete
                # The user can call /otp/send and /otp/verify to complete auth
                logger.warning("Initialization continuing despite auth error - OTP may be required")
                logger.info("VehicleManager created but not authenticated. Use /otp/status to check requirements.")
                # Return True to allow OTP endpoints to work (skip vehicle update)
                return True

            logger.info("Updating vehicle states...")
            try:
                # Log before the call
                logger.info("Calling update_all_vehicles_with_cached_state()...")
                vehicle_manager.update_all_vehicles_with_cached_state()

                # Log the raw vehicles dict
                logger.info(f"Raw vehicles dict: {vehicle_manager.vehicles}")
                logger.info(f"Vehicles dict type: {type(vehicle_manager.vehicles)}")
                logger.info(f"Vehicles dict keys: {list(vehicle_manager.vehicles.keys()) if vehicle_manager.vehicles else 'EMPTY'}")
                logger.info(f"Connected! Found {len(vehicle_manager.vehicles)} vehicle(s).")
            except Exception as update_error:
                logger.error(f"Error during update_all_vehicles_with_cached_state: {update_error}", exc_info=True)
                raise

            if not vehicle_manager.vehicles:
                logger.error("No vehicles found in the account.")
                return False

            # Log vehicle details
            for vid, vehicle in vehicle_manager.vehicles.items():
                logger.info(f"Vehicle - ID: {vid}, Name: {vehicle.name}, Model: {vehicle.model}")

        # Set VEHICLE_ID if not already set
        if VEHICLE_ID is None:
            env_vehicle_id = os.environ.get("VEHICLE_ID", "").strip()
            if env_vehicle_id:
                VEHICLE_ID = env_vehicle_id
                logger.info(f"Using VEHICLE_ID from environment: {VEHICLE_ID}")
            else:
                if not vehicle_manager.vehicles:
                    logger.error("No vehicles found in the account.")
                    return False
                VEHICLE_ID = next(iter(vehicle_manager.vehicles.keys()))
                logger.info(f"No VEHICLE_ID provided. Auto-detected first vehicle: {VEHICLE_ID}")

        return True
    except Exception as e:
        logger.error(f"Failed to initialize vehicle manager: {e}")
        vehicle_manager = None
        VEHICLE_ID = None
        import traceback
        traceback.print_exc()
        return False

def get_cached_vehicle_state():
    """Get vehicle state with caching."""
    if vehicle_manager is None:
        raise RuntimeError("Vehicle manager not initialized")

    if VEHICLE_ID is None:
        raise RuntimeError("VEHICLE_ID not set")

    now = datetime.now()
    if (vehicle_state_cache["last_update"] is None or
        (now - vehicle_state_cache["last_update"]).total_seconds() > CACHE_TTL_SECONDS):
        logger.info("Cache expired or empty, refreshing vehicle states...")
        vehicle_manager.update_all_vehicles_with_cached_state()
        vehicle_state_cache["last_update"] = now

    logger.info(f"Getting vehicle with ID: {VEHICLE_ID}")
    return vehicle_manager.get_vehicle(VEHICLE_ID)

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
    """Refresh token if needed."""
    if vehicle_manager is None:
        return
    try:
        vehicle_manager.check_and_refresh_token()
    except Exception as e:
        logger.warning(f"Token refresh check failed: {e}")

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
        "vehicles_count": len(vehicle_manager.vehicles) if vehicle_manager else 0,
        "vehicle_manager_initialized": vehicle_manager is not None,
        "vehicle_id_set": VEHICLE_ID is not None,
        "vehicle_id": VEHICLE_ID if VEHICLE_ID else "not set"
    }

    if initialized and vehicle_manager:
        response["vehicles"] = list(vehicle_manager.vehicles.keys())

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

# ── OTP Endpoints (for 2FA authentication) ──
@app.route('/otp/send', methods=['POST'])
def send_otp():
    """
    Request OTP to be sent via SMS/email.

    Body: {"method": "sms"} or {"method": "email"}
    """
    global vehicle_manager

    # Initialize if needed (serverless instances don't persist state)
    if vehicle_manager is None:
        logger.info("VehicleManager not initialized, initializing now...")
        if not init_vehicle_manager():
            return jsonify({"error": "Failed to initialize vehicle manager"}), 503

    data = request.get_json() or {}
    method = data.get("method", "sms").lower()

    if method not in ["sms", "email"]:
        return jsonify({"error": "Method must be 'sms' or 'email'"}), 400

    try:
        logger.info(f"Requesting OTP via {method}...")

        # Check if we have library OTPRequest (USA) or manual Canada OTP context
        if otp_state.get("otp_request") is not None:
            # USA region - use library's OTP support
            from hyundai_kia_connect_api.ApiImpl import OTP_NOTIFY_TYPE
            notify_type = OTP_NOTIFY_TYPE.EMAIL if method == "email" else OTP_NOTIFY_TYPE.SMS

            logger.info(f"Using USA OTP flow - otp_key: {otp_state['otp_request'].otp_key[:10]}...")
            result = vehicle_manager.api.send_otp(otp_state["otp_request"], notify_type)
            logger.info(f"send_otp() returned: {result}")

        else:
            # Canada region - use manual MFA flow
            # (auto-fetches xid if needed, then calls selverifmeth -> sendotp)
            logger.info("Using manual Canada MFA flow...")
            result = manual_canada_send_otp(vehicle_manager.api, method)
            logger.info(f"Manual send_otp() returned: {result}")

        otp_state["sent"] = True
        otp_state["required"] = True

        return jsonify({
            "status": "OTP sent",
            "method": method,
            "message": f"Check your {method} for the OTP code, then call POST /otp/verify",
            "region": "USA (library)" if otp_state.get("otp_request") else "Canada (manual)"
        }), 200
    except Exception as e:
        logger.error(f"Failed to send OTP: {e}", exc_info=True)
        otp_state["error"] = str(e)
        return jsonify({"error": str(e), "type": type(e).__name__}), 500

@app.route('/otp/verify', methods=['POST'])
def verify_otp():
    """
    Verify the OTP code you received.

    Body: {"otp": "123456"}
    """
    global vehicle_manager

    # Initialize if needed (serverless instances don't persist state)
    if vehicle_manager is None:
        logger.info("VehicleManager not initialized, initializing now...")
        if not init_vehicle_manager():
            return jsonify({"error": "Failed to initialize vehicle manager"}), 503

    data = request.get_json() or {}
    otp = data.get("otp", "").strip()

    if not otp:
        return jsonify({"error": "Missing 'otp' in request body"}), 400

    if not otp.isdigit():
        return jsonify({"error": "OTP must be numeric"}), 400

    try:
        logger.info(f"Verifying OTP code (length: {len(otp)})...")

        # Check if we have library OTPRequest (USA) or manual Canada OTP context
        if otp_state.get("otp_request") is not None:
            # USA region - use library's OTP support
            logger.info("Using USA OTP verification flow...")
            token = vehicle_manager.api.verify_otp_and_complete_login(
                username=USERNAME,
                password=PASSWORD,
                otp_code=otp,
                otp_request=otp_state["otp_request"],
                pin=PIN
            )
            logger.info(f"OTP verification successful! Token: {token.access_token[:20]}...")
            vehicle_manager.token = token

        elif otp_state.get("otpKey"):
            # Canada region - use manual MFA verification flow
            logger.info("Using manual Canada MFA verification flow...")
            sid, rmtoken = manual_canada_verify_otp(vehicle_manager.api, otp)
            logger.info(f"OTP verified! sid: {sid[:20] if sid else None}..., rmtoken: {rmtoken[:20] if rmtoken else None}...")

            # Create token manually (Canada doesn't have verify_otp_and_complete_login)
            from hyundai_kia_connect_api.ApiImpl import Token
            from datetime import datetime, timezone, timedelta

            token = Token(
                username=USERNAME,
                password=PASSWORD,
                access_token=sid,
                refresh_token=rmtoken,
                valid_until=datetime.now(timezone.utc) + timedelta(hours=24),
                device_id=vehicle_manager.api.device_id,
                pin=PIN
            )
            vehicle_manager.token = token

        else:
            return jsonify({"error": "No OTP context available. Call /otp/send first"}), 400

        otp_state["verified"] = True
        otp_state["required"] = False
        otp_state["otp_request"] = None
        otp_state["xid"] = None
        otp_state["otpkey"] = None

        # Now initialize vehicles
        logger.info("Initializing vehicles after OTP verification...")
        vehicle_manager.initialize_vehicles()
        vehicle_manager.update_all_vehicles_with_cached_state()

        return jsonify({
            "status": "OTP verified",
            "message": "Authentication complete. You can now use the API normally.",
            "vehicles_found": len(vehicle_manager.vehicles) if vehicle_manager.vehicles else 0,
            "region": "USA (library)" if otp_state.get("otp_request") else "Canada (manual)"
        }), 200
    except Exception as e:
        logger.error(f"Failed to verify OTP: {e}", exc_info=True)
        otp_state["error"] = str(e)
        return jsonify({"error": str(e), "type": type(e).__name__}), 500

@app.route('/otp/status', methods=['GET'])
def otp_status():
    """Check OTP authentication status."""
    return jsonify({
        "otp_required": otp_state["required"],
        "otp_sent": otp_state["sent"],
        "otp_verified": otp_state["verified"],
        "error": otp_state["error"],
        "vehicle_manager_initialized": vehicle_manager is not None,
        "instructions": "If OTP required: 1) POST /otp/send, 2) Check SMS/email, 3) POST /otp/verify with code"
    }), 200

# ── List Vehicles Endpoint ──
@app.route('/list_vehicles', methods=['GET'])
@require_auth
def list_vehicles():
    """List all vehicles in the account."""
    logger.info("Received request to /list_vehicles")

    try:
        refresh_token_if_needed()
        vehicle_manager.update_all_vehicles_with_cached_state()

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

        pct = vehicle.ev_battery_percentage
        dur = vehicle.ev_estimated_current_charge_duration
        charging = bool(vehicle.ev_battery_is_charging)

        # ── Plug type detection ──
        # 0 = not plugged, 1 = DC (fast), 2 = AC (Level 2/portable)
        plug_type_raw = vehicle.ev_battery_is_plugged_in
        try:
            plug_type_int = int(plug_type_raw) if plug_type_raw is not None else 0
        except (ValueError, TypeError):
            plug_type_int = 0

        plugged_in = plug_type_int > 0
        plug_type_map = {0: None, 1: "DC", 2: "AC"}
        plug_type = plug_type_map.get(plug_type_int, None)

        # ── Charge limits ──
        charge_limit_ac = vehicle.ev_charge_limits_ac
        charge_limit_dc = vehicle.ev_charge_limits_dc

        # Active limit based on plug type
        if plug_type_int == 1:  # DC
            active_charge_limit = charge_limit_dc
        elif plug_type_int == 2:  # AC
            active_charge_limit = charge_limit_ac
        else:  # Not plugged in - show AC limit as default
            active_charge_limit = charge_limit_ac

        # ── Estimate charging power ──
        estimated_kw = None
        if charging and dur and dur > 0 and pct is not None and active_charge_limit:
            if pct < active_charge_limit:
                fraction = (active_charge_limit - pct) / 100
                estimated_kw = round((BATTERY_CAPACITY_KWH * fraction) / (dur / 60), 1)

        actual_kw = None
        try:
            current = float(vehicle.ev_charging_current)
            voltage = float(vehicle.ev_charging_voltage)
            actual_kw = round((current * voltage) / 1000, 1)
        except Exception:
            pass

        # ── ETA Calculation ──
        eta_time = eta_duration = None
        if charging and dur and dur > 0:
            now = datetime.now(ZoneInfo("America/Toronto"))
            eta_dt = now + timedelta(minutes=dur)
            eta_time = eta_dt.strftime("%-I:%M %p")
            h, m = divmod(dur, 60)
            eta_duration = f"{h}h {m}m remaining"

        # ── Response ──
        resp = {
            "battery_percentage": int(pct) if pct is not None else None,
            "battery_12v": int(vehicle.car_battery_percentage) if vehicle.car_battery_percentage is not None else None,
            "charge_duration": int(dur) if dur is not None else 0,
            "charging_eta": eta_time,
            "charging_duration_formatted": eta_duration,
            "estimated_charging_power_kw": estimated_kw,
            "actual_charging_power_kw": actual_kw,
            "is_charging": charging,
            "plugged_in": plugged_in,
            "plug_type": plug_type,  # "DC", "AC", or null
            "charge_limits": {
                "ac": charge_limit_ac,
                "dc": charge_limit_dc,
                "active": active_charge_limit,  # The limit that applies based on plug type
            },
            "is_locked": bool(vehicle.is_locked) if vehicle.is_locked is not None else None,
            "engine_running": bool(vehicle.engine_is_running) if vehicle.engine_is_running is not None else None,
            "doors": {
                "front_left": bool(int(vehicle.front_left_door_is_open)) if vehicle.front_left_door_is_open is not None else None,
                "front_right": bool(int(vehicle.front_right_door_is_open)) if vehicle.front_right_door_is_open is not None else None,
                "back_left": bool(int(vehicle.back_left_door_is_open)) if vehicle.back_left_door_is_open is not None else None,
                "back_right": bool(int(vehicle.back_right_door_is_open)) if vehicle.back_right_door_is_open is not None else None,
                "trunk": bool(vehicle.trunk_is_open) if vehicle.trunk_is_open is not None else None,
                "hood": bool(vehicle.hood_is_open) if vehicle.hood_is_open is not None else None
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

# ── Climate Presets ──
CLIMATE_PRESETS = {
    "winter": {
        "set_temp": 21,
        "defrost": True,
        "steering_wheel": 1,  # On
        "front_left_seat": 3,  # Driver - High
        "front_right_seat": 3,  # Passenger - High
        "rear_left_seat": 0,
        "rear_right_seat": 0,
        "heating": 1,
    },
    "summer": {
        "set_temp": 21,
        "defrost": False,
        "steering_wheel": 0,  # Off
        "front_left_seat": 0,
        "front_right_seat": 0,
        "rear_left_seat": 0,
        "rear_right_seat": 0,
        "heating": 0,
    },
    "springfall": {
        "set_temp": 21,
        "defrost": True,  # On for morning dew/frost
        "steering_wheel": 0,  # Off
        "front_left_seat": 0,
        "front_right_seat": 0,
        "rear_left_seat": 0,
        "rear_right_seat": 0,
        "heating": 0,
    },
}

# ── Custom Climate Start (with steering wheel & seat heater fix) ──
def _build_climate_payload(vehicle_manager, vehicle_id, options):
    """
    Build climate payload with heatingAccessory for steering wheel.
    The library's Canada implementation is missing this section.
    """

    vehicle = vehicle_manager.get_vehicle(vehicle_id)
    token = vehicle_manager.token  # Token is on vehicle_manager, not api

    # Convert temperature to hex format (library does this internally)
    # Formula: hex(temp * 2) with padding - e.g., 21°C -> 0x2A -> "2A"
    hex_temp = hex(int(options.set_temp * 2))[2:].upper().zfill(2)

    # Build the climate settings
    climate_settings = {
        "airCtrl": 1 if options.climate else 0,
        "defrost": options.defrost,
        "heating1": options.heating if options.heating else 0,
        "airTemp": {
            "value": hex_temp,
            "unit": 0,
            "hvacTempType": 1,
        },
        "igniOnDuration": options.duration,
        "seatHeaterVentCMD": {
            "drvSeatOptCmd": options.front_left_seat or 0,
            "astSeatOptCmd": options.front_right_seat or 0,
            "rlSeatOptCmd": options.rear_left_seat or 0,
            "rrSeatOptCmd": options.rear_right_seat or 0,
        },
        # Add heatingAccessory for steering wheel (missing from library's CA implementation)
        "heatingAccessory": {
            "steeringWheel": options.steering_wheel or 0,
            "sideMirror": 0,
            "rearWindow": 1 if options.defrost else 0,
        },
    }

    # For EV vehicles, wrap in remoteControl or hvacInfo
    # Check if vehicle is EV (has ev_battery_percentage attribute)
    is_ev = hasattr(vehicle, 'ev_battery_percentage') and vehicle.ev_battery_percentage is not None

    if is_ev:
        # Try hvacInfo first (newer EVs like EV6)
        payload = {
            "pin": str(token.pin),
            "hvacInfo": climate_settings,
        }
    else:
        payload = {
            "setting": climate_settings,
            "pin": str(token.pin),
        }

    return payload, is_ev


def _start_climate_custom(vehicle_manager, vehicle_id, options):
    """
    Custom climate start that includes heatingAccessory for steering wheel.
    Falls back to library method if this fails.
    """
    import requests

    api = vehicle_manager.api
    token = vehicle_manager.token  # Token is on vehicle_manager, not api

    payload, is_ev = _build_climate_payload(vehicle_manager, vehicle_id, options)

    logger.info(f"Custom climate payload (is_ev={is_ev}): {payload}")

    # Get the API URL and headers from the library
    base_url = api.API_URL
    headers = copy.deepcopy(api.API_HEADERS) if hasattr(api, 'API_HEADERS') else {}
    headers["accessToken"] = token.access_token
    headers["vehicleId"] = vehicle_id

    # The endpoint for starting climate
    if is_ev:
        endpoint = f"{base_url}rems/evc/rfon"
    else:
        endpoint = f"{base_url}rems/start"

    logger.info(f"Sending climate request to: {endpoint}")

    response = requests.post(endpoint, json=payload, headers=headers, timeout=30)
    logger.info(f"Climate response status: {response.status_code}")
    logger.info(f"Climate response body: {response.text[:500]}")

    response.raise_for_status()
    return response.json()


# ── Start Climate Endpoint ──
@app.route('/start_climate', methods=['POST'])
@require_auth
def start_climate():
    """Start climate control with optional seasonal presets."""
    logger.info("Received request to /start_climate")

    try:
        from hyundai_kia_connect_api import ClimateRequestOptions

        refresh_token_if_needed()
        vehicle_manager.update_all_vehicles_with_cached_state()

        data = request.get_json() or {}
        logger.info(f"Incoming payload: {data}")

        # ── Check for preset ──
        preset = data.get("preset", "").lower()
        if preset:
            if preset not in CLIMATE_PRESETS:
                return jsonify({
                    "error": f"Invalid preset '{preset}'. Valid options: {list(CLIMATE_PRESETS.keys())}"
                }), 400
            # Use preset values, but allow overrides from request
            preset_values = CLIMATE_PRESETS[preset].copy()
            logger.info(f"Using preset '{preset}': {preset_values}")
            # Merge with any explicit overrides from request (except 'preset' itself)
            for key in preset_values:
                if key in data:
                    preset_values[key] = data[key]
            data = preset_values

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

        # Try custom implementation first (includes heatingAccessory for steering wheel)
        use_custom = data.get("use_custom", True)  # Default to custom implementation
        result = None

        if use_custom:
            try:
                logger.info("Attempting custom climate start with heatingAccessory...")
                result = _start_climate_custom(vehicle_manager, VEHICLE_ID, climate_options)
                logger.info(f"Custom climate start succeeded: {result}")
            except Exception as custom_err:
                logger.warning(f"Custom climate start failed: {custom_err}, falling back to library method")
                result = None

        # Fall back to library method if custom failed or not requested
        if result is None:
            logger.info("Using library's start_climate method...")
            result = vehicle_manager.start_climate(VEHICLE_ID, climate_options)
            logger.info(f"Library start_climate result: {result}")

        return jsonify({
            "status": "Climate started",
            "preset": preset if preset else None,
            "settings": {
                "temperature": set_temp,
                "defrost": bool(data.get("defrost", False)),
                "steering_wheel": steering,
                "front_left_seat": int(data.get("front_left_seat", 0)),
                "front_right_seat": int(data.get("front_right_seat", 0)),
            },
            "result": result
        }), 200
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

# ── Vercel Entry Point ──
# This is required for Vercel to properly handle the Flask app
if __name__ != "__main__":
    # When running in Vercel, this will be imported
    pass
