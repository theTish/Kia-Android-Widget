import os
import copy
import logging
import threading
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


def _bool(value):
    """Coerce the API's mixed 0/1/'0'/True door and window flags.

    Note this is deliberately not the library's utils.bool_or_none: that one
    does bool(value), so the string "0" would come back True.
    """
    if value is None:
        return None
    try:
        return bool(int(value))
    except (ValueError, TypeError):
        return bool(value)


def _int(value):
    return int(value) if value is not None else None


def _build_revision():
    """The commit this process is running, or "unknown" if nobody said.

    Worth the eight lines. Without it a deploy is unverifiable from outside:
    /status and /health answer identically on the right code and the wrong
    code, and on 2026-09-18 the Oracle box turned out to have spent two
    sessions on a stale branch, rebuilding and restarting happily each time it
    was deployed. Four attempts to ship a one-line fix went by before anyone
    thought to look at the checkout.

    deploy/kia-deploy.sh passes KIA_GIT_SHA as a build arg. Vercel sets
    VERCEL_GIT_COMMIT_SHA on its own, in full, so it is trimmed to match.
    """
    return (
        _trimmed_env("KIA_GIT_SHA")
        or (_trimmed_env("VERCEL_GIT_COMMIT_SHA") or "")[:7]
        or "unknown"
    )


def _reported_range(value):
    """Report an unknown range as null rather than as zero.

    The car does not send null when it has no range for us, it sends 0. Seen on
    2026-09-17 against a 73% battery, through a Kia maintenance window: the rest
    of the payload carried last-known values while both range figures were
    zeroed, and a forced live poll came back with the same 0 because it went
    through the same unavailable upstream.

    A client cannot tell that 0 apart from a measurement, and "0 km" beside a
    three-quarters-full battery is a reading nobody should act on. A car
    genuinely out of charge has a battery percentage to say so.
    """
    if value is None:
        return None
    try:
        return None if float(value) <= 0 else value
    except (TypeError, ValueError):
        # Not a number at all: pass it through rather than invent a null.
        return value


# ── Pre-conditioning ──
# The two scheduled departures the car keeps, as (library prefix, raw key).
# Kia names the second one "reserveChargeInfo2" - the extra "e" is theirs.
_DEPARTURE_SLOTS = (("ev_first_departure", "reservChargeInfo"),
                    ("ev_second_departure", "reserveChargeInfo2"))


def _child(obj, *path):
    """Walk nested dicts, returning None at the first missing step."""
    for key in path:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(key)
    return obj


def _departure_time(raw, section):
    """Kia's "0730" plus an AM/PM section, as a 24-hour "07:30".

    The car sends a twelve-hour clock with timeSection 1 meaning PM, and
    "0000" for a timer nobody has set - which is unknown, not midnight.
    """
    try:
        text = str(raw).strip()
        if not text or int(text) == 0:
            return None
        hour, minute = int(text[:-2] or 0), int(text[-2:])
        if section is not None and int(section) == 1 and hour < 12:
            hour += 12
        elif section is not None and int(section) == 0 and hour == 12:
            hour = 0
        if hour > 23 or minute > 59:
            return None
        return f"{hour:02d}:{minute:02d}"
    except (TypeError, ValueError):
        return None


def _departure_days(days):
    """Days as sorted ints, 0 = Sunday through 6 = Saturday, as Kia counts."""
    if not isinstance(days, (list, tuple)):
        return None
    try:
        return sorted({int(d) for d in days if 0 <= int(d) <= 6})
    except (TypeError, ValueError):
        return None


def _departure_temperature(value, year):
    """Decode a departure's hex climate code ("0EH") the way the library
    decodes the live one, so both figures come from the same table."""
    if not isinstance(value, str) or not value.endswith("H"):
        return None
    try:
        from hyundai_kia_connect_api.KiaUvoApiCA import KiaUvoApiCA
        table = (KiaUvoApiCA.temperature_range_c_new
                 if (year or 0) >= KiaUvoApiCA.temperature_range_model_year
                 else KiaUvoApiCA.temperature_range_c_old)
        return table[int(value[:-1], 16)]
    except (ImportError, IndexError, ValueError):
        return None


def _departures(vehicle):
    """The car's scheduled departures, or None when it says nothing of them.

    The library only decodes these for some regions. For Canada it decodes
    none of them - KiaUvoApiCA never sets an ev_*_departure_* attribute - so
    for this car they have to come out of the raw status the library keeps,
    using the layout the library reads for Europe. Whatever the library does
    set wins, so a library upgrade that learns Canada takes over by itself.

    A slot the car reports nothing about is left out entirely, and no slots at
    all is None rather than []: "no departures scheduled" is a claim, and a
    car that did not answer has not made it.
    """
    evs = _child(getattr(vehicle, "data", None) or {}, "status", "evStatus", "reservChargeInfos") \
        or _child(getattr(vehicle, "data", None) or {}, "vehicleStatus", "evStatus", "reservChargeInfos") \
        or {}
    out = []
    for n, (prefix, raw_key) in enumerate(_DEPARTURE_SLOTS, start=1):
        raw = _child(evs, raw_key, "reservChargeInfoDetail") or {}
        fatc = raw.get("reservFatcSet") or {}
        lib_time = getattr(vehicle, f"{prefix}_time", None)
        slot = {
            "slot": n,
            "enabled": _bool(getattr(vehicle, f"{prefix}_enabled", None)
                             if getattr(vehicle, f"{prefix}_enabled", None) is not None
                             else raw.get("reservChargeSet")),
            "time": lib_time.strftime("%H:%M") if lib_time is not None
            else _departure_time(_child(raw, "reservInfo", "time", "time"),
                                 _child(raw, "reservInfo", "time", "timeSection")),
            "days": _departure_days(getattr(vehicle, f"{prefix}_days", None)
                                    or _child(raw, "reservInfo", "day")),
            "climate_on": _bool(getattr(vehicle, f"{prefix}_climate_enabled", None)
                                if getattr(vehicle, f"{prefix}_climate_enabled", None) is not None
                                else fatc.get("airCtrl")),
            "climate_temperature": getattr(vehicle, f"{prefix}_climate_temperature", None)
            or _departure_temperature(_child(fatc, "airTemp", "value"), vehicle.year),
            "defrost": _bool(getattr(vehicle, f"{prefix}_climate_defrost", None)
                             if getattr(vehicle, f"{prefix}_climate_defrost", None) is not None
                             else fatc.get("defrost")),
        }
        if any(v is not None for k, v in slot.items() if k != "slot"):
            out.append(slot)
    return out or None


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

# On a long-lived host the manager, its token and the vehicle list live for the
# life of the process, which is the whole point of running there - but that also
# means concurrent requests share them. This serialises initialisation so two
# requests arriving together cannot each start a login.
_init_lock = threading.RLock()
# Only a timestamp: the state itself lives on the VehicleManager's vehicles.
vehicle_state_cache = {"last_update": None}
rate_limit_store = {}

# ── OTP/2FA Support ──
# The library implements the full Canada MFA handshake as of v4.6 (upstream
# PR #1033), so we only track where we are in it.
otp_state = {
    "required": False,
    "sent": False,
    "verified": False,
    "error": None,
    "rate_limited_until": 0,  # Timestamp: don't attempt login until this time
}

# Kia Canada rate-limits repeated logins (error 7901) and EVERY attempt resets
# its timer, so a retry loop locks the account out indefinitely. The library
# has no guard for this, so we keep our own cooldown.
LOGIN_COOLDOWN_SECONDS = 35 * 60

# IMPORTANT: use a STABLE device ID across all requests.
# The library derives its device ID from MAC address + hostname, which is fine
# on a home server but changes on every cold start of a Vercel lambda - and an
# unfamiliar device ID makes Kia demand a fresh OTP. We derive ours from the
# username instead so it survives redeploys, then seed it onto the API object.
# This is byte-for-byte the value the previous hand-rolled MFA flow sent, so the
# existing 90-day device trust carries over and no re-verification is needed.
import hashlib as _hashlib
import uuid as _uuid
import base64 as _base64

_STABLE_DEVICE_ID_BASE = "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.6723.102 Mobile Safari/537.36"
# Through _trimmed_env like every other credential: a stray newline pasted into
# the Vercel dashboard would change this hash, change the device ID, and cost a
# fresh OTP. Never edit _STABLE_DEVICE_ID_BASE either - it only has to be stable.
_device_seed = _trimmed_env("KIA_EMAIL") or USERNAME or "default"
_STABLE_DEVICE_UUID = str(_uuid.UUID(_hashlib.md5(_device_seed.encode()).hexdigest()))
_STABLE_DEVICE_ID = _base64.b64encode(
    f"{_STABLE_DEVICE_ID_BASE}+{_STABLE_DEVICE_UUID}".encode()
).decode()


def _build_vehicle_manager():
    """Construct a VehicleManager with our stable device ID seeded onto it."""
    from hyundai_kia_connect_api import VehicleManager

    vm = VehicleManager(
        region=REGION,
        brand=BRAND_KIA,
        username=USERNAME,
        password=PASSWORD,
        pin=str(PIN),
    )
    # Override the library's MAC-derived device ID (see note above). The API
    # object reads this attribute for the Deviceid header on every MFA call.
    # Assert first: if a library bump renames it this would silently create an
    # unused attribute, fall back to the MAC-derived ID and cost an OTP plus a
    # rate-limit lockout, with nothing in the logs pointing at the cause.
    if not hasattr(vm.api, "_device_id"):
        raise RuntimeError(
            "hyundai_kia_connect_api moved _device_id - re-check the device-ID seam "
            "before deploying, or every cold start will trigger a fresh OTP."
        )
    vm.api._device_id = _STABLE_DEVICE_ID
    return vm


def _start_cooldown(reason: str):
    """Back off after a failed login so we stop resetting Kia's 7901 timer."""
    import time

    otp_state["rate_limited_until"] = time.time() + LOGIN_COOLDOWN_SECONDS
    expires = time.strftime(
        "%H:%M UTC", time.gmtime(otp_state["rate_limited_until"])
    )
    logger.error(
        f"{reason} Backing off until {expires} "
        f"({LOGIN_COOLDOWN_SECONDS // 60} minutes) - each retry resets Kia's timer."
    )


def _cooldown_remaining() -> int:
    """Minutes left on the login cooldown, or 0 if clear."""
    import time

    remaining = otp_state.get("rate_limited_until", 0) - time.time()
    return int(remaining / 60) + 1 if remaining > 0 else 0


def _complete_login(vm) -> bool:
    """Finish setup after a successful login. login() already fetched vehicles."""
    global VEHICLE_ID

    otp_state.update(
        {
            "required": False,
            "sent": False,
            "verified": True,
            "error": None,
            "rate_limited_until": 0,
        }
    )

    if not vm.vehicles:
        logger.error("No vehicles found on the account.")
        return False

    logger.info(f"Connected! Found {len(vm.vehicles)} vehicle(s).")
    for vid, vehicle in vm.vehicles.items():
        logger.info(f"Vehicle - ID: {vid}, Name: {vehicle.name}, Model: {vehicle.model}")

    if VEHICLE_ID is None:
        env_vehicle_id = os.environ.get("VEHICLE_ID", "").strip()
        VEHICLE_ID = env_vehicle_id or next(iter(vm.vehicles.keys()))
        logger.info(f"VEHICLE_ID set to: {VEHICLE_ID}")

    # Deliberately no state read here. login() has already fetched the vehicle
    # list, which is all a command endpoint needs, and get_cached_vehicle_state
    # will fetch state on demand for the ones that read it. Reading it here made
    # every cold start pay for two vendor round trips instead of one.
    return True


def _relogin_locked(reason: str) -> bool:
    """Log in from scratch after a refresh failed. Caller holds _init_lock.

    Canada has no refresh endpoint, so check_and_refresh_token is itself a
    login, and when it fails there is nothing left to fall back on: the token
    is dead and every read answers with Kia's generic "could not be processed"
    message. That is exactly what happened on 2026-09-24, two days into a run -
    the failure was one logged warning and the service then stayed broken until
    somebody restarted the container.

    The cooldown still applies. Kia locks an account out for repeated logins
    (error 7901) and every attempt resets that timer, so a box that cannot log
    in must back off rather than retry itself into a longer lockout.
    """
    global vehicle_manager, VEHICLE_ID
    from hyundai_kia_connect_api.ApiImpl import OTPRequest

    wait_minutes = _cooldown_remaining()
    if wait_minutes:
        logger.error(f"{reason} Login cooldown active - {wait_minutes} minute(s) left.")
        return False

    logger.info(f"{reason} Logging in again.")
    try:
        vm = _build_vehicle_manager()
        result = vm.login()
    except Exception as e:
        logger.error(f"Re-login failed: {e}", exc_info=True)
        otp_state["error"] = str(e)
        _start_cooldown("Re-login raised an error.")
        return False

    if isinstance(result, OTPRequest):
        # The 90-day device trust has lapsed. Nothing here can fix that; the
        # owner has to read an email, so say so and stop.
        logger.warning("Re-login needs an OTP. Use POST /otp/send.")
        otp_state.update({
            "required": True,
            "verified": False,
            "sent": False,
            "error": "OTP required - call POST /otp/send to re-authenticate",
            "rate_limited_until": 0,
        })
        return False

    if result is not True:
        logger.error(f"Unexpected re-login result: {result!r}")
        _start_cooldown("Re-login returned an unexpected result.")
        return False

    vehicle_manager = vm
    if not _complete_login(vm):
        return False

    # The stale token's readings are not worth keeping.
    vehicle_state_cache["last_update"] = None
    logger.info("Re-login succeeded.")
    return True


def init_vehicle_manager():
    """Initialize vehicle manager lazily on first request."""
    global vehicle_manager, VEHICLE_ID

    # VEHICLE_ID is only ever set alongside a live manager, and it is the thing
    # every caller actually needs, so it alone decides whether we are ready.
    # Checked before taking the lock so the warm path stays free.
    if VEHICLE_ID is not None:
        return True

    with _init_lock:
        # Another thread may have finished while we waited.
        if VEHICLE_ID is not None:
            return True

        return _init_vehicle_manager_locked()


def _init_vehicle_manager_locked():
    """The real initialisation. Only ever called holding _init_lock."""
    global vehicle_manager, VEHICLE_ID

    # Check credentials first
    if USERNAME is None or PASSWORD is None or PIN is None:
        logger.error("Missing credentials! Check KIA_USERNAME, KIA_PASSWORD, and KIA_PIN environment variables.")
        return False

    if not SECRET_KEY:
        logger.error("Missing SECRET_KEY environment variable.")
        return False

    import hyundai_kia_connect_api
    from hyundai_kia_connect_api.ApiImpl import OTPRequest

    lib_version = getattr(hyundai_kia_connect_api, "__version__", "unknown")
    logger.info(f"hyundai_kia_connect_api version: {lib_version}")
    logger.info(
        f"Initializing Vehicle Manager (Region: {REGION} ({REGION_CODES.get(REGION, 'Unknown')}), "
        f"Brand: {BRAND_KIA})..."
    )

    # Respect the cooldown - retrying during a 7901 lockout only extends it.
    wait_minutes = _cooldown_remaining()
    if wait_minutes:
        logger.error(
            f"Login cooldown active. Wait {wait_minutes} more minute(s), "
            f"then use POST /otp/send."
        )
        otp_state["required"] = True
        otp_state["verified"] = False
        return True

    try:
        vehicle_manager = _build_vehicle_manager()
        logger.info(f"Logging in with stable device UUID: {_STABLE_DEVICE_UUID}")
        result = vehicle_manager.login()
    except Exception as auth_error:
        logger.error(f"Login failed: {auth_error}", exc_info=True)
        otp_state["error"] = str(auth_error)
        otp_state["required"] = True
        otp_state["verified"] = False
        _start_cooldown("Login raised an error.")
        return True

    if isinstance(result, OTPRequest):
        # Device is outside the 90-day trust window - user must verify by email.
        # VehicleManager.login() has already stored the challenge on itself;
        # we only record that one is outstanding.
        logger.warning("OTP required (device not recognised). Use POST /otp/send.")
        otp_state["required"] = True
        otp_state["verified"] = False
        otp_state["sent"] = False
        otp_state["error"] = "OTP required - call POST /otp/send to start authentication"
        otp_state["rate_limited_until"] = 0
        return True

    if result is not True:
        logger.error(f"Unexpected login result: {result!r}")
        otp_state["error"] = f"Unexpected login result: {result!r}"
        _start_cooldown("Login returned an unexpected result.")
        return True

    logger.info("Login succeeded without OTP - device is remembered.")

    try:
        if not _complete_login(vehicle_manager):
            vehicle_manager = None
            VEHICLE_ID = None
            return False
    except Exception as e:
        logger.error(f"Failed to complete login: {e}", exc_info=True)
        vehicle_manager = None
        VEHICLE_ID = None
        return False

    return True

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
    from hyundai_kia_connect_api.exceptions import AuthenticationOTPRequired

    if vehicle_manager is None:
        return
    try:
        vehicle_manager.check_and_refresh_token()
    except AuthenticationOTPRequired:
        # Canada has no refresh endpoint, so a refresh is a fresh login. If the
        # device trust has lapsed that login comes back asking for an OTP.
        #
        # check_and_refresh_token raises without setting vehicle_manager.otp_request,
        # so there is no challenge to hand to /otp/send yet. Flag it and let
        # /otp/send drive a fresh login, which does set one.
        logger.warning("Token refresh needs a new OTP. Use POST /otp/send.")
        otp_state["required"] = True
        otp_state["verified"] = False
        otp_state["error"] = "OTP required - call POST /otp/send to re-authenticate"
    except Exception as e:
        # Not an OTP challenge, so the token is simply dead: on Canada there is
        # no lesser repair than logging in again.
        logger.warning(f"Token refresh check failed: {e}")
        with _init_lock:
            _relogin_locked("Token refresh failed.")

def json_errors(f):
    """Turn an unhandled exception into a 500 JSON body, logged with a traceback.

    Every endpoint had its own copy of this try/except; /status had a third
    spelling of it using traceback.print_exc().
    """
    @wraps(f)
    def wrapped(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            logger.error(f"Error in {request.path}: {e}", exc_info=True)
            return jsonify({"error": str(e)}), 500
    return wrapped


def require_auth(f):
    """Decorator to require authorization header and verified OTP."""
    @wraps(f)
    def decorated(*args, **kwargs):
        # Check the key and the rate limit BEFORE init_vehicle_manager, because
        # initialising performs a real login against Kia. Doing it the other way
        # let any unauthenticated request burn a login - and repeated ones feed
        # the 7901 lockout the cooldown below exists to avoid.
        auth_header = request.headers.get("Authorization")
        if auth_header != SECRET_KEY:
            logger.warning(f"Unauthorized request to {request.path} from {request.remote_addr}")
            return jsonify({"error": "Unauthorized"}), 403

        client_id = request.remote_addr
        if not check_rate_limit(client_id):
            logger.warning(f"Rate limit exceeded for {client_id}")
            return jsonify({"error": "Rate limit exceeded. Please try again later."}), 429

        if not init_vehicle_manager():
            return jsonify({"error": "Service initialization failed"}), 503

        # Block vehicle actions if OTP is required but not yet verified
        if otp_state.get("required") and not otp_state.get("verified"):
            logger.warning(f"Request to {request.path} blocked: OTP not verified")
            return jsonify({
                "error": "OTP verification required before vehicle commands. Use POST /otp/send to start.",
                "otp_required": True
            }), 401

        # Block if VEHICLE_ID was never set (auth failed, no vehicles loaded)
        if VEHICLE_ID is None:
            logger.warning(f"Request to {request.path} blocked: VEHICLE_ID is None")
            return jsonify({"error": "Vehicle not initialized. Authentication may have failed."}), 503

        return f(*args, **kwargs)
    return decorated

# ── Request Logging ──
@app.before_request
def log_request_info():
    logger.info(f"Incoming request: {request.method} {request.url} from {request.remote_addr}")

# ── Health Check Endpoint ──
@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint for monitoring.
    Does NOT trigger login/init - just reports current state.
    """
    is_initialized = vehicle_manager is not None and VEHICLE_ID is not None
    otp_needed = otp_state.get("required", False) and not otp_state.get("verified", False)

    response = {
        "status": "healthy" if is_initialized else ("otp_required" if otp_needed else "not_initialized"),
        "timestamp": datetime.now(ZoneInfo("America/Toronto")).isoformat(),
        "vehicles_count": len(vehicle_manager.vehicles) if vehicle_manager and vehicle_manager.vehicles else 0,
        "vehicle_manager_initialized": vehicle_manager is not None,
        "vehicle_id_set": VEHICLE_ID is not None,
        "otp_required": otp_needed,
        "otp_verified": otp_state.get("verified", False),
        "revision": _build_revision(),
    }

    if is_initialized and vehicle_manager and vehicle_manager.vehicles:
        response["vehicles"] = list(vehicle_manager.vehicles.keys())

    return jsonify(response), 200

# ── Root Endpoint ──
@app.route('/', methods=['GET'])
def root():
    """Root endpoint."""
    return jsonify({"status": "Welcome to the Kia Vehicle Control API"}), 200

# ── Diagnostic Endpoint ──
@app.route('/diagnostics', methods=['GET'])
def diagnostics():
    """Diagnostic endpoint to check environment configuration (no auth required)."""

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
        "revision": _build_revision(),
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
            "region_name": REGION_CODES.get(REGION, "Unknown"),
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
    Request an OTP be sent to the account owner.

    Body: {"method": "email"}
    Canada only supports email; SMS is accepted for other regions.
    """
    from hyundai_kia_connect_api.const import OTP_NOTIFY_TYPE

    data = request.get_json() or {}
    method = data.get("method", "email").lower()

    if method not in ["sms", "email"]:
        return jsonify({"error": "Method must be 'sms' or 'email'"}), 400

    wait_minutes = _cooldown_remaining()
    if wait_minutes:
        return jsonify({
            "error": f"Login cooldown active. Wait {wait_minutes} more minute(s) before retrying.",
            "retry_after_minutes": wait_minutes,
        }), 429

    # init_vehicle_manager performs the login that produces the OTPRequest.
    if not init_vehicle_manager():
        return jsonify({"error": "Failed to initialize vehicle manager"}), 503

    if otp_state.get("verified") and not otp_state.get("required"):
        return jsonify({
            "status": "authenticated",
            "message": "Device is already trusted - no OTP needed. API is ready to use.",
        }), 200

    # The library owns the challenge (vehicle_manager.otp_request); we do not
    # keep a copy. A lapse detected during a token refresh raises without
    # setting one, so log in again here to produce it.
    if getattr(vehicle_manager, "otp_request", None) is None:
        try:
            logger.info("No OTP challenge held; logging in to request one...")
            vehicle_manager.login()
        except Exception as e:
            logger.error(f"Login while requesting an OTP challenge failed: {e}", exc_info=True)
            otp_state["error"] = str(e)
            _start_cooldown("Login while requesting an OTP challenge failed.")
            return jsonify({"error": str(e), "type": type(e).__name__}), 503

        if getattr(vehicle_manager, "otp_request", None) is None:
            # login() returned a Token, so the device is trusted after all.
            if _complete_login(vehicle_manager):
                return jsonify({
                    "status": "authenticated",
                    "message": "Device is already trusted - no OTP needed. API is ready to use.",
                }), 200
            return jsonify({
                "error": "No OTP challenge available. Login did not request one.",
                "detail": otp_state.get("error"),
            }), 503

    try:
        logger.info(f"Requesting OTP via {method}...")
        notify_type = OTP_NOTIFY_TYPE.EMAIL if method == "email" else OTP_NOTIFY_TYPE.SMS
        vehicle_manager.send_otp(notify_type)

        otp_state["sent"] = True
        otp_state["required"] = True
        otp_state["error"] = None

        return jsonify({
            "status": "OTP sent",
            "method": method,
            "message": "Check your email for the OTP code, then call POST /otp/verify with {\"otp\": \"123456\"}",
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
    data = request.get_json() or {}
    otp = data.get("otp", "").strip()

    if not otp:
        return jsonify({"error": "Missing 'otp' in request body"}), 400

    if not otp.isdigit():
        return jsonify({"error": "OTP must be numeric"}), 400

    if vehicle_manager is None or getattr(vehicle_manager, "otp_request", None) is None:
        return jsonify({"error": "No OTP context available. Call /otp/send first."}), 400

    try:
        logger.info(f"Verifying OTP code (length: {len(otp)})...")
        # Sets the token and fetches the vehicle list, and asks Kia to remember
        # this device for 90 days (mfaYn=Y) so future cold starts skip the OTP.
        vehicle_manager.verify_otp_and_complete_login(otp)
        logger.info("OTP verification successful.")

        if not _complete_login(vehicle_manager):
            return jsonify({"error": "OTP verified but no vehicles found on the account"}), 502

        return jsonify({
            "status": "OTP verified",
            "message": "Authentication complete. You can now use the API normally.",
            "vehicles_found": len(vehicle_manager.vehicles),
        }), 200
    except Exception as e:
        logger.error(f"Failed to verify OTP: {e}", exc_info=True)
        otp_state["error"] = str(e)
        return jsonify({"error": str(e), "type": type(e).__name__}), 500


@app.route('/otp/status', methods=['GET'])
def otp_status():
    """Check OTP authentication status."""
    wait_minutes = _cooldown_remaining()
    return jsonify({
        "otp_required": otp_state["required"],
        "otp_sent": otp_state["sent"],
        "otp_verified": otp_state["verified"],
        "error": otp_state["error"],
        "cooldown_minutes_remaining": wait_minutes,
        "vehicle_manager_initialized": vehicle_manager is not None,
        "instructions": "If OTP required: 1) POST /otp/send, 2) Check your email, 3) POST /otp/verify with code"
    }), 200

# ── List Vehicles Endpoint ──
@app.route('/list_vehicles', methods=['GET'])
@require_auth
@json_errors
def list_vehicles():
    """List all vehicles in the account."""

    refresh_token_if_needed()
    # No state refresh: login() already populated the vehicle list, and this
    # endpoint only reads its metadata.
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

# ── Vehicle Status Endpoint ──
@app.route('/status', methods=['POST'])
@require_auth
@json_errors
def vehicle_status():
    """Get current vehicle status."""

    refresh_token_if_needed()

    # Kia serves a cached view of the car, and that cache sometimes comes back
    # with no EV data at all - no battery, no range - while still reporting the
    # 12V. Rendering that as 0% would read as a flat battery rather than "not
    # reported", so allow a direct poll of the car instead.
    #
    # Not the default: a force refresh wakes the car's modem and costs a little
    # 12V, which is why the cheap cached read is still what normal calls use.
    force = bool((request.get_json(silent=True) or {}).get("force"))
    if force:
        logger.info("Forcing a live refresh from the car...")
        vehicle_manager.force_refresh_vehicle_state(VEHICLE_ID)
        vehicle_state_cache["last_update"] = None

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
    # NOTE: the Canada API does not report instantaneous current/voltage
    # (KiaUvoApiCA never populates ev_charging_current or _voltage), so this
    # estimate derived from the remaining time is the only figure available.
    estimated_kw = None
    if charging and dur and dur > 0 and pct is not None and active_charge_limit:
        if pct < active_charge_limit:
            fraction = (active_charge_limit - pct) / 100
            estimated_kw = round((BATTERY_CAPACITY_KWH * fraction) / (dur / 60), 1)

    # ── ETA Calculation ──
    eta_time = eta_duration = None
    if charging and dur and dur > 0:
        now = datetime.now(ZoneInfo("America/Toronto"))
        eta_dt = now + timedelta(minutes=dur)
        # %-I is a glibc extension and raises on Windows, so strip the
        # leading zero ourselves to keep this runnable off Linux.
        eta_time = eta_dt.strftime("%I:%M %p").lstrip("0")
        h, m = divmod(dur, 60)
        eta_duration = f"{h}h {m}m remaining"

    # ── Response ──
    resp = {
        "battery_percentage": _int(pct),
        "battery_12v": _int(vehicle.car_battery_percentage),
        "charge_duration": int(dur) if dur is not None else 0,
        "charging_eta": eta_time,
        "charging_duration_formatted": eta_duration,
        "estimated_charging_power_kw": estimated_kw,
        "is_charging": charging,
        "plugged_in": plugged_in,
        "plug_type": plug_type,  # "DC", "AC", or null
        "charge_limits": {
            "ac": charge_limit_ac,
            "dc": charge_limit_dc,
            "active": active_charge_limit,  # The limit that applies based on plug type
        },
        "charge_duration_estimates": {
            "fast": _int(vehicle.ev_estimated_fast_charge_duration),
            "portable": _int(vehicle.ev_estimated_portable_charge_duration),
            "station": _int(vehicle.ev_estimated_station_charge_duration),
        },
        "battery_preconditioning": _bool(vehicle.ev_battery_precondition_enabled),
        # battery_preconditioning above stays for older clients; this block is
        # the fuller answer to "is the car set to get itself ready".
        "preconditioning": {
            "battery": _bool(vehicle.ev_battery_precondition_enabled),
            "departures": _departures(vehicle),
        },
        # The library has already mapped the raw unit code to a string
        # ("km"/"mi") when it set these, so they are passed through as-is.
        "range": {
            "ev": _reported_range(vehicle.ev_driving_range),
            "total": _reported_range(vehicle.total_driving_range),
            "unit": vehicle.ev_driving_range_unit,
        },
        "odometer": {
            "value": vehicle.odometer,
            "unit": vehicle.odometer_unit,
        },
        "is_locked": _bool(vehicle.is_locked),
        "engine_running": _bool(vehicle.engine_is_running),
        "doors": {
            "front_left": _bool(vehicle.front_left_door_is_open),
            "front_right": _bool(vehicle.front_right_door_is_open),
            "back_left": _bool(vehicle.back_left_door_is_open),
            "back_right": _bool(vehicle.back_right_door_is_open),
            "trunk": _bool(vehicle.trunk_is_open),
            "hood": _bool(vehicle.hood_is_open),
        },
        "windows": {
            "front_left": _bool(vehicle.front_left_window_is_open),
            "front_right": _bool(vehicle.front_right_window_is_open),
            "back_left": _bool(vehicle.back_left_window_is_open),
            "back_right": _bool(vehicle.back_right_window_is_open),
            "sunroof": _bool(vehicle.sunroof_is_open),
        },
        "climate": {
            "air_control_on": _bool(vehicle.air_control_is_on),
            "set_temperature": vehicle.air_temperature,
            "defrost_on": _bool(vehicle.defrost_is_on),
            "steering_wheel_heater_on": _bool(vehicle.steering_wheel_heater_is_on),
            "side_mirror_heater_on": _bool(vehicle.side_mirror_heater_is_on),
            "rear_window_heater_on": _bool(vehicle.back_window_heater_is_on),
        },
        "warnings": {
            "tire_pressure_any": _bool(vehicle.tire_pressure_all_warning_is_on),
            "tire_pressure_front_left": _bool(vehicle.tire_pressure_front_left_warning_is_on),
            "tire_pressure_front_right": _bool(vehicle.tire_pressure_front_right_warning_is_on),
            "tire_pressure_rear_left": _bool(vehicle.tire_pressure_rear_left_warning_is_on),
            "tire_pressure_rear_right": _bool(vehicle.tire_pressure_rear_right_warning_is_on),
            "washer_fluid_low": _bool(vehicle.washer_fluid_warning_is_on),
            "brake_fluid_low": _bool(vehicle.brake_fluid_warning_is_on),
        },
        "service": {
            "distance_since_last": vehicle.last_service_distance,
            "distance_to_next": vehicle.next_service_distance,
        },
        "location": {
            "latitude": vehicle.location_latitude,
            "longitude": vehicle.location_longitude,
            "last_updated": vehicle.location_last_updated_at.isoformat()
            if vehicle.location_last_updated_at else None,
        },
        "last_updated_at": vehicle.last_updated_at.isoformat()
        if vehicle.last_updated_at else None,
    }

    return jsonify(resp), 200


# ── Lock Status Endpoint ──
@app.route('/lock_status', methods=['GET'])
@require_auth
@json_errors
def lock_status():
    """Get vehicle lock status."""

    refresh_token_if_needed()
    vehicle = get_cached_vehicle_state()
    # Same coercion as /status: the library passes doorLock through raw, so
    # without this the two endpoints can disagree about the type.
    is_locked = _bool(vehicle.is_locked)

    logger.info(f"Lock status: {'Locked' if is_locked else 'Unlocked'}")
    return jsonify({"is_locked": is_locked}), 200


# ── Unlock Car Endpoint ──
@app.route('/unlock_car', methods=['POST'])
@require_auth
@json_errors
def unlock_car():
    """Unlock the vehicle."""

    refresh_token_if_needed()
    # No state refresh: this command does not read vehicle state, and the
    # caller usually asks for /status straight afterwards anyway.
    result = vehicle_manager.unlock(VEHICLE_ID)
    logger.info(f"Unlock result: {result}")

    return jsonify({"status": "Car unlocked", "result": result}), 200

# ── Lock Car Endpoint ──
@app.route('/lock_car', methods=['POST'])
@require_auth
@json_errors
def lock_car():
    """Lock the vehicle."""

    refresh_token_if_needed()
    # No state refresh: this command does not read vehicle state, and the
    # caller usually asks for /status straight afterwards anyway.
    result = vehicle_manager.lock(VEHICLE_ID)
    logger.info(f"Lock result: {result}")

    return jsonify({"status": "Car locked", "result": result}), 200

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
@json_errors
def start_climate():
    """Start climate control with optional seasonal presets."""

    from hyundai_kia_connect_api import ClimateRequestOptions

    refresh_token_if_needed()
    # Reads state below, so go through the cache rather than always refetching.
    get_cached_vehicle_state()

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

# ── Stop Climate Endpoint ──
@app.route('/stop_climate', methods=['POST'])
@require_auth
@json_errors
def stop_climate():
    """Stop climate control."""

    refresh_token_if_needed()
    # No state refresh: this command does not read vehicle state, and the
    # caller usually asks for /status straight afterwards anyway.
    result = vehicle_manager.stop_climate(VEHICLE_ID)
    logger.info(f"Stop climate result: {result}")

    return jsonify({"status": "Climate stopped", "result": result}), 200


# ── Charge Control Endpoints ──
@app.route('/start_charge', methods=['POST'])
@require_auth
@json_errors
def start_charge():
    """Start charging. Only works while the car is plugged in."""

    refresh_token_if_needed()
    result = vehicle_manager.start_charge(VEHICLE_ID)
    logger.info(f"Start charge result: {result}")

    return jsonify({"status": "Charging started", "result": result}), 200


@app.route('/stop_charge', methods=['POST'])
@require_auth
@json_errors
def stop_charge():
    """Stop charging."""

    refresh_token_if_needed()
    result = vehicle_manager.stop_charge(VEHICLE_ID)
    logger.info(f"Stop charge result: {result}")

    return jsonify({"status": "Charging stopped", "result": result}), 200


@app.route('/set_charge_limits', methods=['POST'])
@require_auth
@json_errors
def set_charge_limits():
    """
    Set the AC and DC charge limits.

    Body: {"ac": 80, "dc": 80}
    Either key may be omitted; the current limit is kept for whichever is left out.
    Kia accepts limits in 10% steps between 50 and 100.
    """

    data = request.get_json() or {}

    refresh_token_if_needed()
    vehicle = get_cached_vehicle_state()

    ac = data.get("ac", vehicle.ev_charge_limits_ac)
    dc = data.get("dc", vehicle.ev_charge_limits_dc)

    if ac is None or dc is None:
        return jsonify({
            "error": "Both 'ac' and 'dc' limits are required - the current "
                     "values could not be read from the vehicle."
        }), 400

    try:
        ac, dc = int(ac), int(dc)
    except (ValueError, TypeError):
        return jsonify({"error": "Charge limits must be whole numbers"}), 400

    for name, value in (("ac", ac), ("dc", dc)):
        if not 50 <= value <= 100 or value % 10 != 0:
            return jsonify({
                "error": f"Invalid {name} limit {value}. Must be 50-100 in steps of 10."
            }), 400

    result = vehicle_manager.set_charge_limits(VEHICLE_ID, ac, dc)
    logger.info(f"Set charge limits result: {result}")

    return jsonify({
        "status": "Charge limits set",
        "limits": {"ac": ac, "dc": dc},
        "result": result,
    }), 200
# ── Debug Vehicle Endpoint ──
@app.route('/debug_vehicle', methods=['POST'])
@require_auth
@json_errors
def debug_vehicle():
    """Debug endpoint to view raw vehicle data."""

    refresh_token_if_needed()
    vehicle = get_cached_vehicle_state()

    # Access the raw private vehicle data
    # The library keeps the raw payload on vehicle.data - there is no
    # _vehicle_data, which is why this used to return nothing. Canada files
    # evStatus under "status", other regions under "vehicleStatus".
    raw_data = getattr(vehicle, "data", None) or {}
    ev_status = (_child(raw_data, "status", "evStatus")
                 or _child(raw_data, "vehicleStatus", "evStatus") or {})

    logger.info(f"Found evStatus keys: {list(ev_status.keys())}")

    return jsonify({
        "ev_status_raw": ev_status,
        "keys": list(ev_status.keys()),
    }), 200


# ── Error Handlers ──
# ── Token keepalive (long-lived hosts only) ──
# Kia's access token expires, and on Canada a refresh is a full re-login. The
# library exposes a cheap "get vehicle list" call for exactly this: hitting it
# every few minutes keeps the token alive, so a box that stays up logs in about
# once a day instead of once per request.
#
# Off unless KIA_KEEPALIVE_SECONDS is set, because it is meaningless on a
# serverless deployment where the process dies between requests.
def _keepalive_loop(interval: int):
    import time

    while True:
        time.sleep(interval)
        try:
            if vehicle_manager is None or vehicle_manager.token is None:
                continue
            with _init_lock:
                alive = vehicle_manager.api.test_token(vehicle_manager.token)
                if not alive:
                    logger.info("Keepalive: token stale, refreshing...")
                    try:
                        vehicle_manager.check_and_refresh_token()
                    except Exception as e:
                        # This tick is the first thing to notice an expired
                        # token, so it is also where the repair belongs -
                        # waiting for a request means answering that request
                        # with an error first.
                        logger.warning(f"Keepalive refresh failed: {e}")
                        _relogin_locked("Keepalive refresh failed.")
        except Exception as e:
            # Never let this kill the thread - the next tick may well succeed,
            # and a request can always re-initialise on its own.
            logger.warning(f"Keepalive tick failed: {e}")


_KEEPALIVE_SECONDS = int(os.environ.get("KIA_KEEPALIVE_SECONDS", "0") or 0)
if _KEEPALIVE_SECONDS > 0:
    logger.info(f"Starting token keepalive every {_KEEPALIVE_SECONDS}s")
    threading.Thread(
        target=_keepalive_loop, args=(_KEEPALIVE_SECONDS,), daemon=True
    ).start()


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
