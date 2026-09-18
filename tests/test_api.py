"""Offline contract tests for the Kia API.

Exercises every endpoint against a stubbed VehicleManager, so it needs no
credentials and never touches the car. Run this after a library upgrade to
confirm the vehicle attributes /status reads still exist:

    uv sync
    .venv/Scripts/python tests/test_api.py      # or .venv/bin/python
"""
import os, sys, json, datetime
os.environ.update(KIA_USERNAME="u@e.com", KIA_PASSWORD="pw", KIA_PIN="1234",
                  SECRET_KEY="testsecret", KIA_REGION="2")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import api.index as app_mod
from hyundai_kia_connect_api.Vehicle import Vehicle
from hyundai_kia_connect_api.ApiImpl import OTPRequest

def make_vehicle():
    v = Vehicle(id="VID1", name="EV6", model="EV6", year=2023)
    v.ev_battery_percentage = 72
    v.ev_battery_is_charging = True
    v.ev_battery_is_plugged_in = 2
    v.ev_estimated_current_charge_duration = (95, 1)
    v.ev_estimated_fast_charge_duration = (40, 1)
    v.ev_estimated_portable_charge_duration = (600, 1)
    v.ev_estimated_station_charge_duration = (95, 1)
    v.ev_charge_limits_ac = 80
    v.ev_charge_limits_dc = 80
    v.car_battery_percentage = 87
    v.is_locked = True
    v.engine_is_running = False
    v.front_left_door_is_open = 0
    v.front_left_window_is_open = 1
    v.odometer = (18342.5, "km")
    v.ev_driving_range = (310.0, "km")
    v.total_driving_range = (310.0, "km")
    v.air_temperature = (21.0, "C")
    v.tire_pressure_all_warning_is_on = 0
    v.washer_fluid_warning_is_on = 1
    v.location = (45.4215, -75.6972, datetime.datetime.now(datetime.UTC))
    v.last_updated_at = datetime.datetime.now(datetime.UTC)
    return v

class FakeVM:
    def __init__(self, otp=False):
        self.vehicles = {}
        self.token = None
        self.otp_request = None
        self._otp = otp
        self.calls = []
    def login(self):
        if self._otp:
            self.otp_request = OTPRequest(request_id="uuid", otp_key=None, has_email=True,
                                          has_sms=False, email="u@e.com", sms=None)
            return self.otp_request
        self.vehicles = {"VID1": make_vehicle()}
        return True
    def send_otp(self, t): self.calls.append(("send_otp", t))
    def verify_otp_and_complete_login(self, code):
        self.calls.append(("verify", code)); self.vehicles = {"VID1": make_vehicle()}
    def update_all_vehicles_with_cached_state(self): pass
    def check_and_refresh_token(self): pass
    def get_vehicle(self, vid): return self.vehicles[vid]
    def set_charge_limits(self, vid, ac, dc): self.calls.append(("limits", ac, dc)); return "OK"
    def start_charge(self, vid): return "OK"
    def stop_charge(self, vid): return "OK"

def reset(otp=False):
    fake = FakeVM(otp=otp)
    app_mod.vehicle_manager = None
    app_mod.VEHICLE_ID = None
    app_mod.vehicle_state_cache["last_update"] = None
    app_mod.otp_state.update(required=False, sent=False, verified=False,
                             error=None, otp_request=None, rate_limited_until=0)
    app_mod._build_vehicle_manager = lambda: fake
    return fake

client = app_mod.app.test_client()
H = {"Authorization": "testsecret"}
fails = []
def check(label, cond, extra=""):
    print(("  PASS  " if cond else "  FAIL  ") + label + (" :: "+str(extra) if not cond else ""))
    if not cond: fails.append(label)

print("\n--- happy path: trusted device ---")
reset()
r = client.post("/status", headers=H)
check("/status 200", r.status_code == 200, r.get_data(as_text=True)[:300])
d = r.get_json() if r.status_code == 200 else {}
if d:
    print(json.dumps(d, indent=2)[:1100])
    check("battery", d["battery_percentage"] == 72)
    check("windows.front_left True", d["windows"]["front_left"] is True)
    check("doors.front_left False", d["doors"]["front_left"] is False)
    check("odometer value", d["odometer"]["value"] == 18342.5)
    check("odometer unit km", d["odometer"]["unit"] == "km")
    check("location lat", d["location"]["latitude"] == 45.4215)
    check("washer warning", d["warnings"]["washer_fluid_low"] is True)
    check("no actual_charging_power_kw key", "actual_charging_power_kw" not in d)
    check("charge est power present", d["estimated_charging_power_kw"] is not None)
    check("last_updated_at set", d["last_updated_at"] is not None)
    check("range reported", d["range"]["ev"] == 310.0)

print("\n--- a range of zero means unknown, not empty ---")
# The car sends 0 rather than null when it has no range for us - seen through a
# Kia maintenance window, next to a 73% battery, and a forced live poll returned
# the same 0. A client cannot tell that 0 apart from a measurement, so the API
# must not hand it on as one.
fake = reset()
client.post("/status", headers=H)          # populates the vehicle list
v = fake.vehicles["VID1"]
v.ev_driving_range = (0.0, "km")
v.total_driving_range = (0.0, "km")
app_mod.vehicle_state_cache["last_update"] = None
d = client.post("/status", headers=H).get_json()
check("zero ev range is null", d["range"]["ev"] is None, d["range"])
check("zero total range is null", d["range"]["total"] is None, d["range"])
check("unit survives", d["range"]["unit"] == "km", d["range"])
check("battery untouched", d["battery_percentage"] == 72, d["battery_percentage"])

print("\n--- auth ---")
reset()
check("bad key 403", client.post("/status", headers={"Authorization":"nope"}).status_code == 403)

print("\n--- OTP flow ---")
fake = reset(otp=True)
r = client.post("/status", headers=H)
check("blocked pre-OTP 401", r.status_code == 401, r.get_data(as_text=True)[:200])
r = client.post("/otp/send", json={"method":"email"}, headers=H)
check("/otp/send 200", r.status_code == 200, r.get_data(as_text=True)[:300])
check("send_otp called w/ EMAIL", any(c[0]=="send_otp" and c[1].name=="EMAIL" for c in fake.calls), fake.calls)
r = client.post("/otp/verify", json={"otp":"123456"}, headers=H)
check("/otp/verify 200", r.status_code == 200, r.get_data(as_text=True)[:300])
check("verified state", app_mod.otp_state["verified"] is True)
check("/status works after OTP", client.post("/status", headers=H).status_code == 200)
r = client.post("/otp/verify", json={"otp":"abc"}, headers=H)
check("non-numeric OTP 400", r.status_code == 400)

print("\n--- charge limits validation ---")
fake = reset()
client.post("/status", headers=H)
check("valid 80/80 -> 200", client.post("/set_charge_limits", json={"ac":80,"dc":80}, headers=H).status_code == 200)
check("85 rejected", client.post("/set_charge_limits", json={"ac":85,"dc":80}, headers=H).status_code == 400)
check("40 rejected", client.post("/set_charge_limits", json={"ac":40,"dc":80}, headers=H).status_code == 400)
check("partial ac-only ok", client.post("/set_charge_limits", json={"ac":90}, headers=H).status_code == 200)
check("start_charge 200", client.post("/start_charge", headers=H).status_code == 200)
check("stop_charge 200", client.post("/stop_charge", headers=H).status_code == 200)

print("\n--- cooldown guard ---")
reset()
app_mod._start_cooldown("test")
check("cooldown minutes ~35", 30 <= app_mod._cooldown_remaining() <= 36, app_mod._cooldown_remaining())
r = client.post("/otp/send", json={"method":"email"}, headers=H)
check("/otp/send 429 during cooldown", r.status_code == 429, r.get_data(as_text=True)[:200])

print("\n--- /otp/status + /diagnostics ---")
reset()
check("/otp/status 200", client.get("/otp/status").status_code == 200)
check("/diagnostics 200", client.get("/diagnostics").status_code == 200)
# The deploy script reads this back out of /health to confirm it is serving
# what it just built, so both endpoints have to carry it.
check("/health reports a revision", "revision" in client.get("/health").get_json())
check("/diagnostics reports a revision", "revision" in client.get("/diagnostics").get_json())

print("\n" + ("ALL APP CHECKS PASSED" if not fails else f"{len(fails)} FAILURES: {fails}"))
sys.exit(1 if fails else 0)
