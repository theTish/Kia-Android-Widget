# Plan — Kia-Android-Widget
*Updated: 2026-09-21*

## Current Status
Phone app, widget, watch tile and API are all on `main` at `34ef222` (API
deployed at `b616464`). Auto-lock runs in Shadow at 75 m with the parking-time
bug fixed and holds now logged. The Climate button's settings are chosen on the
phone and synced to the watch; pre-conditioning shows as an On/Off row with a
read-only schedule.

## Next Session
1. Read the Auto-lock log (Settings → Auto-lock) after a few ordinary
   park-and-walk-away trips. Expect "Did nothing: already locked" when the car
   locked itself, and a lock decision when it was left unlocked. Only then
   consider Armed.
2. Press Climate on the watch once and confirm the car gets the phone's
   settings (currently 21.5°, 10 min). Not tested this session because it
   starts the car.
3. Tap the widget's upper area and confirm it opens the app — built and
   installed, not seen working.
4. Decide whether the tile should say what it will send (it reads the phone's
   choice silently at tap time).
5. Carried over: verify the zero-range handling at the next Kia outage;
   optional Cloudflare IP cron on the box.

## Blockers
- None.

## Context to reload
- `android/app/src/main/kotlin/ca/thetish/kia/app/Geofences.kt` — initial EXIT
  trigger when the car's position moves more than 30 m.
- `android/core/src/main/kotlin/ca/thetish/kia/core/ClimateSync.kt` — Data
  Layer item `/climate`; requires matching applicationId on both ends.
- `api/index.py` — `preconditioning` block reads raw `reservChargeInfos`, since
  the library does not decode it for Canada.
