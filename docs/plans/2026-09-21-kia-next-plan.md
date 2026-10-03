# Plan — Kia-Android-Widget
*Updated: 2026-10-02*

## Current Status
Auto-lock was rebuilt on 2026-10-02 after a false lock with the phone left in
the car. It now triggers on the car's Bluetooth dropping, takes the phone's own
fix at that instant as the car's position, and locks only once the phone is
clear of it for 60 seconds with the car off and unlocked. `main` is at
`1c5c6a3` and the build is on the phone, which is still set to Armed with no car
Bluetooth device chosen - so nothing triggers yet.

## Next Session
1. On the phone, **Settings → Auto-lock → The car's Bluetooth**: pick the car
   and grant nearby-device permission. Without it there is no trigger.
2. Decide Shadow or Armed. Recommended: Shadow for a few days of drives first.
3. After a few drives, read the Auto-lock log. Per parking, expect "inside the
   50m ring" beside the car, then "Waiting", then a lock or a named refusal. A
   run of "left the car on a fix accurate only to…" means anchors are too vague
   where you park - check underground and garage parking specifically.
4. Check the 2026-09-26 token renewal happened unattended:
   `docker logs kia-api | grep -i "re-login\|keepalive"` on the Oracle box.
5. Verify the charging display while plugged in (tile bolt and kW, widget and
   phone lines) - unseen since 2026-09-23.
6. Put the AC charge limit back to 80 when it is no longer needed at 100.
7. Still open: tap above the widget's buttons once to confirm it opens the app.

## Blockers
- None. Step 1 needs Lee's phone in hand.

## Context to reload
- `android/core/src/main/kotlin/ca/thetish/kia/core/Geofence.kt` — the decision: anchor, margin, dwell, refusals.
- `android/app/src/main/kotlin/ca/thetish/kia/app/Geofences.kt` — `CarBluetoothReceiver`, `AnchorWorker`, `GeofenceWorker` and the 1-minute watch.
- Vault: `Kia-Android-Widget/notes/2026-10-02-session.md` and `decisions.md` — why Kia's position and home Wi-Fi are not used.
- adb on this laptop can wedge (daemon starts, never listens on 5037): kill `adb.exe` and start it through a PowerShell job.
