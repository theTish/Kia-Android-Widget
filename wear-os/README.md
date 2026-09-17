# Kia EV6 Wear OS tile

A single Wear OS tile with three buttons: **Lock**, **Unlock** and **Climate**.
Each one calls the Flask API that already backs the phone widget, so the watch
talks to Vercel directly rather than relaying through Tasker.

## Why a tile and not a watch app

A tile sits one swipe from the watch face and needs no app launch. That matters
for the case this exists for: standing next to the car, phone inside it.

## What it needs at runtime

The watch needs its own route to the internet. Any of these work:

- LTE watch on cellular
- Watch on Wi-Fi
- Watch in Bluetooth range of the phone, tethering through it

If the watch has no route, the button reports a network error rather than
failing silently.

## Setup

The API key is **never** stored in a tracked file. It is read at build time from
`local.properties`, which is gitignored.

```bash
cp local.properties.example local.properties
```

Then edit `local.properties`:

```properties
sdk.dir=C\:\\Users\\<you>\\AppData\\Local\\Android\\Sdk
KIA_BASE_URL=https://kia-android-widget.vercel.app
KIA_SECRET=<the current SECRET_KEY from your Vercel environment>
KIA_CLIMATE_PRESET=winter
```

`KIA_CLIMATE_PRESET` accepts `winter`, `summer` or `springfall`, matching
`CLIMATE_PRESETS` in `api/index.py`.

If `KIA_SECRET` is left empty the app still builds, and the tile reports
`No key in build` instead of calling anything.

## Build

```bash
./gradlew assembleDebug
```

The APK lands at `tile/build/outputs/apk/debug/tile-debug.apk`.

## Install on the watch

Enable ADB debugging and Debug over Wi-Fi on the watch under
Settings, Developer options. Note the IP it shows, then:

```bash
adb connect <watch-ip>:5555
adb -s <watch-ip>:5555 install -r tile/build/outputs/apk/debug/tile-debug.apk
```

Accept the debugging prompt on the watch. Then add the tile: long-press the
watch face, swipe to the end of the tile carousel, tap **+**, pick **EV6**.

The app has no launcher icon on purpose. It is a tile and nothing else.

## Behaviour

- **Lock** and **Climate** fire immediately on one tap.
- **Unlock** needs two taps. The first arms it and the button changes to
  *Confirm unlock* for ten seconds. A watch screen is easy to brush against,
  and an accidental unlock in a car park is worth one extra tap.
- The line at the top shows the last result, taken from the API's own
  `status` or `error` field.

## Rotating the key

The key is compiled in, so a rotation means editing `local.properties` and
reinstalling:

```bash
./gradlew assembleDebug && adb -s <watch-ip>:5555 install -r tile/build/outputs/apk/debug/tile-debug.apk
```
