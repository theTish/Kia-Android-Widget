# Kia EV6 Android clients

Native clients for the Flask API that already backs the KWGT widget, so the
watch and phone talk to Vercel directly rather than relaying through Tasker.

## Modules

| Module  | What it is | Package |
|---------|------------|---------|
| `:core` | The API client and the build-time secrets. Everything else depends on it. | `ca.thetish.kia.core` |
| `:tile` | Wear OS tile: Lock, Unlock, Climate. | `ca.thetish.kiatile` |
| `:app`  | Phone app and the home screen widget. | `ca.thetish.kia.app` |

`:core` owns the networking, so it declares `INTERNET` and
`ACCESS_NETWORK_STATE` and those merge into both consumers. It is also the only
place the API key is read, which keeps the secret in one file rather than three.

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

If `KIA_SECRET` is left empty everything still builds, and the clients report
`No key in build` instead of calling anything.

Gradle needs a JDK. If `java` is not on your PATH, Android Studio ships one:

```bash
export JAVA_HOME="/c/Program Files/Android/Android Studio/jbr"
```

## Build

```bash
./gradlew assembleDebug
```

APKs land at `tile/build/outputs/apk/debug/tile-debug.apk` and
`app/build/outputs/apk/debug/app-debug.apk`.

## Install on the watch

Enable ADB debugging and Debug over Wi-Fi on the watch under
Settings, Developer options. Wear OS uses **separate ports for pairing and
connecting**, and they are not 5555 — `adb mdns services` lists both
(`_adb-tls-pairing` and `_adb-tls-connect`):

```bash
adb mdns services
adb pair <watch-ip>:<pairing-port>
adb connect <watch-ip>:<connect-port>
adb -s <watch-ip>:<connect-port> install -r tile/build/outputs/apk/debug/tile-debug.apk
```

Then add the tile: long-press the watch face, swipe to the end of the tile
carousel, tap **+**, pick **EV6**.

The tile has no launcher icon on purpose. It is a tile and nothing else.

## Install on the phone

```bash
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

Then long-press the home screen, choose **Widgets**, and drag **Kia EV6** out.
It is resizable; the default is four cells by two.

## The widget

Built with Glance, so the layout is Compose rather than `RemoteViews` by hand.
It shows battery, range and lock state, with Lock, Unlock, Climate and Refresh.
An unlocked car is coloured amber, because that is the one state worth noticing
from across the room.

Two things about it are deliberate and easy to undo by accident:

**Taps run in a `CoroutineWorker`, not in the Glance `ActionCallback`.** Glance
dispatches actions through a `BroadcastReceiver`, and the system stops giving a
receiver CPU after about ten seconds. A cold car regularly takes longer than
that to answer, so the call would be killed part-way with the widget still
showing `Locking…` and no way to tell whether the car heard it. `KiaWorker`
survives that window.

**`updatePeriodMillis` is 0.** The system's periodic update only re-renders the
widget, it does not run the network call, so a schedule there would wake the
device without refreshing anything. Status is fetched when Refresh is tapped and
after any command succeeds. If you want it to update on its own, that wants a
periodic `WorkManager` job, not `updatePeriodMillis`.

## Behaviour

Both clients behave the same way:

- **Lock** and **Climate** fire immediately on one tap.
- **Unlock** needs two taps. The first arms it and the button changes to
  *Tap again to unlock* for ten seconds. A watch screen is easy to brush
  against, and an accidental unlock in a car park is worth one extra tap.
- The status line shows the last result, taken from the API's own `status` or
  `error` field.

## Which host the clients use

The phone app and its widget read the API address from **Settings** on the
device, so moving hosts is a text field. The watch tile cannot - it is a
separate device with separate storage and no practical settings UI - so it uses
whatever `KIA_BASE_URL` was compiled in, and moving it means a rebuild and a
reinstall.

Both default to `https://kia.tishman.ca` (the Oracle box). Vercel stays deployed
as a standby: on the phone that is two taps in Settings, on the watch it is a
rebuild.

One catch if you ever change the tile's icons: `RESOURCES_VERSION` in
`KiaTileService` must be bumped, or a watch that already has the tile keeps
serving the cached images. A reinstall clears the cache, which is why moving the
drawables into `:core` did not visibly break anything.

## Rotating the key

The key is compiled in, so a rotation means editing `local.properties` and
reinstalling:

```bash
./gradlew assembleDebug
adb -s <watch-ip>:<connect-port> install -r tile/build/outputs/apk/debug/tile-debug.apk
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

Note that a compiled-in key is extractable from the APK by anyone holding it.
It is fine for a personal sideload; it is not what you would ship. The real fix
is per-device tokens issued by the API rather than one shared secret.
