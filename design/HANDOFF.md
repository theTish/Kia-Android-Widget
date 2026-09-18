# EV6 GT redesign — handoff for implementation

Mockups in this folder are HTML reference files (open any `.dc.html` in a browser for the layout; values in them are exact). They are **reference, not code to port** — rebuild natively in the existing modules. Sample numbers (78%, 412 km, tyre warning, etc.) are placeholders; wire everything to `VehicleStatus` and keep the existing rule: unknown renders as unknown, never 0.

Car image: `../design-assets/ev6gt-front34.png` (875×429, transparent, front three-quarter). Add as a drawable in `:core` so app, widget and tile share it.

## Design tokens

Replace `KiaColors.kt` + `core/res/values/colors.xml` values (keep them in step, as today):

| Token | Value | Use |
|---|---|---|
| background | `#000000` | phone screens, watch |
| surface | `#111417` | cards, secondary buttons |
| surface_2 | `#15191C` | widget buttons (solid mode) |
| line | `#262B30` | 1px borders |
| divider | `#22272B` | row dividers in cards |
| text | `#F3F5F0` | primary text |
| text_dim | `#A3ABB0` | labels, secondary |
| text_muted | `#7C858B` | "Not reported" |
| accent | `#CEDE27` | GT lime, sampled from the GT drive-mode button on the steering wheel. Flat fill, no gradients. Uses: battery bars, charging state, primary Lock on phone/watch, Save, watch battery arc |
| accent_ink | `#0B0D05` | text/icons on accent |
| armed | `#FFB547` | unlock-confirm state, warnings |
| armed_bg / armed_line | `#211808` / `#4A340F` | "Needs attention" card |

Type: **Chakra Petch** (600/700) for numbers and section labels; **Manrope** (400–700) for body. Use downloadable Google Fonts or bundle the TTFs in `res/font`. Section labels: 13sp, uppercase, 0.14em letter-spacing, `text_dim`.

Radii: cards 20dp, big control buttons 22dp, pills fully rounded, widget card 28dp.

## Phone — Home (`Main.dc.html`)

Order top to bottom: header (EV6 **GT** + "Updated HH:MM", refresh + settings icon buttons 48dp) → car hero (~208dp tall, faint accent glow ellipse under the wheels) → battery % at 88sp Chakra Petch + range, lock-state chip on the right → battery bar (10dp, accent fill, white tick at AC charge limit, "Not plugged in"/charging text left, "Limit 80%" right) → 3-up control grid (Lock accent-filled, Unlock outline, Climate surface; 104dp tall) → armed hint line → Needs attention card (only when warnings/openings/engine running) → Charge card (AC limit / DC limit / 12V) → Climate + Service cards side by side → Odometer / Doors & boot / Windows rows → Show on map (only with a location).

Unlock keeps the existing `UnlockGuard` flow: first tap turns the button `armed` (amber fill, label "Confirm", hint "Tap Confirm to unlock"), second tap sends.

## Phone — Settings (`Settings.dc.html`)

Back arrow + title. Outlined 56dp fields on `surface` for API address and API key (with show/hide eye). Climate preset becomes a 3-way segmented control (Winter / Summer / Spring/Fall, values `winter`/`summer`/`springfall`). Test connection (outline pill) with result line below in accent on success. Footnote about the watch tile, then full-width accent **Save** pinned to the bottom.

## Home screen widget (`Widget*.dc.html`)

Card: car image left (~168dp), right column: % (44sp) + state icon, "412 km · Locked", optional status line, 4dp battery bar with limit tick. Bottom: 4 equal 48dp icon-only pills — Lock, Unlock, Climate, Refresh — **all neutral, no accent on Lock**.

Three charge states:
- **Unplugged:** no icon, no status line.
- **Charging:** accent bolt icon next to %, accent line "Charging · {chargeRemainingText} left" (drop the line if that field is null).
- **Plugged in, not charging:** white plug icon, white line "Plugged in · not charging".

Requires a new `pluggedIn` pref key written by `KiaWorker` alongside `charging` (the widget only stores `charging` today).

Background, two options (setting, default Glass):
- **Glass:** no real blur (widgets can't blur what's behind them). Background drawable = `#570C0E14` tint (≈34% alpha) + a 145° white gradient overlay (20% → 5% → 10%), 1dp `#47FFFFFF` border, a soft white radial highlight top-left. Buttons `#24FFFFFF` fill with `#3DFFFFFF` 1dp border. Secondary text white at 80%, battery track white at 20%, slight text shadow for legibility. Ship it as a 9-patch/layered drawable since Glance can't compose these.
- **Solid:** card `#0B0D0F`, buttons `surface_2` with `line` border, `text_dim` secondary.

Glance can't use custom fonts easily — system font fallback in the widget is acceptable.

## Wear OS tile (`WatchTile.dc.html`)

Accent battery arc around the bezel (ProtoLayout `Arc`, 6dp, track `#1A1E22`), car image ~148dp wide at top, "78% · 412 km" (30sp) with lock state under it, two 64dp circle buttons (Lock accent, Unlock surface; armed state as today), Climate pill below. Keep the existing centring-in-an-expanding-Box approach.
