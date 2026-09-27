# SquachWatch-Pager — SquachWatch Pager theme (design)

**Date:** 2026-09-27 · **Status:** implemented and checked on the user's Pager on 2026-09-27
**Look ported from:** SquachWatch-CYD at commit `9e41660` (v1.22.0, GPL-3.0, same licence as this project).

## 1. Goal

Give SquachWatch's screen and its alert pop-up the original CYD app's synthwave look, with Squachy, using only the
Pager's own theme system (pictures and layout files). SquachWatch's code does not change.

A Pager theme is always for the whole Pager, and the user picks it in Settings. Only two pictures/layouts change:
- the payload screen, where SquachWatch's lines appear (background image, and text wrapped at 36 characters
  instead of the stock 50 -- every payload's log screen, not just SquachWatch's)
- the alert pop-up

Two things reach further than that, because the theme system's colours are Pager-wide by nature: the neon
values of the four colour names SquachWatch prints in apply everywhere those names are used -- menus,
dashboards, dialogs, settings, icon recolours -- not only on SquachWatch's own screen.

Everything else (boot screen, main menu, every other dialog's pictures and layouts) keeps the stock look; those
can be themed later.

## 2. Decisions taken with the user (2026-09-27)

| Question | Decision |
|---|---|
| Mascot | Squachy, ported from the original's own drawing code, credited (§8). |
| Approach | A Pager theme. The Pager has no per-app themes, and a payload cannot draw its own screen over the Pager's UI without taking the screen over entirely, which was not built. |
| Scope | Payload screen, alert pop-up and four palette colours. Boot screen and main menu later, on request. |
| Payload screen layout | B: a darkened sunset, with Squachy and the sun bright at the right. The on-device check (§6) showed long lines ran over Squachy at the stock 50-character width, so text now wraps at 36 characters instead (still layout B) -- that cleared him. The fallback considered was C: a starry night-sky text area, with a sunset band and a small Squachy along the bottom -- not needed. |
| Alert pop-up | The CYD card: rainbow border, pink "HEADS UP!" strip (neutral wording, since every payload's alerts use it), the alert text in cyan in a dark data plate, and a radar with Squachy's face. |

## 3. What the Pager allows (measured 2026-09-27)

- **Where themes live:** in `/root/themes/<name>/` (that is `/mmc/root/themes`). The folder name is the name in
  Settings. The stock theme is `/lib/pager/themes/wargames` (theme framework 0.7). Its README says to make a new
  theme by copying it.
- **Payload screen** (`components/payload_log.json`): one full-screen background image (480×222), plus the payload
  title, text settings (`start_x` 6, `start_y` 24, `visible_lines` 14, `max_chars` 50, `text_size` small) and
  status indicators. The real text is about 9.3 px per character, so a 50-character SquachWatch line spans almost
  the whole width.
- **Alert pop-up** (`components/alerts/alert_info_dialog.json`): a 429×222 background at x = 28, the timestamp at
  (340, 10), and the alert text through the template `components/templates/alert_info_dialog_text.json`. The
  stock template uses `text_color_palette` yellow, `max_chars` 42, `wrap_text` true, `max_lines` 13, and
  `center_text_within` x 80–400, y 26–190.
- **Colours:** the `color_palette` in `theme.json`. `LOG <colour>` in any payload uses these names.
- **Stock images** are 256-colour PNGs. The original CYD also shows 8-bit colour.
- **A theme with errors can crash the Pager's UI**, which then restarts itself (seen during testing), so a
  half-built theme must never be selectable (§5).

## 4. What ships in the repository

| Path | What it is |
|---|---|
| `themes/SquachWatch/assets/payload_bg.png` | 480×222, 256 colours. Layout B, or C if chosen after §6. |
| `themes/SquachWatch/assets/alert_card.png` | 429×222, 256 colours. The CYD card. |
| `themes/SquachWatch/install.sh` | POSIX `sh` (BusyBox ash). Builds the theme on the Pager (§5). |
| `themes/SquachWatch/CREDITS` | Credits (§8). |
| `tools/theme/render_assets.sh`, `tools/theme/compose.py`, `tools/theme/sim.patch` | Regenerate the pictures on a PC (§7). |
| `test/theme_test.sh` | Offline tests (§9). |

No file from Hak5's stock theme is stored in the repository. The install script copies the stock theme on the
Pager itself.

## 5. The install script

`install.sh` runs on the Pager and does this:

1. Copy `/lib/pager/themes/wargames` to a temporary folder `/root/themes/.SquachWatch.tmp.<pid>`.
2. Copy our PNGs into its `assets/squachwatch/`.
3. Patch with `jq` (no regex needed):
   - `components/payload_log.json`: `.background.layers[0].image_path` = `assets/squachwatch/payload_bg.png`,
     and `max_chars` 36 (layout B, chosen after §6, so every payload's log text wraps clear of Squachy, not
     just SquachWatch's); layout C, not used, would have patched `visible_lines` instead.
   - `components/alerts/alert_info_dialog.json`: `.background.layers[0].image_path` =
     `assets/squachwatch/alert_card.png`.
   - `components/templates/alert_info_dialog_text.json`: `text_color_palette` cyan, `max_chars` 26,
     `max_lines` 8, `center_text_within` x 44–296, y 58–196, which is the card's data plate.
   - `components/templates/timestamp.json`: `text_color_palette` black, so the alert pop-up's time reads on the
     card's pink strip -- but only once the installer confirms, on the stock theme it is actually installing
     over (not assumed from the one Pager this was checked on), that the palette has a black and the alert
     pop-up is the only component using this template; otherwise it leaves the time colour as shipped and
     prints a note. Added at the user's request after the on-device check.
   - `theme.json` `color_palette`:
     - magenta (255,113,206)
     - yellow (255,251,148)
     - cyan (0,255,255)
     - green (0,255,0)
4. Check the result:
   - every `.json` in the temporary folder parses (`jq empty`)
   - every `image_path` in the three patched components names a file that exists
   - our two PNGs start with the PNG signature
5. Only then replace `/root/themes/SquachWatch` with the temporary folder: any existing destination is moved
   aside first, the temporary folder is `mv`ed into its place, and the moved-aside copy is then removed --
   restored to `/root/themes/SquachWatch` if that final move fails.

On any failure it removes the temporary folder, prints the reason, and exits non-zero. The old `SquachWatch`
folder, if any, is left untouched.

For tests, `SW_THEME_STOCK` and `SW_THEME_DEST` override the source and destination.

**Using it:** copy the folder over with `scp -r themes/SquachWatch root@172.16.52.1:/tmp/`, then run
`ssh root@172.16.52.1 'sh /tmp/SquachWatch/install.sh'`. Pick **SquachWatch** in the Pager's theme setting.
Re-running the script after an update rebuilds the theme; re-select the theme, or restart the Pager, to load it.

**Recovery** if the Pager's UI ever fails with this theme: over SSH, set `system.@pager[0].theme_path` back to
`/rom/lib/pager/themes/wargames` and `theme_name` to `[wargames]`, run `uci commit system`, then
`service pineapplepager restart`. The README carries the exact command.

## 6. On-device checks (with the user)

1. Install, then have the user select the theme and launch SquachWatch. Take a screenshot (read `/dev/fb0` over SSH).
   - **Check:** the sunset and Squachy background shows, and the text is readable.
   - **Check:** long lines (`Apple Find My (separated) <MAC> -91dBm`) versus Squachy.
2. If long lines run over Squachy, test `max_chars` 36 once: does the Pager wrap or cut them?
   - If it **wraps**, keep layout B with `max_chars` 36.
   - Otherwise switch to **layout C** (`visible_lines` 9, full width).
3. Trigger one test alert over SSH with a made-up MAC (it makes the usual alert sound). Screenshot: the text must
   sit inside the data plate.
4. The user checks it by eye, and goes back to the stock theme and returns to confirm switching works.

Device screenshots show real MACs and are never committed.

## 7. The art pipeline (PC only)

`tools/theme/render_assets.sh` does this:
1. Clone SquachWatch-CYD at the pinned commit into a temporary folder.
2. Apply `tools/theme/sim.patch`: two environment switches in `src/ui_clear.cpp`, `SIM_NO_SQUACHY` and
   `SIM_NO_CHROME`, which hide Squachy and the CYD's corner icons for clean renders. Nothing else changes.
3. Build the PC emulator (`sim/`, `make squachsim`).
4. Render:
   - the SYNTHWAVE scene with no Squachy, 800×264, cropped so the sun sits at x = 400 (layout B) or wherever C needs it
   - the same scene with Squachy, to cut him out by difference
5. Run `tools/theme/compose.py` (Pillow), which builds the two PNGs and quantises them to 256 colours.

Preview PNGs and all intermediate files stay in the temporary folder. Only the two finished PNGs are copied into
`themes/SquachWatch/assets/`.

## 8. Credits and licences

- Squachy, the SYNTHWAVE scene and the card design are rendered from SquachWatch-CYD's GPL-3.0 code. The
  original's FAQ says its author runs Talking Sasquach and that the vaporwave look belongs to that brand.
  `CREDITS` and the README say so, and call this an unofficial port.
- The "HEADS UP!" lettering is an image rendered with the Bangers font (SIL OFL 1.1). The font itself is not
  shipped.
- The stock theme is not redistributed (§4).

## 9. Testing (offline)

`test/theme_test.sh` builds a small **synthetic** stock theme in a temporary folder. It has the five files we
patch, plus one untouched component and one image, all written by the test, so none of Hak5's files are needed.
It runs `install.sh` with `SW_THEME_STOCK` and `SW_THEME_DEST` under `sh` and checks:

- the five patched files have exactly the new values, and the untouched component is byte-for-byte unchanged
- the palette has the four new colours, and the other colours are unchanged
- **failure paths:** a stock tree missing `payload_log.json`, or a broken JSON file, makes the script exit
  non-zero, leaves no temporary folder, and leaves an existing destination unchanged
- running it twice gives the same result
- the two shipped PNGs are the right size, in palette mode (PNG colour type 3), and have at most 256 colours
  (read from the PNG header with `od`)

Each failure-path test has a positive control, so a check that never ran cannot pass.

## 10. Out of scope

- The boot screen, the main menu, other dialogs and menus: the stock look for now.
- Animation: a theme cannot animate Squachy on the payload screen.
- Any change to SquachWatch's payload code.
- Publishing the theme to Hak5's themes repository: the user's decision, later.
