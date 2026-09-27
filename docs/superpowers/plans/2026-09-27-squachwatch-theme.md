# SquachWatch Pager Theme Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Task 3 runs on the user's Pager with the user present, so the controller runs it, not a subagent.

**Goal:** Ship an installable Pager theme, "SquachWatch", that gives SquachWatch's payload screen and the alert pop-up the original CYD app's synthwave look with Squachy, and changes nothing else.

**Architecture:** The repository holds only our two pictures, a POSIX `sh` installer and credits. On the Pager, the installer copies the stock theme into a temporary folder, adds the pictures, patches four JSON files with `jq`, checks everything, and only then moves the folder into `/root/themes/SquachWatch`. The pictures are rendered on a PC by SquachWatch-CYD's own PC emulator (pinned commit plus a two-line patch) and composed with Pillow.

**Tech Stack:** POSIX sh (BusyBox ash on the Pager, `dash` on the PC for tests), `jq` (no regex), bash test harness (`test/run.sh`), Python 3 + Pillow (PC only), g++/make (PC only, to build the CYD emulator).

**Spec:** `docs/superpowers/specs/2026-09-27-squachwatch-theme-design.md`

## Global Constraints

- **Public repository.**
  - Never commit real MACs, device screenshots or local paths. Use made-up MACs only.
  - Commit with `TZ=UTC git -c user.name=Ziggy -c user.email=79704039+therealziggy@users.noreply.github.com commit ...`.
  - Every commit message ends with exactly one line: `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
  - Do not push. Pushing needs the user's OK after a private-data grep.
- **Nothing from Hak5's stock theme goes into the repository.** The installer copies it on the Pager.
- **SquachWatch's payload code** (`payloads/`) does not change.
- **`install.sh` must run under BusyBox ash:**
  - POSIX `sh` only, with no bash-isms
  - no `[:class:]` in `tr`
  - no `mktemp` suffix after `XXXXXX`
  - `jq` filters without regex
  - use `dd`, not `head -c`
- **CYD source is pinned:** `https://github.com/skizzophrenic/SquachWatch-CYD.git` at commit `9e41660fd0eb9428dc3c5d85df730269c83b7e3e`.
- **Picture formats:** `payload_bg.png` is 480×222 and `alert_card.png` is 429×222, both 8-bit palette PNGs (PNG colour type 3).
- **Patched values**, copied verbatim from the spec:
  - payload screen background: `assets/squachwatch/payload_bg.png`
  - alert background: `assets/squachwatch/alert_card.png`
  - alert text template: `text_color_palette` `"cyan"`, `max_chars` 26, `max_lines` 8, `center_text_within` `{"draw_bounds": false, "start_x": 44, "end_x": 296, "start_y": 58, "end_y": 196}`
  - palette: magenta `{"r":255,"g":113,"b":206}`, yellow `{"r":255,"g":251,"b":148}`, cyan `{"r":0,"g":255,"b":255}`, green `{"r":0,"g":255,"b":0}`
- **All tests stay green:** `bash test/run.sh` ends with `FAIL=0`.

## File Structure

| File | Responsibility |
|---|---|
| `tools/theme/sim.patch` | Two environment switches in the CYD emulator, for clean renders (no Squachy, no corner icons). |
| `tools/theme/render_assets.sh` | PC: fetch the pinned CYD source, patch, build the emulator, render, call `compose.py`. |
| `tools/theme/compose.py` | PC: build `payload_bg.png` (layout B or C) and `alert_card.png` from the renders. |
| `themes/SquachWatch/assets/payload_bg.png` | Generated. The payload screen background. |
| `themes/SquachWatch/assets/alert_card.png` | Generated. The alert pop-up background. |
| `themes/SquachWatch/install.sh` | Pager: build and install the theme safely. |
| `themes/SquachWatch/CREDITS` | Credits and licences. |
| `test/theme_test.sh` | Offline tests of `install.sh` against a synthetic stock theme, plus PNG header checks. |
| `test/portability_test.sh` | Modify: also scan `themes/`. |
| `tools/pager_screenshot.sh` | PC: save what the Pager's screen shows as a PNG (for Task 3). |
| `README.md` | Modify: a "SquachWatch theme (optional)" section. |

---

### Task 1: Render the two pictures

**Files:**
- Create: `tools/theme/sim.patch`
- Create: `tools/theme/render_assets.sh`
- Create: `tools/theme/compose.py`
- Create (generated): `themes/SquachWatch/assets/payload_bg.png`, `themes/SquachWatch/assets/alert_card.png`

**Interfaces:**
- Produces: `tools/theme/render_assets.sh [B|C]` writes both PNGs into `themes/SquachWatch/assets/` (layout B is the default). Task 2's tests read those two files, and Task 3 may re-run it with `C`.

- [ ] **Step 1: Create `tools/theme/sim.patch`** with exactly this content:

```diff
diff --git a/src/ui_clear.cpp b/src/ui_clear.cpp
index a8a0ca5..11e5b56 100644
--- a/src/ui_clear.cpp
+++ b/src/ui_clear.cpp
@@ -1,3 +1,4 @@
+#include <cstdlib>
 // SquachWatch-CYD — clear (idle) screen implementation
 #include "ui_clear.h"
 #include "clock.h"      // the watch's corner clock
@@ -2886,7 +2887,7 @@ void uiClearTick(TFT_eSPI& t, uint32_t now, const DetectionEngine& eng, bool adv
         CrowdBench::draw(t, now, titleBottom, squachyBottom);
     else
 #endif
-    if (!Settings::boringMode()) {
+    if (!Settings::boringMode() && !getenv("SIM_NO_SQUACHY")) {
         // The last argument is the SIZE row in Settings. CLEAR is the only
         // screen that passes it: everywhere else he is a cameo in a box
         // somebody sized deliberately, and shrinking him there would just
@@ -2974,7 +2975,7 @@ void uiClearTick(TFT_eSPI& t, uint32_t now, const DetectionEngine& eng, bool adv
     Theme::drawBackgroundOverlay(t, now);
 
     // Title bar at the top
-    if (DrawBand::has(0, titleBottom)) Theme::drawTitleBar(t, ">> SQUACHWATCH <<  SCANNING");
+    if (DrawBand::has(0, titleBottom) && !getenv("SIM_NO_CHROME")) Theme::drawTitleBar(t, ">> SQUACHWATCH <<  SCANNING");
 
     // The watch/hunt indicator, in the title bar's empty middle. AFTER the bar
     // itself, which repaints that whole band -- see drawWatchPill()'s comment
```

- [ ] **Step 2: Create `tools/theme/render_assets.sh`**

```bash
#!/usr/bin/env bash
# tools/theme/render_assets.sh — regenerate themes/SquachWatch/assets/*.png from SquachWatch-CYD's own
# drawing code, through its PC emulator. PC only: needs git, make, g++, python3 and Pillow.
# Usage: tools/theme/render_assets.sh [B|C]    (payload screen layout; B is the default, see the spec)
set -euo pipefail
LAYOUT="${1:-B}"
case "$LAYOUT" in B|C) ;; *) echo "usage: $0 [B|C]" >&2; exit 2 ;; esac
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CYD_URL="https://github.com/skizzophrenic/SquachWatch-CYD.git"
CYD_REV="9e41660fd0eb9428dc3c5d85df730269c83b7e3e"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

git clone -q --filter=blob:none "$CYD_URL" "$WORK/cyd"
git -C "$WORK/cyd" checkout -q "$CYD_REV"
git -C "$WORK/cyd" apply "$ROOT/tools/theme/sim.patch"
make -C "$WORK/cyd/sim" -j"$(nproc)" squachsim >/dev/null
SIM="$WORK/cyd/sim/squachsim"

# The SYNTHWAVE scene (background 10, the CYD's default). The 800-wide render puts the sun at x=400 of
# the 480 we keep. The two 480-wide renders differ only by Squachy, so their difference cuts him out.
SIM_NO_SQUACHY=1 SIM_NO_CHROME=1 "$SIM" clear "$WORK/scene_wide.png" --noseed --bg 10 --size 800x264 --frames 60 >/dev/null
SIM_NO_SQUACHY=1 SIM_NO_CHROME=1 "$SIM" clear "$WORK/scene.png"      --noseed --bg 10 --size 480x264 --frames 60 >/dev/null
SIM_NO_CHROME=1                  "$SIM" clear "$WORK/scene_sq.png"   --noseed --bg 10 --size 480x264 --frames 60 >/dev/null

python3 "$ROOT/tools/theme/compose.py" --layout "$LAYOUT" \
  --wide "$WORK/scene_wide.png" --plain "$WORK/scene.png" --with-squachy "$WORK/scene_sq.png" \
  --font "$WORK/cyd/sim/Bangers-Regular.ttf" --out "$ROOT/themes/SquachWatch/assets"
echo "wrote themes/SquachWatch/assets/payload_bg.png (layout $LAYOUT) and alert_card.png"
```

Then run: `chmod +x tools/theme/render_assets.sh`

- [ ] **Step 3: Create `tools/theme/compose.py`**

```python
#!/usr/bin/env python3
"""Build the SquachWatch theme's two pictures from SquachWatch-CYD emulator renders (PC only).

payload_bg.png (480x222)
  layout B: the sunset with the sun at x=400, darkened on the left for the text, and Squachy standing
            in front of the sun.
  layout C: a starry night sky for the text, and a sunset band with a small Squachy along the bottom.
alert_card.png (429x222): the CYD alert card, with a rainbow border, a pink strip, a dark data plate,
  and a radar with Squachy's face.
Both are saved as 256-colour palette PNGs, like the stock theme's images.
"""
import argparse
import math
import os

from PIL import Image, ImageChops, ImageDraw, ImageFont

W, H = 480, 222
BG = (8, 0, 8)                                   # CYD VAPRW4VE BG, 0x0801
PINK = (255, 45, 123)                            # PINK, 0xF96F
VPINK = (255, 113, 206)                          # VAPOR_PINK, 0xFB99
PURPLE = (173, 130, 255)                         # PURPLE, 0xAC1F
GREEN = (0, 255, 0)                              # GREEN, 0x07E0
RINGS = ((0, 48, 45), (0, 64, 60), (0, 90, 86))  # the CYD radar rings, outer to inner
STARS = [((i * 97) % 480, 24 + (i * 53) % 100) for i in range(40)]  # fixed, so renders repeat


def squachy_cutout(plain, with_sq):
    """Squachy alone (RGBA): the pixels where the render with him differs from the one without."""
    mask = ImageChops.difference(plain, with_sq).convert('L').point(lambda v: 255 if v else 0)
    box = mask.getbbox()
    if box is None:
        raise SystemExit('no Squachy found: the two renders are identical')
    cut = with_sq.crop(box).convert('RGBA')
    cut.putalpha(mask.crop(box))
    return cut


def scene_band(wide):
    """The 480x222 left part of the 800-wide scene (sun at x=400). Rows 204-221 repeat the water, which
    covers the CYD's counter row."""
    s = wide.crop((0, 0, W, H)).copy()
    s.paste(wide.crop((0, 176, W, 194)), (0, 204))
    return s


def layout_b(wide, cut):
    img = scene_band(wide).convert('RGBA')
    shade = Image.new('RGBA', (W, H), (0, 0, 0, 0))
    d = ImageDraw.Draw(shade)
    for x in range(W):  # dark behind the text on the left, fading out toward Squachy
        d.line((x, 0, x, H), fill=BG + (int(235 - 150 * max(0.0, (x - 250) / 230)),))
    img = Image.alpha_composite(img, shade)
    band = Image.new('RGBA', (W, H), (0, 0, 0, 0))
    ImageDraw.Draw(band).rectangle((0, 20, 330, H - 1), fill=BG + (120,))
    img = Image.alpha_composite(img, band)
    img.alpha_composite(cut, (405 - cut.width // 2, H - cut.height))
    return img.convert('RGB')


def layout_c(wide, cut):
    img = Image.new('RGB', (W, H))
    d = ImageDraw.Draw(img)
    for y in range(H):
        t = y / H
        d.line((0, y, W, y), fill=(int(10 + 30 * t), 0, int(15 + 45 * t)))
    for p in STARS:
        d.point(p, fill=(200, 200, 255))
    band = scene_band(wide).crop((0, 60, W, 140))
    img.paste(band, (0, H - band.height))
    small = cut.resize((cut.width // 2, cut.height // 2), Image.NEAREST)
    img.paste(small, (400 - small.width // 2, H - small.height), small)
    return img


def rainbow(t):
    """Hue t in [0, 1) -> fully saturated RGB."""
    return tuple(int(255 * max(0.0, min(1.0, abs((t * 6 + k) % 6 - 3) - 1))) for k in (0, 4, 2))


def alert_card(cut, font_path):
    cw, ch = 429, 222
    card = Image.new('RGB', (cw, ch), BG)
    d = ImageDraw.Draw(card)
    for i in range(cw):  # 2 px rainbow border (the CYD's rotating border, frozen)
        c = rainbow(i / cw)
        d.line((i, 0, i, 1), fill=c)
        d.line((cw - 1 - i, ch - 2, cw - 1 - i, ch - 1), fill=c)
    for j in range(ch):
        c = rainbow(j / ch)
        d.line((0, j, 1, j), fill=c)
        d.line((cw - 2, ch - 1 - j, cw - 1, ch - 1 - j), fill=c)
    d.rectangle((2, 2, cw - 3, 42), fill=PINK)
    d.line((2, 43, cw - 3, 43), fill=(120, 10, 60))
    d.text((14, 4), 'HEADS UP!', font=ImageFont.truetype(font_path, 32), fill=BG)
    d.rectangle((12, 54, 272, 208), fill=(4, 0, 8), outline=PURPLE)   # the data plate (screen x 40-300)
    cx, cy, r = 350, 128, 62
    for rr, col in zip((r, r * 2 // 3, r // 3), RINGS):
        d.ellipse((cx - rr, cy - rr, cx + rr, cy + rr), outline=col, width=2)
    d.line((cx - r, cy, cx + r, cy), fill=RINGS[1])
    d.line((cx, cy - r, cx, cy + r), fill=RINGS[1])
    d.line((cx, cy, cx + int(r * math.cos(-0.9)), cy + int(r * math.sin(-0.9))), fill=GREEN, width=2)
    d.ellipse((cx - r - 3, cy - r - 3, cx + r + 3, cy + r + 3), outline=VPINK, width=3)
    face = cut.crop((0, 0, cut.width, 64)).resize((cut.width * 2 // 3, 42), Image.NEAREST)
    card.paste(face, (cx - face.width // 2, cy - 21), face)
    return card


def save_256(img, path):
    q = img.convert('RGB').quantize(colors=256, method=Image.Quantize.MEDIANCUT,
                                    dither=Image.Dither.FLOYDSTEINBERG)
    q.save(path, optimize=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--layout', choices=('B', 'C'), default='B')
    ap.add_argument('--wide', required=True)
    ap.add_argument('--plain', required=True)
    ap.add_argument('--with-squachy', required=True, dest='with_sq')
    ap.add_argument('--font', required=True)
    ap.add_argument('--out', required=True)
    a = ap.parse_args()
    wide = Image.open(a.wide).convert('RGB')
    cut = squachy_cutout(Image.open(a.plain).convert('RGB'), Image.open(a.with_sq).convert('RGB'))
    os.makedirs(a.out, exist_ok=True)
    save_256(layout_b(wide, cut) if a.layout == 'B' else layout_c(wide, cut),
             os.path.join(a.out, 'payload_bg.png'))
    save_256(alert_card(cut, a.font), os.path.join(a.out, 'alert_card.png'))


if __name__ == '__main__':
    main()
```

- [ ] **Step 4: Generate the pictures**

Run: `tools/theme/render_assets.sh`
Expected: the last line is `wrote themes/SquachWatch/assets/payload_bg.png (layout B) and alert_card.png`.

- [ ] **Step 5: Check the PNG headers**

Run: `for f in payload_bg alert_card; do printf '%s: ' $f; od -An -tu1 -j16 -N10 themes/SquachWatch/assets/$f.png | awk '{printf "%d %d %d %d\n", $1*16777216+$2*65536+$3*256+$4, $5*16777216+$6*65536+$7*256+$8, $9, $10}'; done`

Expected:
```
payload_bg: 480 222 8 3
alert_card: 429 222 8 3
```

- [ ] **Step 6: Commit**

```bash
git add tools/theme/sim.patch tools/theme/render_assets.sh tools/theme/compose.py themes/SquachWatch/assets/payload_bg.png themes/SquachWatch/assets/alert_card.png
TZ=UTC git -c user.name=Ziggy -c user.email=79704039+therealziggy@users.noreply.github.com commit -m "theme: render the SquachWatch theme's pictures from SquachWatch-CYD's own drawing code" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: The installer, with offline tests

**Files:**
- Create: `test/theme_test.sh`
- Create: `themes/SquachWatch/install.sh`
- Create: `themes/SquachWatch/CREDITS`
- Modify: `test/portability_test.sh` (append two assertions)

**Interfaces:**
- Consumes: `themes/SquachWatch/assets/payload_bg.png` and `alert_card.png` (Task 1).
- Produces:
  - `sh themes/SquachWatch/install.sh` exits 0 and prints `SquachWatch theme installed in <dest>. ...` on success.
  - On any failure it exits 1 with `SquachWatch theme NOT installed: <reason>` on stderr.
  - Environment overrides: `SW_THEME_STOCK` (default `/lib/pager/themes/wargames`) and `SW_THEME_DEST` (default `/root/themes/SquachWatch`).
  - The line that patches the payload screen is `jpatch "$PL" '...'`; Task 3 may extend its filter.

- [ ] **Step 1: Write the failing tests in `test/theme_test.sh`**

```bash
# test/theme_test.sh — the SquachWatch theme installer, run under POSIX sh against a SYNTHETIC stock
# theme written here (no Hak5 files needed), plus header checks of the two shipped pictures.
_th_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
_th_inst="$_th_root/themes/SquachWatch/install.sh"
_th_tmp="$(mktemp -d)"

_th_mkstock() {  # $1 = folder to create: a minimal stock theme with the files install.sh patches
  mkdir -p "$1/components/alerts" "$1/components/templates" "$1/assets/payloadlog"
  cat > "$1/theme.json" <<'J'
{"theme_version": "1.1.0",
 "payload_log_path": "components/payload_log.json",
 "alert_dialog_path": "components/alerts/alert_info_dialog.json",
 "string_templates": {"alert_info_dialog_text": "components/templates/alert_info_dialog_text.json"},
 "color_palette": {"magenta": {"r": 205, "g": 85, "b": 155}, "yellow": {"r": 231, "g": 197, "b": 74},
                   "cyan": {"r": 96, "g": 205, "b": 205}, "green": {"r": 42, "g": 180, "b": 42},
                   "red": {"r": 250, "g": 72, "b": 9}}}
J
  cat > "$1/components/payload_log.json" <<'J'
{"background": {"layers": [{"image_path": "assets/payloadlog/payload_log_bg.png", "x": 0, "y": 0},
                           {"variable_name": "$_INPUT_NAME", "use_template": "payload_title", "x": 0, "y": 0}]},
 "scroll_up_indicator": [{"image_path": "assets/payloadlog/scroll_up_indicator.png", "x": 465, "y": 40}],
 "visible_lines": 14, "max_chars": 50, "start_x": 6, "start_y": 24}
J
  cat > "$1/components/alerts/alert_info_dialog.json" <<'J'
{"windowed_canvas": true,
 "background": {"layers": [{"image_path": "assets/alert_dialog_bg_term_blue.png", "x": 28, "y": 0}]}}
J
  cat > "$1/components/templates/alert_info_dialog_text.json" <<'J'
{"text_size": "small", "text_color_palette": "yellow", "max_chars": 42, "wrap_text": true, "max_lines": 13,
 "center_text_within": {"draw_bounds": false, "start_x": 80, "end_x": 400, "start_y": 26, "end_y": 190}}
J
  printf '{"untouched": true}\n' > "$1/components/lock_screen.json"
  printf 'stock picture\n' > "$1/assets/payloadlog/payload_log_bg.png"
  printf 'stock picture\n' > "$1/assets/payloadlog/scroll_up_indicator.png"
  printf 'stock picture\n' > "$1/assets/alert_dialog_bg_term_blue.png"
}
_th_run() {  # $1 = stock folder, $2 = destination; prints install.sh's exit code
  SW_THEME_STOCK="$1" SW_THEME_DEST="$2" sh "$_th_inst" >/dev/null 2>&1; echo "$?"
}
_th_sum() { (cd "$1" && find . -type f | LC_ALL=C sort | xargs md5sum) 2>/dev/null | md5sum | cut -c1-32; }
_th_png() {  # $1 = PNG -> "width height bitdepth colourtype" from its IHDR chunk
  od -An -tu1 -j16 -N10 "$1" | awk '{printf "%d %d %d %d", $1*16777216+$2*65536+$3*256+$4, $5*16777216+$6*65536+$7*256+$8, $9, $10}'
}

# --- a good install ---
_th_mkstock "$_th_tmp/stock"
_th_d="$_th_tmp/themes/SquachWatch"
assert_eq "$(_th_run "$_th_tmp/stock" "$_th_d")" "0" theme_install_ok
assert_eq "$(jq -r '.background.layers[0].image_path' "$_th_d/components/payload_log.json")" \
  "assets/squachwatch/payload_bg.png" theme_payload_bg_patched
assert_eq "$(jq -r '.background.layers[1].variable_name' "$_th_d/components/payload_log.json")" \
  '$_INPUT_NAME' theme_payload_title_layer_kept
assert_eq "$(jq -c '[.visible_lines, .max_chars, .start_x, .start_y]' "$_th_d/components/payload_log.json")" \
  '[14,50,6,24]' theme_payload_text_settings
assert_eq "$(jq -r '.background.layers[0].image_path' "$_th_d/components/alerts/alert_info_dialog.json")" \
  "assets/squachwatch/alert_card.png" theme_alert_card_patched
assert_eq "$(jq -c '[.text_color_palette, .max_chars, .max_lines, .wrap_text, .center_text_within]' \
  "$_th_d/components/templates/alert_info_dialog_text.json")" \
  '["cyan",26,8,true,{"draw_bounds":false,"start_x":44,"end_x":296,"start_y":58,"end_y":196}]' \
  theme_alert_text_inside_the_plate
assert_eq "$(jq -c '.color_palette | [.magenta, .yellow, .cyan, .green]' "$_th_d/theme.json")" \
  '[{"r":255,"g":113,"b":206},{"r":255,"g":251,"b":148},{"r":0,"g":255,"b":255},{"r":0,"g":255,"b":0}]' \
  theme_palette_neon
assert_eq "$(jq -c '.color_palette.red' "$_th_d/theme.json")" '{"r":250,"g":72,"b":9}' theme_palette_red_kept
assert_eq "$(cat "$_th_d/components/lock_screen.json")" '{"untouched": true}' theme_other_component_untouched
assert_eq "$(cmp -s "$_th_d/assets/squachwatch/payload_bg.png" "$_th_root/themes/SquachWatch/assets/payload_bg.png" && echo same)" \
  same theme_payload_picture_copied
assert_eq "$(cmp -s "$_th_d/assets/squachwatch/alert_card.png" "$_th_root/themes/SquachWatch/assets/alert_card.png" && echo same)" \
  same theme_alert_picture_copied
assert_eq "$(ls -A "$_th_tmp/themes" | tr '\n' ' ')" "SquachWatch " theme_no_temp_folder_left
assert_eq "$(jq -r '.background.layers[0].image_path' "$_th_tmp/stock/components/payload_log.json")" \
  "assets/payloadlog/payload_log_bg.png" theme_stock_left_untouched

# --- running it again gives the same result; control: the checksum does see a change ---
_th_s1="$(_th_sum "$_th_d")"
assert_eq "$(_th_run "$_th_tmp/stock" "$_th_d")" "0" theme_reinstall_ok
assert_eq "$(_th_sum "$_th_d")" "$_th_s1" theme_reinstall_same_result
printf 'x' >> "$_th_d/components/lock_screen.json"
assert_eq "$([ "$(_th_sum "$_th_d")" != "$_th_s1" ] && echo differs)" differs theme_sum_control_sees_a_change

# --- failures: exit 1, no temporary folder left, the existing theme untouched ---
printf 'marker\n' > "$_th_d/MARKER"
_th_s2="$(_th_sum "$_th_d")"
cp -r "$_th_tmp/stock" "$_th_tmp/stock_nolog"; rm "$_th_tmp/stock_nolog/components/payload_log.json"
assert_eq "$(_th_run "$_th_tmp/stock_nolog" "$_th_d")" "1" theme_missing_component_fails
assert_eq "$(_th_sum "$_th_d")" "$_th_s2" theme_missing_component_keeps_old
assert_eq "$(ls -A "$_th_tmp/themes" | tr '\n' ' ')" "SquachWatch " theme_missing_component_no_temp
cp -r "$_th_tmp/stock" "$_th_tmp/stock_badjson"; printf '{' > "$_th_tmp/stock_badjson/components/lock_screen.json"
assert_eq "$(_th_run "$_th_tmp/stock_badjson" "$_th_d")" "1" theme_bad_json_fails
assert_eq "$(_th_sum "$_th_d")" "$_th_s2" theme_bad_json_keeps_old
assert_eq "$(ls -A "$_th_tmp/themes" | tr '\n' ' ')" "SquachWatch " theme_bad_json_no_temp
cp -r "$_th_tmp/stock" "$_th_tmp/stock_noimg"; rm "$_th_tmp/stock_noimg/assets/payloadlog/scroll_up_indicator.png"
assert_eq "$(_th_run "$_th_tmp/stock_noimg" "$_th_d")" "1" theme_missing_picture_fails
assert_eq "$(_th_sum "$_th_d")" "$_th_s2" theme_missing_picture_keeps_old
# control: a good install DOES replace that destination (so "untouched" above is not vacuous)
assert_eq "$(_th_run "$_th_tmp/stock" "$_th_d")" "0" theme_control_good_install
assert_eq "$([ -e "$_th_d/MARKER" ] && echo still || echo gone)" gone theme_control_old_theme_replaced

# --- the shipped pictures: size and 8-bit palette (PNG colour type 3) ---
assert_eq "$(_th_png "$_th_root/themes/SquachWatch/assets/payload_bg.png")" "480 222 8 3" theme_payload_png_header
assert_eq "$(_th_png "$_th_root/themes/SquachWatch/assets/alert_card.png")" "429 222 8 3" theme_alert_png_header

rm -rf "$_th_tmp"
unset -f _th_mkstock _th_run _th_sum _th_png
unset _th_root _th_inst _th_tmp _th_d _th_s1 _th_s2
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `bash test/run.sh 2>&1 | grep -E 'theme_|PASS=' | head -20`
Expected: FAIL lines such as `FAIL: theme_install_ok: expected [0] got [127]`, because `install.sh` does not exist yet. The two PNG header checks already pass.

- [ ] **Step 3: Create `themes/SquachWatch/install.sh`**

```sh
#!/bin/sh
# SquachWatch Pager theme: installer. Runs ON the Pager (BusyBox ash):   sh install.sh
# It copies the Pager's stock theme into a new theme folder, adds SquachWatch's two pictures, and
# patches four files: the payload screen's background, the alert pop-up, its text box, and four
# colours. Nothing from the stock theme ships with SquachWatch. A half-built theme is never left where
# the Pager could offer it: everything is built in a temporary folder, checked, then moved into place.
# Spec: docs/superpowers/specs/2026-09-27-squachwatch-theme-design.md
set -u
SRC="$(cd "$(dirname "$0")" && pwd)"
STOCK="${SW_THEME_STOCK:-/lib/pager/themes/wargames}"
DEST="${SW_THEME_DEST:-/root/themes/SquachWatch}"
PARENT="$(dirname "$DEST")"
TMP="$PARENT/.$(basename "$DEST").tmp.$$"
OLD="$TMP.old"

fail() {
  echo "SquachWatch theme NOT installed: $*" >&2
  rm -rf "$TMP"
  exit 1
}

# jpatch FILE FILTER: rewrite TMP/FILE through a jq filter, or fail.
jpatch() {
  _f="$TMP/$1"
  [ -f "$_f" ] || fail "the stock theme has no $1"
  if ! jq "$2" "$_f" > "$_f.new" 2>/dev/null || [ ! -s "$_f.new" ]; then
    rm -f "$_f.new"
    fail "could not patch $1"
  fi
  mv -f "$_f.new" "$_f" || fail "could not write $1"
}

command -v jq >/dev/null 2>&1 || fail "jq is missing"
[ -f "$STOCK/theme.json" ] || fail "no stock theme at $STOCK"
for _p in payload_bg.png alert_card.png; do
  [ -f "$SRC/assets/$_p" ] || fail "missing $SRC/assets/$_p"
done
mkdir -p "$PARENT" || fail "could not create $PARENT"
rm -rf "$TMP" "$OLD"
cp -r "$STOCK" "$TMP" || fail "could not copy $STOCK"
mkdir -p "$TMP/assets/squachwatch" || fail "could not create the pictures folder"
cp "$SRC/assets/payload_bg.png" "$SRC/assets/alert_card.png" "$TMP/assets/squachwatch/" \
  || fail "could not copy the pictures"

# Where this firmware keeps the three components: read from theme.json, not assumed.
PL="$(jq -r '.payload_log_path // empty' "$TMP/theme.json" 2>/dev/null)"
AD="$(jq -r '.alert_dialog_path // empty' "$TMP/theme.json" 2>/dev/null)"
AT="$(jq -r '.string_templates.alert_info_dialog_text // empty' "$TMP/theme.json" 2>/dev/null)"
[ -n "$PL" ] && [ -n "$AD" ] && [ -n "$AT" ] \
  || fail "the stock theme.json does not name the payload screen, the alert pop-up and its text"
for _c in "$PL" "$AD"; do
  [ -f "$TMP/$_c" ] || fail "the stock theme has no $_c"
  jq -e '.background.layers[0].image_path' "$TMP/$_c" >/dev/null 2>&1 \
    || fail "$_c does not start with a background picture"
done

jpatch "$PL" '.background.layers[0].image_path = "assets/squachwatch/payload_bg.png"'
jpatch "$AD" '.background.layers[0].image_path = "assets/squachwatch/alert_card.png"'
jpatch "$AT" '.text_color_palette = "cyan" | .max_chars = 26 | .max_lines = 8
  | .center_text_within = {"draw_bounds": false, "start_x": 44, "end_x": 296, "start_y": 58, "end_y": 196}'
jpatch theme.json '.color_palette.magenta = {"r": 255, "g": 113, "b": 206}
  | .color_palette.yellow = {"r": 255, "g": 251, "b": 148}
  | .color_palette.cyan = {"r": 0, "g": 255, "b": 255}
  | .color_palette.green = {"r": 0, "g": 255, "b": 0}'

# Checks before the theme can be offered: every JSON parses, every picture the patched components
# name exists, and our two pictures really are PNGs.
_bad="$(find "$TMP" -name '*.json' -exec sh -c 'jq empty "$1" >/dev/null 2>&1 || echo "$1"' _ {} \;)"
[ -z "$_bad" ] || fail "invalid JSON: $(echo "$_bad" | sed "s#$TMP/##" | tr '\n' ' ')"
for _c in "$PL" "$AD"; do
  jq -r '.. | objects | .image_path? // empty' "$TMP/$_c" | while IFS= read -r _i; do
    [ -f "$TMP/$_i" ] || echo "$_i"
  done
done > "$TMP/.missing"
[ -s "$TMP/.missing" ] && fail "missing picture(s): $(tr '\n' ' ' < "$TMP/.missing")"
printf '\211PNG\r\n\032\n' > "$TMP/.sig"
for _p in payload_bg.png alert_card.png; do
  dd if="$TMP/assets/squachwatch/$_p" of="$TMP/.head" bs=8 count=1 2>/dev/null
  cmp -s "$TMP/.head" "$TMP/.sig" || fail "$_p is not a PNG"
done
rm -f "$TMP/.missing" "$TMP/.sig" "$TMP/.head"

# Swap in. The old theme is moved aside first, and put back if the move fails.
if [ -e "$DEST" ]; then
  mv "$DEST" "$OLD" || fail "could not move the old $DEST aside"
fi
if ! mv "$TMP" "$DEST"; then
  [ -e "$OLD" ] && mv "$OLD" "$DEST"
  fail "could not move the new theme into place"
fi
rm -rf "$OLD"
echo "SquachWatch theme installed in $DEST. Pick \"SquachWatch\" in the Pager's theme setting."
```

Then run: `chmod +x themes/SquachWatch/install.sh`

- [ ] **Step 4: Create `themes/SquachWatch/CREDITS`**

```text
SquachWatch Pager theme: credits

Squachy, the synthwave sunset and the alert card design are rendered from SquachWatch-CYD's own
drawing code (https://github.com/skizzophrenic/SquachWatch-CYD, commit 9e41660, GPL-3.0). Squachy
comes from talkingsasquach.com's drawSquachy(). The original's FAQ says its author runs Talking
Sasquach and that the vaporwave look belongs to that brand. This theme is an unofficial port.

The "HEADS UP!" lettering is rendered with the Bangers font (Copyright 2010 The Bangers Project
Authors, SIL Open Font License 1.1). The font itself is not included.

The Pager's stock theme is not included: install.sh copies it on the Pager itself.
```

- [ ] **Step 5: Extend `test/portability_test.sh` to cover the theme** (append these lines at the end of the file)

```bash
# The theme installer runs under BusyBox ash too.
SW_THEMES="$(cd "$(dirname "${BASH_SOURCE[0]}")/../themes" && pwd)"
assert_empty "$(grep -rn "['\"]\[:" "$SW_THEMES")" no_posix_tr_classes_in_themes
assert_empty "$(grep -rn 'XXXXXX\.' "$SW_THEMES")" no_mktemp_suffix_in_themes
assert_empty "$(grep -rn 'head -c' "$SW_THEMES")" no_head_c_in_themes
assert_contains "$(ls "$SW_THEMES/SquachWatch")" "install.sh" portability_walk_reads_themes
```

- [ ] **Step 6: Run all tests**

Run: `bash test/run.sh 2>&1 | tail -3`
Expected: `PASS=<n> FAIL=0`, where `<n>` is the previous total plus 32 (28 in `theme_test.sh`, 4 in `portability_test.sh`).

- [ ] **Step 7: Commit**

```bash
git add test/theme_test.sh test/portability_test.sh themes/SquachWatch/install.sh themes/SquachWatch/CREDITS
TZ=UTC git -c user.name=Ziggy -c user.email=79704039+therealziggy@users.noreply.github.com commit -m "theme: installer that builds the SquachWatch theme from the stock one, with offline tests" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Install on the Pager and check it (controller + user)

**Files:**
- Create: `tools/pager_screenshot.sh`
- Modify, depending on Step 5: `themes/SquachWatch/install.sh` (the `jpatch "$PL"` line), `test/theme_test.sh` (the `theme_payload_text_settings` assertion), and possibly both PNGs.

**Interfaces:**
- Consumes: Tasks 1 and 2.
- Produces: the final payload-screen settings, committed.

- [ ] **Step 1: Create `tools/pager_screenshot.sh`**

```bash
#!/usr/bin/env bash
# tools/pager_screenshot.sh OUT.png [HOST] — save what the Pager's screen shows now, the right way up.
# PC only (python3 + Pillow). Screenshots show real MACs: keep them OUT of the repository.
set -euo pipefail
OUT="${1:?usage: $0 OUT.png [HOST]}"; HOST="${2:-root@172.16.52.1}"
RAW="$(mktemp)"; trap 'rm -f "$RAW"' EXIT
ssh -o BatchMode=yes "$HOST" 'cat /dev/fb0' </dev/null > "$RAW"
python3 - "$RAW" "$OUT" <<'PY'
import sys
from PIL import Image
fb = open(sys.argv[1], 'rb').read(); W, H = 222, 480   # the panel is portrait, RGB565 little-endian
if len(fb) != W * H * 2:
    sys.exit(f'unexpected framebuffer size {len(fb)}')
im = Image.new('RGB', (H, W)); px = im.load()
for y in range(H):
    for x in range(W):
        v = fb[(y * W + x) * 2] | (fb[(y * W + x) * 2 + 1] << 8)
        px[y, W - 1 - x] = (((v >> 11) & 31) * 255 // 31, ((v >> 5) & 63) * 255 // 63, (v & 31) * 255 // 31)
im.save(sys.argv[2])
PY
echo "saved $OUT"
```

Then run: `chmod +x tools/pager_screenshot.sh`

- [ ] **Step 2: Install on the Pager**

Run:
```bash
scp -r themes/SquachWatch root@172.16.52.1:/tmp/
ssh root@172.16.52.1 'sh /tmp/SquachWatch/install.sh; rc=$?; rm -rf /tmp/SquachWatch; exit $rc'
```
Expected: `SquachWatch theme installed in /root/themes/SquachWatch. Pick "SquachWatch" in the Pager's theme setting.`

- [ ] **Step 3: The user selects the theme and launches SquachWatch**

Ask the user to pick **SquachWatch** in the Pager's theme setting, launch SquachWatch from Payloads → reconnaissance, and reply when its screen shows a few detections.

- [ ] **Step 4: Screenshot and judge the layout**

Run: `tools/pager_screenshot.sh /tmp/sw_theme_1.png`, then view `/tmp/sw_theme_1.png`.

Check:
- the sunset and Squachy background shows
- the text is readable
- whether any line runs over Squachy (x ≈ 355–455)

If no line runs over him, skip to Step 6.

- [ ] **Step 5: Only if lines run over Squachy, test wrapping**

Run:
```bash
ssh root@172.16.52.1 "jq '.max_chars = 36' /root/themes/SquachWatch/components/payload_log.json > /tmp/pl.json && mv /tmp/pl.json /root/themes/SquachWatch/components/payload_log.json"
```

Ask the user to re-select the SquachWatch theme and relaunch SquachWatch. Then run `tools/pager_screenshot.sh /tmp/sw_theme_2.png` and view it.

- **If long lines WRAP onto a second line**, keep layout B.
  - In `install.sh`, replace the line
    `jpatch "$PL" '.background.layers[0].image_path = "assets/squachwatch/payload_bg.png"'`
    with
    `jpatch "$PL" '.background.layers[0].image_path = "assets/squachwatch/payload_bg.png" | .max_chars = 36'`
  - In `test/theme_test.sh`, change the expected value of `theme_payload_text_settings` from `'[14,50,6,24]'` to `'[14,36,6,24]'`.
- **If long lines are CUT OFF**, switch to layout C.
  - Run `tools/theme/render_assets.sh C`.
  - In `install.sh`, replace the same line with
    `jpatch "$PL" '.background.layers[0].image_path = "assets/squachwatch/payload_bg.png" | .visible_lines = 9'`
  - In `test/theme_test.sh`, change the expected value of `theme_payload_text_settings` from `'[14,50,6,24]'` to `'[9,50,6,24]'`.

Then run `bash test/run.sh 2>&1 | tail -1` (expected: `FAIL=0`), repeat Step 2, ask the user to re-select the theme and relaunch SquachWatch, and take a new screenshot to confirm.

- [ ] **Step 6: Check the alert pop-up**

Tell the user that a test alert with a made-up MAC is coming, and that it makes the usual alert sound. Then run:
```bash
ssh root@172.16.52.1 'ALERT "$(printf "Flock Safety camera\n24:0A:C4:00:00:01 -68dBm")"'
tools/pager_screenshot.sh /tmp/sw_theme_alert.png
```
View it. The text must sit inside the dark data plate, and the timestamp must be readable on the pink strip.
- **If the text is outside the plate**, adjust the `center_text_within` numbers in `install.sh` and in the matching test expectation by the measured offset, then repeat Step 2 and this step.
- **If the timestamp is unreadable on pink**, tell the user and ask which they prefer: a darker strip end, or leaving it.

- [ ] **Step 7: The user checks by eye**

Ask the user to look at the Pager, switch to the stock theme and back, and confirm it looks right. Delete the screenshots: `rm -f /tmp/sw_theme_*.png`.

- [ ] **Step 8: Commit**

```bash
git add tools/pager_screenshot.sh themes/SquachWatch test/theme_test.sh
TZ=UTC git -c user.name=Ziggy -c user.email=79704039+therealziggy@users.noreply.github.com commit -m "theme: settings checked on the Pager; screenshot tool" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: README, final checks, and the push question

**Files:**
- Modify: `README.md` (add a section after the Install section)

**Interfaces:**
- Consumes: Tasks 1–3.

- [ ] **Step 1: Add this section to `README.md`**, directly after the Install section:

```markdown
## SquachWatch theme (optional)

A Pager theme that gives SquachWatch's screen and the alert pop-up the original SquachWatch-CYD look:
the synthwave sunset with Squachy, and the CYD's alert card. Every other screen keeps the stock look.
Themes apply to the whole Pager, so other payloads' screens get the same background.

Install (from this folder on your PC):

    scp -r themes/SquachWatch root@172.16.52.1:/tmp/
    ssh root@172.16.52.1 'sh /tmp/SquachWatch/install.sh; rm -rf /tmp/SquachWatch'

Then pick **SquachWatch** in the Pager's theme setting. The installer copies the Pager's own stock
theme and changes four files; nothing of Hak5's is stored in this repository. To regenerate the
pictures, run `tools/theme/render_assets.sh` (PC only: git, make, g++, python3 + Pillow).

If the Pager's screen ever fails with this theme, go back to the stock one over SSH:

    ssh root@172.16.52.1 "uci set system.@pager[0].theme_path='/rom/lib/pager/themes/wargames'; uci set system.@pager[0].theme_name='[wargames]'; uci commit system; service pineapplepager restart"

Credits: see `themes/SquachWatch/CREDITS`. This is an unofficial port of the original's look.
```

- [ ] **Step 2: Run everything**

Run: `bash test/run.sh 2>&1 | tail -1`
Expected: `PASS=<n> FAIL=0`

- [ ] **Step 3: Private-data grep of everything not yet pushed**

Run:
```bash
git diff origin/main --stat
git diff origin/main | grep -nE "$HOME|$(whoami)|([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}" | grep -vE '24:0A:C4:00:00:01|00:00:00:00:00'
```
Expected: the second command prints nothing. Each remaining MAC-like hit must be a made-up value; fix any other hit.

- [ ] **Step 4: Commit**

```bash
git add README.md
TZ=UTC git -c user.name=Ziggy -c user.email=79704039+therealziggy@users.noreply.github.com commit -m "docs: README section for the optional SquachWatch theme" -m "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

- [ ] **Step 5: Ask the user** whether to push. Push only on a clear yes.
