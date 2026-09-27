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
