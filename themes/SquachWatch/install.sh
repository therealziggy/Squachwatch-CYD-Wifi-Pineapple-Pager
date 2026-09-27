#!/bin/sh
# SquachWatch Pager theme: installer. Runs ON the Pager (BusyBox ash):   sh install.sh
# It copies the Pager's stock theme into a new theme folder, adds SquachWatch's two pictures, and
# patches five things: the payload screen's background and text width, the alert pop-up's picture,
# its text box, the alert time colour (only when that is safe on this theme -- see the note below),
# and four palette colours used across the whole Pager UI. Nothing from the stock theme ships with
# SquachWatch. A half-built theme is never left where the Pager could offer it: everything is built
# in a temporary folder, checked, then moved into place.
# Spec: docs/superpowers/specs/2026-09-27-squachwatch-theme-design.md
set -u
SRC="$(cd "$(dirname "$0")" && pwd)"
STOCK="${SW_THEME_STOCK:-/lib/pager/themes/wargames}"
DEST="${SW_THEME_DEST:-/root/themes/SquachWatch}"
PARENT="$(dirname "$DEST")"
TMP="$PARENT/.$(basename "$DEST").tmp.$$"
OLD="$TMP.old"
trap 'fail "interrupted"' HUP INT TERM

fail() {
  echo "SquachWatch theme NOT installed: $*" >&2
  rm -rf "$TMP"
  if [ ! -e "$DEST" ] && [ -e "$OLD" ]; then
    mv "$OLD" "$DEST" || echo "the old theme is still at $OLD" >&2
  fi
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
echo "Building the SquachWatch theme from $STOCK (this can take a minute on the Pager)..."
mkdir -p "$PARENT" || fail "could not create $PARENT"
rm -rf "$TMP" "$OLD"
cp -rL "$STOCK" "$TMP" || fail "could not copy $STOCK"
mkdir -p "$TMP/assets/squachwatch" || fail "could not create the pictures folder"
cp "$SRC/assets/payload_bg.png" "$SRC/assets/alert_card.png" "$TMP/assets/squachwatch/" \
  || fail "could not copy the pictures"

# Where this firmware keeps the four components: read from theme.json, not assumed.
PL="$(jq -r '.payload_log_path // empty' "$TMP/theme.json" 2>/dev/null)"
AD="$(jq -r '.alert_dialog_path // empty' "$TMP/theme.json" 2>/dev/null)"
AT="$(jq -r '.string_templates.alert_info_dialog_text // empty' "$TMP/theme.json" 2>/dev/null)"
TS="$(jq -r '.string_templates.timestamp // empty' "$TMP/theme.json" 2>/dev/null)"
[ -n "$PL" ] && [ -n "$AD" ] && [ -n "$AT" ] && [ -n "$TS" ] \
  || fail "the stock theme.json does not name the payload screen, the alert pop-up, its text and its time"
for _c in "$PL" "$AD"; do
  [ -f "$TMP/$_c" ] || fail "the stock theme has no $_c"
  jq -e '.background.layers[0].image_path' "$TMP/$_c" >/dev/null 2>&1 \
    || fail "$_c does not start with a background picture"
done

jpatch "$PL" '.background.layers[0].image_path = "assets/squachwatch/payload_bg.png" | .max_chars = 36'
jpatch "$AD" '.background.layers[0].image_path = "assets/squachwatch/alert_card.png"'
jpatch "$AT" '.text_color_palette = "cyan" | .max_chars = 26 | .max_lines = 8
  | .center_text_within = {"draw_bounds": false, "start_x": 44, "end_x": 296, "start_y": 58, "end_y": 196}'
# The alert pop-up's time sits on the card's pink strip, where the stock gray is hard to read. That's
# only safe to force black when the palette actually names a black and no OTHER component draws with
# this same template (both were checked on one Pager only) -- otherwise leave the time colour alone
# rather than assume.
_ts_black_ok="$(jq -e '.color_palette.black != null' "$TMP/theme.json" 2>/dev/null)"
_ts_other="$(find "$TMP" -name '*.json' | while IFS= read -r _cf; do
  [ "$_cf" = "$TMP/$AD" ] && continue
  jq -r '.. | objects | .use_template? // empty' "$_cf" 2>/dev/null
done | grep -c '^timestamp$')"
if [ "$_ts_black_ok" = "true" ] && [ "$_ts_other" -eq 0 ]; then
  jpatch "$TS" '.text_color_palette = "black"'
else
  echo "note: left the alert pop-up's time colour as shipped (black not confirmed safe on this stock theme)"
fi
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
trap - HUP INT TERM
rm -rf "$OLD"
echo "SquachWatch theme installed in $DEST. Pick \"SquachWatch\" in the Pager's theme setting."
