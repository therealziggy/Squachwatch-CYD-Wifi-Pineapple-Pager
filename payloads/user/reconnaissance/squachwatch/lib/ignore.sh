#!/bin/bash
# lib/ignore.sh — the owner's own devices (Tier-3 spec §6). Without this, your own Tile or
# SmartTag in your bag would raise a follow alert every cooldown forever. The file lives in
# the loot dir so a payload redeploy never overwrites it; it is read once at startup.

sw_load_ignore() {
  # $1 = ignore file: one MAC per line, '#' comments, any case, CRLF tolerated.
  # Prints " MAC1 MAC2 " (upper-case, space-padded) for a fork-free membership test.
  local line out=" "
  if [ -f "$1" ]; then
    while IFS= read -r line || [ -n "$line" ]; do
      line="${line%%#*}"; line="${line//[[:space:]]/}"
      [ -n "$line" ] && out="$out${line^^} "
    done < "$1"
  fi
  printf '%s' "$out"
}

sw_ignored() {
  # $1 = detection (cat|label|conf|tclass|radio|mac|ident|rssi), $2 = sw_load_ignore set.
  # rc 0 = drop it. Only the MAC column is compared.
  local r="${1#*|*|*|*|*|}"
  case "$2" in *" ${r%%|*} "*) return 0 ;; esac
  return 1
}
