#!/bin/bash
# lib/ignore.sh — the owner's own devices (Tier-3 spec §6). Without this, your own Tile or
# SmartTag in your bag would raise a follow alert every cooldown forever. The file lives in
# the loot dir so a payload redeploy never overwrites it; it is read once at startup.

sw_load_ignore() {
  # $1 = ignore file: one MAC per line, '#' comments, any case, CRLF tolerated. A line
  # "evil_twin:<MAC>" silences the evil twin with that address, and nothing else (sw_ignored); a line
  # "drone:<Remote ID>" silences that drone (or "drone:<MAC>" one that sends no ID).
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
  # rc 0 = drop it. Only the MAC column is compared. An evil twin is dropped only by an explicit
  # "evil_twin:<MAC>" line, never by a plain one: its address is whatever the attacker chose to
  # broadcast, and a copy made under one of your own addresses (your router's, your Flipper's)
  # must not be silenced by it (spec 2026-09-29, user decision).
  local r="${1#*|*|*|*|*|}" mac id
  mac="${r%%|*}"
  if [ "${1%%|*}" = evil_twin ]; then
    case "$2" in *" EVIL_TWIN:$mac "*) return 0 ;; esac
  elif [ "${1%%|*}" = drone_rid ]; then
    # A drone is dropped only by "drone:<its Remote ID>", or "drone:<MAC>" when it sends no ID: its
    # address can change, and anyone can broadcast any address (spec 2026-10-01 §4). The ID is compared
    # the way sw_load_ignore stores its lines: no spaces, upper case.
    r="${r#*|}"; id="${r%%|*}"; id="${id//[[:space:]]/}"; id="${id^^}"
    if [ -n "$id" ]; then
      case "$2" in *" DRONE:$id "*) return 0 ;; esac
    else
      case "$2" in *" DRONE:$mac "*) return 0 ;; esac
    fi
  else
    case "$2" in *" $mac "*) return 0 ;; esac
  fi
  return 1
}
