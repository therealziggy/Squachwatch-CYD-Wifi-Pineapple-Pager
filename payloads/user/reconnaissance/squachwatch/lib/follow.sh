#!/bin/bash
# lib/follow.sh — escalate a tracker that STAYS with you (Tier-3 spec §5).
#
# A tracker that is merely nearby is logged at med by sw_emit. One seen continuously for
# FOLLOW_SECS becomes a second, HIGH-confidence detection "<category>_follow", which sw_emit
# turns into a full ALERT with its own mac+category cooldown.
# State: one line per tracker, "mac|category|first_seen|last_seen".
# Runs per tracker DETECTION (a handful per lap), not per record, so it may fork.

_sw_follow_unwritable() {
  # $1 = trackfile. Follow state could not be written: say so, never go quietly dark.
  LOG yellow "WARN: follow state unwritable ($1) — follow alerts OFF" 2>/dev/null
  return 1
}

sw_follow_update() {
  # $1=detection $2=now $3=trackfile $4=follow_secs $5=gap_secs
  # Prints the escalated detection, or nothing. rc 1 if the state could not be written.
  local det="$1" now="$2" tf="$3" follow="$4" gap="$5"
  local cat label conf tclass radio mac ident rssi r
  cat="${det%%|*}";  r="${det#*|}"
  label="${r%%|*}";  r="${r#*|}"
  conf="${r%%|*}";   r="${r#*|}"
  tclass="${r%%|*}"; r="${r#*|}"
  radio="${r%%|*}";  r="${r#*|}"
  mac="${r%%|*}";    r="${r#*|}"
  ident="${r%%|*}";  rssi="${r#*|}"
  [ "$tclass" = tracker ] || return 0
  # Follow floor (spec 2026-09-23 §6): a sighting weaker than SW_FOLLOW_MIN_RSSI does not count,
  # so a stationary neighbour's tracker heard through a wall never "follows" you at home. It
  # does not refresh last_seen either: weak for longer than the gap and the clock restarts.
  # A missing or non-numeric RSSI still counts, so a missing reading never hides a tracker.
  # The floor itself counts ONLY when it is a negative integer (I6): empty, "0", a positive
  # number like "85" (both natural off-guesses, since sibling settings use 0 = off), or garbage
  # all mean the floor is OFF, never a working threshold that happens to gate everything.
  local floor="${SW_FOLLOW_MIN_RSSI:-}" floor_re='^-[1-9][0-9]*$' num='^-?[0-9]+$'
  if [[ "$floor" =~ $floor_re ]] && [[ "$rssi" =~ $num ]] && [ "$rssi" -lt "$floor" ]; then return 0; fi
  local key="$mac|$cat" first="$now" tmp line k f l
  # Rewrite via a temp file + mv, so a kill mid-write can't truncate the state.
  if ! tmp="$(mktemp "$tf.XXXXXX" 2>/dev/null)"; then
    _sw_follow_unwritable "$tf"; return 1
  fi
  if [ -f "$tf" ]; then
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      l="${line##*|}"; f="${line%|*}"; f="${f##*|}"; k="${line%|*|*}"
      [ $((now - l)) -le "$gap" ] || continue            # prune: gone longer than the gap
      if [ "$k" = "$key" ]; then first="$f"; continue; fi   # continuous: keep its clock
      printf '%s\n' "$line" >> "$tmp"
    done < "$tf"
  fi
  printf '%s|%s|%s\n' "$key" "$first" "$now" >> "$tmp"
  if ! mv -f "$tmp" "$tf" 2>/dev/null; then
    rm -f "$tmp"; _sw_follow_unwritable "$tf"; return 1
  fi
  if [ $((now - first)) -ge "$follow" ]; then
    printf '%s_follow|%s — following you %d+ min|high|%s|%s|%s|%s|%s\n' \
      "$cat" "$label" $(( (now - first) / 60 )) "$tclass" "$radio" "$mac" "$ident" "$rssi"
  fi
}
