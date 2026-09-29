#!/bin/bash
# tools/replay_evil_twin.sh — replay the evil-twin check over a recon DB's whole history
# (spec 2026-09-29 §8). Usage: bash tools/replay_evil_twin.sh <recon.db> [window seconds]
# Runs the real sw_evil_twin_scan once for every minute that holds beacon data, as a lap at the end
# of that minute would have: only rows last seen by then, inside the window. Read-only. It prints
# real network names and addresses, so keep its output out of the repository.
set -u
db="${1:?usage: replay_evil_twin.sh <recon.db> [window seconds]}"
[ -r "$db" ] || { echo "can't read $db" >&2; exit 1; }
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="$ROOT/payloads/user/reconnaissance/squachwatch/lib"
source "$LIB/match.sh"; source "$LIB/wifi.sh"; source "$LIB/eviltwin.sh"
# no sqlite3 CLI on this machine (a dev PC): use the test suite's python3-backed stand-in
command -v sqlite3 >/dev/null 2>&1 || PATH="$ROOT/test/stubs:$PATH"
SW_RECENCY_SECS="${2:-600}"
declare -A hits=() first=()
mins="$(sqlite3 -readonly "$db" "SELECT DISTINCT time / 60 FROM ssid WHERE type = 8 ORDER BY 1;")" \
  || { echo "can't read the history in $db (is it a recon DB?)" >&2; exit 1; }
minutes=0
while IFS= read -r m; do
  [ -n "$m" ] || continue
  minutes=$((minutes + 1))
  end=$(( m * 60 + 59 ))
  while IFS= read -r det; do
    [ -n "$det" ] || continue
    key="${det#*|*|*|*|*|}"; key="${key%|*}"          # "<MAC>|<name>"
    hits[$key]=$(( ${hits[$key]:-0} + 1 ))
    [ -n "${first[$key]:-}" ] || first[$key]="$end"
  done < <(sw_evil_twin_scan "$db" "$end" "$end")
done <<< "$mins"
_sw_evil_twin_window
echo "window ${REPLY}s; minutes with beacon data: $minutes; open copies found: ${#hits[@]}"
for key in "${!hits[@]}"; do
  echo "  ${key%%|*}  '${key#*|}'  minutes it fired: ${hits[$key]}  first: $(date -u -d "@${first[$key]}" '+%Y-%m-%d %H:%M UTC')"
done
