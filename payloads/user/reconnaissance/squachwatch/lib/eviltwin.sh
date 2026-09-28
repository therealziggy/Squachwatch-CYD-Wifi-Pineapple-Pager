#!/bin/bash
# lib/eviltwin.sh — the evil-twin check (spec docs/superpowers/specs/2026-09-29-squachwatch-evil-twin-design.md).
# A network name offered both OPEN and password-protected within the window: each radio offering it
# open is an evil twin, the copy that can lure a phone. Ported from SquachWatch-CYD's test (a mesh
# network never disagrees with itself about security) without CYD's same-maker exemption, which
# hid the one real evil twin in the author's recon history: an open copy under the real router's
# own address. One read-only query per lap on the lap's recon DB copy; SQLite does the grouping, so
# bash only formats the (usually zero) result rows, with builtins.

_sw_evil_twin_window() {
  # REPLY = the window in seconds: SW_RECENCY_SECS when it is a whole number from 1 to 999999999
  # without a leading zero (bash reads "0600" as octal), else 600. "At the same time" needs a
  # window, so 0 (the WiFi sweep then reads the whole DB) still means 600 here.
  if [[ "${SW_RECENCY_SECS:-}" =~ ^[1-9][0-9]{0,8}$ ]]; then REPLY="$SW_RECENCY_SECS"; else REPLY=600; fi
}

_sw_evil_twin_rows() {
  # $1 = since (epoch seconds) -> REPLY = the SQL condition for the beacon rows the check reads:
  # visible access points (hidden radios are skipped: an Enhanced Open network is an open radio plus
  # a hidden protected one with the same name, and must not read as a twin) with a real name (not
  # empty, not only zero bytes), last seen since $1. The blind-spot count (sw_evil_twin_blind) uses
  # the same condition, so it always counts exactly the rows the check reads.
  REPLY="type = 8 AND hidden = 0 AND time >= $1 AND ltrim(hex(ssid), '0') <> ''"
}

sw_evil_twin_scan() {
  # $1 = a recon DB copy (sw_recon_snapshot in lib/wifi.sh): read only, never changed or removed.
  # $2 = the lap's start, epoch seconds. $3 (optional) = leave out rows last seen after this epoch:
  # only tools/replay_evil_twin.sh passes it, to replay history. A lap never does, so a device clock
  # that steps back cannot hide rows that look newer than the lap.
  # Prints one detection per open copy, in the matcher's format:
  #   evil_twin|Evil twin|high|attacker|wifi|<MAC>|<network name>|<its latest signal>
  local db="$1" now="$2" until="${3:-}" since rows cap="" line mac rest sig name
  [[ "$now" =~ ^[1-9][0-9]{0,11}$ ]] || return 0
  if [ -n "$until" ]; then
    [[ "$until" =~ ^[1-9][0-9]{0,11}$ ]] || return 0
    cap=" AND time <= $until"
  fi
  _sw_evil_twin_window; since=$(( now - REPLY ))
  _sw_evil_twin_rows "$since"; rows="$REPLY"
  # The query (spec §6.1). MATERIALIZED reads the window ONCE: one pass over the table, ~0.27 s on
  # the Pager, where SQLite otherwise read it twice (~0.44 s; both measured 2026-09-29). ssid and
  # bssid are BLOBs, so GROUP BY and = compare bytes exactly ("Lobby-WiFi" never pairs with
  # "LOBBY-WIFI"). It reads the rows of _sw_evil_twin_rows that carry a security value.
  # max(w.time) makes SQLite take each open copy's line from its latest row. The name goes LAST, with its line breaks removed: the CLI prints them as
  # they are, and a name holding one could otherwise forge a second result line.
  sqlite3 -readonly "$db" "WITH w AS MATERIALIZED (
      SELECT bssid, ssid, signal, time, encryption FROM ssid
      WHERE $rows$cap AND encryption IS NOT NULL
    ),
    twin AS (
      SELECT ssid FROM w GROUP BY ssid
      HAVING sum(encryption = 0) > 0 AND sum(encryption <> 0) > 0
    )
    SELECT line FROM (
      SELECT w.bssid || char(9) || w.signal || char(9) ||
             replace(replace(CAST(w.ssid AS TEXT), char(10), ''), char(13), '') AS line,
             max(w.time)
      FROM w JOIN twin ON w.ssid = twin.ssid
      WHERE w.encryption = 0
      GROUP BY w.bssid, w.ssid
    );" 2>/dev/null | {
    while IFS= read -r line || [ -n "$line" ]; do
      mac="${line%%$'\t'*}"; rest="${line#*$'\t'}"
      sig="${rest%%$'\t'*}"; name="${rest#*$'\t'}"
      # Only a well-formed row becomes a detection (defence in depth: pineapd writes these rows).
      if [[ "$mac" =~ ^[0-9A-Fa-f]{12}$ ]] && [[ "$sig" =~ ^-?[0-9]{1,3}$ ]]; then
        sw_wifi_colonize "$mac"; mac="$REPLY"
        sw_sanitize_ident "$name"; name="$REPLY"
        printf 'evil_twin|Evil twin|high|attacker|wifi|%s|%s|%s\n' "$mac" "$name" "$sig"
      fi
    done
  }
}

sw_evil_twin_blind() {
  # $1 = recon DB (default SW_RECON_DB). True (0) when the evil-twin check cannot work: the window
  # holds named, visible beacon rows but none carries a security value, or the count fails on a
  # readable copy (a firmware update renamed the column, say). The check would then find nothing,
  # forever, and read as "all clear". False (1) = fine, or no verdict: no copy, no rows in the
  # window (the stale-DB check reports that one), or the copy vanished during the check (the exit
  # trap after a Stop), which is "unknown", never "blind".
  local win now rows tmp out rc named secured
  _sw_evil_twin_window; win="$REPLY"
  now="$(date +%s)"; _sw_evil_twin_rows "$(( now - win ))"; rows="$REPLY"
  sw_recon_snapshot "${1:-$SW_RECON_DB}" || return 1
  tmp="$REPLY"
  out="$(sqlite3 -readonly "$tmp" "SELECT count(*) || char(9) || count(encryption) FROM ssid WHERE $rows;" 2>/dev/null)"; rc=$?
  [ -s "$tmp" ] || { rm -f "$tmp"; return 1; }
  rm -f "$tmp"
  [ "$rc" -eq 0 ] || return 0
  named="${out%%$'\t'*}"; secured="${out#*$'\t'}"
  [[ "$named" =~ ^[0-9]+$ ]] && [[ "$secured" =~ ^[0-9]+$ ]] || return 0
  [ "$named" -gt 0 ] && [ "$secured" -eq 0 ]
}
