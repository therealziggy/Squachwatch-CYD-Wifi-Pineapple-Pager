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
  # $1 = since, $2 = until (epoch seconds) -> REPLY = the SQL condition for the beacon rows the check
  # reads: visible access points (hidden radios are skipped: an Enhanced Open network is an open radio
  # plus a hidden protected one with the same name, and must not read as a twin) with a real name (not
  # empty, not only zero bytes) and a 12-hex address (nothing else can reach a result line), last seen
  # between $1 and $2.
  REPLY="type = 8 AND hidden = 0 AND time >= $1 AND time <= $2 AND ltrim(hex(ssid), '0') <> ''"
  REPLY+=" AND length(bssid) = 12 AND bssid NOT GLOB '*[^0-9A-Fa-f]*'"
}

sw_evil_twin_scan() {
  # $1 = a recon DB copy (sw_recon_snapshot in lib/wifi.sh): read only, never changed or removed.
  # $2 = the lap's start, epoch seconds. $3 (optional) = leave out rows last seen after this epoch. A
  # lap leaves it out and gets its start plus a minute: after the device clock steps back, older
  # history would otherwise look like "right now" and pair up as false twins.
  # tools/replay_evil_twin.sh passes it to replay history.
  # Prints one detection per open copy, in the matcher's format:
  #   evil_twin|Evil twin|high|attacker|wifi|<MAC>|<network name>|<its latest signal>
  local db="$1" now="$2" until="${3:-}" rows line mac rest sig name
  # The name ends each result line, so bash reads bytes (LC_ALL=C): in a UTF-8 locale (the Pager's default too, checked 2026-09-29)
  # a name ending in the first byte of a multi-byte character makes `read` swallow the line break
  # after it, so the NEXT line merged into this one and that device vanished.
  local LC_ALL=C
  [[ "$now" =~ ^[1-9][0-9]{0,11}$ ]] || return 0
  [ -n "$until" ] || until=$(( now + 60 ))
  [[ "$until" =~ ^[1-9][0-9]{0,11}$ ]] || return 0
  _sw_evil_twin_window
  _sw_evil_twin_rows "$(( now - REPLY ))" "$until"; rows="$REPLY"
  # The query (spec §6.1). MATERIALIZED reads the window ONCE: one pass over the table, ~0.27 s on
  # the Pager, where SQLite otherwise read it twice (~0.44 s; both measured 2026-09-29). ssid and
  # bssid are BLOBs, so GROUP BY and = compare bytes exactly ("Lobby-WiFi" never pairs with
  # "LOBBY-WIFI"). Rows with no security value count for neither side. max(w.time) makes SQLite take
  # each open copy's line from its latest row. The name goes LAST, with its line breaks removed: the
  # CLI prints them as they are, and a name holding one could otherwise forge a second result line.
  sqlite3 -readonly "$db" "WITH w AS MATERIALIZED (
      SELECT bssid, ssid, signal, time, encryption FROM ssid
      WHERE $rows AND encryption IS NOT NULL
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
  # $1 = a recon DB copy (read only). 0 = blind: the evil-twin check cannot work, because the window
  # holds beacon rows but none of them has a usable value in one of the columns the check reads
  # (hidden, encryption and signal as numbers, a 12-hex address), its visible rows have no names, or
  # the probe fails for any reason but a damaged copy (a renamed column, an sqlite3 that can't run the
  # check's query). The check would then find nothing, forever, and read as "all clear". 2 = the copy
  # is damaged ("malformed", "not a database", "disk I/O"): usually a copy torn by a write in progress,
  # so the health check looks at one fresh copy before it says anything. 1 = fine, or no verdict: no
  # rows in the window (the stale-DB check reports that one), or a copy that vanished during the check
  # (the exit trap after a Stop). Not caught: a firmware change that keeps these columns but changes
  # what their values mean.
  local now since out rc total hid enc sig mac vis visnamed
  _sw_evil_twin_window
  now="$(date +%s)"; since=$(( now - REPLY ))
  out="$(sqlite3 -readonly "$1" "WITH b AS MATERIALIZED (
      SELECT bssid, ssid, signal, time, hidden, encryption FROM ssid
      WHERE type = 8 AND time >= $since AND time <= $(( now + 60 ))
    )
    SELECT count(*) || char(9) ||
      count(CASE WHEN typeof(hidden) = 'integer' THEN 1 END) || char(9) ||
      count(CASE WHEN typeof(encryption) = 'integer' THEN 1 END) || char(9) ||
      count(CASE WHEN typeof(signal) = 'integer' THEN 1 END) || char(9) ||
      count(CASE WHEN length(bssid) = 12 AND bssid NOT GLOB '*[^0-9A-Fa-f]*' THEN 1 END) || char(9) ||
      count(CASE WHEN hidden = 0 THEN 1 END) || char(9) ||
      count(CASE WHEN hidden = 0 AND ltrim(hex(ssid), '0') <> '' THEN 1 END)
    FROM b;" 2>&1)"; rc=$?
  [ -s "$1" ] || return 1
  if [ "$rc" -ne 0 ]; then
    case "$out" in *malformed*|*"not a database"*|*"disk I/O"*) return 2 ;; esac
    return 0
  fi
  IFS=$'\t' read -r total hid enc sig mac vis visnamed <<< "$out"
  [[ "$total" =~ ^[0-9]+$ && "$hid" =~ ^[0-9]+$ && "$enc" =~ ^[0-9]+$ && "$sig" =~ ^[0-9]+$ && "$mac" =~ ^[0-9]+$ \
     && "$vis" =~ ^[0-9]+$ && "$visnamed" =~ ^[0-9]+$ ]] || return 0
  [ "$total" -gt 0 ] || return 1
  if [ "$hid" -eq 0 ] || [ "$enc" -eq 0 ] || [ "$sig" -eq 0 ] || [ "$mac" -eq 0 ]; then return 0; fi
  if [ "$vis" -gt 0 ] && [ "$visnamed" -eq 0 ]; then return 0; fi
  return 1
}
