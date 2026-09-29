#!/bin/bash
# lib/wifi.sh — read recon.db, emit wifi records. Query a /tmp copy (lock-safe).
: "${SW_RECON_DB:=/root/recon/recon.db}"
# Recency window in seconds: recon.db keeps MONTHS of history (20,346 rows on a real
# Pager, ~222 of them from the last 10 min) and a proximity detector only cares about
# what is nearby now. Unset/0 disables the filter, and each use below reads it as
# "${SW_RECENCY_SECS:-0}". Deliberately NOT defaulted with := here: payload.sh sources
# its libs BEFORE its own config block, so a default assigned here would win and pin the
# operational window to 0 -- which silently swept the whole history every lap.

_sw_wifi_window_sql() {
  # REPLY = extra WHERE clause for the window, or "" when disabled. One date(1) call
  # per sweep, not per row. ssid.time is epoch seconds (P0-confirmed on device).
  REPLY=""
  case "${SW_RECENCY_SECS:-0}" in ''|*[!0-9]*) return 0 ;; 0) return 0 ;; esac
  local now; now="$(date +%s)"
  REPLY=" AND s.time >= $(( now - SW_RECENCY_SECS ))"
}

sw_wifi_stale_db() {
  # True (0) when the window is ON, the DB holds rows, but NONE fall inside it --
  # the recon DB has stopped updating (or its clock is wrong) and WiFi detection is
  # silently dead. A zero-row sweep must never be reported as "all clear".
  case "${SW_RECENCY_SECS:-0}" in ''|*[!0-9]*) return 1 ;; 0) return 1 ;; esac
  local db="${1:-$SW_RECON_DB}" tmp now total fresh
  tmp="$(mktemp "${SW_TMP_DIR:-/tmp}/sw_recon.XXXXXX")" || return 1
  cp "$db" "$tmp" 2>/dev/null || { rm -f "$tmp"; return 1; }
  now="$(date +%s)"
  total="$(sqlite3 "$tmp" "SELECT count(*) FROM ssid;" 2>/dev/null)"
  fresh="$(sqlite3 "$tmp" "SELECT count(*) FROM ssid WHERE time >= $(( now - SW_RECENCY_SECS ));" 2>/dev/null)"
  # A copy that vanished mid-check (the exit trap after a Stop, a relaunch's startup sweep) left
  # the counts an empty new file, which the sqlite3 CLI creates: that is "unknown", not "stale".
  [ -s "$tmp" ] || { rm -f "$tmp"; return 1; }
  rm -f "$tmp"
  [ "${total:-0}" -gt 0 ] && [ "${fresh:-0}" -eq 0 ]
}

sw_wifi_colonize() {
  # $1 = 12 hex chars -> REPLY = AA:BB:CC:DD:EE:FF upper.
  # Builtins only: this runs once per record (see the perf contract in lib/match.sh).
  local m="${1^^}"
  REPLY="${m:0:2}:${m:2:2}:${m:4:2}:${m:6:2}:${m:8:2}:${m:10:2}"
}

sw_wifi_row_to_record() {
  # $1=bssid_hex $2=ssid $3=signal. ssid sanitized (Finding-1) via sw_sanitize_ident
  # from lib/match.sh (payload.sh + the test source match.sh before wifi.sh).
  # Both helpers answer in REPLY, so this stays fork-free — read REPLY before the
  # next call overwrites it.
  local mac ident
  sw_wifi_colonize "$1"; mac="$REPLY"
  sw_sanitize_ident "$2"; ident="$REPLY"
  printf 'wifi|%s|%s|%s\n' "$mac" "$ident" "$3"
}

sw_recon_snapshot() {
  # $1 = recon DB path -> REPLY = the path of a private copy in ${SW_TMP_DIR:-/tmp}, rc 0; or rc 1
  # and REPLY="" when no copy could be made. Every read goes to a copy: the live DB locks while the
  # Recon GUI is open. The caller removes the copy; one stranded by the Pager's Stop is cleared by
  # payload.sh at the next start (sw_clear_tmp removes sw_recon.*).
  REPLY=""
  local tmp
  tmp="$(mktemp "${SW_TMP_DIR:-/tmp}/sw_recon.XXXXXX")" || return 1   # trailing X's only — BusyBox mktemp rejects a suffix after XXXXXX
  cp "$1" "$tmp" 2>/dev/null || { rm -f "$tmp"; return 1; }
  REPLY="$tmp"
}

sw_recon_drop() {
  # $1 = a copy from sw_recon_snapshot: remove it, with the -wal and -shm files a read-only open
  # leaves next to it when the DB is in WAL mode. The Pager's recon.db uses a rollback journal
  # (checked 2026-09-29); this keeps /tmp clean if a firmware update ever switches it to WAL.
  rm -f "$1" "$1-wal" "$1-shm"
}

sw_wifi_records_in() {
  # $1 = a recon DB copy (sw_recon_snapshot). Emits one wifi record per row and leaves the copy in
  # place: a lap (payload.sh, sw_scan_once) shares one copy with the evil-twin check. -readonly: a
  # copy removed under a running lap (the exit trap after a Stop) makes this read fail instead of
  # leaving an empty new file in its place.
  # P0-confirmed schema: join wifi_device for the canonical MAC (clients have EMPTY
  # ssid.bssid; the MAC is only in wifi_device.mac). ssid is a BLOB -> CAST to TEXT.
  # Emit ONE column per row = mac<TAB>signal<TAB>ssid, joined with char(9) in SQL, so we
  # do NOT depend on the sqlite3 CLI's column separator (real CLI defaults to '|', the
  # python test shim to tab). SSID is LAST so any bytes it holds (tabs/pipes/etc.) can't
  # shift mac/signal. mac/signal never contain a tab. The CLI prints a line break inside a
  # value as it is, so line breaks are removed from the SSID in SQL: a network named
  # "x<LF>B41E52112233<TAB>-10<TAB>y" used to read as a second, forged record (a fake Flock
  # Safety camera, full alert included; reproduced 2026-09-29). Only a 12-hex MAC gets through, for
  # the same reason (defence in depth: pineapd writes hex). The { } runs in ONE subshell.
  # bash reads bytes (LC_ALL=C): in a UTF-8 locale (the Pager's default too, checked 2026-09-29)
  # a name ending in the first byte of a multi-byte character makes `read` swallow the line break
  # after it, so the NEXT line merged into this one and that device vanished.
  local LC_ALL=C
  local window; _sw_wifi_window_sql; window="$REPLY"
  sqlite3 -readonly "$1" "SELECT w.mac || char(9) || s.signal || char(9) || replace(replace(CAST(s.ssid AS TEXT), char(10), ''), char(13), '') FROM ssid s JOIN wifi_device w ON s.wifi_device=w.hash WHERE s.type IN (4,8) AND length(w.mac) = 12 AND w.mac NOT GLOB '*[^0-9A-Fa-f]*'$window;" 2>/dev/null | {
    local line mac rest signal ssid
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      mac="${line%%$'\t'*}"; [ -z "$mac" ] && continue
      rest="${line#*$'\t'}"                 # signal<TAB>ssid
      signal="${rest%%$'\t'*}"              # up to 2nd tab
      ssid="${rest#*$'\t'}"                 # everything after 2nd tab (ssid may contain anything)
      sw_wifi_row_to_record "$mac" "$ssid" "$signal"
    done
  }
}

sw_wifi_records() {
  # $1 = db path (default SW_RECON_DB): copy, read, remove the copy. For tests and tools; a lap
  # takes one copy and shares it (payload.sh, sw_scan_once).
  sw_recon_snapshot "${1:-$SW_RECON_DB}" || return 1
  local tmp="$REPLY"
  sw_wifi_records_in "$tmp"
  sw_recon_drop "$tmp"
}
