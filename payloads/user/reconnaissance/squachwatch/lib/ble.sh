#!/bin/bash
# lib/ble.sh — BLE capture via btmon, parsed into ble records (Tier-3 spec §3).
#
# btmon is the single BLE data source for every BLE matcher. `hcitool lescan` only switches
# scanning on; its output is discarded (it buffers its device lines and loses all of them
# unless it exits on SIGINT). One capture per lap is parsed ONCE into one record per MAC:
#   ble|<MAC>|<name>|<rssi>|<tokens>
#   tokens: mfr:<company>:<type>:<len>   uuid:<16-bit>   sd:<16-bit>:<first byte>
# Temp files live in ${SW_TMP_DIR:-/tmp} (a test seam; on the Pager /tmp is RAM).

# One awk pass over a lap's btmon capture -> one line per MAC:
#   MAC<TAB>strongest rssi<TAB>tokens<TAB>name
# The name goes LAST because it is the only free text, so any byte inside it cannot shift
# the other fields. Runs unchanged on mawk (dev box) and BusyBox awk 1.36.1 (Pager).
_sw_btmon_awk() {
  awk '
# One record per MAC: MAC<TAB>rssi<TAB>tokens<TAB>name (name LAST: it is the only free text)
function flush(   n, i, t) {
  if (mac == "") return
  seen[mac] = 1
  if (name != "" && nm[mac] == "") nm[mac] = name
  if (rssi != "" && rssi != "127" && (!(mac in rs) || rssi + 0 > rs[mac] + 0)) rs[mac] = rssi
  n = split(toks, t, " ")
  for (i = 1; i <= n; i++)
    if (index(" " tk[mac] " ", " " t[i] " ") == 0) tk[mac] = (tk[mac] == "" ? t[i] : tk[mac] " " t[i])
  mac = ""; name = ""; rssi = ""; toks = ""; ctx = ""
}
function lastparen(s,   p) {           # "... (76)" -> "76" ; "... (0x3081)" -> "0x3081"
  p = match(s, /\([^()]*\)$/); if (!p) return ""
  return substr(s, RSTART + 1, RLENGTH - 2)
}
# The ONLY way a token enters a record: exactly one of the shapes the matchers expect.
# A malformed UUID once raised a bash arithmetic error that aborted a whole lap of matching.
function emit(t) {
  if (t ~ /^mfr:[0-9a-f][0-9a-f][0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]:[0-9]+$/ ||
      t ~ /^mfr:004c:07:(audio|other):[0-9a-f][0-9a-f][0-9a-f][0-9a-f]$/ ||
      t ~ /^uuid:[0-9a-f][0-9a-f][0-9a-f][0-9a-f]$/ ||
      t ~ /^sd:[0-9a-f][0-9a-f][0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]$/) toks = toks " " t
}
# btmon prints names RAW, so a name holding newlines can forge btmon-shaped lines: every
# field below is shape-checked before use (the name itself is cleaned by sw_sanitize_ident).
/^[^ ]/                  { flush(); inrep = 0; next }          # any new HCI packet / note
/^ +LE (Extended )?Advertising Report/ { flush(); inrep = 1; next }
!inrep                   { next }
/^ +Address: / && $2 ~ /^[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]$/ {
  flush(); mac = toupper($2); next
}
mac == ""                { next }
/^ +RSSI: /              { if ($2 ~ /^-?[0-9]+$/) rssi = $2; ctx = ""; next }
/^ +Name \([a-z]+\): /   { name = $0; sub(/^ +Name \([a-z]+\): /, "", name); ctx = ""; next }
/^ +Company: /           { comp = sprintf("%04x", lastparen($0) + 0); ctx = "mfr"; mtype = ""; next }
ctx == "mfr" && /^ +Type: / { mtype = sprintf("%02x", lastparen($0) + 0); next }
/^ +Service Data: /      { u = lastparen($0); sduuid = tolower(substr(u, 3)); ctx = "sd"; next }
/^ +Data(\[[0-9]+\])?: / {
  hex = tolower($NF); ok = (hex ~ /^[0-9a-f]+$/ && length(hex) % 2 == 0)
  if (ctx == "mfr") {
    if (mtype != "") {
      if (ok) emit("mfr:" comp ":" mtype ":" (length(hex) / 2))
      # Apple Proximity Pairing (0x07): prefix(1) then a 2-byte device MODEL. Every published
      # AirPods/Beats model code ends in 0x20 (furiousMAC/Celosia-Cunche PETS 2020, InfiShark),
      # so those are "audio"; anything else is "other" (an AirTag in setup mode sends 0x07 too,
      # and no source documents its exact code, so nothing depends on it).
      if (ok && comp == "004c" && mtype == "07" && length(hex) >= 6)
        emit("mfr:004c:07:" (substr(hex, 5, 2) == "20" ? "audio" : "other") ":" substr(hex, 3, 4))
      mtype = ""
    }
    else { if (ok) emit("mfr:" comp ":" substr(hex, 1, 2) ":" (length(hex) / 2 - 1)); ctx = "" }
  } else if (ctx == "sd") { if (ok) emit("sd:" sduuid ":" substr(hex, 1, 2)); ctx = "" }
  next
}
/^ +16-bit Service UUIDs/ { ctx = "u16"; uind = match($0, /[^ ]/); next }
# an entry is indented DEEPER than its header: a same-indent "Appearance: (0x3200)" is not one
ctx == "u16" && match($0, /[^ ]/) > uind && /\(0x[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]\)$/ {
  u = lastparen($0); emit("uuid:" tolower(substr(u, 3))); next
}
{ ctx = "" }
END {
  flush()
  for (m in seen) printf "%s\t%s\t%s\t%s\n", m, rs[m], tk[m], nm[m]
}
'
}

sw_btmon_parse() {
  # stdin = btmon text -> stdout "ble|MAC|name|rssi|tokens", one per MAC. The name is
  # cleaned by sw_sanitize_ident (lib/match.sh), the ONE implementation of the Finding-1
  # boundary: never re-implement it in awk.
  local line mac rssi toks r
  _sw_btmon_awk | while IFS= read -r line; do
    mac="${line%%$'\t'*}"; r="${line#*$'\t'}"
    rssi="${r%%$'\t'*}";   r="${r#*$'\t'}"
    toks="${r%%$'\t'*}"
    sw_sanitize_ident "${r#*$'\t'}"
    printf 'ble|%s|%s|%s|%s\n' "$mac" "$REPLY" "$rssi" "$toks"
  done
}

sw_btmon_health() {
  # $1 = btmon capture file, $2 = records parsed from it -> REPLY:
  #   scan_failed     no "LE Set Scan Enable" completion with Status: Success, e.g. the
  #                   controller answered "Command Disallowed" and scanning never started.
  #                   Keyed on the opcode (0x08|0x000c) with "ncmd": btmon TRUNCATES
  #                   command names ("LE Set.. (0x08|0x000c)") when it prefixes a process.
  #   not_understood  advertising reports are present but zero records parsed: btmon's
  #                   text format changed under the parser.
  #   ok              otherwise, INCLUDING a quiet room (scan ran, nobody advertising).
  local cap="$1" n="$2"
  if ! awk 'p ~ /\(0x08\|0x000c\) ncmd/ && /Status: Success/ {ok = 1} {p = $0} END {exit !ok}' "$cap" 2>/dev/null; then
    REPLY=scan_failed
  elif [ "$n" -eq 0 ] && grep -q 'Advertising Report' "$cap" 2>/dev/null; then
    REPLY=not_understood
  else
    REPLY=ok
  fi
}

sw_ble_health_note() {
  # $1 = status from sw_btmon_health (or capture_failed from sw_ble_scan). LOGs only when the
  # status CHANGES, so a dead scan is loud once instead of every lap; a first-lap "ok" is silent.
  local st="$1" sf="${SW_BLE_STATE_FILE:-${SW_TMP_DIR:-/tmp}/sw_ble.state}" prev=""
  [ -f "$sf" ] && read -r prev < "$sf"
  [ "$st" = "$prev" ] && return 0
  printf '%s\n' "$st" > "$sf"
  case "$st" in
    ok)             [ -n "$prev" ] && LOG green "BLE scan recovered" 2>/dev/null ;;
    # no "detection OFF": bluetoothd's own background scan can keep adverts flowing
    scan_failed)    LOG yellow "WARN: BLE scan failed to start" 2>/dev/null ;;
    not_understood) LOG yellow "WARN: BLE capture not understood — BLE detection OFF" 2>/dev/null ;;
    capture_failed) LOG yellow "WARN: BLE capture failed (no temp space?) — BLE detection OFF" 2>/dev/null ;;
  esac
  return 0
}

sw_ble_scan() {
  # $1 = seconds (default 12), $2 = iface (default hci0). Writes ble records to stdout.
  local secs="${1:-12}" iface="${2:-hci0}" cap bpid recs n=0
  hciconfig "$iface" down 2>/dev/null; hciconfig "$iface" reset 2>/dev/null; hciconfig "$iface" up 2>/dev/null
  # a full RAM-backed /tmp must be loud (once), not an empty lap forever
  cap="$(mktemp "${SW_TMP_DIR:-/tmp}/sw_ble.XXXXXX")" || { sw_ble_health_note capture_failed; return 1; }
  # btmon has its OWN timeout: if this payload is SIGKILLed mid-lap, an orphaned btmon
  # still dies within secs+5 s instead of logging into RAM-backed /tmp forever. It is
  # stopped with TERM (timeout's default), not INT: a background job in a non-interactive
  # shell starts with SIGINT ignored, and btmon exits cleanly on TERM.
  timeout -k 2 $((secs + 3)) btmon > "$cap" 2>&1 &
  bpid=$!
  sleep 1                      # let btmon attach, or the first reports are missed
  # lescan only switches scanning ON; its output is discarded. SIGINT so it disables the
  # scan cleanly; -k 2 so an hcitool that ignored SIGINT can't hang the lap.
  timeout -s INT -k 2 "$secs" hcitool -i "$iface" lescan --duplicates > /dev/null 2>&1
  kill "$bpid" 2>/dev/null; wait "$bpid" 2>/dev/null
  recs="$(sw_btmon_parse < "$cap")"
  [ -n "$recs" ] && n="$(printf '%s\n' "$recs" | grep -c .)"
  sw_btmon_health "$cap" "$n"; sw_ble_health_note "$REPLY"
  rm -f "$cap"
  [ -n "$recs" ] && printf '%s\n' "$recs"
  return 0
}
