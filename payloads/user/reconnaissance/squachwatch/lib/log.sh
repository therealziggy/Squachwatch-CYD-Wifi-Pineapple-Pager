#!/bin/bash
# lib/log.sh — CSV detection log with optional GPS tag.
sw_log_init() {
  local dir="$1"; mkdir -p "$dir"
  local csv="$dir/detections.csv"
  [ -f "$csv" ] || echo "time,category,label,confidence,threat_class,radio,mac,ident,rssi,gps" > "$csv"
}

# _sw_csv_field: render a value as one safe CSV cell. Quote-wraps and doubles internal
# quotes, AND neutralizes spreadsheet formula injection — a cell beginning with = + - @
# (or a TAB/CR) is prefixed with a single quote so Excel/Sheets/LibreOffice treat it as
# text, not a formula. The loot CSV is reviewed in spreadsheets and its ident field is an
# attacker-chosen SSID/BLE name, so this closes an =HYPERLINK/DDE/WEBSERVICE vector.
_sw_csv_field() { _sw_csv_cell "$1"; printf '%s' "$REPLY"; }

# _sw_csv_cell: the same cell in REPLY, with builtins only, for callers that build many cells per row
# (lib/remoteid.sh) and must not fork for each one.
_sw_csv_cell() {
  local v="$1"
  case "$v" in
    [=+@-]*) v="'$v" ;;
    $'\t'*)  v="'$v" ;;
    $'\r'*)  v="'$v" ;;
  esac
  while [ "${v%$'\n'}" != "$v" ]; do v="${v%$'\n'}"; done   # as $( ) did: trailing line breaks dropped
  REPLY="\"${v//\"/\"\"}\""
}

sw_log_write() {
  # $1=dir $2=detection $3=now_epoch
  local dir="$1" det="$2" now="$3" gps
  [ -f "$dir/detections.csv" ] || sw_log_init "$dir"   # self-init if caller skipped sw_log_init
  gps="$(GPS_GET 2>/dev/null | tr ' ' ',' )"   # stub prints SW_FAKE_GPS; device prints coords
  local cat label conf tclass radio mac ident rssi detail
  IFS='|' read -r cat label conf tclass radio mac ident rssi detail <<EOF
$det
EOF
  # Quote/escape the free-text + attacker-influenced fields. gps must be quoted because real
  # GPS_GET returns space-separated lat lon alt acc that tr turns into commas (would overflow
  # the 10-column header unquoted). ident (SSID/BLE name) and label go through the formula guard.
  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$now" "$cat" "$(_sw_csv_field "$label")" "$conf" "$tclass" "$radio" "$mac" \
    "$(_sw_csv_field "$ident")" "$rssi" "$(_sw_csv_field "$gps")" \
    >> "$dir/detections.csv"
}
