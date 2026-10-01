#!/bin/bash
# test/remoteid_test.sh — Remote ID over WiFi (spec 2026-10-01). Reads the committed fixtures in
# test/fixtures/rid/ (made by tools/rid_fixtures/build.sh from opendroneid-core-c).
SW_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../payloads/user/reconnaissance/squachwatch" && pwd)"
_RFIX="$(cd "$(dirname "${BASH_SOURCE[0]}")/fixtures" && pwd)/rid"

# --- the fixtures: tcpdump -t -nn -xx text, radiotap with a signal, no clock times ---
for _f in beacon nan parrot multi unknowns equator order quiet truncated badlink; do
  assert_eq "$([ -s "$_RFIX/$_f.txt" ] && echo ok)" "ok" "rid_fixture_present_$_f"
done
assert_contains "$(cat "$_RFIX/beacon.txt")" "-47dBm signal Beacon (TEST-DRONE)" rid_fixture_signal_header
assert_empty "$(grep -lE '^[0-9]{2}:[0-9]{2}:[0-9]{2}\.' "$_RFIX"/*.txt)" rid_fixtures_no_clock_times
# control: the same check does see a clock time at the start of a line
assert_contains "$(printf '22:13:20.000000 Beacon\n' | grep -E '^[0-9]{2}:[0-9]{2}:[0-9]{2}\.')" "22:13:20" rid_fixture_clock_check_works
unset _f

# --- the decoder: tcpdump -t -nn -xx text -> S/D lines ---
# lib/remoteid.sh uses sw_sanitize_ident (match.sh), sw_wifi_colonize (wifi.sh), _sw_csv_cell (log.sh),
# sw_stopped (ble.sh) and sw_ignored (ignore.sh): source them all here, so this file passes on its own too
source "$SW_ROOT/lib/match.sh"; source "$SW_ROOT/lib/wifi.sh"; source "$SW_ROOT/lib/log.sh"
source "$SW_ROOT/lib/ble.sh"; source "$SW_ROOT/lib/ignore.sh"; source "$SW_ROOT/lib/remoteid.sh"
_dec() { _sw_rid_decode_awk < "$_RFIX/$1.txt"; }
# _rf LINES FIELD: a field of the first D line, by name (the contract's order, after the "D" tag)
_rf() { local c; case "$2" in mac) c=2;; rssi) c=3;; forms) c=4;; id_type) c=5;; id_hex) c=6;; id2_type) c=7;;
  id2_hex) c=8;; ua_type) c=9;; status) c=10;; lat) c=11;; lon) c=12;; alt_geo) c=13;; alt_baro) c=14;; height) c=15;;
  height_ref) c=16;; speed) c=17;; vspeed) c=18;; heading) c=19;; pilot_type) c=20;; pilot_lat) c=21;; pilot_lon) c=22;;
  pilot_alt) c=23;; operator_id) c=24;; self_id) c=25;; esac
  printf '%s\n' "$1" | awk -F'\t' -v c="$c" '$1 == "D" { print $c; exit }'; }
# _rs LINES N: field N of the S line (2 frames, 3 understood, 4 rid_frames, 5 more_drones)
_rs() { printf '%s\n' "$1" | awk -F'\t' -v c="$2" '$1 == "S" { print $c; exit }'; }
_serial1=3030303046535754455354303030303030303031   # "0000FSWTEST000000001"
_serial2=3030303046535754455354303030303030303032   # "0000FSWTEST000000002"

# a full ASD-STAN beacon: every field decoded (values are gen.c's inputs)
_o="$(_dec beacon)"
assert_eq "$(_rf "$_o" mac)" "80e126aabbcc" rid_beacon_mac
assert_eq "$(_rf "$_o" rssi)" "-47" rid_beacon_rssi
assert_eq "$(_rf "$_o" forms)" "1" rid_beacon_form_asdstan
assert_eq "$(_rf "$_o" id_type)" "1" rid_beacon_idtype_serial
assert_eq "$(_rf "$_o" id_hex)" "$_serial1" rid_beacon_serial_hex
assert_eq "$(_rf "$_o" ua_type)" "2" rid_beacon_uatype_multirotor
assert_eq "$(_rf "$_o" status)" "2" rid_beacon_status_airborne
assert_eq "$(_rf "$_o" lat)" "473977600" rid_beacon_lat_raw
assert_eq "$(_rf "$_o" lon)" "85454200" rid_beacon_lon_raw
assert_eq "$(_rf "$_o" alt_geo)" "3040" rid_beacon_altgeo_enc           # (520 + 1000) / 0.5
assert_eq "$(_rf "$_o" height)" "2174" rid_beacon_height_enc            # (87 + 1000) / 0.5
assert_eq "$(_rf "$_o" height_ref)" "0" rid_beacon_height_over_takeoff
assert_eq "$(_rf "$_o" speed)" "1200" rid_beacon_speed_centi           # 12.00 m/s
assert_eq "$(_rf "$_o" vspeed)" "30" rid_beacon_vspeed_deci            # 3.0 m/s
assert_eq "$(_rf "$_o" heading)" "215" rid_beacon_heading
assert_eq "$(_rf "$_o" pilot_type)" "1" rid_beacon_pilot_type_live
assert_eq "$(_rf "$_o" pilot_lat)" "473980000" rid_beacon_pilot_lat_raw
assert_eq "$(_rf "$_o" pilot_lon)" "85410200" rid_beacon_pilot_lon_raw
assert_eq "$(_rf "$_o" operator_id)" "5357544553544f50455241544f523031" rid_beacon_operator_id   # "SWTESTOPERATOR01"
assert_eq "$(_rf "$_o" alt_baro)" "" rid_beacon_altbaro_unknown_empty   # the encoder's default: unknown
assert_eq "$(_rs "$_o" 2)/$(_rs "$_o" 3)/$(_rs "$_o" 4)/$(_rs "$_o" 5)" "1/1/1/0" rid_beacon_stats

# NAN: the same pack in a different outer frame (form bit 2)
_o="$(_dec nan)"
assert_eq "$(_rf "$_o" forms)" "2" rid_nan_form
assert_eq "$(_rf "$_o" id_hex)" "$_serial1" rid_nan_serial
assert_eq "$(_rf "$_o" pilot_lat)" "473980000" rid_nan_pilot_lat
# Parrot's OUI (form bit 4), any type byte
_o="$(_dec parrot)"
assert_eq "$(_rf "$_o" forms)" "4" rid_parrot_form
assert_eq "$(_rf "$_o" id_hex)" "$_serial1" rid_parrot_serial
# the Order bit: 4 more header bytes before the fixed fields
assert_eq "$(_rf "$(_dec order)" id_hex)" "$_serial1" rid_order_bit_header

# the standard's "unknown" values become EMPTY fields, never numbers
_o="$(_dec unknowns)"
for _k in lat lon height alt_geo speed vspeed heading pilot_lat pilot_lon; do
  assert_eq "$(_rf "$_o" "$_k")" "" "rid_unknown_${_k}_empty"
done
# control: the record itself is real (its ID is there; only its values are unknown)
assert_eq "$(_rf "$_o" id_hex)" "$_serial1" rid_unknown_control_serial
# latitude 0 with a real longitude is a place on the equator, not "unknown"
_o="$(_dec equator)"
assert_eq "$(_rf "$_o" lat)/$(_rf "$_o" lon)" "0/85454200" rid_equator_lat_zero_kept

# two drones, each its own line; the stronger signal first
_o="$(_dec multi)"
assert_eq "$(printf '%s\n' "$_o" | grep -c '^D')" "2" rid_multi_two_drones
assert_eq "$(_rf "$_o" id_hex)" "$_serial1" rid_multi_strongest_first
assert_contains "$_o" "$_serial2" rid_multi_second_serial
# the cap keeps the strongest and counts the rest; 0 = no cap
_o="$(SW_RID_MAX_DRONES=1 _dec multi)"
assert_eq "$(printf '%s\n' "$_o" | grep -c '^D')" "1" rid_cap_one_line
assert_eq "$(_rf "$_o" id_hex)" "$_serial1" rid_cap_keeps_strongest
assert_eq "$(_rs "$_o" 5)" "1" rid_cap_counts_overflow
assert_eq "$(SW_RID_MAX_DRONES=0 _dec multi | grep -c '^D')" "2" rid_cap_zero_means_no_cap

# an ordinary beacon: counted and understood (the frame parser works), but no drone
_o="$(_dec quiet)"
assert_eq "$(_rs "$_o" 2)/$(_rs "$_o" 3)/$(_rs "$_o" 4)" "1/1/0" rid_quiet_stats
assert_empty "$(printf '%s\n' "$_o" | grep '^D')" rid_quiet_no_drone
# a frame cut short inside its pack: rejected, and the pass still ends with its stats line
_o="$(_dec truncated)"
assert_empty "$(printf '%s\n' "$_o" | grep '^D')" rid_truncated_no_drone
assert_eq "$(_rs "$_o" 2)" "1" rid_truncated_stats_still_printed
# a malformed frame BEFORE a good one cannot hide the good one (the Tier-3 lesson)
_o="$( { cat "$_RFIX/truncated.txt"; cat "$_RFIX/beacon.txt"; } | _sw_rid_decode_awk )"
assert_eq "$(_rf "$_o" id_hex)" "$_serial1" rid_bad_frame_does_not_hide_next
assert_eq "$(_rs "$_o" 2)" "2" rid_bad_frame_both_counted

# the decoder runs the same on BusyBox awk (the Pager) as on this box's awk
if command -v busybox >/dev/null 2>&1; then
  for _f in beacon nan parrot multi unknowns equator order quiet truncated badlink; do
    assert_eq "$(busybox awk -v max=32 "$(_sw_rid_awk_src)" < "$_RFIX/$_f.txt")" "$(_dec "$_f")" "rid_busybox_parity_$_f"
  done
else
  fail "rid_busybox_parity: busybox not installed (sudo apt install busybox)"
fi
unset _o _k _f _serial1 _serial2; unset -f _dec _rf _rs

