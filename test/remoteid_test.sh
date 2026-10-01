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

# --- from the decoder's lines to detections and remoteid.csv rows ---
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/helpers/rid.sh"    # sw_test_rid_line
_rl="$(mktemp -d)"
_recs() { SW_FAKE_GPS= SW_RID_FILE= sw_rid_records 1700000000 "$_rl"; }   # stdin = decoder lines; no GPS fix; rows in $_rl
_csv1() { tail -1 "$_rl/remoteid.csv"; }

# formatters
sw_rid_coord 473977600 5; assert_eq "$REPLY" "47.39776" rid_fmt_coord5
sw_rid_coord 473977600 7; assert_eq "$REPLY" "47.3977600" rid_fmt_coord7
sw_rid_coord -1234567 7;  assert_eq "$REPLY" "-0.1234567" rid_fmt_coord_negative
sw_rid_coord 0 5;         assert_eq "$REPLY" "0.00000" rid_fmt_coord_zero
sw_rid_alt 2174;          assert_eq "$REPLY" "87.0" rid_fmt_alt
sw_rid_alt 1999;          assert_eq "$REPLY" "-0.5" rid_fmt_alt_below_zero
sw_rid_m 2174;            assert_eq "$REPLY" "87" rid_fmt_metres
sw_rid_mps 1200;          assert_eq "$REPLY" "12" rid_fmt_mps
sw_rid_mps2 1225;         assert_eq "$REPLY" "12.25" rid_fmt_mps2
sw_rid_dmps -25;          assert_eq "$REPLY" "-2.5" rid_fmt_dmps_negative
sw_rid_text 3030303046535754455354303030303030303031; assert_eq "$REPLY" "0000FSWTEST000000001" rid_fmt_text

# a full drone: one detection (ID = the serial) and a remoteid.csv row with the full precision
_det="$(sw_test_rid_line | _recs)"
assert_eq "$_det" "drone_rid|Drone|high|surveillance|wifi|80:E1:26:AA:BB:CC|0000FSWTEST000000001|-47|multirotor	87m up, 12m/s	pilot (live) 47.39800,8.54102" rid_rec_detection
assert_eq "$(head -1 "$_rl/remoteid.csv")" "time,form,mac,rssi,id_type,id,id2_type,id2,ua_type,status,lat,lon,alt_geo_m,alt_baro_m,height_m,height_ref,speed_mps,vspeed_mps,heading_deg,pilot_loc,pilot_lat,pilot_lon,pilot_alt_m,operator_id,self_id,gps" rid_csv_header
assert_eq "$(_csv1)" '1700000000,beacon,80:E1:26:AA:BB:CC,-47,serial,"0000FSWTEST000000001",,"",multirotor,airborne,47.3977600,8.5454200,520.0,,87.0,takeoff,12.00,3.0,215,live,47.3980000,8.5410200,,"SWTESTOPERATOR01","",""' rid_csv_row
assert_eq "$(wc -l < "$_rl/remoteid.csv" | tr -d ' ')" "2" rid_csv_one_row_one_header
# with a GPS attached, every row also records the Pager's own fix (GPS_GET), so distances can be worked out later
sw_test_rid_line | SW_FAKE_GPS="1.5 2.5" SW_RID_FILE= sw_rid_records 1700000000 "$_rl" >/dev/null
assert_eq "$(_csv1 | awk -F'"' '{print $(NF-1)}')" "1.5,2.5" rid_csv_records_own_gps_fix
# the pilot's location kinds, as the alert words them
assert_contains "$(sw_test_rid_line pilot_type=0 | _recs)" "takeoff point 47.39800,8.54102" rid_rec_takeoff_point
assert_contains "$(sw_test_rid_line pilot_type=2 | _recs)" "pilot (fixed) 47.39800,8.54102" rid_rec_pilot_fixed
# no height: the geodetic altitude instead; no System message: "no pilot location"
assert_contains "$(sw_test_rid_line height= | _recs)" "	alt 520m, 12m/s	" rid_rec_altitude_fallback
_det="$(sw_test_rid_line pilot_type= pilot_lat= pilot_lon= | _recs)"
assert_contains "$_det" "	no pilot location" rid_rec_no_pilot_location
assert_eq "$(_csv1 | cut -d, -f20-22)" ",," rid_csv_no_pilot_cells_empty
# every motion value unknown: the motion piece is empty, never "m up" with no number
_det="$(sw_test_rid_line height= alt_geo= speed= | _recs)"
assert_contains "$_det" "|multirotor		pilot (live)" rid_rec_unknown_motion_empty
# no Basic ID: an empty ID (the drone is then known by its address)
assert_eq "$(sw_test_rid_line id_type= id_hex= | _recs | cut -d'|' -f6-8)" "80:E1:26:AA:BB:CC||-47" rid_rec_no_id
# two Basic IDs, the serial second: the serial is the ID, the other one goes in id2
_det="$(sw_test_rid_line id_type=2 id_hex=434141 id2_type=1 id2_hex=3030303046535754455354303030303030303031 | _recs)"
assert_contains "$_det" "|0000FSWTEST000000001|" rid_rec_prefers_serial
assert_contains "$(_csv1)" ',serial,"0000FSWTEST000000001",caa,"CAA",' rid_csv_second_id
# forms: every form heard is named
assert_contains "$(sw_test_rid_line forms=7 | _recs >/dev/null; _csv1)" ",beacon+nan+parrot," rid_csv_all_forms

# hostile IDs: they cannot forge a field, a line or a spreadsheet formula
#   "=HYPERLINK(1)" -> the CSV cell starts with a quote mark, so a spreadsheet keeps it as text
_det="$(sw_test_rid_line id_hex=3d48595045524c494e4b283129 | _recs)"
assert_contains "$_det" "|=HYPERLINK(1)|" rid_rec_formula_id_in_detection
assert_contains "$(_csv1)" ",\"'=HYPERLINK(1)\"," rid_csv_formula_guarded
#   "a|b,c<LF>d\"e" -> the pipe and the line break are removed, the comma and the quote stay inside one cell
_det="$(sw_test_rid_line id_hex=617c622c630a642265 | _recs)"
assert_eq "$(printf '%s\n' "$_det" | grep -c .)" "1" rid_rec_hostile_one_line
assert_contains "$_det" "|ab,cd\"e|" rid_rec_hostile_cleaned
assert_contains "$(_csv1)" ',"ab,cd""e",' rid_csv_hostile_one_cell
#   a zero byte inside the hex: the text ends there (a C string)
assert_contains "$(sw_test_rid_line id_hex=4142004344 | _recs)" "|AB|" rid_rec_text_stops_at_zero
# malformed lines are dropped: a leading zero (bash would read it as octal), a bad address, a field missing
assert_empty "$(sw_test_rid_line lat=0473977600 | _recs)" rid_rec_leading_zero_dropped
assert_empty "$(sw_test_rid_line mac=80e126aabbcz | _recs)" rid_rec_bad_mac_dropped
assert_empty "$(sw_test_rid_line | cut -f1-24 | _recs)" rid_rec_short_line_dropped
# control: the same helper, unbroken, does produce a detection (the drops above are the checks, not the helper)
assert_contains "$(sw_test_rid_line | _recs)" "drone_rid|" rid_rec_control_valid_line
# S lines and anything else are ignored
assert_empty "$(printf 'S\t1\t1\t1\t0\n' | _recs)" rid_rec_stats_line_ignored
# the CSV cell helper writes the cells the old _sw_csv_field wrote: each value is pinned to its literal cell
# (a ' before a leading = + - @ TAB or CR, quotes doubled, trailing line breaks dropped)
_pin() { _sw_csv_cell "$1"; assert_eq "$REPLY" "$2" "csv_cell_matches_field_[$1]"; }
_pin "plain"      '"plain"'
_pin "=SUM(1)"    $'"\'=SUM(1)"'
_pin "+1"         $'"\'+1"'
_pin "-1"         $'"\'-1"'
_pin "@x"         $'"\'@x"'
_pin $'\tlead'    $'"\'\tlead"'
_pin $'\rlead'    $'"\'\rlead"'
_pin 'q"uote'     '"q""uote"'
_pin $'trail\n\n' '"trail"'
_pin ""           '""'
_pin "a,b"        '"a,b"'
unset -f _pin
# the owner's own drone (ignore.txt: drone:<its ID>) leaves no detection and no row
rm -f "$_rl/remoteid.csv"
assert_empty "$(sw_test_rid_line | SW_IGNORE_SET=" DRONE:0000FSWTEST000000001 " _recs)" rid_rec_ignored_no_detection
assert_eq "$([ -e "$_rl/remoteid.csv" ] && echo written)" "" rid_rec_ignored_no_row
# control: a plain address line never silences a drone (its address can change; anyone can send any)
assert_contains "$(sw_test_rid_line | SW_IGNORE_SET=" 80:E1:26:AA:BB:CC " _recs)" "drone_rid|" rid_rec_plain_mac_not_ignored
# a stopped payload writes and reports nothing
bash -c 'exit 0' & _rd=$!; wait "$_rd"
rm -f "$_rl/remoteid.csv"
assert_empty "$(sw_test_rid_line | SW_MAIN_PID="$_rd" _recs)" rid_rec_stopped_no_detection
assert_eq "$([ -e "$_rl/remoteid.csv" ] && echo written)" "" rid_rec_stopped_no_csv
rm -rf "$_rl"; unset _rl _det _v _rd; unset -f _recs _csv1

# --- the per-lap capture (test/stubs/tcpdump models the Pager's tcpdump) ---
_cap_dir="$(mktemp -d)"; _cap_loot="$(mktemp -d)"
# _cap FIXTURE [VAR=VALUE...]: one 1-second capture window in its own shell, run as a lap runs it
# (sw_rid_start and sw_rid_collect in the same shell). FIXTURE "" = a capture with no frames.
_cap() { local fx="$1"; shift
  env SW_TMP_DIR="$_cap_dir" SW_REMOTE_ID=1 SW_RID_SECONDS=1 SW_RID_IFACE=wlan1mon \
      SW_FAKE_TCPDUMP="${fx:+$_RFIX/$fx.txt}" "$@" bash -c '
    source "$1/lib/match.sh"; source "$1/lib/wifi.sh"; source "$1/lib/log.sh"; source "$1/lib/ble.sh"; source "$1/lib/ignore.sh"; source "$1/lib/remoteid.sh"
    sw_rid_start 1700000000; sw_rid_collect 1700000000 "$2"' _ "$SW_ROOT" "$_cap_loot"; }
_cap_state() { head -1 "$_cap_dir/sw_rid.state" 2>/dev/null; }
_cap_reset() { rm -f "$_cap_dir"/sw_rid.* "$_cap_loot/remoteid.csv"; : > "$SW_STUB_LOG"; }

# a beacon capture: one drone detection and a remoteid.csv row; only the health state is left behind
_cap_reset; _out="$(_cap beacon)"
assert_contains "$_out" "drone_rid|Drone|high|surveillance|wifi|80:E1:26:AA:BB:CC|0000FSWTEST000000001|-47|" cap_beacon_detection
assert_contains "$(tail -1 "$_cap_loot/remoteid.csv")" "1700000000,beacon,80:E1:26:AA:BB:CC,-47,serial," cap_beacon_csv_row
assert_eq "$(_cap_state)" "ok" cap_beacon_status_ok
assert_empty "$(ls -A "$_cap_dir" | grep -v '^sw_rid\.state$')" cap_leaves_no_capture_files
# tcpdump ran read only (-p), on the configured interface, without clock times (-t), with the frame cap
assert_contains "$(grep '^tcpdump ' "$SW_STUB_LOG")" "tcpdump -i wlan1mon -p -l -t -nn -xx -c 1500 type mgt subtype beacon or (wlan[0] & 0xfc = 0xd0 and wlan addr1 51:6f:9a:01:00:00)" cap_tcpdump_args

# an ordinary beacon only: no drone, no WARN, and the capture was judged healthy (it ran)
_cap_reset; _out="$(_cap quiet)"
assert_empty "$(printf '%s\n' "$_out" | grep '^drone_rid')" cap_quiet_no_drone
assert_eq "$(_cap_state)" "ok" cap_quiet_status_ok
assert_empty "$(grep -F 'WARN' "$SW_STUB_LOG")" cap_quiet_no_warn
# no frames at all (a place with no WiFi) is ok too: "listening on" proves the capture ran
_cap_reset; _cap "" >/dev/null
assert_eq "$(_cap_state)" "ok" cap_no_frames_is_ok

# a capture that never starts: one WARN, not one per lap; then a green line once it works again
_cap_reset; _cap beacon SW_FAKE_TCPDUMP_FAIL=1 >/dev/null
assert_eq "$(_cap_state)" "capture_failed" cap_failed_status
assert_eq "$(grep -c 'WiFi capture failed' "$SW_STUB_LOG")" "1" cap_failed_warns
_cap beacon SW_FAKE_TCPDUMP_FAIL=1 >/dev/null
assert_eq "$(grep -c 'WiFi capture failed' "$SW_STUB_LOG")" "1" cap_failed_warns_once
_cap beacon >/dev/null
assert_contains "$(cat "$SW_STUB_LOG")" "Remote ID capture recovered" cap_failed_then_recovered

# a link type that is not 802.11 + radiotap: a WARN, and no drone from those bytes
# (control: the same fixture under the Pager's link type gives the drone, cap_beacon_detection)
_cap_reset; _out="$(_cap beacon SW_FAKE_TCPDUMP_LINK='EN10MB (Ethernet)')"
assert_eq "$(_cap_state)" "not_understood" cap_wrong_link_status
assert_contains "$(cat "$SW_STUB_LOG")" "WiFi capture not understood" cap_wrong_link_warns
assert_empty "$(printf '%s\n' "$_out" | grep '^drone_rid')" cap_wrong_link_no_drone

# the frame cap: tcpdump stops at -c frames; one WARN per SW_COOLDOWN, and what was heard still counts
_cap_reset; _out="$(_cap multi SW_RID_MAX_FRAMES=1)"
assert_eq "$(_cap_state)" "capped" cap_capped_status
assert_eq "$(grep -c 'hit its frame limit' "$SW_STUB_LOG")" "1" cap_capped_warns
assert_eq "$(printf '%s\n' "$_out" | grep -c '^drone_rid')" "1" cap_capped_reports_what_it_heard
_cap multi SW_RID_MAX_FRAMES=1 >/dev/null
assert_eq "$(grep -c 'hit its frame limit' "$SW_STUB_LOG")" "1" cap_capped_warns_once_per_cooldown
# ...and again once the cooldown has passed (SW_COOLDOWN=0: every capped lap may warn)
_cap multi SW_RID_MAX_FRAMES=1 SW_COOLDOWN=0 >/dev/null
assert_eq "$(grep -c 'hit its frame limit' "$SW_STUB_LOG")" "2" cap_capped_warns_again_after_cooldown

# more drones than SW_RID_MAX_DRONES: the strongest are reported, the rest counted on one line
_cap_reset; _out="$(_cap multi SW_RID_MAX_DRONES=1)"
assert_eq "$(printf '%s\n' "$_out" | grep -c '^drone_rid')" "1" cap_drone_cap_one_detection
assert_contains "$_out" "|0000FSWTEST000000001|" cap_drone_cap_keeps_strongest
assert_contains "$(cat "$SW_STUB_LOG")" "LOG magenta ...and 1 more drones (Remote ID flood?)" cap_drone_cap_more_line

# SW_REMOTE_ID=0: no tcpdump at all (control: cap_tcpdump_args, where the stub logged itself)
_cap_reset; _cap beacon SW_REMOTE_ID=0 >/dev/null
assert_empty "$(grep '^tcpdump ' "$SW_STUB_LOG")" cap_off_runs_no_tcpdump

# A Stop during the window: the main shell is gone when the window ends. The capture is dropped unread,
# nothing is reported or written, and its files go. Control: the capture did start (the stub logged).
_cap_reset; sleep 30 & _fm=$!
_out="$(env SW_TMP_DIR="$_cap_dir" SW_REMOTE_ID=1 SW_RID_SECONDS=1 SW_FAKE_TCPDUMP="$_RFIX/beacon.txt" SW_MAIN_PID="$_fm" bash -c '
  source "$1/lib/match.sh"; source "$1/lib/wifi.sh"; source "$1/lib/log.sh"; source "$1/lib/ble.sh"; source "$1/lib/ignore.sh"; source "$1/lib/remoteid.sh"
  sw_rid_start 1700000000
  kill "$3"; while [ -e "/proc/$3" ] && [ "$(cut -d" " -f3 "/proc/$3/stat" 2>/dev/null)" != Z ]; do sleep 0.01; done
  sw_rid_collect 1700000000 "$2"' _ "$SW_ROOT" "$_cap_loot" "$_fm")"
wait "$_fm" 2>/dev/null
assert_contains "$(cat "$SW_STUB_LOG")" "tcpdump -i wlan1mon" cap_stopped_control_capture_started
assert_empty "$(printf '%s\n' "$_out" | grep '^drone_rid')" cap_stopped_reports_nothing
assert_eq "$([ -e "$_cap_loot/remoteid.csv" ] && echo written)" "" cap_stopped_writes_no_csv
assert_empty "$(ls -A "$_cap_dir")" cap_stopped_leaves_no_files

# The Pager's Stop kills the main shell only, so the capture's helpers must end on their own: SIGKILL the
# shell that started a capture, then watch tcpdump (the stub) end within SW_RID_SECONDS + 2 s.
_pids="$_cap_dir/stub.pids"; : > "$_pids"
env SW_TMP_DIR="$_cap_dir" SW_REMOTE_ID=1 SW_RID_SECONDS=1 SW_STUB_PIDS="$_pids" bash -c '
  source "$1/lib/match.sh"; source "$1/lib/wifi.sh"; source "$1/lib/log.sh"; source "$1/lib/ble.sh"; source "$1/lib/ignore.sh"; source "$1/lib/remoteid.sh"
  sw_rid_start 1700000000; sleep 30' _ "$SW_ROOT" 2>/dev/null &
_sp=$!
for _i in $(seq 100); do [ -s "$_pids" ] && break; sleep 0.05; done
kill -9 "$_sp" 2>/dev/null; wait "$_sp" 2>/dev/null
_alive() { local p n=0; while read -r p; do kill -0 "$p" 2>/dev/null && n=$((n + 1)); done < "$_pids"; echo "$n"; }
# control: tcpdump was alive when its shell died, so "none left" below is not vacuous
assert_eq "$(_alive)" "1" cap_orphan_control_alive_after_kill
SECONDS=0; while [ "$(_alive)" != 0 ] && [ "$SECONDS" -lt 10 ]; do sleep 0.2; done
assert_eq "$(_alive)" "0" cap_orphan_ends_by_itself
rm -rf "$_cap_dir" "$_cap_loot"; unset _cap_dir _cap_loot _out _fm _pids _sp _i; unset -f _cap _cap_state _cap_reset _alive
