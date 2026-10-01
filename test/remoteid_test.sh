#!/bin/bash
# test/remoteid_test.sh — Remote ID over WiFi (spec 2026-10-01). Reads the committed fixtures in
# test/fixtures/rid/ (made by tools/rid_fixtures/build.sh from opendroneid-core-c), and the crafted frames in
# test/fixtures/rid/hostile/ (byte edits of those fixtures, each documented with its test below).
SW_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../payloads/user/reconnaissance/squachwatch" && pwd)"
_RFIX="$(cd "$(dirname "${BASH_SOURCE[0]}")/fixtures" && pwd)/rid"

# --- the fixtures: tcpdump -t -nn -xx text, radiotap with a signal, no clock times ---
for _f in beacon nan parrot multi unknowns equator order quiet truncated badlink full emptyserial; do
  assert_eq "$([ -s "$_RFIX/$_f.txt" ] && echo ok)" "ok" "rid_fixture_present_$_f"
done
assert_contains "$(cat "$_RFIX/beacon.txt")" "-47dBm signal Beacon (TEST-DRONE)" rid_fixture_signal_header
# no time stamp of any kind tcpdump prints: its default (HH:MM:SS.micro), -tt (epoch.micro) and -tttt (a date)
_clock_re='^([0-9]{2}:[0-9]{2}:[0-9]{2}\.|[0-9]{9,}\.[0-9]{6} |[0-9]{4}-[0-9]{2}-[0-9]{2} )'
assert_empty "$(grep -lE "$_clock_re" "$_RFIX"/*.txt "$_RFIX"/hostile/*.txt)" rid_fixtures_no_clock_times
# control: the same regex sees each of the three at the start of a line
for _l in '00:00:00.000000 Beacon' '0000000000.000000 Beacon' '0000-00-00 00:00:00.000000 Beacon'; do
  assert_contains "$(printf '%s\n' "$_l" | grep -E "$_clock_re")" "Beacon" "rid_fixture_clock_check_works_[${_l%% *}]"
done
# The beacon timestamp (the 8 bytes after the 802.11 header, in beacons and probe responses) is zero in every
# fixture: the reference library writes the generating machine's uptime there, and gen.c zeroes it.
# _tsf FILE...: prints FILE:N for each such frame (the Nth in its file) whose timestamp is not zero
_tsf() { awk 'function b(i) { return hx[substr(h, 1 + i * 2, 1)] * 16 + hx[substr(h, 2 + i * 2, 1)] }
  function chk(  off, fc, hl, j) { if (h == "") return; off = b(2) + b(3) * 256; fc = b(off); fc -= fc % 4
    if (fc != 128 && fc != 80) return
    hl = (b(off + 1) >= 128) ? 28 : 24
    for (j = 0; j < 8; j++) if (b(off + hl + j)) { print fn ":" n; return } }
  BEGIN { for (k = 0; k <= 9; k++) hx[k] = k; hx["a"] = 10; hx["b"] = 11; hx["c"] = 12; hx["d"] = 13; hx["e"] = 14; hx["f"] = 15 }
  $1 !~ /^0x[0-9a-f]+:$/ { chk(); h = ""; fn = FILENAME; n = (FNR == 1) ? 1 : n + 1; next }
  { for (k = 2; k <= NF; k++) h = h $k }
  END { chk() }' "$@"; }
assert_empty "$(_tsf "$_RFIX"/*.txt "$_RFIX"/hostile/*.txt)" rid_fixtures_no_uptime
# control: the check does see a timestamp that is not zero (the beacon's bytes 0x21-0x22 set)
_f="$(mktemp)"; sed $'s/^\t0x0020:  0000 0000/\t0x0020:  0012 3400/' "$_RFIX/beacon.txt" > "$_f"
assert_eq "$(_tsf "$_f")" "$_f:1" rid_fixture_uptime_check_works
rm -f "$_f"; unset _f _l _clock_re; unset -f _tsf

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

# a reference frame holding every message the decoder reads, with values no other fixture uses (gen.c's "full")
_o="$(_dec full)"
assert_eq "$(_rf "$_o" mac)/$(_rf "$_o" rssi)" "80e126ff0001/-52" rid_full_address_signal
assert_eq "$(_rf "$_o" id_type)/$(_rf "$_o" id_hex)" "2/4653572d4341412d544553542d30303031" rid_full_first_id_caa   # "FSW-CAA-TEST-0001"
assert_eq "$(_rf "$_o" id2_type)/$(_rf "$_o" id2_hex)" "1/3030303046535754455354303030303030303034" rid_full_second_id_serial   # "0000FSWTEST000000004"
assert_eq "$(_rf "$_o" ua_type)" "15" rid_full_airframe_other
assert_eq "$(_rf "$_o" status)" "3" rid_full_status_emergency
assert_eq "$(_rf "$_o" lat)/$(_rf "$_o" lon)" "473901234/85301234" rid_full_position
assert_eq "$(_rf "$_o" alt_baro)/$(_rf "$_o" alt_geo)/$(_rf "$_o" height)/$(_rf "$_o" height_ref)" "3020/3040/2060/1" rid_full_altitudes_height_over_ground   # 510 m, 520 m, 30 m
assert_eq "$(_rf "$_o" speed)/$(_rf "$_o" vspeed)/$(_rf "$_o" heading)" "6975/-25/90" rid_full_motion   # 69.75 m/s (the multiplier), -2.5 m/s, 90 degrees
assert_eq "$(_rf "$_o" pilot_type)/$(_rf "$_o" pilot_lat)/$(_rf "$_o" pilot_lon)/$(_rf "$_o" pilot_alt)" "0/473900000/85300000/3030" rid_full_takeoff_point   # at 515 m
assert_eq "$(_rf "$_o" self_id)" "5357544553542d53454c462d49442d46554c4c2d323343" rid_full_self_id   # "SWTEST-SELF-ID-FULL-23C", all 23 bytes
assert_eq "$(_rf "$_o" operator_id)" "5357544553544f50455241544f523032" rid_full_operator_id   # "SWTESTOPERATOR02"
# a serial number with no text, then a CAA registration (gen.c's "emptyserial"): both kept, as sent
_o="$(_dec emptyserial)"
assert_eq "$(_rf "$_o" id_type)/$(_rf "$_o" id_hex)/$(_rf "$_o" id2_type)/$(_rf "$_o" id2_hex)" "1//2/4653572d4341412d544553542d30303032" rid_emptyserial_both_ids_kept   # "FSW-CAA-TEST-0002"

# --- crafted frames (spec §8): test/fixtures/rid/hostile/ holds byte edits of the fixtures above, as tcpdump
# text only (no pcap of them exists, and no tool makes them). Each edit is written next to its test: offsets
# are tcpdump's 0x.. byte offsets, counted from the start of the radiotap header. Every case is decoded by this
# box's awk and by BusyBox awk (the Pager's), which must agree byte for byte.
_RH="$_RFIX/hostile"
_bD="$(_dec beacon | grep '^D')"               # the reference beacon's drone line
_hd() { cat "$@" | _sw_rid_decode_awk; }        # _hd FILE...: the decoder over the files
_hdb() { cat "$@" | busybox awk -v max="${SW_RID_MAX_DRONES:-32}" "$(_sw_rid_awk_src)"; }   # ...on BusyBox awk
# controls: every frame below was edited from beacon, nan or quiet, which decode unpatched (quiet: understood)
assert_eq "$(_dec beacon | grep -c '^D')/$(_dec nan | grep -c '^D')/$(_rs "$(_dec quiet)" 3)" "1/1/1" rid_h_sources_decode_unpatched
# _bad NAME FRAMES UNDERSTOOD: hostile/NAME.txt is rejected. Alone it gives no drone line, only the stats line
# S FRAMES UNDERSTOOD 0 0; and the reference beacon right after it decodes exactly as it does alone.
_hbad=(); _hfr=0; _hun=0
_bad() { local f="$_RH/$1.txt" o n
  o="$(_hd "$f")"; n="$(_hd "$f" "$_RFIX/beacon.txt")"
  assert_eq "$o" "S	$2	$3	0	0" "rid_h_${1}_rejected"
  assert_eq "$n" "$_bD"$'\n'"S	$(( $2 + 1 ))	$(( $3 + 1 ))	1	0" "rid_h_${1}_next_frame_decodes"
  assert_eq "$(_hdb "$f")|$(_hdb "$f" "$_RFIX/beacon.txt")" "$o|$n" "rid_h_${1}_busybox"
  _hbad+=("$f"); _hfr=$(( _hfr + $2 )); _hun=$(( _hun + $3 )); }
# the pack check (okpack): type nibble F, message size 25, 1 to 9 messages, all inside their container
_bad pack_type 1 1            # beacon 0x43 f2->e2: the pack's type nibble is E
_bad pack_size 1 1            # beacon 0x44 19->18: message size 24
_bad pack_count0 1 1          # beacon 0x45 04->00: a pack of no messages
_bad pack_count5 1 1          # beacon 0x45 04->05: five messages declared, four sent (it runs past the element)
_bad pack_short_element 1 1   # beacon 0x3d 6c->6b: the element is one byte shorter than its pack
_bad pack_count10 1 1         # nan: ten messages (count 0x37 04->0a; six copies of the 4th inserted at 0x9c), its
                              # service info (0x33 68->fe) and attribute (0x28 7200->0801) grown to hold them: only
                              # NAN has room for a pack of more than 9
# the frame: whole bytes, a radiotap header of at least 8 bytes, a beacon or action frame, room for its header
_bad odd_hex 1 0              # beacon with its last hex digit removed
_bad radiotap_short 1 0       # beacon 0x02 09->04, bytes 0x04-0x08 removed: a 4-byte radiotap header (no signal)
_bad probe_response 1 0       # quiet 0x09 80->50: a probe response
_bad order_cut 1 0            # quiet 0x0a 00->80 (the Order bit: a 28-byte header), the frame cut at 35 bytes
# the beacon's element walk
_bad elements_65 1 1          # beacon + 62 empty elements (de00) at 0x3c: the Remote ID element is the 65th, past
                              # the walk's 64 (control: elements_64 below)
_bad asdstan_type 1 1         # beacon 0x41 0d->0c (ASD-STAN type 0x0C), and 0x2f-0x32 "TEST"->fa0bbc0d so the frame
                              # still holds what the pre-test looks for (the header line shows that name)
# NAN: its address and action header, the Service Descriptor attribute, and what its control byte announces
_bad nan_addr1 1 1            # nan 0x12 00->01: addr1 is not 51:6f:9a:01:00:00
_bad nan_type 1 1             # nan 0x26 13->12: not the NAN action type
_bad nan_attr_id 1 1          # nan 0x27 03->04: the attribute with the service id is not a Service Descriptor
_bad attrs_65 1 1             # nan + 64 empty attributes (0e0000) at 0x27: the Service Descriptor is the 65th
                              # (control: attrs_64 below)
_bad attr_overrun 1 1         # nan 0x28 72->ff: the Service Descriptor runs past the frame's end
_bad si_short 1 1             # nan 0x33 68->60: the service info is shorter than its pack
_bad si_overrun 1 1           # nan 0x33 68->70: the service info runs past the Service Descriptor
_bad nan_bitmap 1 1           # nan control 0x32 10->50: a binding bitmap announced, none there
_bad nan_mfilter 1 1          # nan control 0x32 10->14: a matching filter announced, none there
_bad nan_srf 1 1              # nan control 0x32 10->18: a service response filter announced, none there
_bad nan_no_si 1 1            # nan control 0x32 10->00: no service info
# All 23 together, most from the good drone's own address, then the good beacon: exactly its drone line, and
# every frame counted (spec §8: "a malformed frame before a good one")
assert_eq "${#_hbad[@]}/$_hfr/$_hun" "23/23/19" rid_hostile_case_count
_o="$(_hd "${_hbad[@]}" "$_RFIX/beacon.txt")"
assert_eq "$_o" "$_bD"$'\n'"S	24	20	1	0" rid_hostile
assert_eq "$(_hdb "${_hbad[@]}" "$_RFIX/beacon.txt")" "$_o" rid_hostile_busybox
# _good NAME SOURCE: hostile/NAME.txt decodes exactly as SOURCE.txt, the fixture it was edited from
_good() { local f="$_RH/$1.txt" o
  o="$(_hd "$f")"
  assert_eq "$o" "$(_dec "$2")" "rid_h_${1}_decodes"
  assert_eq "$(_hdb "$f")" "$o" "rid_h_${1}_busybox"; }
_good elements_64 beacon      # beacon + 61 empty elements at 0x3c: the Remote ID element is the 64th
_good attrs_64 nan            # nan + 63 empty attributes at 0x27: the Service Descriptor is the 64th
_good nan_bitmap_ok nan       # nan control 0x32 10->50, a 2-byte binding bitmap (5a5a) at 0x33, length 0x28 72->74
_good nan_mfilter_ok nan      # nan control 0x32 10->14, a matching filter (025a5a) at 0x33, length 0x28 72->75
_good nan_srf_ok nan          # nan control 0x32 10->18, a service response filter (035a5a5a) at 0x33, 0x28 72->76
# _hpar NAME FILE...: the files decode the same on BusyBox awk
_hpar() { local n="$1"; shift; assert_eq "$(_hdb "$@")" "$(_hd "$@")" "rid_h_${n}_busybox"; }
# values the decoder must clean (each still decodes its drone: the ID is there)
_o="$(_hd "$_RH/id_trailing_spaces.txt")"     # beacon 0x5a-0x5b 3031->2020: the ID ends in two spaces
assert_eq "$(_rf "$_o" id_hex)" "303030304653575445535430303030303030" rid_h_id_trailing_spaces_dropped
_hpar id_trailing_spaces "$_RH/id_trailing_spaces.txt"
_o="$(_hd "$_RH/lat_out_of_range.txt")"       # beacon 0x64-0x67 0053401c->01e9a435: latitude 90.0000001
assert_eq "$(_rf "$_o" lat)/$(_rf "$_o" lon)/$(_rf "$_o" id_hex)" "//$_serial1" rid_h_lat_out_of_range_empty
_hpar lat_out_of_range "$_RH/lat_out_of_range.txt"
_o="$(_hd "$_RH/lon_out_of_range.txt")"       # beacon 0x68-0x6b 78ed1705->ff2db694: longitude -180.0000001
assert_eq "$(_rf "$_o" lat)/$(_rf "$_o" lon)/$(_rf "$_o" id_hex)" "//$_serial1" rid_h_lon_out_of_range_empty
_hpar lon_out_of_range "$_RH/lon_out_of_range.txt"
_o="$(_hd "$_RH/vspeed_down.txt")"            # beacon 0x63 06->82: falling at 63 m/s, the standard's "unknown"
assert_eq "$(_rf "$_o" vspeed)/$(_rf "$_o" speed)/$(_rf "$_o" id_hex)" "/1200/$_serial1" rid_h_vspeed_down_unknown_empty
_hpar vspeed_down "$_RH/vspeed_down.txt"
# The signal is the header's FIRST "-NNdBm signal": tcpdump prints the radiotap field before any frame text.
# sig_in_name: the beacon's network name made "-1dBm signal" (0x2d 000a "TEST-DRONE" -> 000c "-1dBm signal"),
# so its header reads "-47dBm signal Beacon (-1dBm signal) ..."
assert_eq "$(_rf "$(_hd "$_RH/sig_in_name.txt")" rssi)" "-47" rid_h_signal_first_match
_hpar sig_in_name "$_RH/sig_in_name.txt"
# A frame whose header has no signal has none, even right after one that has (quiet.txt, -55dBm): no_signal is
# the beacon from a radiotap header with no signal field (0x02 09->08, 0x04 20->00, 0x08 d1 removed)
assert_eq "$(_rf "$(_hd "$_RFIX/quiet.txt" "$_RH/no_signal.txt")" rssi)/$(_rf "$(_hd "$_RH/no_signal.txt")" id_hex)" "/$_serial1" rid_h_no_signal_no_rssi
_hpar no_signal "$_RFIX/quiet.txt" "$_RH/no_signal.txt"
# Per address, the strongest signal: a weaker copy heard later (beacon 0x08 d1->ba, header -70dBm) does not
# lower it; a stronger one heard later (nan 0x08 d1->e2, header -30dBm) raises it
assert_eq "$(_rf "$(_hd "$_RFIX/beacon.txt" "$_RH/sig_weaker_copy.txt")" rssi)" "-47" rid_h_signal_weaker_copy_ignored
_hpar sig_weaker_copy "$_RFIX/beacon.txt" "$_RH/sig_weaker_copy.txt"
assert_eq "$(_rf "$(_hd "$_RFIX/beacon.txt" "$_RH/sig_stronger_nan.txt")" rssi)" "-30" rid_h_signal_stronger_copy_wins
_hpar sig_stronger_nan "$_RFIX/beacon.txt" "$_RH/sig_stronger_nan.txt"
# one address, two forms: the drone's beacon and its NAN frame merge into ONE line, with forms 1 + 2 = 3
_o="$(_hd "$_RFIX/beacon.txt" "$_RFIX/nan.txt")"
assert_eq "$_o" "$(printf '%s\n' "$_bD" | awk -F'\t' -v OFS='\t' '{ $4 = 3; print }')"$'\n'"S	2	2	2	0" rid_h_one_address_two_forms_one_line
_hpar two_forms "$_RFIX/beacon.txt" "$_RFIX/nan.txt"
# The first two distinct Basic IDs per address: the beacon twice, then with ID ...0002 (0x5b 31->32), then with
# ID ...0003 (0x5b 31->33): the ID is ...0001 and the second ID ...0002, each a serial number (type 1)
_o="$(_hd "$_RFIX/beacon.txt" "$_RFIX/beacon.txt" "$_RH/id_0002.txt" "$_RH/id_0003.txt")"
assert_eq "$(_rf "$_o" id_type)/$(_rf "$_o" id_hex)/$(_rf "$_o" id2_type)/$(_rf "$_o" id2_hex)" "1/$_serial1/1/$_serial2" rid_h_first_two_distinct_ids
_hpar two_ids "$_RFIX/beacon.txt" "$_RFIX/beacon.txt" "$_RH/id_0002.txt" "$_RH/id_0003.txt"
unset _RH _bD _hbad _hfr _hun; unset -f _hd _hdb _bad _good _hpar

# the decoder runs the same on BusyBox awk (the Pager) as on this box's awk
if command -v busybox >/dev/null 2>&1; then
  for _f in beacon nan parrot multi unknowns equator order quiet truncated badlink full emptyserial; do
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
# The ID is the first one with any text, a serial number preferred (spec §3): an empty serial gives way to the
# other ID, which then names the drone everywhere (screen, ledger, ignore list, remoteid.csv)
_det="$(sw_test_rid_line id_type=1 id_hex= id2_type=2 id2_hex=434141 | _recs)"
assert_contains "$_det" "|80:E1:26:AA:BB:CC|CAA|-47|" rid_rec_empty_serial_gives_way
assert_contains "$(_csv1)" ',-47,caa,"CAA",,"",' rid_csv_empty_serial_gives_way
assert_contains "$(sw_test_rid_line id_type=2 id_hex=434141 id2_type=1 id2_hex= | _recs)" "|CAA|" rid_rec_empty_second_serial_not_preferred

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
# A drone is silenced only when EVERY ID it sent is listed (user decision 2026-10-02): a spoofer can send a copy
# of the owner's ID from another drone's address, and must not hide that drone with it
_ign=" DRONE:0000FSWTEST000000001 "
rm -f "$_rl/remoteid.csv"
assert_contains "$(sw_test_rid_line id2_type=2 id2_hex=434141 | SW_IGNORE_SET="$_ign" _recs)" "|0000FSWTEST000000001|" rid_rec_shown_id_listed_other_not_reported
assert_contains "$(_csv1)" ',serial,"0000FSWTEST000000001",caa,"CAA",' rid_rec_shown_id_listed_row_has_both
assert_contains "$(sw_test_rid_line id_type=2 id_hex=434141 id2_type=1 id2_hex=3030303046535754455354303030303030303031 | SW_IGNORE_SET="$_ign" _recs)" "drone_rid|" rid_rec_serial_listed_caa_not_reported
# control: with both listed it is silenced
assert_empty "$(sw_test_rid_line id2_type=2 id2_hex=434141 | SW_IGNORE_SET="$_ign DRONE:CAA " _recs)" rid_rec_both_ids_listed_silenced
unset _ign
# a stopped payload writes and reports nothing
bash -c 'exit 0' & _rd=$!; wait "$_rd"
rm -f "$_rl/remoteid.csv"
assert_empty "$(sw_test_rid_line | SW_MAIN_PID="$_rd" _recs)" rid_rec_stopped_no_detection
assert_eq "$([ -e "$_rl/remoteid.csv" ] && echo written)" "" rid_rec_stopped_no_csv
rm -rf "$_rl"; unset _rl _det _rd; unset -f _recs _csv1

# --- the per-lap capture (test/stubs/tcpdump models the Pager's tcpdump) ---
_cap_dir="$(mktemp -d)"; _cap_loot="$(mktemp -d)"
# _cap FIXTURE [VAR=VALUE...]: one 1-second capture window in its own shell, run as a lap runs it
# (sw_rid_start and sw_rid_collect in the same shell). FIXTURE "" = a capture with no frames; a name is
# test/fixtures/rid/NAME.txt, and a path (starting with /) is used as it is.
_cap() { local fx="$1"; shift
  case "$fx" in /*) ;; ?*) fx="$_RFIX/$fx.txt" ;; esac
  env SW_TMP_DIR="$_cap_dir" SW_REMOTE_ID=1 SW_RID_SECONDS=1 SW_RID_IFACE=wlan1mon \
      SW_FAKE_TCPDUMP="$fx" "$@" bash -c '
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

# output cut short: tcpdump's summary counts more packets than the decoder saw frames (here 3 against 1), so
# frames were lost on the way: one WARN. (control: cap_beacon_status_ok, the same capture with an honest summary)
_cap_reset; _cap beacon SW_FAKE_TCPDUMP_CAPTURED=3 >/dev/null
assert_eq "$(_cap_state)" "not_understood" cap_cut_short_status
assert_eq "$(grep -c 'WiFi capture not understood' "$SW_STUB_LOG")" "1" cap_cut_short_warns

# 5 frames and none of them parses as a beacon or action frame: the format changed under us, the same WARN.
# The frames are the quiet fixture's, five times, with the radiotap version byte (the first byte) changed from
# 0 to 1. Controls: the same five unchanged are ok, and so are four changed ones (under 5 frames is no signal).
_fr="$_cap_dir/frames.txt"
for _i in 1 2 3 4 5; do cat "$_RFIX/quiet.txt"; done > "$_fr"
_cap_reset; _cap "$_fr" >/dev/null
assert_eq "$(_cap_state)" "ok" cap_five_beacons_status_ok
for _i in 1 2 3 4 5; do sed 's/0x0000:  00/0x0000:  01/' "$_RFIX/quiet.txt"; done > "$_fr"
_cap_reset; _cap "$_fr" >/dev/null
assert_eq "$(_cap_state)" "not_understood" cap_format_changed_status
assert_eq "$(grep -c 'WiFi capture not understood' "$SW_STUB_LOG")" "1" cap_format_changed_warns
for _i in 1 2 3 4; do sed 's/0x0000:  00/0x0000:  01/' "$_RFIX/quiet.txt"; done > "$_fr"
_cap_reset; _cap "$_fr" >/dev/null; rm -f "$_fr"
assert_eq "$(_cap_state)" "ok" cap_four_unparsed_is_ok

# the frame cap: tcpdump stops at -c frames; one WARN per SW_COOLDOWN, and what was heard still counts
# (one frame: tcpdump's summary says "1 packet captured", so these tests need the parser to read the singular)
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
rm -rf "$_cap_dir" "$_cap_loot"; unset _cap_dir _cap_loot _out _fm _pids _sp _i _fr; unset -f _cap _cap_state _cap_reset _alive
unset _RFIX
