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
# a serial number with no text, then a CAA registration (gen.c's "emptyserial"): an ID with no text takes no place
# (user decision 2026-10-02), so the CAA ID is the first kept, and its airframe is the first Basic ID's
_o="$(_dec emptyserial)"
assert_eq "$(_rf "$_o" id_type)/$(_rf "$_o" id_hex)/$(_rf "$_o" id2_type)/$(_rf "$_o" id2_hex)/$(_rf "$_o" ua_type)" "2/4653572d4341412d544553542d30303032///2" rid_emptyserial_empty_id_takes_no_place   # "FSW-CAA-TEST-0002"

# The hex lines: one regex rule before the header rule takes a line of exactly tcpdump's prefix (a tab, "0x", four
# hex digits, ":", two blanks) with at least one hex word as its text after the prefix, and decode() strips the
# blanks once per frame; any other line takes the field loop (spec 2026-10-08). The output must not change: the
# reference below is the same decoder with that rule and the strip removed, which leaves the old joining, made here
# from the decoder's own source.
_rid_new="$(_sw_rid_awk_src)"
_rid_fast='/^\t0x[0-9a-f][0-9a-f][0-9a-f][0-9a-f]:  / && NF > 1 { hex = hex substr($0, 11); next }
'
_rid_strip='  gsub(/[ \t]/, "", hex)                                    # the joining left blanks: one strip per frame
'
_rid_ref="${_rid_new/"$_rid_fast"/}"
_rid_ref="${_rid_ref/"$_rid_strip"/}"
assert_contains "$_rid_new" "$_rid_fast" rid_join_fast_path_in_the_decoder
assert_contains "$_rid_new" "$_rid_strip" rid_join_strip_in_the_decoder
# control: the reference is the old joining (else every comparison below is the decoder against itself)
assert_empty "$(printf '%s\n' "$_rid_ref" | grep -F -e 'substr($0, 11)' -e 'gsub(/[ \t]/')" rid_join_reference_has_no_fast_path
assert_contains "$_rid_ref" '{ for (k = 2; k <= NF; k++) hex = hex $k }' rid_join_reference_has_the_field_loop
# Lines of another shape take the field loop, a tab between the hex words goes in the strip, and a frame whose only
# hex line has no hex words (the prefix and blanks) is no frame at all: each variant of the reference beacon decodes
# as the beacon does (control: each variant's text differs from the beacon's)
_rid_vd="$(mktemp -d)"; _rid_want="$(_dec beacon)"
assert_eq "$(_rf "$_rid_want" mac)/$(_rf "$_rid_want" id_hex)" "80e126aabbcc/$_serial1" rid_join_control_the_beacon_decodes
for _v in "no_tab|s/^\t//" "one_blank|s/^\(\t0x[0-9a-f]*:\)  /\1 /" "short_offset|s/^\t0x0\([0-9a-f]\{3\}\):/\t0x\1:/" \
          "tab_between_words|s/^\(\t0x[0-9a-f]*:  [0-9a-f]*\) /\1\t/" \
          "blank_hex_line|1h;\$G;\$s/\$/\n\t0x0000:   /"; do
  sed "${_v#*|}" "$_RFIX/beacon.txt" > "$_rid_vd/${_v%%|*}.txt"
  assert_eq "$(_sw_rid_decode_awk < "$_rid_vd/${_v%%|*}.txt")" "$_rid_want" "rid_join_${_v%%|*}_decodes_as_the_beacon"
  if cmp -s "$_rid_vd/${_v%%|*}.txt" "$_RFIX/beacon.txt"; then fail "rid_join_${_v%%|*}_variant_differs"; else pass; fi
done
# One more variant, for the differential only: an uppercase hex digit in an offset (the last line's 0x00a0). tcpdump
# prints lowercase offsets, so under the old joining and under the decoder alike such a line is not a hex line: the
# header rule takes it and it ends the frame. It does not decode as the beacon; the differential decides that the
# decoder's output on it equals the reference's. Control: its text differs from the beacon's.
sed $'s/^\t0x00a0:/\t0x00A0:/' "$_RFIX/beacon.txt" > "$_rid_vd/uppercase_offset.txt"
if cmp -s "$_rid_vd/uppercase_offset.txt" "$_RFIX/beacon.txt"; then fail "rid_join_uppercase_offset_variant_differs"; else pass; fi
# The differential: every fixture, every hostile frame and the variants above, then the two whole streams at max 32,
# 0 and 1, without and with a drone: key, on this machine's awk and on BusyBox awk: the decoder's output equals the
# reference's (2 awks x 2 key sets x (74 files + 6 streams) = 320 comparisons)
if command -v busybox >/dev/null 2>&1; then
  _rid_bad=""; _rid_n=0
  cat "$_RFIX"/*.txt > "$_rid_vd/stream_top"; cat "$_RFIX"/hostile/*.txt "$_RFIX/beacon.txt" > "$_rid_vd/stream_hostile"
  for _awk in awk "busybox awk"; do
    for _keys in " " " :0000FSWTEST000000001 "; do
      for _f in "$_RFIX"/*.txt "$_RFIX"/hostile/*.txt "$_rid_vd"/*.txt; do
        _rid_n=$((_rid_n + 1))
        [ "$($_awk -v max=32 -v ignkeys="$_keys" "$_rid_ref" < "$_f")" = "$($_awk -v max=32 -v ignkeys="$_keys" "$_rid_new" < "$_f")" ] \
          || _rid_bad="$_rid_bad ${_awk#busybox }:${_f##*/}"
      done
      for _s in stream_top stream_hostile; do for _m in 32 0 1; do
        _rid_n=$((_rid_n + 1))
        [ "$($_awk -v max="$_m" -v ignkeys="$_keys" "$_rid_ref" < "$_rid_vd/$_s")" = "$($_awk -v max="$_m" -v ignkeys="$_keys" "$_rid_new" < "$_rid_vd/$_s")" ] \
          || _rid_bad="$_rid_bad ${_awk#busybox }:$_s:$_m"
      done; done
    done
  done
  assert_eq "$_rid_n" "320" rid_join_differential_count
  assert_empty "$_rid_bad" rid_join_same_output_as_the_field_loop
  # control: the same comparison sees a difference (the multi fixture's two drones at max 1 and at max 32)
  [ "$(awk -v max=1 -v ignkeys=" " "$_rid_ref" < "$_RFIX/multi.txt")" != "$(awk -v max=32 -v ignkeys=" " "$_rid_new" < "$_RFIX/multi.txt")" ] \
    && pass || fail "rid_join_differential_sees_a_difference"
else
  fail "rid_join_differential: busybox not installed (sudo apt install busybox)"
fi
rm -rf "$_rid_vd"; unset _rid_new _rid_fast _rid_strip _rid_ref _rid_vd _rid_want _v _rid_bad _rid_n _awk _keys _f _s _m

# --- crafted frames (spec §8): test/fixtures/rid/hostile/ holds byte edits of the fixtures above, as tcpdump
# text only (no pcap of them exists, and no tool makes them). Each edit is written next to its test: offsets
# are tcpdump's 0x.. byte offsets, counted from the start of the radiotap header. Every case is decoded by this
# box's awk and by BusyBox awk (the Pager's), which must agree byte for byte.
_RH="$_RFIX/hostile"
_bD="$(_dec beacon | grep '^D')"               # the reference beacon's drone line
_hd() { cat "$@" | _sw_rid_decode_awk; }        # _hd FILE...: the decoder over the files
_hdb() { _sw_rid_keys; cat "$@" | busybox awk -v max="${SW_RID_MAX_DRONES:-32}" -v ignkeys="$REPLY" "$(_sw_rid_awk_src)"; }   # ...on BusyBox awk
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
_bad parrot_garbage 1 1       # parrot 0x43-0x46 f2190402->5a3c9e17: Parrot's OUI holding no message pack (Parrot
                              # sends other vendor elements too: only a valid pack makes a drone)
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
# All 24 together, most from the good drone's own address, then the good beacon: exactly its drone line, and
# every frame counted (spec §8: "a malformed frame before a good one")
assert_eq "${#_hbad[@]}/$_hfr/$_hun" "24/24/20" rid_hostile_case_count
_o="$(_hd "${_hbad[@]}" "$_RFIX/beacon.txt")"
assert_eq "$_o" "$_bD"$'\n'"S	25	21	1	0" rid_hostile
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
# The address is addr2, read from the frame's bytes: a network name "SA:02:00:00:00:00:99" does not change it
# (sa_in_name: 0x2d 000a "TEST-DRONE" -> 0014 and that name)
assert_eq "$(_rf "$(_hd "$_RH/sa_in_name.txt")" mac)" "80e126aabbcc" rid_h_address_from_bytes_not_name
_hpar sa_in_name "$_RH/sa_in_name.txt"
# A frame whose header has no signal has none, even right after one that has (quiet.txt, -55dBm): no_signal is
# the beacon from a radiotap header with no signal field (0x02 09->08, 0x04 20->00, 0x08 d1 removed)
assert_eq "$(_rf "$(_hd "$_RFIX/quiet.txt" "$_RH/no_signal.txt")" rssi)/$(_rf "$(_hd "$_RH/no_signal.txt")" id_hex)" "/$_serial1" rid_h_no_signal_no_rssi
_hpar no_signal "$_RFIX/quiet.txt" "$_RH/no_signal.txt"
# A radiotap signal is one signed byte (-128..127): anything else matched on the header line came from frame
# text, a network name read on a radio whose radiotap header has no signal field, so the frame has no signal.
# Each sig_name_* is the beacon from such a header (as no_signal), its network name made "1000dBm signal",
# "-0dBm signal" or "128dBm signal" (0x2d 000a "TEST-DRONE" -> 000e/000c/000d and the name).
for _n in 1000 minus0 128; do
  assert_eq "$(_rf "$(_hd "$_RH/sig_name_$_n.txt")" rssi)/$(_rf "$(_hd "$_RH/sig_name_$_n.txt")" id_hex)" "/$_serial1" "rid_h_sig_name_${_n}_no_rssi"
  # ...and after the drone's own frame with a signal, its signal stands (not raised to a made-up one)
  assert_eq "$(_rf "$(_hd "$_RFIX/beacon.txt" "$_RH/sig_name_$_n.txt")" rssi)" "-47" "rid_h_sig_name_${_n}_signal_stands"
  _hpar "sig_name_$_n" "$_RFIX/beacon.txt" "$_RH/sig_name_$_n.txt"
done
unset _n
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
# An ID with no text takes no place, and a third distinct ID flags the address (user decision 2026-10-02): forms
# bit 8, "sent more IDs than are kept" (sw_rid_records never silences such a drone). Distinct = another text or
# another ID type. owner_id is the reference beacon with the owner's ID "0000FSWTESTOWNER001" (0x48-0x5b);
# empty_id has an empty serial (0x48-0x5b zeroed).
_own=30303030465357544553544f574e4552303031
_o="$(_hd "$_RH/owner_id.txt" "$_RH/empty_id.txt" "$_RFIX/beacon.txt")"
assert_eq "$(_rf "$_o" forms)/$(_rf "$_o" id_hex)/$(_rf "$_o" id2_type)/$(_rf "$_o" id2_hex)" "1/$_own/1/$_serial1" rid_h_empty_id_takes_no_place
_hpar empty_id_no_place "$_RH/owner_id.txt" "$_RH/empty_id.txt" "$_RFIX/beacon.txt"
# ...also when it shares a frame with a kept one: owner_and_empty_id is owner_id with its 4th message (the
# Operator ID) made an empty serial (0x91 52->02, 0x92 00->12, 0x93-0xa6 zeroed)
_o="$(_hd "$_RH/owner_and_empty_id.txt" "$_RFIX/beacon.txt")"
assert_eq "$(_rf "$_o" forms)/$(_rf "$_o" id_hex)/$(_rf "$_o" id2_type)/$(_rf "$_o" id2_hex)" "1/$_own/1/$_serial1" rid_h_empty_id_in_one_frame_takes_no_place
_hpar empty_id_one_frame "$_RH/owner_and_empty_id.txt" "$_RFIX/beacon.txt"
# ...and alone it is no ID, while its airframe still counts (the first Basic ID's)
_o="$(_hd "$_RH/empty_id.txt")"
assert_eq "$(_rf "$_o" id_type)/$(_rf "$_o" id_hex)/$(_rf "$_o" ua_type)" "//2" rid_h_empty_id_alone_no_id_airframe_kept
# three distinct serials from one address: the first two are kept and the address is flagged (1 + 8)
_o="$(_hd "$_RFIX/beacon.txt" "$_RH/id_0002.txt" "$_RH/id_0003.txt")"
assert_eq "$(_rf "$_o" forms)/$(_rf "$_o" id_hex)/$(_rf "$_o" id2_hex)" "9/$_serial1/$_serial2" rid_h_third_id_flags
_hpar third_id_flags "$_RFIX/beacon.txt" "$_RH/id_0002.txt" "$_RH/id_0003.txt"
# the same text under another ID type is another ID: owner_caa is owner_id as a CAA registration (0x47 12->22)
_o="$(_hd "$_RH/owner_id.txt" "$_RH/owner_caa.txt" "$_RFIX/beacon.txt")"
assert_eq "$(_rf "$_o" forms)/$(_rf "$_o" id_type)/$(_rf "$_o" id_hex)/$(_rf "$_o" id2_type)/$(_rf "$_o" id2_hex)" "9/1/$_own/2/$_own" rid_h_same_text_other_type_flags
_hpar same_text_other_type "$_RH/owner_id.txt" "$_RH/owner_caa.txt" "$_RFIX/beacon.txt"
# ...also when it is the third: id_0002_caa is id_0002 as a CAA registration (0x47 12->22), the second kept ID's
# text under another type, so it flags the address (re-review 2026-10-02, Minor 2: compared by text only, it
# would not)
_o="$(_hd "$_RFIX/beacon.txt" "$_RH/id_0002.txt" "$_RH/id_0002_caa.txt")"
assert_eq "$(_rf "$_o" forms)/$(_rf "$_o" id_hex)/$(_rf "$_o" id2_type)/$(_rf "$_o" id2_hex)" "9/$_serial1/1/$_serial2" rid_h_third_id_other_type_flags
_hpar third_id_other_type "$_RFIX/beacon.txt" "$_RH/id_0002.txt" "$_RH/id_0002_caa.txt"
# texts that bash cleans into the owner's ID are other IDs here (the decoder sees bytes): each copy after owner_id,
# then the beacon, flags the address. owner_lower: 0x4c-0x57 lowercased; owner_space: 0x48-0x5b a space and then
# the ID; owner_ctrl: 0x5b 00->01, a control byte after the ID
for _n in lower:30303030667377746573746f776e6572303031 space:2030303030465357544553544f574e4552303031 ctrl:30303030465357544553544f574e455230303101; do
  _o="$(_hd "$_RH/owner_id.txt" "$_RH/owner_${_n%%:*}.txt" "$_RFIX/beacon.txt")"
  assert_eq "$(_rf "$_o" forms)/$(_rf "$_o" id_hex)/$(_rf "$_o" id2_hex)" "9/$_own/${_n#*:}" "rid_h_owner_${_n%%:*}_copy_flags"
  _hpar "owner_${_n%%:*}_copy" "$_RH/owner_id.txt" "$_RH/owner_${_n%%:*}.txt" "$_RFIX/beacon.txt"
done
# the flag joins the form bits: the same three serials, then the drone's NAN frame (1 + 2 + 8)
assert_eq "$(_rf "$(_hd "$_RFIX/beacon.txt" "$_RH/id_0002.txt" "$_RH/id_0003.txt" "$_RFIX/nan.txt")" forms)" "11" rid_h_flag_joins_the_forms
_hpar flag_and_forms "$_RFIX/beacon.txt" "$_RH/id_0002.txt" "$_RH/id_0003.txt" "$_RFIX/nan.txt"
# controls: the two kept IDs heard again, each of them, and an empty one after them are not more IDs
_o="$(_hd "$_RFIX/beacon.txt" "$_RH/id_0002.txt" "$_RFIX/beacon.txt" "$_RH/id_0002.txt" "$_RH/empty_id.txt")"
assert_eq "$(_rf "$_o" forms)/$(_rf "$_o" id_hex)/$(_rf "$_o" id2_hex)" "1/$_serial1/$_serial2" rid_h_kept_ids_again_no_flag
_hpar kept_ids_again "$_RFIX/beacon.txt" "$_RH/id_0002.txt" "$_RFIX/beacon.txt" "$_RH/id_0002.txt" "$_RH/empty_id.txt"
unset _own _n
unset _RH _bD _hbad _hfr _hun; unset -f _hd _hdb _bad _good _hpar

# the decoder runs the same on BusyBox awk (the Pager) as on this box's awk
if command -v busybox >/dev/null 2>&1; then
  for _f in beacon nan parrot multi unknowns equator order quiet truncated badlink full emptyserial; do
    assert_eq "$(busybox awk -v max=32 "$(_sw_rid_awk_src)" < "$_RFIX/$_f.txt")" "$(_dec "$_f")" "rid_busybox_parity_$_f"
  done
  # ...and on every crafted frame, each alone (the tests above also decode them in their combinations)
  _k=0
  for _f in "$_RFIX"/hostile/*.txt; do
    assert_eq "$(busybox awk -v max=32 "$(_sw_rid_awk_src)" < "$_f")" "$(_sw_rid_decode_awk < "$_f")" "rid_busybox_parity_hostile_$(basename "$_f" .txt)"
    _k=$(( _k + 1 ))
  done
  # control: the loop saw every crafted frame (56 committed), so its passes are not vacuous
  assert_eq "$_k" "56" rid_busybox_parity_hostile_count
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
# spaces trimmed at both ends AFTER the cleaning, so a control byte cannot shield one
sw_rid_text 20414220;     assert_eq "$REPLY" "AB" rid_fmt_text_trimmed_both_ends
sw_rid_text 41422001;     assert_eq "$REPLY" "AB" rid_fmt_text_trimmed_after_cleaning

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
# an ID of a space and a control byte is no ID: the drone is known by its address, on screen, in the ledger and
# on the ignore list alike (and a blank serial gives way to a CAA ID)
_det="$(sw_test_rid_line id_hex=2001 | _recs)"
assert_contains "$_det" "|80:E1:26:AA:BB:CC||-47|" rid_rec_blank_id_is_no_id
assert_contains "$(_csv1)" ',-47,,"",' rid_csv_blank_id_is_no_id
assert_empty "$(sw_test_rid_line id_hex=2001 | SW_IGNORE_SET=" DRONE:80:E1:26:AA:BB:CC " _recs)" rid_rec_blank_id_ignored_by_address
assert_contains "$(sw_test_rid_line id_type=1 id_hex=2001 id2_type=2 id2_hex=434141 | _recs)" "|CAA|" rid_rec_blank_serial_gives_way
# ...also from frames: the decoder keeps a blank ID (it has bytes; only an empty one takes no place), so this rule
# is bash's: hostile/blank_id (a serial of a space and a control byte) then hostile/caa_id (the reference ID as a
# CAA registration) from one address are named by the CAA ID
_det="$(cat "$_RFIX/hostile/blank_id.txt" "$_RFIX/hostile/caa_id.txt" | _sw_rid_decode_awk | _recs)"
assert_contains "$_det" "|80:E1:26:AA:BB:CC|0000FSWTEST000000001|-47|" rid_rec_blank_serial_gives_way_from_frames
assert_contains "$(_csv1)" ',-47,caa,"0000FSWTEST000000001",,"",' rid_csv_blank_serial_gives_way_from_frames
# airframe "none" (ua_type 0) is a declared value: "none" in remoteid.csv and nothing on screen; no Basic ID at
# all leaves the cell empty (spec §6.5)
_det="$(sw_test_rid_line ua_type=0 | _recs)"
assert_contains "$_det" "|-47|	87m up" rid_rec_airframe_none_not_shown
assert_contains "$(_csv1)" ',"",none,airborne,' rid_csv_airframe_none
sw_test_rid_line ua_type= | _recs >/dev/null
assert_contains "$(_csv1)" ',"",,airborne,' rid_csv_airframe_unknown_empty
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
#   printf and shell syntax stay plain text all the way (nothing expands them); a byte that is not UTF-8 is
#   kept as it came; a C1 control (NEL, c2 85) is removed, like any control byte (spec §7.4)
_det="$(sw_test_rid_line id_hex=2573 | _recs)"
assert_contains "$_det" "|%s|" rid_rec_printf_id_plain
assert_contains "$(_csv1)" ',serial,"%s",' rid_csv_printf_id_plain
assert_contains "$(sw_test_rid_line id_hex=2428782960786060 | _recs)" '|$(x)`x``|' rid_rec_shell_id_plain
assert_contains "$(sw_test_rid_line id_hex=41ff42 | _recs)" $'|A\xffB|' rid_rec_non_utf8_id_kept
assert_contains "$(sw_test_rid_line id_hex=41c28542 | _recs)" "|AB|" rid_rec_c1_control_removed
# malformed lines are dropped: a leading zero (bash would read it as octal), a bad address, a field missing
assert_empty "$(sw_test_rid_line lat=0473977600 | _recs)" rid_rec_leading_zero_dropped
assert_empty "$(sw_test_rid_line mac=80e126aabbcz | _recs)" rid_rec_bad_mac_dropped
assert_empty "$(sw_test_rid_line | cut -f1-24 | _recs)" rid_rec_short_line_dropped
# a | inside the last field (the decoder never writes one) splits off an extra field: the line is dropped
assert_empty "$(sw_test_rid_line self_id='61|62' | _recs)" rid_rec_extra_field_dropped
assert_contains "$(sw_test_rid_line self_id=6162 | _recs)" "drone_rid|" rid_rec_extra_field_control
# control: the same helper, unbroken, does produce a detection (the drops above are the checks, not the helper)
assert_contains "$(sw_test_rid_line | _recs)" "drone_rid|" rid_rec_control_valid_line
# a frame whose network name posed as a signal still makes a drone (the decoder drops the made-up signal; here
# the reference beacon after it with its name "1000dBm signal", as the decoder now prints it)
assert_contains "$(cat "$_RFIX/hostile/sig_name_1000.txt" | _sw_rid_decode_awk | _recs)" "|80:E1:26:AA:BB:CC|0000FSWTEST000000001||" rid_rec_name_posing_as_signal_reported
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
# of the owner's ID from another drone's address, and must not hide that drone with it. When one of its two IDs is
# listed and the other is not, it is named by the one that is NOT (the user's second decision that day): in its
# detection (so on screen, in the alert and in its ledger key) and as the ID in remoteid.csv, the listed one second
_ign=" DRONE:0000FSWTEST000000001 "
rm -f "$_rl/remoteid.csv"
assert_contains "$(sw_test_rid_line id2_type=2 id2_hex=434141 | SW_IGNORE_SET="$_ign" _recs)" "|80:E1:26:AA:BB:CC|CAA|-47|" rid_rec_shown_id_listed_other_not_reported
assert_contains "$(_csv1)" ',-47,caa,"CAA",serial,"0000FSWTEST000000001",' rid_rec_shown_id_listed_row_has_both
assert_contains "$(sw_test_rid_line id_type=2 id_hex=434141 id2_type=1 id2_hex=3030303046535754455354303030303030303031 | SW_IGNORE_SET="$_ign" _recs)" "|80:E1:26:AA:BB:CC|CAA|-47|" rid_rec_serial_listed_caa_not_reported
# control: the serial keeps the name while it is the one not listed (and with neither listed: rid_rec_prefers_serial)
assert_contains "$(sw_test_rid_line id2_type=2 id2_hex=434141 | SW_IGNORE_SET=" DRONE:CAA " _recs)" "|80:E1:26:AA:BB:CC|0000FSWTEST000000001|-47|" rid_rec_unlisted_serial_keeps_the_name
# control: with both listed it is silenced
assert_empty "$(sw_test_rid_line id2_type=2 id2_hex=434141 | SW_IGNORE_SET="$_ign DRONE:CAA " _recs)" rid_rec_both_ids_listed_silenced
# A drone whose address sent more IDs than the decoder keeps (forms bit 8) is NEVER silenced (user decision
# 2026-10-02): a spoofer heard first can fill both kept IDs with copies of the owner's, and the other drone's own
# ID is then the one not kept. Its detail says "also sends other IDs", first in the motion piece, which is on the
# screen line and in the alert body. The same lines without the flag are silenced (the controls:
# rid_rec_ignored_no_detection, rid_rec_both_ids_listed_silenced, rid_rec_blank_id_ignored_by_address).
rm -f "$_rl/remoteid.csv"
assert_eq "$(sw_test_rid_line forms=9 | SW_IGNORE_SET="$_ign" _recs)" "drone_rid|Drone|high|surveillance|wifi|80:E1:26:AA:BB:CC|0000FSWTEST000000001|-47|multirotor	also sends other IDs, 87m up, 12m/s	pilot (live) 47.39800,8.54102" rid_rec_more_ids_never_silenced
assert_contains "$(_csv1)" '1700000000,beacon,80:E1:26:AA:BB:CC,-47,serial,"0000FSWTEST000000001",,"",' rid_csv_more_ids_row
# ...with both IDs listed: named serial first, as when neither is (the note tells the owner it is not theirs)
assert_contains "$(sw_test_rid_line forms=9 id_type=2 id_hex=434141 id2_type=1 id2_hex=3030303046535754455354303030303030303031 | SW_IGNORE_SET="$_ign DRONE:CAA " _recs)" "|80:E1:26:AA:BB:CC|0000FSWTEST000000001|-47|multirotor	also sends other IDs, " rid_rec_more_ids_both_listed_reported
# ...with one of the two listed, named by the other, as an unflagged drone is (re-review 2026-10-02, Minor 2: in an
# attack the real drone is heard first half the time, and its own ID then sits beside the owner's)
assert_contains "$(sw_test_rid_line forms=9 id2_type=2 id2_hex=434141 | SW_IGNORE_SET="$_ign" _recs)" "|80:E1:26:AA:BB:CC|CAA|-47|multirotor	also sends other IDs, " rid_rec_more_ids_one_listed_named_by_the_other
# ...and with no ID, not by its address either
assert_contains "$(sw_test_rid_line forms=9 id_type= id_hex= | SW_IGNORE_SET=" DRONE:80:E1:26:AA:BB:CC " _recs)" "|80:E1:26:AA:BB:CC||-47|multirotor	also sends other IDs, " rid_rec_more_ids_no_id_not_silenced_by_address
# the note alone when no motion value is known; the flag is no form, so remoteid.csv names only the forms (1 + 2)
assert_contains "$(sw_test_rid_line forms=11 height= alt_geo= speed= | _recs)" "|multirotor	also sends other IDs	pilot (live) " rid_rec_more_ids_note_alone
assert_contains "$(_csv1)" ',beacon+nan,80:E1:26:AA:BB:CC,' rid_csv_more_ids_not_a_form
# no flag, no note (every form bit set)
assert_empty "$(sw_test_rid_line forms=7 | _recs | grep -F 'other IDs')" rid_rec_no_flag_no_note
# the shape gate takes forms 1 to 15 (three form bits and the flag) and drops anything else, 8 too: the flag with
# no form, which the decoder cannot write, since every address it reports was heard in some form (re-review
# 2026-10-02, Minor 4). Controls: 7 and 9 on either side are taken (rid_csv_all_forms, rid_rec_more_ids_*).
assert_contains "$(sw_test_rid_line forms=15 | _recs)" "|0000FSWTEST000000001|" rid_rec_forms_15_taken
assert_empty "$(sw_test_rid_line forms=16 | _recs)" rid_rec_forms_16_dropped
assert_empty "$(sw_test_rid_line forms=0 | _recs)" rid_rec_forms_0_dropped
assert_empty "$(sw_test_rid_line forms=8 | _recs)" rid_rec_forms_8_dropped
unset _ign

# The per-lap drone cap (SW_RID_MAX_DRONES) chooses LAST the addresses that the ignore list may silence (re-review
# 2026-10-02, Important 1: 32 copies of the owner's ID, each from its own louder address, took all 32 places and
# were then silenced, so the real drone got no alert and no row; user decision the same day: "rank, never
# silence"). Bash hands the decoder the list's drone: lines as keys, their ASCII letters and digits in upper case
# (_sw_rid_keys). An address MAY be silenced when it is not flagged and every kept ID that bash would name the drone
# by (all but one that cleans to nothing) has its key listed, or, with no such ID, its own address is listed: what
# sw_rid_records silences, and besides only near misses (bash compares the whole cleaned ID). Within each group the
# strongest signal comes first, as before. The ranking only orders the lines: every line kept is printed, and only
# sw_rid_records silences.
# The keys: drone: lines only (no plain address, no evil_twin: line), letters and digits in upper case, each after a
# ":" (a line with neither is ":" alone)
SW_IGNORE_SET=" 80:E1:26:AA:BB:CC DRONE:0000FSWTESTOWNER001 EVIL_TWIN:02:11:22:33:44:66 DRONE:80:E1:26:11:22:33 DRONE:-- DRONE:ab-c1 DRONE:A"$'\xff'"B " _sw_rid_keys
assert_eq "$REPLY" " :0000FSWTESTOWNER001 :80E126112233 : :ABC1 :AB " rid_keys_drone_lines_only
SW_IGNORE_SET=" 80:E1:26:AA:BB:CC EVIL_TWIN:02:11:22:33:44:66 " _sw_rid_keys
assert_eq "$REPLY" " " rid_keys_no_drone_line
SW_IGNORE_SET= _sw_rid_keys
assert_eq "$REPLY" " " rid_keys_empty_list
# sw_test_rid_at (test/helpers/rid.sh) sends a fixture's frame from another address at another signal, a text edit.
# Controls: given the frame's own address and signal it prints the committed file unchanged; an edit reaches the
# decoder (address and signal) and the radiotap byte, while the ID stays the frame's; another layout is refused.
assert_eq "$(sw_test_rid_at "$_RFIX/hostile/owner_id.txt" 80e126aabbcc -47)" "$(cat "$_RFIX/hostile/owner_id.txt")" rid_at_control_identity
assert_eq "$(sw_test_rid_at "$_RFIX/hostile/owner_id.txt" 02aabbcc0001 -20 | _sw_rid_decode_awk | grep '^D' | cut -f2-6)" "02aabbcc0001	-20	1	1	30303030465357544553544f574e4552303031" rid_at_control_moves_the_frame
assert_contains "$(sw_test_rid_at "$_RFIX/hostile/owner_id.txt" 02aabbcc0001 -20)" $'\t0x0000:  0000 0900 2000 0000 ec80 ' rid_at_control_radiotap_signal
assert_eq "$(sw_test_rid_at "$_RFIX/nan.txt" 02aabbcc0001 -20 2>/dev/null; echo "rc=$?")" "rc=1" rid_at_refuses_another_layout
# sw_test_rid_id (the same file) writes another ID into a frame, a text edit. Controls: given the frame's own ID it
# prints the committed file unchanged; a new ID reaches the decoder; another layout, half a byte or more than 20
# bytes are refused
assert_eq "$(sw_test_rid_id "$_RFIX/beacon.txt" 3030303046535754455354303030303030303031)" "$(cat "$_RFIX/beacon.txt")" rid_id_control_identity
assert_eq "$(sw_test_rid_id "$_RFIX/beacon.txt" d094d0a0d09ed09d | _sw_rid_decode_awk | grep '^D' | cut -f2,6)" "80e126aabbcc	d094d0a0d09ed09d" rid_id_control_writes_the_id
assert_eq "$(sw_test_rid_id "$_RFIX/nan.txt" 41 2>/dev/null; echo "rc=$?")" "rc=1" rid_id_refuses_another_layout
assert_eq "$(sw_test_rid_id "$_RFIX/beacon.txt" 414 2>/dev/null; echo "rc=$?")/$(sw_test_rid_id "$_RFIX/beacon.txt" 414141414141414141414141414141414141414141 2>/dev/null; echo "rc=$?")" "rc=1/rc=1" rid_id_refuses_half_a_byte_or_too_long
# _rank IGNORE CAP: decodes $_hf on this box's awk and on BusyBox awk (the Pager's), under ignore list IGNORE and
# drone cap CAP -> REPLY = the addresses of its drone lines in order, then "/" and its more_drones count; _rb is 1
# when the two awks printed the same, byte for byte
_hf="$(mktemp)"; _oign=" DRONE:0000FSWTESTOWNER001 "
_rank() { local o b
  o="$(SW_IGNORE_SET="$1" SW_RID_MAX_DRONES="$2" _sw_rid_decode_awk < "$_hf")"
  SW_IGNORE_SET="$1" _sw_rid_keys
  b="$(busybox awk -v max="$2" -v ignkeys="$REPLY" "$(_sw_rid_awk_src)" < "$_hf")"
  _rb=0; [ "$b" = "$o" ] && _rb=1
  REPLY="$(printf '%s\n' "$o" | awk -F'\t' '$1 == "D" { printf "%s ", $2 } $1 == "S" { printf "/%s", $5 }')"; }
# _rrec IGNORE: the decoder over $_hf under IGNORE with room for every drone, then sw_rid_records under IGNORE ->
# the address and ID of each drone it reports, one per line
_rrec() { SW_IGNORE_SET="$1" SW_RID_MAX_DRONES=0 _sw_rid_decode_awk < "$_hf" | SW_IGNORE_SET="$1" _recs | cut -d'|' -f6-7; }
# 1. a copy of the owner's ID from a louder address, then the real drone: nothing listed, the stronger first, as
#    before; the owner listed, the copy last (cap 1: the real drone kept; cap 2: both, the copy second; no cap: as
#    heard). sw_rid_records still decides: it silences the copy and reports the real drone.
{ sw_test_rid_at "$_RFIX/hostile/owner_id.txt" 02aabbcc0001 -20; cat "$_RFIX/beacon.txt"; } > "$_hf"
_rank "" 1;       assert_eq "$REPLY|$_rb" "02aabbcc0001 /1|1" rid_rank_control_strongest_first
_rank "$_oign" 1; assert_eq "$REPLY|$_rb" "80e126aabbcc /1|1" rid_rank_listed_copy_last
_rank "$_oign" 2; assert_eq "$REPLY|$_rb" "80e126aabbcc 02aabbcc0001 /0|1" rid_rank_only_orders
_rank "$_oign" 0; assert_eq "$REPLY|$_rb" "02aabbcc0001 80e126aabbcc /0|1" rid_rank_no_cap_as_heard
assert_eq "$(_rrec "$_oign")" "80:E1:26:AA:BB:CC|0000FSWTEST000000001" rid_rank_copy_still_silenced_by_bash
# 2. a near miss: the owner's ID with a dash (hostile/owner_dash.txt: owner_id 0x48-0x5b "0000-FSWTESTOWNER001") has
#    the owner's key, so it is ranked with the listed ones, but it is not listed (bash compares the whole ID): it is
#    REPORTED whenever it is kept
{ sw_test_rid_at "$_RFIX/hostile/owner_dash.txt" 02aabbcc0001 -20; cat "$_RFIX/beacon.txt"; } > "$_hf"
_rank "$_oign" 1;  assert_eq "$REPLY|$_rb" "80e126aabbcc /1|1" rid_rank_near_miss_last
_rank "$_oign" 32; assert_eq "$REPLY|$_rb" "80e126aabbcc 02aabbcc0001 /0|1" rid_rank_near_miss_kept_within_the_cap
_det="$(SW_IGNORE_SET="$_oign" SW_RID_MAX_DRONES=32 _sw_rid_decode_awk < "$_hf" | SW_IGNORE_SET="$_oign" _recs)"
assert_contains "$_det" "|02:AA:BB:CC:00:01|0000-FSWTESTOWNER001|-20|" rid_rank_near_miss_reported
assert_contains "$_det" "|80:E1:26:AA:BB:CC|0000FSWTEST000000001|-47|" rid_rank_near_miss_real_drone_reported
# 3. a drone that sends no ID (hostile/empty_id.txt) whose address is listed as drone:<MAC> is ranked last too, and
#    silenced by bash; control: its address not listed (another drone's ID is), it keeps its place, the stronger
{ sw_test_rid_at "$_RFIX/hostile/empty_id.txt" 02aabbcc0002 -20; cat "$_RFIX/beacon.txt"; } > "$_hf"
_rank " DRONE:02:AA:BB:CC:00:02 " 1; assert_eq "$REPLY|$_rb" "80e126aabbcc /1|1" rid_rank_listed_address_last
_rank "$_oign" 1;                    assert_eq "$REPLY|$_rb" "02aabbcc0002 /1|1" rid_rank_unlisted_address_control
assert_eq "$(_rrec " DRONE:02:AA:BB:CC:00:02 ")" "80:E1:26:AA:BB:CC|0000FSWTEST000000001" rid_rank_listed_address_silenced_by_bash
# 4. a flagged address (forms bit 8) is never one the list may silence: here the real drone's, where a spoofer sent
#    the owner's ID as a serial and as a CAA registration first, beside a louder copy of the owner's ID elsewhere
{ sw_test_rid_at "$_RFIX/hostile/owner_id.txt" 02aabbcc0001 -20; cat "$_RFIX/hostile/owner_id.txt" "$_RFIX/hostile/owner_caa.txt" "$_RFIX/beacon.txt"; } > "$_hf"
_rank "$_oign" 1; assert_eq "$REPLY|$_rb" "80e126aabbcc /1|1" rid_rank_flagged_never_last
# 5. a kept ID with no letter or digit (hostile/blank_id.txt: a space and a control byte, which clean to nothing)
#    does not keep the owner's ID beside it from ranking the address last, in either order: bash names that drone
#    by the owner's ID alone and silences it
for _n in owner_id:blank_id blank_id:owner_id; do
  { sw_test_rid_at "$_RFIX/hostile/${_n%%:*}.txt" 02aabbcc0003 -20; sw_test_rid_at "$_RFIX/hostile/${_n#*:}.txt" 02aabbcc0003 -20; cat "$_RFIX/beacon.txt"; } > "$_hf"
  _rank "$_oign" 1; assert_eq "$REPLY|$_rb" "80e126aabbcc /1|1" "rid_rank_blank_beside_listed_last_[$_n]"
  assert_eq "$(_rrec "$_oign")" "80:E1:26:AA:BB:CC|0000FSWTEST000000001" "rid_rank_blank_beside_listed_silenced_by_bash_[$_n]"
done
# 6. a lower-case copy of the owner's ID (hostile/owner_lower.txt): bash compares it upper-cased, and so do the keys
{ sw_test_rid_at "$_RFIX/hostile/owner_lower.txt" 02aabbcc0005 -20; cat "$_RFIX/beacon.txt"; } > "$_hf"
_rank "$_oign" 1; assert_eq "$REPLY|$_rb" "80e126aabbcc /1|1" rid_rank_lower_case_copy_last
assert_eq "$(_rrec "$_oign")" "80:E1:26:AA:BB:CC|0000FSWTEST000000001" rid_rank_lower_case_copy_silenced_by_bash
# 7. an ID with no letter or digit at all (hostile/dash_id.txt: empty_id 0x48-0x49 2d2d, the ID "--") listed as
#    drone:-- (a key of ""): bash silences it, so it is ranked last; control: not listed, it keeps its place
{ sw_test_rid_at "$_RFIX/hostile/dash_id.txt" 02aabbcc0004 -20; cat "$_RFIX/beacon.txt"; } > "$_hf"
_rank " DRONE:-- " 1; assert_eq "$REPLY|$_rb" "80e126aabbcc /1|1" rid_rank_listed_punctuation_id_last
_rank "$_oign" 1;     assert_eq "$REPLY|$_rb" "02aabbcc0004 /1|1" rid_rank_unlisted_punctuation_id_control
assert_eq "$(_rrec " DRONE:-- ")" "80:E1:26:AA:BB:CC|0000FSWTEST000000001" rid_rank_listed_punctuation_id_silenced_by_bash
# 8. the re-review's input at the default cap: 32 copies of the owner's ID (02:aa:bb:cc:00:01 to :20, -20 dBm), then
#    the real drone, which is kept, first (the full lap: payload_test.sh)
{ for (( _i = 1; _i <= 32; _i++ )); do printf -v _n %02x "$_i"; sw_test_rid_at "$_RFIX/hostile/owner_id.txt" "02aabbcc00$_n" -20; done; cat "$_RFIX/beacon.txt"; } > "$_hf"
_rank "$_oign" 32; assert_eq "${REPLY%% *}|${REPLY##*/}|$_rb" "80e126aabbcc|1|1" rid_rank_32_copies_real_drone_kept
# 9. An ID with no ASCII letter or digit (adversarial review 2026-10-02): bash skips it only when it cleans to
#    nothing (sw_sanitize_ident, then the spaces at both ends); any other it names the drone by, as it would a
#    binary UTM UUID, a punctuation-only or a non-Latin ID. So the owner's ID sent from a drone's address does not
#    make that drone one the list may silence, unless its other ID cleans to nothing. Each X below goes with the
#    owner's ID from one louder address (02:aa:bb:cc:00:07; X written into the reference beacon by sw_test_rid_id,
#    a text edit), then the real drone, at cap 1. The decoder ranks that address last exactly when sw_rid_records
#    silences it (b: X cleans to nothing) and not when bash reports it under X (n). b: a space and a C0 control,
#    DEL, "|", the C1 controls NEL and APC, U+2028, U+2029, NEL between spaces, NEL split by a C0 control, U+2028
#    split by a C1 control. n: "--", a lone c2, a lone 85, NBSP, c2 a8 (no C1 control), an unfinished U+2028,
#    U+202A, "ДРОН", ff, binary UUID bytes.
for _x in b:2001 b:7f b:7c b:c285 b:c29f b:e280a8 b:e280a9 b:20c28520 b:c20185 b:e2c28080a8 \
          n:2d2d n:c2 n:85 n:c2a0 n:c2a8 n:e280 n:e280aa n:d094d0a0d09ed09d n:ff n:8f12a3c4e5079b212e3f8091a2b3c4d5; do
  { sw_test_rid_at "$_RFIX/hostile/owner_id.txt" 02aabbcc0007 -20
    sw_test_rid_at <(sw_test_rid_id "$_RFIX/beacon.txt" "${_x#*:}") 02aabbcc0007 -20; cat "$_RFIX/beacon.txt"; } > "$_hf"
  _rank "$_oign" 1
  if [ "${_x%%:*}" = b ]; then
    assert_eq "$REPLY|$_rb" "80e126aabbcc /1|1" "rid_rank_no_letter_id_cleans_to_nothing_last_[${_x#*:}]"
    assert_eq "$(_rrec "$_oign")" "80:E1:26:AA:BB:CC|0000FSWTEST000000001" "rid_rank_no_letter_id_cleans_to_nothing_silenced_by_bash_[${_x#*:}]"
  else
    assert_eq "$REPLY|$_rb" "02aabbcc0007 /1|1" "rid_rank_no_letter_id_named_not_last_[${_x#*:}]"
    assert_contains "$(_rrec "$_oign")" "02:AA:BB:CC:00:07|" "rid_rank_no_letter_id_named_reported_by_bash_[${_x#*:}]"
  fi
done
#    ...and with X heard first, then the owner's ID (each of the two kept IDs is checked on its own)
for _x in b:2001 b:c285 n:2d2d n:d094d0a0d09ed09d; do
  { sw_test_rid_at <(sw_test_rid_id "$_RFIX/beacon.txt" "${_x#*:}") 02aabbcc0007 -20
    sw_test_rid_at "$_RFIX/hostile/owner_id.txt" 02aabbcc0007 -20; cat "$_RFIX/beacon.txt"; } > "$_hf"
  _rank "$_oign" 1
  if [ "${_x%%:*}" = b ]; then
    assert_eq "$REPLY|$_rb" "80e126aabbcc /1|1" "rid_rank_no_letter_id_first_cleans_to_nothing_last_[${_x#*:}]"
    assert_eq "$(_rrec "$_oign")" "80:E1:26:AA:BB:CC|0000FSWTEST000000001" "rid_rank_no_letter_id_first_cleans_to_nothing_silenced_by_bash_[${_x#*:}]"
  else
    assert_eq "$REPLY|$_rb" "02aabbcc0007 /1|1" "rid_rank_no_letter_id_first_named_not_last_[${_x#*:}]"
    assert_contains "$(_rrec "$_oign")" "02:AA:BB:CC:00:07|" "rid_rank_no_letter_id_first_named_reported_by_bash_[${_x#*:}]"
  fi
done
# 10. A key of "" (a listed ID with no letter or digit, drone:--) does not rank last an address that bash knows by no
#     ID: one that sent none (hostile/empty_id.txt) or only a blank one (hostile/blank_id.txt), which only drone:<MAC>
#     silences. Here such a drone beside a louder copy of the owner's ID, at cap 1: it keeps its place.
for _n in empty_id blank_id; do
  { sw_test_rid_at "$_RFIX/hostile/owner_id.txt" 02aabbcc0001 -20; sw_test_rid_at "$_RFIX/hostile/$_n.txt" 02aabbcc0002 -30; } > "$_hf"
  _rank "$_oign DRONE:-- " 1; assert_eq "$REPLY|$_rb" "02aabbcc0002 /1|1" "rid_rank_listed_no_letter_key_no_id_not_last_[$_n]"
done
# 11. The keys (adversarial review 2026-10-02): a bare drone: line silences nothing (sw_ignored never matches it), so
#     it gives no key; only ASCII letters and digits count, whatever the caller's locale (the Pager's is UTF-8, where
#     upper-casing turns dotless ı and long ſ into I and S, and en_US's ranges keep them); words split on any space,
#     tab or line break, and nothing is expanded
SW_IGNORE_SET=" DRONE: DRONE:0000FSWTESTOWNER001 " _sw_rid_keys
assert_eq "$REPLY" " :0000FSWTESTOWNER001 " rid_keys_bare_drone_line_no_key
#     ...also in a caller that ends on the first failing command (set -e): reading the list stops at its end with
#     status 1, which must not end that shell (adversarial re-review 2026-10-02)
assert_eq "$(set -e; SW_IGNORE_SET=" DRONE:A " _sw_rid_keys; echo "survived$REPLY")" "survived :A " rid_keys_survive_errexit
for _l in C.UTF-8 en_US.UTF-8; do
  LC_ALL="$_l" SW_IGNORE_SET=" DRONE:ı1 DRONE:ſX DRONE:É2 DRONE:A	DRONE:B
DRONE:* " _sw_rid_keys 2>/dev/null
  assert_eq "$REPLY" " :1 :X :2 :A :B : " "rid_keys_ascii_only_[$_l]"
done
# 12. ...and sw_rid_records compares in the C locale too, whatever the caller's: in a UTF-8 one, upper-casing would
#     make a lookalike of the owner's ID ("0000FſWTESTOWNER001", a long s for the S) the owner's ID and silence it,
#     while its key ("0000FWTESTOWNER001") is not listed, so the drone cap would not rank it last. Byte for byte it
#     is another ID: it is reported. (Control: in C.UTF-8 the shell does upper-case ſ to S.)
assert_eq "$(LC_ALL=C.UTF-8 bash -c 'w=ſı; printf %s "${w^^}"' 2>&1)" "SI" rid_utf8_locale_control
assert_contains "$(sw_test_rid_line id_hex=3030303046c5bf57544553544f574e4552303031 | LC_ALL=C.UTF-8 SW_IGNORE_SET="$_oign" _recs 2>/dev/null)" "|80:E1:26:AA:BB:CC|0000FſWTESTOWNER001|-47|" rid_rec_lookalike_of_listed_id_reported
rm -f "$_hf"; unset _hf _oign _rb _n _i _x _l; unset -f _rank _rrec
# a stopped payload writes and reports nothing
bash -c 'exit 0' & _rd=$!; wait "$_rd"
rm -f "$_rl/remoteid.csv"
assert_empty "$(sw_test_rid_line | SW_MAIN_PID="$_rd" _recs)" rid_rec_stopped_no_detection
assert_eq "$([ -e "$_rl/remoteid.csv" ] && echo written)" "" rid_rec_stopped_no_csv
# A Stop while the lap reads the GPS (the first drone's row records the Pager's own fix; on the device a gpsd
# query) drops that drone's row and detection too (spec §7.3). The GPS_GET stub kills the stand-in main shell
# during the read.
sleep 30 & _fm=$!
rm -f "$_rl/remoteid.csv"; : > "$SW_STUB_LOG"
_det="$(sw_test_rid_line | SW_MAIN_PID="$_fm" SW_STUB_STOP_ON_GPS="$_fm" _recs)"
wait "$_fm" 2>/dev/null
assert_contains "$(cat "$SW_STUB_LOG")" "GPS_GET" rid_rec_stop_in_gps_control_gps_read
assert_empty "$_det" rid_rec_stop_in_gps_no_detection
assert_eq "$([ -e "$_rl/remoteid.csv" ] && echo written)" "" rid_rec_stop_in_gps_no_csv
unset _fm
rm -rf "$_rl"; unset _rl _det _rd; unset -f _recs _csv1 sw_test_rid_line sw_test_rid_at

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
# the stub words its summary as tcpdump 4.99 does ("%u packet%s ..."): the singular for exactly one only. Its
# "received by filter" is captured + dropped unless set, as in a normal window (Phase 0 on the Pager saw 0 to 2 more)
_sum() { "$@" 2>&1 >/dev/null | grep -E ' (captured|received by filter|dropped by kernel)$'; }
assert_eq "$(SW_FAKE_TCPDUMP="$_RFIX/beacon.txt" _sum tcpdump -i wlan1mon -c 1)" $'1 packet captured\n1 packet received by filter\n0 packets dropped by kernel' tcpdump_stub_one_packet
assert_eq "$(SW_FAKE_TCPDUMP="$_RFIX/multi.txt" _sum tcpdump -i wlan1mon -c 2)" $'2 packets captured\n2 packets received by filter\n0 packets dropped by kernel' tcpdump_stub_two_packets
assert_eq "$(SW_FAKE_TCPDUMP="$_RFIX/beacon.txt" SW_FAKE_TCPDUMP_CAPTURED=0 _sum tcpdump -i wlan1mon -c 1)" $'0 packets captured\n0 packets received by filter\n0 packets dropped by kernel' tcpdump_stub_zero_packets
assert_eq "$(SW_FAKE_TCPDUMP="$_RFIX/beacon.txt" SW_FAKE_TCPDUMP_DROPPED=1 _sum tcpdump -i wlan1mon -c 1)" $'1 packet captured\n2 packets received by filter\n1 packet dropped by kernel' tcpdump_stub_one_dropped
assert_eq "$(SW_FAKE_TCPDUMP="$_RFIX/beacon.txt" SW_FAKE_TCPDUMP_DROPPED=7 _sum tcpdump -i wlan1mon -c 1)" $'1 packet captured\n8 packets received by filter\n7 packets dropped by kernel' tcpdump_stub_seven_dropped
# ...and a "received by filter" of its own, the other two lines unchanged (control: tcpdump_stub_one_packet)
assert_eq "$(SW_FAKE_TCPDUMP="$_RFIX/beacon.txt" SW_FAKE_TCPDUMP_RECEIVED=9 _sum tcpdump -i wlan1mon -c 1)" $'1 packet captured\n9 packets received by filter\n0 packets dropped by kernel' tcpdump_stub_received
# ...and, stuck writing to the decoder at the TERM (Phase 0 on the Pager), no summary: only the write error, after
# the frames it printed (control: tcpdump_stub_one_packet, the same capture with its summary)
assert_empty "$(SW_FAKE_TCPDUMP="$_RFIX/beacon.txt" SW_FAKE_TCPDUMP_NOSUMMARY=1 _sum tcpdump -i wlan1mon -c 1)" tcpdump_stub_no_summary
assert_contains "$(SW_FAKE_TCPDUMP="$_RFIX/beacon.txt" SW_FAKE_TCPDUMP_NOSUMMARY=1 tcpdump -i wlan1mon -c 1 2>&1 >/dev/null)" "tcpdump: Unable to write output: Interrupted system call" tcpdump_stub_no_summary_says_why
assert_contains "$(SW_FAKE_TCPDUMP="$_RFIX/beacon.txt" SW_FAKE_TCPDUMP_NOSUMMARY=1 tcpdump -i wlan1mon -c 1 2>/dev/null)" "-47dBm signal Beacon (TEST-DRONE)" tcpdump_stub_no_summary_frames_printed
# ...a summary cut short, as a KILL between its lines leaves it (tcpdump writes them one by one): only the first line,
# or the first two (control: tcpdump_stub_one_packet, all three)
assert_eq "$(SW_FAKE_TCPDUMP="$_RFIX/beacon.txt" SW_FAKE_TCPDUMP_SUMMARY_CUT=1 _sum tcpdump -i wlan1mon -c 1)" '1 packet captured' tcpdump_stub_summary_cut_1
assert_eq "$(SW_FAKE_TCPDUMP="$_RFIX/beacon.txt" SW_FAKE_TCPDUMP_SUMMARY_CUT=2 _sum tcpdump -i wlan1mon -c 1)" $'1 packet captured\n1 packet received by filter' tcpdump_stub_summary_cut_2
# ...and a capture that ends on an error by itself, before any TERM: tcpdump 4.99 prints "tcpdump: pcap_loop:" and the
# error, then its summary, and exits 1. The frames, the error, the summary; and below its -c limit it does not wait
# for a TERM. (controls: tcpdump_stub_one_packet, the summary alone; the same capture's exit status without the
# error, 0 at its -c limit)
assert_eq "$(SW_FAKE_TCPDUMP="$_RFIX/beacon.txt" SW_FAKE_TCPDUMP_LOOPERR=1 tcpdump -i wlan1mon -c 1 2>&1 >/dev/null | grep -E 'pcap_loop|captured$|received by filter$|dropped by kernel$')" $'tcpdump: pcap_loop: The interface went down\n1 packet captured\n1 packet received by filter\n0 packets dropped by kernel' tcpdump_stub_loop_error_then_summary
assert_contains "$(SW_FAKE_TCPDUMP="$_RFIX/beacon.txt" SW_FAKE_TCPDUMP_LOOPERR=1 tcpdump -i wlan1mon -c 1 2>/dev/null)" "-47dBm signal Beacon (TEST-DRONE)" tcpdump_stub_loop_error_frames_printed
assert_eq "$(SW_FAKE_TCPDUMP="$_RFIX/beacon.txt" SW_FAKE_TCPDUMP_LOOPERR=1 tcpdump -i wlan1mon -c 1 >/dev/null 2>&1; echo "$?")/$(SW_FAKE_TCPDUMP="$_RFIX/beacon.txt" tcpdump -i wlan1mon -c 1 >/dev/null 2>&1; echo "$?")" "1/0" tcpdump_stub_loop_error_exit_status
assert_eq "$(SW_FAKE_TCPDUMP="$_RFIX/beacon.txt" SW_FAKE_TCPDUMP_LOOPERR=1 timeout 10 tcpdump -i wlan1mon -c 5 >/dev/null 2>&1; echo "$?")" "1" tcpdump_stub_loop_error_ends_by_itself
unset -f _sum

# a beacon capture: one drone detection and a remoteid.csv row; only the health state is left behind
_cap_reset; _out="$(_cap beacon)"
assert_contains "$_out" "drone_rid|Drone|high|surveillance|wifi|80:E1:26:AA:BB:CC|0000FSWTEST000000001|-47|" cap_beacon_detection
assert_contains "$(tail -1 "$_cap_loot/remoteid.csv")" "1700000000,beacon,80:E1:26:AA:BB:CC,-47,serial," cap_beacon_csv_row
assert_eq "$(_cap_state)" "ok" cap_beacon_status_ok
assert_empty "$(ls -A "$_cap_dir" | grep -v '^sw_rid\.state$')" cap_leaves_no_capture_files
# tcpdump ran read only (-p), on the configured interface, without clock times (-t), keeping only the first 1024
# bytes of each frame (-s 1024), with the frame cap (700 by default). Phase 0 on the Pager (2026-10-02): no beacon
# heard there came near 1024 bytes (the largest was 526), and a crafted 4 KB frame cut to 1024 costs the decoder about
# 8 times less. With the cheaper joining (spec 2026-10-08) an ordinary beacon costs the decoder about 6 ms and
# tcpdump about 2 ms, so 700 frames are about 5.7 s of CPU (measured on the Pager, 2026-10-09), what 300 cost before
assert_contains "$(grep '^tcpdump ' "$SW_STUB_LOG")" "tcpdump -i wlan1mon -p -l -t -nn -xx -s 1024 -c 700 type mgt subtype beacon or (wlan[0] & 0xfc = 0xd0 and wlan addr1 51:6f:9a:01:00:00)" cap_tcpdump_args
# ...on the interface SW_RID_IFACE names, not a fixed one
_cap_reset; _cap beacon SW_RID_IFACE=wlan7mon >/dev/null
assert_contains "$(grep '^tcpdump ' "$SW_STUB_LOG")" "tcpdump -i wlan7mon -p " cap_tcpdump_follows_the_setting

# an ordinary beacon only: no drone, no WARN, and the capture was judged healthy (it ran)
_cap_reset; _out="$(_cap quiet)"
assert_empty "$(printf '%s\n' "$_out" | grep '^drone_rid')" cap_quiet_no_drone
assert_eq "$(_cap_state)" "ok" cap_quiet_status_ok
assert_empty "$(grep -F 'WARN' "$SW_STUB_LOG")" cap_quiet_no_warn
# no frames at all (a place with no WiFi) is ok too: "listening on" proves the capture ran
_cap_reset; _cap "" >/dev/null
assert_eq "$(_cap_state)" "ok" cap_no_frames_is_ok
# A decoder that never finished (no stats line, which it prints last) is not understood, also in a lap with no
# frames, where tcpdump's summary cannot show it, and also when tcpdump printed no summary either, counted more
# frames received than it processed, or ended on an error (the OFF statuses come first, spec §7.2). The test swaps
# in a decoder that prints nothing. (controls: cap_no_frames_is_ok and cap_beacon_status_ok, the same captures with
# the real decoder)
for _fx in "" beacon; do
  for _kn in "" SW_FAKE_TCPDUMP_NOSUMMARY=1 SW_FAKE_TCPDUMP_RECEIVED=100 SW_FAKE_TCPDUMP_LOOPERR=1; do
    case "$_kn" in *NOSUMMARY*) _nm=", no summary" ;; *RECEIVED*) _nm=", 100 received" ;; *LOOPERR*) _nm=", pcap_loop error" ;; *) _nm="" ;; esac
    _cap_reset
    env SW_TMP_DIR="$_cap_dir" SW_REMOTE_ID=1 SW_RID_SECONDS=1 SW_FAKE_TCPDUMP="${_fx:+$_RFIX/$_fx.txt}" ${_kn:+"$_kn"} bash -c '
      source "$1/lib/match.sh"; source "$1/lib/wifi.sh"; source "$1/lib/log.sh"; source "$1/lib/ble.sh"; source "$1/lib/ignore.sh"; source "$1/lib/remoteid.sh"
      _sw_rid_awk_src() { echo "END { }"; }
      sw_rid_start 1700000000; sw_rid_collect 1700000000 "$2"' _ "$SW_ROOT" "$_cap_loot" >/dev/null
    assert_eq "$(_cap_state)" "not_understood" "cap_dead_decoder_not_understood_[${_fx:-no frames}$_nm]"
  done
done
unset _fx _kn _nm

# A capture that never starts. The recon radio's interface goes down for about half a second every 30 s (Phase 0
# on the Pager, 2026-10-02), and a capture that starts in that gap fails once (about 2% of laps), so one failed
# lap says nothing: the second in a row says OFF, once however long it lasts; then a green line once it works again.
_cap_reset; _cap beacon SW_FAKE_TCPDUMP_FAIL=1 >/dev/null
assert_empty "$(grep -F 'WiFi capture' "$SW_STUB_LOG")" cap_failed_once_silent
assert_contains "$(grep '^tcpdump ' "$SW_STUB_LOG")" "tcpdump -i wlan1mon" cap_failed_once_control_tried
_cap beacon SW_FAKE_TCPDUMP_FAIL=1 >/dev/null
assert_eq "$(_cap_state)" "capture_failed" cap_failed_status
assert_eq "$(grep -c 'WiFi capture failed' "$SW_STUB_LOG")" "1" cap_failed_warns
for _i in 3 4 5; do _cap beacon SW_FAKE_TCPDUMP_FAIL=1 >/dev/null; done
assert_eq "$(grep -c 'WiFi capture failed' "$SW_STUB_LOG")/$(grep -c '^tcpdump ' "$SW_STUB_LOG")" "1/5" cap_failed_warns_once
_cap beacon >/dev/null
assert_contains "$(cat "$SW_STUB_LOG")" "Remote ID capture recovered" cap_failed_then_recovered
# It takes two failed laps IN A ROW: failed, captured, failed, captured says nothing at all, not even "recovered",
# since no OFF line was shown. (controls: the four laps ran; cap_failed_warns, two failed laps back to back)
_cap_reset
_cap beacon SW_FAKE_TCPDUMP_FAIL=1 >/dev/null; _cap beacon >/dev/null; _cap beacon SW_FAKE_TCPDUMP_FAIL=1 >/dev/null; _cap beacon >/dev/null
assert_empty "$(grep -E 'WiFi capture|recovered' "$SW_STUB_LOG")" cap_failed_ok_failed_silent
assert_eq "$(grep -c '^tcpdump ' "$SW_STUB_LOG")" "4" cap_failed_ok_failed_control_four_laps
# A temp file that cannot be made is never the interface's half-second blink: a missing folder (SW_TMP_DIR) says OFF
# on the first lap, and on every lap while it lasts, since the state cannot be kept there either; tcpdump never runs.
# (controls: cap_failed_once_silent and cap_failed_warns, a capture that fails to start in a folder that works says
# nothing on the first lap and OFF on the second; cap_failed_once_control_tried, the stub logs its runs)
_cap_reset; _cap beacon SW_TMP_DIR="$_cap_dir/missing" >/dev/null 2>&1
assert_eq "$(grep -c 'WiFi capture failed — Remote ID over WiFi OFF' "$SW_STUB_LOG")/$(grep -c '^tcpdump ' "$SW_STUB_LOG")" "1/0" cap_no_temp_dir_warns_at_once
for _i in 2 3 4; do _cap beacon SW_TMP_DIR="$_cap_dir/missing" >/dev/null 2>&1; done
assert_eq "$(grep -c 'WiFi capture failed' "$SW_STUB_LOG")" "4" cap_no_temp_dir_warns_every_lap
# ...and the state it cannot keep there fails quietly: no shell error reaches the payload's output. (control: the same
# write with nothing to quiet it does print one)
_out="$(SW_TMP_DIR="$_cap_dir/missing" sw_rid_health_note capture_failed 1700000000 at_once 2>&1)"
assert_empty "$_out" cap_no_temp_dir_state_write_quiet
assert_contains "$( { printf x > "$_cap_dir/missing/sw_rid.state"; } 2>&1 )" "missing/sw_rid.state" cap_no_temp_dir_control_write_complains
# ...and so is the second temp file (tcpdump's messages) that cannot be made: OFF at once, the first file removed, no
# capture started. The test swaps in a mktemp that makes one file (and notes its name), fails every time after that,
# and counts its calls.
_mtlap() { env SW_TMP_DIR="$_cap_dir" SW_REMOTE_ID=1 SW_RID_SECONDS=1 SW_FAKE_TCPDUMP="$_RFIX/beacon.txt" bash -c '
  source "$1/lib/match.sh"; source "$1/lib/wifi.sh"; source "$1/lib/log.sh"; source "$1/lib/ble.sh"; source "$1/lib/ignore.sh"; source "$1/lib/remoteid.sh"
  m="$2/made"
  mktemp() { local f; printf "x\n" >> "$m.calls"; [ -e "$m" ] && return 1; f="$(command mktemp "$@")" || return 1; printf "%s\n" "$f" > "$m"; printf "%s\n" "$f"; }
  sw_rid_start 1700000000; sw_rid_collect 1700000000 "$3"' _ "$SW_ROOT" "$_cap_dir" "$_cap_loot" >/dev/null; }
_cap_reset; _mtlap
_mf="$(cat "$_cap_dir/made" 2>/dev/null)"
assert_eq "$(grep -c 'WiFi capture failed — Remote ID over WiFi OFF' "$SW_STUB_LOG")/$(grep -c '^tcpdump ' "$SW_STUB_LOG")" "1/0" cap_second_temp_file_warns_at_once
assert_contains "$_mf" "$_cap_dir/sw_rid." cap_second_temp_file_control_first_made
assert_eq "$([ -e "$_mf" ] && echo kept)" "" cap_second_temp_file_first_removed
# ...but once OFF, a next lap that cannot make its temp file either (here the first one; the state is kept, the folder
# works) says nothing more: one OFF line, not one a lap. (control: three mktemp calls, so the second lap did try)
_mtlap
assert_eq "$(grep -c 'WiFi capture failed' "$SW_STUB_LOG")/$(grep -c x "$_cap_dir/made.calls")" "1/3" cap_temp_file_fails_twice_off_once
rm -f "$_cap_dir/made" "$_cap_dir/made.calls"; unset _mf; unset -f _mtlap
# ...and so is a first temp file that cannot be made while the folder itself works, so the state is kept there (a
# mktemp that fails for want of inodes, say): OFF at once with the status kept, then nothing more while it lasts;
# tcpdump never runs. The missing folder above cannot tell this apart from a note that cannot be kept (below), which
# says OFF too. (controls: cap_failed_once_silent, a capture that fails to start in this folder says nothing on its
# first lap; the state file read back shows the note was kept, not lost)
_mflap() { env SW_TMP_DIR="$_cap_dir" SW_REMOTE_ID=1 SW_RID_SECONDS=1 SW_FAKE_TCPDUMP="$_RFIX/beacon.txt" bash -c '
  source "$1/lib/match.sh"; source "$1/lib/wifi.sh"; source "$1/lib/log.sh"; source "$1/lib/ble.sh"; source "$1/lib/ignore.sh"; source "$1/lib/remoteid.sh"
  mktemp() { return 1; }
  sw_rid_start 1700000000; sw_rid_collect 1700000000 "$2"' _ "$SW_ROOT" "$_cap_loot" >/dev/null; }
_cap_reset; _mflap
assert_eq "$(grep -c 'WiFi capture failed — Remote ID over WiFi OFF' "$SW_STUB_LOG")/$(grep -c '^tcpdump ' "$SW_STUB_LOG")/$(head -1 "$_cap_dir/sw_rid.state" 2>/dev/null)" "1/0/capture_failed" cap_first_temp_file_warns_at_once
_mflap
assert_eq "$(grep -c 'WiFi capture failed' "$SW_STUB_LOG")" "1" cap_first_temp_file_fails_twice_off_once
unset -f _mflap
# A state that cannot be kept (a /tmp already full at launch: mktemp still makes empty files there, but tcpdump's
# "listening on" cannot be written, so every lap fails to start, and the note of one failed lap is lost as well) says
# OFF at once, on every lap while it lasts. (controls: cap_failed_once_silent, the same failure with a state file
# that works says nothing on the first lap; the stub ran on every lap)
_cap_reset; _cap beacon SW_FAKE_TCPDUMP_FAIL=1 SW_RID_STATE_FILE="$_cap_dir/missing/sw_rid.state" >/dev/null 2>&1
assert_eq "$(grep -c 'WiFi capture failed — Remote ID over WiFi OFF' "$SW_STUB_LOG")/$(grep -c '^tcpdump ' "$SW_STUB_LOG")" "1/1" cap_unkept_note_warns_at_once
for _i in 2 3; do _cap beacon SW_FAKE_TCPDUMP_FAIL=1 SW_RID_STATE_FILE="$_cap_dir/missing/sw_rid.state" >/dev/null 2>&1; done
assert_eq "$(grep -c 'WiFi capture failed' "$SW_STUB_LOG")/$(grep -c '^tcpdump ' "$SW_STUB_LOG")" "3/3" cap_unkept_note_warns_every_lap

# a link type that is not 802.11 + radiotap: a WARN, and no drone from those bytes
# (control: the same fixture under the Pager's link type gives the drone, cap_beacon_detection)
_cap_reset; _out="$(_cap beacon SW_FAKE_TCPDUMP_LINK='EN10MB (Ethernet)')"
assert_eq "$(_cap_state)" "not_understood" cap_wrong_link_status
assert_contains "$(cat "$SW_STUB_LOG")" "WiFi capture not understood" cap_wrong_link_warns
assert_empty "$(printf '%s\n' "$_out" | grep '^drone_rid')" cap_wrong_link_no_drone
# One failed lap leaves the status in effect as it was: "not understood", a failed lap, "not understood" again is one
# OFF line on the screen, not two (or three)
_cap_reset; _cap beacon SW_FAKE_TCPDUMP_LINK='EN10MB (Ethernet)' >/dev/null; _cap beacon SW_FAKE_TCPDUMP_FAIL=1 >/dev/null
_cap beacon SW_FAKE_TCPDUMP_LINK='EN10MB (Ethernet)' >/dev/null
assert_eq "$(grep -E '^LOG ' "$SW_STUB_LOG" | sed 's/^LOG [a-z]* //')" "WARN: WiFi capture not understood — Remote ID over WiFi OFF" cap_failed_once_keeps_the_off_line

# output cut short: tcpdump's summary counts more packets than the decoder saw frames (here 3 against 1), so
# frames were lost on the way: one WARN, "partly blind", never "OFF" in a lap that still reports its drone.
# (control: cap_beacon_status_ok, the same capture with an honest summary)
_cap_reset; _out="$(_cap beacon SW_FAKE_TCPDUMP_CAPTURED=3)"
assert_eq "$(_cap_state)" "lost" cap_cut_short_status
assert_eq "$(grep -c 'WiFi capture lost frames (CPU busy?) — Remote ID partly blind' "$SW_STUB_LOG")" "1" cap_cut_short_warns
assert_contains "$_out" "|0000FSWTEST000000001|" cap_cut_short_reports_what_it_heard
assert_empty "$(grep -F 'OFF' "$SW_STUB_LOG")" cap_cut_short_never_off

# No summary at all: tcpdump was stuck writing to the decoder when the window's TERM came (the decoder had fallen
# behind: a busy CPU, a beacon flood, costly frames) and ended without one (Phase 0 on the Pager, 2026-10-02), so
# neither the frame cap nor lost frames can be counted. Partly blind: the same WARN, at most once per SW_COOLDOWN,
# never "OFF", and what was heard still counts. Such a lap used to read "ok".
# (control: cap_beacon_status_ok, the same capture with its summary)
_cap_reset; _out="$(_cap beacon SW_FAKE_TCPDUMP_NOSUMMARY=1)"
assert_eq "$(_cap_state)" "lost" cap_no_summary_status
assert_eq "$(grep -c 'WiFi capture lost frames (CPU busy?) — Remote ID partly blind' "$SW_STUB_LOG")" "1" cap_no_summary_warns
assert_contains "$_out" "|0000FSWTEST000000001|" cap_no_summary_reports_what_it_heard
assert_empty "$(grep -F 'OFF' "$SW_STUB_LOG")" cap_no_summary_never_off
_cap beacon SW_FAKE_TCPDUMP_NOSUMMARY=1 >/dev/null
assert_eq "$(grep -c 'lost frames' "$SW_STUB_LOG")" "1" cap_no_summary_warns_once_per_cooldown
# ...also in a lap with no frames: only the summary says that the capture ended as it should
# (control: cap_no_frames_is_ok, the same lap with its summary)
_cap_reset; _cap "" SW_FAKE_TCPDUMP_NOSUMMARY=1 >/dev/null
assert_eq "$(_cap_state)" "lost" cap_no_summary_no_frames_status
# ...while an OFF status still comes first (spec §7.2): a link type that is not 802.11 + radiotap is "not
# understood" with no summary too (control: cap_wrong_link_status, the same with its summary)
_cap_reset; _cap beacon SW_FAKE_TCPDUMP_NOSUMMARY=1 SW_FAKE_TCPDUMP_LINK='EN10MB (Ethernet)' >/dev/null
assert_eq "$(_cap_state)" "not_understood" cap_no_summary_wrong_link_not_understood
# Part of a summary cannot be counted either: tcpdump writes its three lines one by one, so a KILL can land between
# them. Without the "dropped by kernel" line, or without that and "received by filter", the lap is partly blind too:
# the same WARN, never "OFF", and what was heard still counts. Such a lap used to read "ok".
# (control: cap_beacon_status_ok, the whole summary)
_cap_reset; _out="$(_cap beacon SW_FAKE_TCPDUMP_SUMMARY_CUT=2)"
assert_eq "$(_cap_state)" "lost" cap_summary_cut_2_status
assert_eq "$(grep -c 'WiFi capture lost frames (CPU busy?) — Remote ID partly blind' "$SW_STUB_LOG")" "1" cap_summary_cut_warns
assert_contains "$_out" "|0000FSWTEST000000001|" cap_summary_cut_reports_what_it_heard
assert_empty "$(grep -F 'OFF' "$SW_STUB_LOG")" cap_summary_cut_never_off
_cap_reset; _cap beacon SW_FAKE_TCPDUMP_SUMMARY_CUT=1 >/dev/null
assert_eq "$(_cap_state)" "lost" cap_summary_cut_1_status
# ...and so is any one count that cannot be read, as a reworded line would be (here a word where tcpdump puts the
# number): "received by filter", or "packets captured". (controls: cap_received_5_more_ok and cap_beacon_status_ok,
# the same lap with numbers there)
_cap_reset; _cap beacon SW_FAKE_TCPDUMP_RECEIVED=some >/dev/null
assert_eq "$(_cap_state)" "lost" cap_summary_received_unreadable_lost
_cap_reset; _cap beacon SW_FAKE_TCPDUMP_CAPTURED=some >/dev/null
assert_eq "$(_cap_state)" "lost" cap_summary_captured_unreadable_lost
# A capture that ended on an error before its window did (tcpdump prints "tcpdump: pcap_loop: ..." and then its
# summary: the interface removed, say, or a driver error) was deaf for the rest of the window: partly blind, the same
# WARN, never "OFF", and what was heard still counts; also in a lap with no frames. Such a lap used to read "ok".
# (controls: cap_beacon_status_ok and cap_no_frames_is_ok, the same laps without the error)
_cap_reset; _out="$(_cap beacon SW_FAKE_TCPDUMP_LOOPERR=1)"
assert_eq "$(_cap_state)" "lost" cap_loop_error_status
assert_eq "$(grep -c 'WiFi capture lost frames (CPU busy?) — Remote ID partly blind' "$SW_STUB_LOG")" "1" cap_loop_error_warns
assert_contains "$_out" "|0000FSWTEST000000001|" cap_loop_error_reports_what_it_heard
assert_empty "$(grep -F 'OFF' "$SW_STUB_LOG")" cap_loop_error_never_off
_cap_reset; _cap "" SW_FAKE_TCPDUMP_LOOPERR=1 >/dev/null
assert_eq "$(_cap_state)" "lost" cap_loop_error_no_frames_status
# ...while an OFF status still comes first (control: cap_wrong_link_status, the same without the error)
_cap_reset; _cap beacon SW_FAKE_TCPDUMP_LOOPERR=1 SW_FAKE_TCPDUMP_LINK='EN10MB (Ethernet)' >/dev/null
assert_eq "$(_cap_state)" "not_understood" cap_loop_error_wrong_link_not_understood

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
# ...also when tcpdump printed no summary, or ended on an error (the OFF statuses come first)
_cap_reset; _cap "$_fr" SW_FAKE_TCPDUMP_NOSUMMARY=1 >/dev/null
assert_eq "$(_cap_state)" "not_understood" cap_no_summary_format_changed_not_understood
_cap_reset; _cap "$_fr" SW_FAKE_TCPDUMP_LOOPERR=1 >/dev/null
assert_eq "$(_cap_state)" "not_understood" cap_loop_error_format_changed_not_understood
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
# ...at the default cap, 700 (the quiet fixture's beacon 700 times, the setting unset), and with a setting that is
# not a plain number ("abc"), which gives the default at both ends: tcpdump's -c and the count the lap is judged by.
# (control: cap_five_beacons_status_ok, fewer frames than the cap)
for _i in $(seq 700); do cat "$_RFIX/quiet.txt"; done > "$_fr"
_cap_reset; _cap "$_fr" >/dev/null
assert_eq "$(_cap_state)" "capped" cap_capped_at_the_default
_cap_reset; _cap "$_fr" SW_RID_MAX_FRAMES=abc >/dev/null
assert_contains "$(grep '^tcpdump ' "$SW_STUB_LOG")" " -c 700 " cap_frame_cap_setting_checked
assert_eq "$(_cap_state)" "capped" cap_capped_setting_checked
# ...and 300 frames, the cap before 2026-10-08, no longer fill it, at both ends (the setting unset, and "abc")
for _i in $(seq 300); do cat "$_RFIX/quiet.txt"; done > "$_fr"
_cap_reset; _cap "$_fr" >/dev/null
assert_eq "$(_cap_state)" "ok" cap_three_hundred_frames_ok_at_the_default
_cap_reset; _cap "$_fr" SW_RID_MAX_FRAMES=abc >/dev/null
assert_eq "$(_cap_state)" "ok" cap_three_hundred_frames_ok_setting_checked
rm -f "$_fr"
# Frames the kernel dropped (tcpdump's "N packets dropped by kernel": the CPU did not keep up) leave Remote ID
# partly blind: a WARN at most once per SW_COOLDOWN, like the frame cap, and what was heard still counts.
# (control: cap_beacon_status_ok, the same capture with 0 dropped)
_cap_reset; _out="$(_cap beacon SW_FAKE_TCPDUMP_DROPPED=900)"
assert_eq "$(_cap_state)" "lost" cap_dropped_status
assert_eq "$(grep -c 'WiFi capture lost frames (CPU busy?) — Remote ID partly blind' "$SW_STUB_LOG")" "1" cap_dropped_warns
assert_contains "$_out" "|0000FSWTEST000000001|" cap_dropped_reports_what_it_heard
_cap beacon SW_FAKE_TCPDUMP_DROPPED=900 >/dev/null
assert_eq "$(grep -c 'lost frames' "$SW_STUB_LOG")" "1" cap_dropped_warns_once_per_cooldown
# one partly-blind WARN per SW_COOLDOWN whichever the reason: a frame cap right after is silent too
_cap multi SW_RID_MAX_FRAMES=1 >/dev/null
assert_eq "$(grep -c 'partly blind' "$SW_STUB_LOG")" "1" cap_partly_blind_shares_one_cooldown
# tcpdump's singular for exactly one ("1 packet dropped by kernel")
_cap_reset; _cap beacon SW_FAKE_TCPDUMP_DROPPED=1 >/dev/null
assert_eq "$(_cap_state)" "lost" cap_dropped_one_status
# ...read as a count, not taken for a summary short of its last line: a lap at the frame cap with one frame dropped
# stays capped (the cap is judged first, spec §7.2)
_cap_reset; _cap multi SW_RID_MAX_FRAMES=1 SW_FAKE_TCPDUMP_DROPPED=1 >/dev/null
assert_eq "$(_cap_state)" "capped" cap_dropped_one_capped_stays_capped
# tcpdump's "N packets received by filter" also counts frames it never processed: those still waiting in the capture
# buffer when the window ended (a tcpdump short of CPU, its decoder keeping up, stops with a backlog there and still
# prints a normal summary), the last batch not handed over yet, and a few that slip in before its filter is attached.
# More of them than 5 + a twelfth of the received count (about the window's last second at the default 12 s) is
# partly blind: the same WARN, never "OFF", and what was heard still counts. Such a lap used to read "ok"; a shallower
# backlog still does (the dev box's 37 to 48 frames at 300 a second, about 0.15 s, are inside the slack). The slack
# at its edge: 1 frame captured and 6 received (5 more: the slack is 5 + 6/12 = 5) is ok, 7 received (6 more) is
# lost. (control: cap_beacon_status_ok, the same lap counted as usual)
_cap_reset; _cap beacon SW_FAKE_TCPDUMP_RECEIVED=6 >/dev/null
assert_eq "$(_cap_state)" "ok" cap_received_5_more_ok
_cap_reset; _out="$(_cap beacon SW_FAKE_TCPDUMP_RECEIVED=7)"
assert_eq "$(_cap_state)" "lost" cap_received_6_more_lost
assert_eq "$(grep -c 'WiFi capture lost frames (CPU busy?) — Remote ID partly blind' "$SW_STUB_LOG")" "1" cap_received_more_warns
assert_contains "$_out" "|0000FSWTEST000000001|" cap_received_more_reports_what_it_heard
assert_empty "$(grep -F 'OFF' "$SW_STUB_LOG")" cap_received_more_never_off
# ...and its twelfth, which grows with the frames received: 60 frames and 70 received (10 more; 5 + 70/12 = 10) is ok, 71
# (11 more) is lost; 65 frames and 76 received (11 more; 5 + 76/12 = 11) is ok, 77 (12 more) is lost. So the slack is
# neither a fixed 5 nor an eleventh or a thirteenth. (The quiet fixture's beacon, 60 and 65 times.)
for _i in $(seq 60); do cat "$_RFIX/quiet.txt"; done > "$_fr"
_cap_reset; _cap "$_fr" SW_FAKE_TCPDUMP_RECEIVED=70 >/dev/null
assert_eq "$(_cap_state)" "ok" cap_received_60_frames_10_more_ok
_cap_reset; _cap "$_fr" SW_FAKE_TCPDUMP_RECEIVED=71 >/dev/null
assert_eq "$(_cap_state)" "lost" cap_received_60_frames_11_more_lost
for _i in $(seq 65); do cat "$_RFIX/quiet.txt"; done > "$_fr"
_cap_reset; _cap "$_fr" SW_FAKE_TCPDUMP_RECEIVED=76 >/dev/null
assert_eq "$(_cap_state)" "ok" cap_received_65_frames_11_more_ok
_cap_reset; _cap "$_fr" SW_FAKE_TCPDUMP_RECEIVED=77 >/dev/null
assert_eq "$(_cap_state)" "lost" cap_received_65_frames_12_more_lost
# The OFF statuses still come first (spec §7.2), and a capped lap stays capped: tcpdump stops at the cap while frames
# keep coming. (controls: cap_received_6_more_lost, the same excess alone; cap_wrong_link_status,
# cap_format_changed_status and cap_capped_status, the same laps counted as usual)
_cap_reset; _cap beacon SW_FAKE_TCPDUMP_RECEIVED=100 SW_FAKE_TCPDUMP_LINK='EN10MB (Ethernet)' >/dev/null
assert_eq "$(_cap_state)" "not_understood" cap_received_more_wrong_link_not_understood
for _i in 1 2 3 4 5; do sed 's/0x0000:  00/0x0000:  01/' "$_RFIX/quiet.txt"; done > "$_fr"
_cap_reset; _cap "$_fr" SW_FAKE_TCPDUMP_RECEIVED=100 >/dev/null
assert_eq "$(_cap_state)" "not_understood" cap_received_more_format_changed_not_understood
rm -f "$_fr"
_cap_reset; _cap multi SW_RID_MAX_FRAMES=1 SW_FAKE_TCPDUMP_RECEIVED=100 >/dev/null
assert_eq "$(_cap_state)" "capped" cap_received_more_capped_stays_capped
# An OFF line is followed by the green "recovered" line as soon as the capture works again, also in a lap that is
# only partly blind (re-review 2026-10-02, Minor 1): lap 1 drops frames, laps 2 and 3 fail (the OFF line comes with
# the second), lap 4 drops frames again (inside the partly-blind cooldown: no WARN), lap 5 is fine. One
# "recovered", right after the OFF line.
_cap_reset
_cap beacon SW_FAKE_TCPDUMP_DROPPED=900 >/dev/null; _cap beacon SW_FAKE_TCPDUMP_FAIL=1 >/dev/null; _cap beacon SW_FAKE_TCPDUMP_FAIL=1 >/dev/null
_cap beacon SW_FAKE_TCPDUMP_DROPPED=900 >/dev/null; _cap beacon >/dev/null
assert_eq "$(grep -E '^LOG ' "$SW_STUB_LOG" | sed 's/^LOG [a-z]* //')" "WARN: WiFi capture lost frames (CPU busy?) — Remote ID partly blind
WARN: WiFi capture failed — Remote ID over WiFi OFF
Remote ID capture recovered" cap_off_then_lost_recovers
# ...and a capped lap after "not understood": recovered, then its own partly-blind WARN (no cooldown running)
_cap_reset; _cap beacon SW_FAKE_TCPDUMP_LINK='EN10MB (Ethernet)' >/dev/null; _cap multi SW_RID_MAX_FRAMES=1 >/dev/null
assert_eq "$(grep -E '^LOG ' "$SW_STUB_LOG" | sed 's/^LOG [a-z]* //')" "WARN: WiFi capture not understood — Remote ID over WiFi OFF
Remote ID capture recovered
WARN: WiFi capture hit its frame limit (beacon flood?) — Remote ID partly blind" cap_off_then_capped_recovers

# more drones than SW_RID_MAX_DRONES: the strongest are reported, the rest counted on one line
_cap_reset; _out="$(_cap multi SW_RID_MAX_DRONES=1)"
assert_eq "$(printf '%s\n' "$_out" | grep -c '^drone_rid')" "1" cap_drone_cap_one_detection
assert_contains "$_out" "|0000FSWTEST000000001|" cap_drone_cap_keeps_strongest
assert_contains "$(cat "$SW_STUB_LOG")" "LOG magenta ...and 1 more drones (Remote ID flood?)" cap_drone_cap_more_line
# A Stop after the capture's wait (spec §7.3): no health line and no state file (the exit trap removed it). A
# main shell already gone gets no line at all; one stopped during the line (the LOG stub kills the stand-in
# then) gets no state file after it. Control: alive, the same note prints and writes. (The OFF status here is "not
# understood", which says so at once.)
_sf="$_cap_dir/sw_rid.state"
bash -c 'exit 0' & _rd=$!; wait "$_rd"
_cap_reset; SW_TMP_DIR="$_cap_dir" SW_MAIN_PID="$_rd" sw_rid_health_note not_understood 1700000000
assert_empty "$(grep -F 'WiFi capture' "$SW_STUB_LOG")" cap_health_stopped_no_line
assert_eq "$([ -e "$_sf" ] && echo written)" "" cap_health_stopped_no_state
sleep 30 & _fm=$!
_cap_reset; SW_TMP_DIR="$_cap_dir" SW_MAIN_PID="$_fm" SW_STUB_STOP_ON_LOG="$_fm" sw_rid_health_note not_understood 1700000000
wait "$_fm" 2>/dev/null
assert_contains "$(cat "$SW_STUB_LOG")" "WARN: WiFi capture not understood" cap_health_stop_mid_line_control_line
assert_eq "$([ -e "$_sf" ] && echo written)" "" cap_health_stop_mid_line_no_state
_cap_reset; SW_TMP_DIR="$_cap_dir" sw_rid_health_note not_understood 1700000000
assert_eq "$(grep -c 'WiFi capture not understood' "$SW_STUB_LOG")/$(head -1 "$_sf")" "1/not_understood" cap_health_control_line_and_state
# ...and for a capture that fails: after a first failed lap (its note written alive), a Stop before the second
# one's note gives no line and leaves the state file as the first lap left it; a Stop in the first failed lap
# writes no state either. Controls: alive, the second note prints its line and writes the OFF status, and the
# first one writes its note without a line.
_cap_reset; SW_TMP_DIR="$_cap_dir" sw_rid_health_note capture_failed 1700000000; cp "$_sf" "$_cap_dir/first"; : > "$SW_STUB_LOG"
SW_TMP_DIR="$_cap_dir" SW_MAIN_PID="$_rd" sw_rid_health_note capture_failed 1700000000
assert_empty "$(grep -F 'WiFi capture' "$SW_STUB_LOG")" cap_health_stopped_second_failure_no_line
assert_eq "$(cmp -s "$_sf" "$_cap_dir/first" && echo kept)" "kept" cap_health_stopped_second_failure_state_kept
SW_TMP_DIR="$_cap_dir" sw_rid_health_note capture_failed 1700000000
assert_eq "$(grep -c 'WiFi capture failed' "$SW_STUB_LOG")/$(head -1 "$_sf")" "1/capture_failed" cap_health_second_failure_control_line_and_state
_cap_reset; SW_TMP_DIR="$_cap_dir" SW_MAIN_PID="$_rd" sw_rid_health_note capture_failed 1700000000
assert_eq "$([ -e "$_sf" ] && echo written)" "" cap_health_stopped_first_failure_no_state
_cap_reset; SW_TMP_DIR="$_cap_dir" sw_rid_health_note capture_failed 1700000000
assert_eq "$([ -e "$_sf" ] && echo written)/$(grep -c 'WiFi capture' "$SW_STUB_LOG")" "written/0" cap_health_first_failure_control_written_silently
rm -f "$_cap_dir/first"
# ...and for a temp file that cannot be made, which says OFF at once: stopped, no line and no state. (control: alive,
# the line and the OFF status)
_cap_reset; SW_TMP_DIR="$_cap_dir" SW_MAIN_PID="$_rd" sw_rid_health_note capture_failed 1700000000 at_once
assert_eq "$(grep -c 'WiFi capture' "$SW_STUB_LOG")/$([ -e "$_sf" ] && echo written)" "0/" cap_health_stopped_at_once_no_line_no_state
_cap_reset; SW_TMP_DIR="$_cap_dir" sw_rid_health_note capture_failed 1700000000 at_once
assert_eq "$(grep -c 'WiFi capture failed' "$SW_STUB_LOG")/$(head -1 "$_sf")" "1/capture_failed" cap_health_at_once_control_line_and_state
# ...and for a first failed lap whose note cannot be kept, which says OFF at once too: stopped, no line. Only a noted
# failure speaks for the state it cannot keep: a lap that captured fine says nothing about it. (control: alive, the
# OFF line)
_cap_reset; SW_RID_STATE_FILE="$_cap_dir/missing/sw_rid.state" SW_MAIN_PID="$_rd" sw_rid_health_note capture_failed 1700000000
assert_empty "$(grep -F 'WiFi capture' "$SW_STUB_LOG")" cap_health_stopped_unkept_note_no_line
_cap_reset; SW_RID_STATE_FILE="$_cap_dir/missing/sw_rid.state" sw_rid_health_note capture_failed 1700000000
assert_eq "$(grep -c 'WiFi capture failed — Remote ID over WiFi OFF' "$SW_STUB_LOG")" "1" cap_health_unkept_note_control_line
_cap_reset; SW_RID_STATE_FILE="$_cap_dir/missing/sw_rid.state" sw_rid_health_note ok 1700000000
assert_empty "$(grep -F 'WiFi capture' "$SW_STUB_LOG")" cap_health_unkept_ok_no_line
# The same in a whole capture: a flood lap (2 frames at a cap of 2: "capped"; 2 drones at a cap of 1: the
# "...and 1 more" line) stopped during its capped WARN reports nothing after it: no state, no drone, no flood
# line. (control: cap_drone_cap_more_line, the flood line of a lap left alone)
sleep 30 & _fm=$!
_cap_reset; _out="$(_cap multi SW_RID_MAX_FRAMES=2 SW_RID_MAX_DRONES=1 SW_MAIN_PID="$_fm" SW_STUB_STOP_ON_LOG="$_fm")"
wait "$_fm" 2>/dev/null
assert_contains "$(cat "$SW_STUB_LOG")" "hit its frame limit" cap_stop_in_warn_control_warned
assert_eq "$([ -e "$_sf" ] && echo written)" "" cap_stop_in_warn_no_state
assert_empty "$(printf '%s\n' "$_out" | grep '^drone_rid')" cap_stop_in_warn_no_drone
assert_empty "$(grep -F 'more drones' "$SW_STUB_LOG")" cap_stop_in_warn_no_flood_line
unset _sf _rd _fm

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
  sw_rid_start 1700000000; exec sleep 30' _ "$SW_ROOT" 2>/dev/null &
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
