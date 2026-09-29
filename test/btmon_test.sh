# test/btmon_test.sh  (sourced by run.sh) — the btmon parser (Tier-3 spec §3).
SW_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../payloads/user/reconnaissance/squachwatch" && pwd)"
_FIX="$(cd "$(dirname "${BASH_SOURCE[0]}")/fixtures" && pwd)"
source "$SW_ROOT/lib/match.sh"; source "$SW_ROOT/lib/ble.sh"

# REAL capture, 2026-09-22: 7 distinct devices -> exactly one record each.
_live="$(sw_btmon_parse < "$_FIX/btmon_live_2026-09-22.txt")"
assert_eq "$(printf '%s\n' "$_live" | grep -c '^ble|')" "7" btmon_live_one_record_per_mac
assert_contains "$_live" "ble|F9:C1:A3:83:F0:48||-96|mfr:004c:12:25" btmon_live_findmy_separated
assert_contains "$_live" "ble|FB:E5:3D:E8:87:19||-99|mfr:004c:12:2" btmon_live_findmy_nearowner
assert_contains "$_live" "ble|6C:E3:68:45:20:97||-99|mfr:004c:10:5" btmon_live_apple_nearby_info
assert_contains "$_live" "ble|80:E1:26:FA:D6:22|MyFlipper|-74|uuid:3082" btmon_live_flipper
assert_contains "$_live" "ble|06:92:D4:30:B1:09||-99|sd:fcf1:04" btmon_live_service_data
assert_contains "$_live" "ble|D4:06:74:62:37:27|InfiniTime|-92|" btmon_live_128bit_only_no_tokens

_syn="$(sw_btmon_parse < "$_FIX/btmon_synthetic.txt")"
# two sightings of one MAC merge: strongest RSSI (-55 beats -60), name kept, token once
assert_contains "$_syn" "ble|80:E1:26:00:00:01|Flipper aa|-55|uuid:3082" btmon_merge_strongest_rssi
assert_eq "$(printf '%s\n' "$_syn" | grep -c '80:E1:26:00:00:01')" "1" btmon_merge_one_record
assert_contains "$_syn" "ble|58:8E:81:12:34:56|Penguin-1234|-70|" btmon_name_only
assert_contains "$_syn" "ble|AA:00:00:00:00:01||-80|sd:fd5a:02" btmon_smarttag_service_data
assert_contains "$_syn" "ble|AA:00:00:00:00:02||-81|uuid:feed" btmon_tile_uuid16
assert_contains "$_syn" "ble|AA:00:00:00:00:03||-82|sd:feaa:41" btmon_gfmd_service_data
assert_contains "$_syn" "ble|AA:00:00:00:00:04||-83|sd:feaa:10" btmon_eddystone_service_data
assert_contains "$_syn" "ble|AA:00:00:00:00:07||-86|uuid:3501" btmon_uuid16_outside_range
# multi-report event -> two devices
assert_contains "$_syn" "ble|AA:00:00:00:00:08|MultiA|-87|" btmon_multi_report_a
assert_contains "$_syn" "ble|AA:00:00:00:00:09|MultiB|-88|" btmon_multi_report_b
# extended report: RSSI comes BEFORE the data, and "Direct address:" is not a device
assert_contains "$_syn" "ble|AA:00:00:00:00:0A||-71|sd:fd5a:02" btmon_extended_report
assert_empty "$(printf '%s\n' "$_syn" | grep '00:00:00:00:00:00')" btmon_direct_address_not_a_device
# name only in the SCAN_RSP still lands on the record (v1 parity: unknown-first keeps the name)
assert_contains "$_syn" "ble|AA:BB:CC:00:11:22|Tracker-9|-72|" btmon_name_from_scan_response
# Finding-1: '|' in an advertised name is stripped (single sanitizer: sw_sanitize_ident)
assert_contains "$_syn" "ble|AA:00:00:00:00:0B|Evil|-74|" btmon_name_sanitized
# manufacturer data WITHOUT a btmon "Type:" line: type = first byte, len = the rest
assert_contains "$_syn" "ble|AA:00:00:00:00:0C||-75|mfr:0006:01:8" btmon_mfr_without_type_line

# --- HOSTILE capture: a name holding newlines forges btmon-shaped lines (btmon prints names raw)
_host="$(sw_btmon_parse < "$_FIX/btmon_hostile.txt")"
_rec() { printf '%s\n' "$_host" | grep "^ble|$1|"; }
# positive controls: the legitimate devices AFTER the forged lines still parse
assert_contains "$_host" "ble|F9:C1:A3:83:F0:48||-90|mfr:004c:12:25" hostile_legit_findmy_parsed
assert_contains "$_host" "ble|AA:00:00:00:00:71|Kitchen Speaker|-77|" hostile_legit_named_parsed
# every token has one of the three well-formed shapes (a malformed UUID once aborted matching)
_bad_toks() { awk -F'|' '{ print $NF }' | tr ' ' '\n' | grep -vE '^$|^(mfr:[0-9a-f]{4}:[0-9a-f]{2}:[0-9]+|mfr:004c:07:(audio|other):[0-9a-f]{4}|uuid:[0-9a-f]{4}|sd:[0-9a-f]{4}:[0-9a-f]{2})$'; }
assert_empty "$(printf '%s\n' "$_host" | _bad_toks)" hostile_only_well_formed_tokens
# ...and that check is live: it REJECTS hand-made bad tokens and accepts the good shapes
assert_eq "$(printf 'ble|AA:00:00:00:00:66||-80|sd::41 uuid:3100 sd:zzzz:41 mfr:1869f:41:0 mfr:004c:07:weird:0055 mfr:004c:07:other:00\n' | _bad_toks | tr '\n' ' ')" "sd::41 sd:zzzz:41 mfr:1869f:41:0 mfr:004c:07:weird:0055 mfr:004c:07:other:00 " hostile_token_check_rejects_bad
assert_empty "$(printf 'ble|X||-1|mfr:004c:12:25 uuid:feed sd:fd5a:02 mfr:004c:07:other:0055 mfr:004c:07:audio:0e20\n' | _bad_toks)" hostile_token_check_accepts_good
# the MAC column is six hex pairs (a forged "Address: AA|BB|..." once shifted every field),
# every record has exactly 5 fields, and rssi is only ever -?[0-9]*
assert_empty "$(printf '%s\n' "$_host" | grep -vE '^ble\|([0-9A-F]{2}:){5}[0-9A-F]{2}\|')" hostile_mac_six_pairs
assert_empty "$(printf '%s\n' "$_host" | awk -F'|' 'NF != 5')" hostile_five_fields
assert_empty "$(printf '%s\n' "$_host" | awk -F'|' '$4 !~ /^-?[0-9]*$/')" hostile_rssi_numeric
# the forged lines are dropped: the device keeps its real RSSI and gains no token
assert_eq "$(_rec AA:00:00:00:00:66)" "ble|AA:00:00:00:00:66|Mallory|-80|" hostile_injected_lines_dropped
# extended report: RSSI precedes the name, so a forged RSSI would be the LAST one seen
assert_eq "$(_rec AA:00:00:00:00:65)" "ble|AA:00:00:00:00:65|MalloryExt|-72|" hostile_forged_rssi_ignored
# non-hex and odd-length Data make no token (control: the legit Find My Data above does)
assert_eq "$(_rec AA:00:00:00:00:67)" "ble|AA:00:00:00:00:67||-79|" hostile_nonhex_data_no_token
# RSSI 127 is btmon's "not available": never the record's rssi (control: :65 keeps -72)
assert_eq "$(_rec AA:00:00:00:00:77)" "ble|AA:00:00:00:00:77|||" hostile_rssi_127_not_available
# a NAME containing "LE Advertising Report" is not a report start (it used to flush the record)
assert_eq "$(_rec AA:00:00:00:00:72)" "ble|AA:00:00:00:00:72|LE Advertising Report|-78|" hostile_name_is_not_a_report_start
# 16-bit UUID list entries are keyed on indentation: a same-indent "Appearance: (0x3200)"
# line is not an entry (uuid:3200 would false-match Raven 3100-3500)
assert_contains "$(_rec AA:00:00:00:00:70)" "uuid:feed" u16_indented_entry_kept
assert_empty "$(_rec AA:00:00:00:00:70 | grep 'uuid:3200')" u16_same_indent_line_not_an_entry
# END TO END with the real signatures: the separated Find My is still detected...
_sigs_real="$(sw_load_signatures "$SW_ROOT/signatures.db")"
assert_contains "$(sw_btmon_parse < "$_FIX/btmon_hostile.txt" | sw_match_stream "$_sigs_real")" "tracker_findmy|Apple Find My (separated)|med|tracker|ble|F9:C1:A3:83:F0:48||-90" hostile_e2e_findmy_detected
# ...also in the worst case of awk's hash order, hostile records FIRST (sort: AA:.. < FB:..)
assert_contains "$(sw_btmon_parse < "$_FIX/btmon_hostile.txt" | sort | sw_match_stream "$_sigs_real")" "tracker_findmy|Apple Find My (separated)|med|tracker|ble|F9:C1:A3:83:F0:48||-90" hostile_e2e_findmy_detected_hostile_first
# --- Apple Proximity Pairing (type 0x07): the model code tells an AirTag from AirPods ---
# Every published AirPods/Beats model code ends in 0x20 (furiousMAC dissector table + InfiShark),
# so those are tagged "audio"; any other model is "other" (an AirTag in setup mode, whose exact
# code no source documents, so the rule must not depend on it).
_FIXPP="$(cd "$(dirname "${BASH_SOURCE[0]}")/fixtures" && pwd)/btmon_apple_pp.txt"
_pp="$(sw_btmon_parse < "$_FIXPP")"
assert_contains "$_pp" "ble|AA:00:00:00:00:A1||-60|mfr:004c:07:25 mfr:004c:07:other:0055" pp_airtag_like_is_other
assert_contains "$_pp" "ble|AA:00:00:00:00:A2||-61|mfr:004c:07:25 mfr:004c:07:audio:0e20" pp_airpods_pro_is_audio
assert_contains "$_pp" "ble|AA:00:00:00:00:A3||-62|mfr:004c:07:25 mfr:004c:07:audio:0a20" pp_airpods_max_is_audio
assert_contains "$_pp" "ble|AA:00:00:00:00:A4||-63|mfr:004c:07:25 mfr:004c:07:audio:0620" pp_beats_is_audio
# a 0x07 too short to hold a model keeps its plain token and gains no model token
assert_eq "$(printf '%s\n' "$_pp" | grep '^ble|AA:00:00:00:00:A5|')" "ble|AA:00:00:00:00:A5||-65|mfr:004c:07:2" pp_short_payload_no_model
# two Apple messages in one advert: both decoded, and the 0x07 one classified
assert_contains "$_pp" "ble|AA:00:00:00:00:A6||-66|mfr:004c:10:5 mfr:004c:07:25 mfr:004c:07:other:0055" pp_multi_tlv
assert_empty "$(printf '%s\n' "$_pp" | _bad_toks)" pp_only_well_formed_tokens
# only APPLE 0x07 carries this model field: a non-Apple payload starting 07 gets no model token
_np="$(printf '> HCI Event: LE Meta Event (0x3e) plen 20 #1 [hci0] 1.0\n      LE Advertising Report (0x02)\n        Address: AA:00:00:00:00:B1 (Static)\n        Company: Microsoft (6)\n          Data: 07010e20\n        RSSI: -70 dBm (0xba)\n' | sw_btmon_parse)"
assert_eq "$_np" "ble|AA:00:00:00:00:B1||-70|mfr:0006:07:3" pp_non_apple_no_model
unset _FIXPP _pp _np
unset -f _rec _bad_toks; unset _host _sigs_real

# no advertising reports -> no records, and command-parameter lines ("Type: Active" under
# LE Set Scan Parameters) are never read as devices. Positive control: _live above has 7.
assert_empty "$(sw_btmon_parse < "$_FIX/btmon_scan_failed.txt")" btmon_no_reports_no_records

# BUDGET: a crowded room. ~31k lines must parse in well under a lap (one awk pass).
_big="$(mktemp)"; for _i in $(seq 45); do cat "$_FIX/btmon_live_2026-09-22.txt"; done > "$_big"
SECONDS=0; _n="$(sw_btmon_parse < "$_big" | grep -c '^ble|')"; _el=$SECONDS
assert_eq "$_n" "7" btmon_big_capture_positive_control
if [ "$_el" -lt 5 ]; then pass; else fail "btmon_parse_budget: $(wc -l < "$_big") lines took ${_el}s (budget 5s)"; fi
rm -f "$_big"
unset _FIX _live _syn _big _i _n _el

# --- BLE health (spec §7): a blind BLE path must never read as "all clear" ---
_FIX="$(cd "$(dirname "${BASH_SOURCE[0]}")/fixtures" && pwd)"
_n_of() { sw_btmon_parse < "$1" | grep -c '^ble|'; }
# REPLY may be unset here (earlier callers set it only inside subshells). Under run.sh's
# `set -u` a missing function would then ABORT the whole runner instead of failing asserts.
REPLY=""
sw_btmon_health "$_FIX/btmon_live_2026-09-22.txt" "$(_n_of "$_FIX/btmon_live_2026-09-22.txt")"
assert_eq "$REPLY" "ok" health_live_ok
sw_btmon_health "$_FIX/btmon_quiet.txt" 0
assert_eq "$REPLY" "ok" health_quiet_room_is_not_a_fault
sw_btmon_health "$_FIX/btmon_scan_failed.txt" 0
assert_eq "$REPLY" "scan_failed" health_command_disallowed
sw_btmon_health "$_FIX/btmon_unknown_format.txt" "$(_n_of "$_FIX/btmon_unknown_format.txt")"
assert_eq "$REPLY" "not_understood" health_format_changed

# state-change logging: loud once, never every ~20 s lap; a first-lap "ok" is silent
_st="$(mktemp -d)"; : > "$SW_STUB_LOG"
SW_BLE_STATE_FILE="$_st/ble.state" sw_ble_health_note ok
SW_BLE_STATE_FILE="$_st/ble.state" sw_ble_health_note scan_failed
SW_BLE_STATE_FILE="$_st/ble.state" sw_ble_health_note scan_failed
SW_BLE_STATE_FILE="$_st/ble.state" sw_ble_health_note ok
SW_BLE_STATE_FILE="$_st/ble.state" sw_ble_health_note not_understood
_log="$(cat "$SW_STUB_LOG")"
assert_eq "$(printf '%s\n' "$_log" | grep -c 'BLE scan failed to start')" "1" health_note_warns_once
# bluetoothd's own background scan can keep adverts flowing when OURS failed to start, so the
# WARN must not claim detection is OFF (control: health_note_warns_once found that line)
assert_empty "$(printf '%s\n' "$_log" | grep 'BLE scan failed to start' | grep 'detection OFF')" health_scan_failed_no_off_claim
assert_eq "$(printf '%s\n' "$_log" | grep -c 'BLE scan recovered')" "1" health_note_recovers_once
assert_eq "$(printf '%s\n' "$_log" | grep -c 'BLE capture not understood')" "1" health_note_format_warn
assert_eq "$(printf '%s\n' "$_log" | grep -c .)" "3" health_note_first_ok_silent
assert_eq "$(cat "$_st/ble.state")" "not_understood" health_note_state_persisted
rm -rf "$_st"; unset -f _n_of; unset _FIX _st _log
# a name ending in the first byte of a multi-byte character cannot swallow the next device's line
# (bash's `read` did, in a UTF-8 locale; the Pager's default behaves the same, checked 2026-09-29)
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/helpers/btmon_gen.sh"   # sw_test_btmon_devs
_lb="$( { sw_test_btmon_devs C1:00:00:00:00 4 $'Caf\xe9' -60; sw_test_btmon_devs C2:00:00:00:00 4 'Flipper x' -55; } | sw_btmon_parse)"
assert_eq "$(printf '%s\n' "$_lb" | grep -a -c '^ble|')" "8" btmon_lead_byte_name_one_record_each
assert_eq "$(printf '%s\n' "$_lb" | grep -a -c '|Flipper x|')" "4" btmon_lead_byte_name_hides_no_device
# the sanitizer strips the C1 controls on the BLE path too (bytes: NEL between A and B)
assert_contains "$(sw_test_btmon_devs C3:00:00:00:00 1 $'A\xc2\x85B' -50 | sw_btmon_parse)" "ble|C3:00:00:00:00:01|AB|-50|" btmon_sanitize_strips_c1
unset _lb; unset -f sw_test_btmon_devs
