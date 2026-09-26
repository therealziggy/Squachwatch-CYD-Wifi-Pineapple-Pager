# test/index_test.sh  (sourced by run.sh) — the matcher's index (spec 2026-09-26 §6.2, §8).
# The index decides which rules sw_match_record even looks at. The one way it can go wrong is
# by leaving out a rule that would have hit, so these tests compare the indexed matcher with a
# FULL scan of every rule (exactly what the matcher did before the index), byte for byte.
SW_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../payloads/user/reconnaissance/squachwatch" && pwd)"
_IFIX="$(cd "$(dirname "${BASH_SOURCE[0]}")/fixtures" && pwd)"
source "$SW_ROOT/lib/match.sh"; source "$SW_ROOT/lib/ble.sh"; source "$SW_ROOT/lib/wifi.sh"

# Synthetic rules: every match type, including shapes the index must NOT key (ranges, bad
# companies and UUIDs, empty patterns) and a type the matcher does not know.
_IX_SYN='wifi_oui|aa:bb:cc|x_oui|OUI (lowercase in file)|high|attacker
wifi_oui||x_oui_empty|Empty OUI|low|attacker
ble_oui|C1:00:00|x_boui|BLE OUI|med|attacker
wifi_ssid_sub|net|x_sub|SSID substring|low|surveillance
wifi_ssid_pre|home|x_pre|SSID prefix|med|surveillance
wifi_ssid_pre||x_pre_empty|Empty prefix|low|surveillance
ble_name_sub|flip|x_name|Name|low|attacker
ble_mfr|004C|x_mfr_co|Apple any|low|tracker
ble_mfr|004c:12|x_mfr_type|Find My any|med|tracker
ble_mfr|004c:12:25|x_mfr_full|Find My separated|high|tracker
ble_mfr|zz:12|x_mfr_bad|Bad company|low|tracker
ble_mfr||x_mfr_empty|Empty mfr|low|tracker
ble_uuid|FD5A|x_uuid|SmartTag (uppercase in file)|med|tracker
ble_uuid|feaa:41|x_uuid_fb|Google Find My|med|tracker
ble_uuid|feaa:4|x_uuid_badfb|Short first byte|low|tracker
ble_uuid|3100-3500|x_range|Range|low|surveillance
ble_uuid|zzzz|x_uuid_bad|Bad UUID|low|surveillance
ble_uuid||x_uuid_empty|Empty UUID|low|surveillance
ble_company|0x004C|x_unknown|Unknown type|high|tracker'

# Records: every fixture capture, the recon fixture, and hand-made / hostile records.
_ix_recs="$(for _f in "$_IFIX"/btmon_*.txt; do sw_btmon_parse < "$_f"; done
  SW_RECENCY_SECS=0 sw_wifi_records "$_IFIX/recon.db"
  printf '%s\n' \
    'wifi|AA:BB:CC:00:00:01|HomeNet|-50' \
    'wifi|AA:BB:CC:00:00:02||-50' \
    'wifi|12:34:56:00:00:03|home-office|-51' \
    'wifi|12:34:56:00:00:04|MyNet|-52' \
    'wifi|||-1' \
    'wifi|B4:1E:52:00:00:05|flock-7A2C|-40' \
    'wifi|70:C9:4E:11:22:33|AB3-X7Q2|-41' \
    'wifi|02:13:37:00:00:06|Pineapple_1A2B|-42' \
    'wifi|00:25:DF:00:00:07|pwned|-43' \
    'ble|C1:00:00:00:00:01|Flipper Bob|-55' \
    'ble|C1:00:00:00:00:02||-56|mfr:004c:12:25 sd:feaa:41 uuid:fd5a' \
    'ble|80:E1:26:00:00:03|flipper|-57|uuid:3082 mfr:0e29:01:4' \
    'ble|AA:00:00:00:00:66||-80|sd::41 uuid:zzzz' \
    'ble|AA:00:00:00:00:67||-80|uuid:* sd:feaa:4 mfr:zz:12:1 mfr:' \
    'ble|AA:00:00:00:00:68|HC-05|-81|uuid:1101 uuid:fffa uuid:fd5f mfr:01ab:02:3 mfr:09c8:00:6' \
    'ble|||' \
    'ble|AA:00:00:00:00:69||-82|uuid:3150 uuid:3100 sd:3200:01' \
    'ble|80:e1:26:00:00:0a|lower mac|-60|uuid:FD5A mfr:004C:12:25' \
    'zzz|70:C9:4E:11:22:33|x|1')"
unset _f
# the differential really sees the fixtures (not just the 19 hand-made records)
assert_eq "$([ "$(printf '%s\n' "$_ix_recs" | grep -c .)" -gt 600 ] && echo y)" "y" index_records_floor

_ix_run() {  # $1 = signature text -> every record's detections, in record order
  local _r
  while IFS= read -r _r; do [ -n "$_r" ] && sw_match_record "$_r" "$1"; done <<< "$_ix_recs"
}
# Full scan: every rule is a candidate, which is what the matcher did before the index.
_ix_fullscan() {
  _sw_candidates() { SW_CAND=(); local k; for (( k = 0; k < ${#SW_SIG_TYPE[@]}; k++ )); do SW_CAND[k]=1; done; }
}
_ix_compare() {  # $1 = signature text, $2 = test name: the indexed output must equal the full scan's
  local _idx _full
  _idx="$(_ix_run "$1")"
  _ix_fullscan; _full="$(_ix_run "$1")"
  source "$SW_ROOT/lib/match.sh"    # restores the real _sw_candidates
  assert_eq "$_idx" "$_full" "$2"
  _IX_LAST="$_idx"
}

_ix_real="$(sw_load_signatures "$SW_ROOT/signatures.db")"
_ix_all="$(sed 's/^#off //' "$SW_ROOT/signatures.db" | grep -v '^[[:space:]]*#' | grep -v '^[[:space:]]*$')"
assert_eq "$(printf '%s\n' "$_ix_all" | grep -c .)" "125" index_all_rule_count
_ix_compare "$_IX_SYN" index_equals_fullscan_synthetic
# non-vacuity: the synthetic comparison exercised keyed, scanned, range and unkeyable rules
assert_contains "$_IX_LAST" "x_mfr_full|Find My separated|high" index_syn_keyed_mfr_hit
assert_contains "$_IX_LAST" "x_range|Range|low" index_syn_range_hit
assert_contains "$_IX_LAST" "x_pre|SSID prefix|med" index_syn_prefix_hit
assert_contains "$_IX_LAST" "x_uuid_bad|Bad UUID|low" index_syn_unkeyed_uuid_hit
_ix_compare "$_ix_real" index_equals_fullscan_real
assert_contains "$_IX_LAST" "hacker_flipper|Flipper Zero|high" index_real_nonvacuous
_ix_compare "$_ix_all" index_equals_fullscan_real_with_off_rules
# non-vacuity: a switched-off rule really took part (70:C9:4E is a Lite-On #off prefix)
assert_contains "$_IX_LAST" "flock_chip|Possible Flock (Lite-On chip)|low" index_all_nonvacuous

# POSITIVE CONTROL: the comparison can fail. Drop one key from a prepared index and the
# indexed matcher loses the Apple rules, so it must now DIFFER from the full scan.
sw_prepare_sigs "$_IX_SYN"; SW_SIGS_CACHE="$_IX_SYN"
unset 'SW_IX[m:004c]'
_ix_broken="$(_ix_run "$_IX_SYN")"
_ix_fullscan; _ix_ok="$(_ix_run "$_IX_SYN")"; source "$SW_ROOT/lib/match.sh"
assert_eq "$([ "$_ix_broken" != "$_ix_ok" ] && echo differs)" "differs" index_compare_can_fail
unset SW_SIGS_CACHE    # the index above is broken: force the next caller to re-prepare

# Candidate counts: the speed property, deterministic and machine-independent. The synthetic
# set scans rules 3,4,5 (WiFi) and 6,10,11,14,15,16,17 (BLE); rule 18 (an unknown type) is
# neither scanned nor keyed; every other rule is keyed.
sw_prepare_sigs "$_IX_SYN"; SW_SIGS_CACHE="$_IX_SYN"
_sw_candidates wifi "12:34:56" "";  assert_eq "${#SW_CAND[@]}" "3" index_wifi_scans_ssid_rules_only
_sw_candidates wifi "AA:BB:CC" "";  assert_eq "${#SW_CAND[@]}" "4" index_wifi_adds_its_oui_rule
_sw_candidates ble "12:34:56" "";   assert_eq "${#SW_CAND[@]}" "7" index_ble_scans_unkeyable_rules_only
_sw_candidates ble "C1:00:00" "mfr:004c:12:25 sd:feaa:41 uuid:fd5a"
assert_eq "${!SW_CAND[*]}" "2 6 7 8 9 10 11 12 13 14 15 16 17" index_ble_candidates_in_file_order
_sw_candidates zzz "12:34:56" "uuid:fd5a"; assert_eq "${#SW_CAND[@]}" "0" index_unknown_radio_no_candidates
# hostile tokens: no error, and nothing keyed
assert_empty "$( { _sw_candidates ble "12:34:56" "sd::41 uuid:zzzz mfr: uuid:"; } 2>&1 )" index_hostile_tokens_no_error
_sw_candidates ble "12:34:56" "sd::41 uuid:zzzz mfr: uuid:"; assert_eq "${#SW_CAND[@]}" "7" index_hostile_tokens_add_nothing
# a token is never a file pattern: in a folder holding a file named "uuid:fd5a", the token
# "uuid:*" must not expand to it (which would add the SmartTag rule)
_ixg="$(mktemp -d)"; : > "$_ixg/uuid:fd5a"
assert_eq "$(cd "$_ixg" && set -- uuid:*; echo "$1")" "uuid:fd5a" index_glob_control_would_expand
assert_eq "$(cd "$_ixg" && _sw_candidates ble "12:34:56" "uuid:*" && echo "${#SW_CAND[@]}")" "7" index_tokens_never_glob
rm -rf "$_ixg"

# with the SHIPPED rule set, a record meets only the rules that could fit it (spec §6.3):
# 9 WiFi prefix/substring rules, 13 BLE name rules, plus whatever its OUI and tokens key
sw_prepare_sigs "$_ix_real"; SW_SIGS_CACHE="$_ix_real"
assert_eq "${#SW_SIG_TYPE[@]}" "83" index_real_rule_count
_sw_candidates wifi "12:34:56" "";  assert_eq "${#SW_CAND[@]}" "9" index_real_wifi_candidates
_sw_candidates wifi "B4:1E:52" "";  assert_eq "${#SW_CAND[@]}" "10" index_real_wifi_oui_candidates
_sw_candidates ble "12:34:56" "";   assert_eq "${#SW_CAND[@]}" "13" index_real_ble_candidates
_sw_candidates ble "80:E1:26" "uuid:3082 mfr:004c:12:25"; assert_eq "${#SW_CAND[@]}" "17" index_real_flipper_candidates
# The top-level `declare -gA SW_IX` in lib/match.sh is load-bearing: with NO signatures loaded
# (payload.sh's degraded "no signatures loaded" lap) sw_match_record never prepares, so without
# the declaration the first lookup evaluates "w:AA:BB:CC" as arithmetic and errors on EVERY record.
assert_eq "$(bash -c 'set -u; source "$1/lib/match.sh"; sw_match_record "wifi|AA:BB:CC:00:00:01|Net|-50" ""; echo "rc=$?"' _ "$SW_ROOT" 2>&1)" "rc=0" index_empty_rules_clean_noop
# control: the same fresh-shell probe does report a hit when there is one
assert_contains "$(bash -c 'set -u; source "$1/lib/match.sh"; sw_match_record "wifi|AA:BB:CC:00:00:01|Net|-50" "wifi_oui|AA:BB:CC|x|X|low|attacker"' _ "$SW_ROOT" 2>&1)" "x|X|low" index_fresh_shell_control
unset SW_SIGS_CACHE
unset _IX_SYN _IX_LAST _ix_recs _ix_real _ix_all _ix_broken _ix_ok _ixg _IFIX
unset -f _ix_run _ix_fullscan _ix_compare
