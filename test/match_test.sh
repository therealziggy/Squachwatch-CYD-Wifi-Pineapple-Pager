# test/match_test.sh  (sourced by run.sh; SW_ROOT set below)
SW_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../payloads/user/reconnaissance/squachwatch" && pwd)"
source "$SW_ROOT/lib/match.sh"
SIGS='wifi_oui|70:C9:4E|flock_alpr|Flock Falcon camera|high|surveillance
wifi_ssid_sub|pineapple|hacker_pineapple|WiFi Pineapple|high|attacker
ble_name_sub|flipper|hacker_flipper|Flipper Zero|high|attacker'

# OUI extraction
sw_oui '70:c9:4e:aa:bb:cc'; assert_eq "$REPLY" "70:C9:4E" oui_upper

# POSITIVE: a Flock OUI wifi record must produce exactly one detection
det="$(sw_match_record 'wifi|70:C9:4E:11:22:33||-40' "$SIGS")"
assert_contains "$det" "flock_alpr|Flock Falcon camera|high|surveillance|wifi|70:C9:4E:11:22:33||-40" flock_hit

# POSITIVE: ssid substring (case-insensitive) hits pineapple
det2="$(sw_match_record 'wifi|AA:BB:CC:00:11:22|MyPineappleNet|-55' "$SIGS")"
assert_contains "$det2" "hacker_pineapple|WiFi Pineapple|high|attacker|wifi" pineapple_hit

# POSITIVE: ble name hits flipper
det3="$(sw_match_record 'ble|80:E1:26:00:00:01|Flipper aa|' "$SIGS")"
assert_contains "$det3" "hacker_flipper|Flipper Zero|high|attacker|ble" flipper_hit

# NEGATIVE (clean control): unrelated device produces nothing
assert_empty "$(sw_match_record 'wifi|12:34:56:78:9A:BC|HomeWiFi|-60' "$SIGS")" clean_silent

# NON-VACUITY control: remove the Flock sig -> the Flock record now matches nothing
SIGS_NOFLOCK="$(printf '%s\n' "$SIGS" | grep -v flock_alpr)"
assert_empty "$(sw_match_record 'wifi|70:C9:4E:11:22:33||-40' "$SIGS_NOFLOCK")" nonvacuous

# an unknown match_type (here the old draft name ble_company) is ignored, never an error
SIG_CO='ble_company|0x004C|apple_findmy|AirTag/Find My|med|tracker'
assert_empty "$(sw_match_record 'ble|DE:AD:BE:EF:00:01||' "$SIG_CO")" tier3_ignored

# sw_load_signatures strips comment and blank lines
SIGFILE="$(mktemp)"; printf '# comment\n\nwifi_oui|70:C9:4E|flock|Flock|high|surveillance\n' > "$SIGFILE"
assert_eq "$(sw_load_signatures "$SIGFILE")" "wifi_oui|70:C9:4E|flock|Flock|high|surveillance" load_strips
rm -f "$SIGFILE"

# ble_oui positive + negative (clean) control
assert_contains "$(sw_match_record 'ble|80:E1:26:00:00:09||' 'ble_oui|80:E1:26|hacker_flipper|Flipper|high|attacker')" "hacker_flipper" ble_oui_hit
assert_empty "$(sw_match_record 'ble|11:22:33:00:00:09||' 'ble_oui|80:E1:26|hacker_flipper|Flipper|high|attacker')" ble_oui_clean

# sw_match_stream over two records: one hit, one clean -> exactly one detection
stream_sig='wifi_oui|70:C9:4E|flock|Flock|high|surveillance'
stream_out="$(printf '%s\n' 'wifi|70:C9:4E:11:22:33||-40' 'wifi|12:34:56:78:9A:BC|Home|-60' | sw_match_stream "$stream_sig")"
assert_contains "$stream_out" "flock|Flock|high|surveillance|wifi|70:C9:4E:11:22:33||-40" stream_hit
assert_eq "$(printf '%s\n' "$stream_out" | grep -c .)" "1" stream_one

# sw_sanitize_ident removes '|' and control chars; keeps normal text
sw_sanitize_ident 'Ev|il'; assert_eq "$REPLY" "Evil" sanitize_pipe
sw_sanitize_ident "$(printf 'a\tb')"; assert_eq "$REPLY" "ab" sanitize_tab
sw_sanitize_ident 'clean name'; assert_eq "$REPLY" "clean name" sanitize_keep
# evasion resistance: a signature substring split by '|' still matches after sanitize
sw_sanitize_ident 'Fli|pper'
assert_contains "$(sw_match_record "ble|80:E1:26:00:00:01|$REPLY|" 'ble_name_sub|flipper|hacker_flipper|Flipper|high|attacker')" "hacker_flipper" sanitize_evasion

# empty pattern must NOT match everything
assert_empty "$(sw_match_record 'wifi|AA:BB:CC:00:11:22|anything|-50' 'wifi_ssid_sub||x|X|low|attacker')" empty_pat_guard

# --- Tier-3: ble_mfr / ble_uuid over btmon token records (spec §4) ---
_T3='ble_mfr|004c:12:25|tracker_findmy|Apple Find My (separated)|med|tracker
ble_uuid|fd5a|tracker_smarttag|Samsung SmartTag|med|tracker
ble_uuid|feed|tracker_tile|Tile|med|tracker
ble_uuid|feaa:41|tracker_gfmd|Google Find My (separated)|med|tracker
ble_uuid|3100-3500|surveillance_raven|Raven gunshot sensor (possible)|low|surveillance'
# positives (the detection keeps 8 fields: the token field is NOT copied into it)
assert_eq "$(sw_match_record 'ble|F9:C1:A3:83:F0:48||-96|mfr:004c:12:25' "$_T3")" "tracker_findmy|Apple Find My (separated)|med|tracker|ble|F9:C1:A3:83:F0:48||-96" t3_findmy_separated
assert_contains "$(sw_match_record 'ble|AA:00:00:00:00:01||-80|sd:fd5a:02' "$_T3")" "tracker_smarttag|" t3_smarttag_by_service_data
assert_contains "$(sw_match_record 'ble|AA:00:00:00:00:02||-81|uuid:feed' "$_T3")" "tracker_tile|" t3_tile_by_uuid16
assert_contains "$(sw_match_record 'ble|AA:00:00:00:00:03||-82|sd:feaa:41' "$_T3")" "tracker_gfmd|" t3_gfmd_separated
assert_contains "$(sw_match_record 'ble|AA:00:00:00:00:05||-84|uuid:3100' "$_T3")" "surveillance_raven|" t3_raven_low_boundary
assert_contains "$(sw_match_record 'ble|AA:00:00:00:00:06||-85|uuid:3500' "$_T3")" "surveillance_raven|" t3_raven_high_boundary
# negatives, where the false positives live
assert_empty "$(sw_match_record 'ble|FB:E5:3D:E8:87:19||-99|mfr:004c:12:2' "$_T3")" t3_findmy_nearowner_silent
assert_empty "$(sw_match_record 'ble|6C:E3:68:45:20:97||-99|mfr:004c:10:5' "$_T3")" t3_apple_nearby_info_silent
assert_empty "$(sw_match_record 'ble|AA:00:00:00:00:04||-83|sd:feaa:10' "$_T3")" t3_eddystone_not_gfmd
assert_empty "$(sw_match_record 'ble|80:E1:26:FA:D6:22|MyFlipper|-74|uuid:3082' "$_T3")" t3_flipper_uuid_below_raven
assert_empty "$(sw_match_record 'ble|AA:00:00:00:00:07||-86|uuid:3501' "$_T3")" t3_uuid_above_raven
# whole-segment prefix: a near-owner rule must NOT match the separated token...
assert_empty "$(sw_match_record 'ble|F9:C1:A3:83:F0:48||-96|mfr:004c:12:25' 'ble_mfr|004c:12:2|near|Near owner|low|tracker')" t3_mfr_whole_segment
# ...while shorter prefixes DO match on segment boundaries (positive controls)
assert_contains "$(sw_match_record 'ble|F9:C1:A3:83:F0:48||-96|mfr:004c:12:25' 'ble_mfr|004c:12|anyfm|Any Find My|low|tracker')" "anyfm|" t3_mfr_prefix_type
assert_contains "$(sw_match_record 'ble|6C:E3:68:45:20:97||-99|mfr:004c:10:5' 'ble_mfr|004C|apple|Any Apple|low|tracker')" "apple|" t3_mfr_prefix_company_case_insensitive
# the tokens only count on BLE: a wifi record can't match a BLE rule
assert_empty "$(sw_match_record 'wifi|AA:00:00:00:00:02|uuid:feed|-81' "$_T3")" t3_wifi_ignored
# non-vacuity: drop the Find My signature and the separated record matches nothing
assert_empty "$(sw_match_record 'ble|F9:C1:A3:83:F0:48||-96|mfr:004c:12:25' "$(printf '%s\n' "$_T3" | grep -v tracker_findmy)")" t3_nonvacuous
# a 4-field v1-shape record still splits correctly (rssi is not swallowed by an empty 5th field)
assert_contains "$(sw_match_record 'ble|80:E1:26:00:00:01|Flipper aa|-60' 'ble_name_sub|flipper|hacker_flipper|Flipper|high|attacker')" "hacker_flipper|Flipper|high|attacker|ble|80:E1:26:00:00:01|Flipper aa|-60" t3_four_field_record
# ONE malformed token must not abort the stream: $((16#)) on an empty/non-hex UUID used to
# kill the whole sw_match_stream loop, so every later record went unmatched (a blinded lap).
_f1="$(printf '%s\n' 'ble|AA:00:00:00:00:66||-80|sd::41 uuid:zzzz' 'ble|F9:C1:A3:83:F0:48||-96|mfr:004c:12:25' | sw_match_stream "$_T3")"
assert_contains "$_f1" "tracker_findmy|Apple Find My (separated)|med|tracker|ble|F9:C1:A3:83:F0:48||-96" t3_bad_token_does_not_abort_stream
assert_empty "$(printf '%s\n' "$_f1" | grep 'AA:00:00:00:00:66')" t3_bad_tokens_match_nothing
# a good token next to a bad one still range-matches: the bad one is skipped, not fatal
assert_contains "$(sw_match_record 'ble|AA:00:00:00:00:05||-84|sd::41 uuid:3100' "$_T3")" "surveillance_raven|" t3_good_token_after_bad_still_matches
unset _T3 _f1

# --- one detection per record per category: strongest wins (spec 2026-09-23 §3.1) ---
# A device matching two rules of ONE category used to print twice, and the first (maybe
# weaker) hit took its cooldown slot: a med name hit would then swallow a high prefix alert.
_SW2='ble_name_sub|flipper|hacker_flipper|Flipper Zero (by name)|med|attacker
ble_oui|80:E1:26|hacker_flipper|Flipper Zero|high|attacker
ble_name_sub|tile|tracker_tile|Tile tracker|med|tracker
ble_uuid|feed|tracker_tile|Tile|med|tracker
ble_name_sub|bob|flock_generic|Flock device|med|surveillance'
_SW2r='ble_oui|80:E1:26|hacker_flipper|Flipper Zero|high|attacker
ble_name_sub|flipper|hacker_flipper|Flipper Zero (by name)|med|attacker'
# weaker rule first, stronger later -> ONE line, the strong one (assert_eq: no second line)
assert_eq "$(sw_match_record 'ble|80:E1:26:00:00:01|Flipper Al|-60' "$_SW2")" \
  "hacker_flipper|Flipper Zero|high|attacker|ble|80:E1:26:00:00:01|Flipper Al|-60" strongest_wins_later_high
# stronger rule first, weaker later -> the weaker one must not replace it
assert_eq "$(sw_match_record 'ble|80:E1:26:00:00:01|Flipper Al|-60' "$_SW2r")" \
  "hacker_flipper|Flipper Zero|high|attacker|ble|80:E1:26:00:00:01|Flipper Al|-60" strongest_wins_first_high_kept
# a tie keeps the FIRST rule (its label)
assert_eq "$(sw_match_record 'ble|AA:00:00:00:00:02|Tile Mate|-70|uuid:feed' "$_SW2")" \
  "tracker_tile|Tile tracker|med|tracker|ble|AA:00:00:00:00:02|Tile Mate|-70" strongest_wins_tie_first_rule
# different categories on one device are independent: both print, in first-hit order
assert_eq "$(sw_match_record 'ble|80:E1:26:00:00:01|Flipper Bob|-60' "$_SW2")" \
  "hacker_flipper|Flipper Zero|high|attacker|ble|80:E1:26:00:00:01|Flipper Bob|-60
flock_generic|Flock device|med|surveillance|ble|80:E1:26:00:00:01|Flipper Bob|-60" strongest_wins_categories_independent
# control: the name rule alone still matches (the dedupe did not just drop name hits)
assert_eq "$(sw_match_record 'ble|C1:00:00:00:00:01|Flipper Al|-60' "$_SW2")" \
  "hacker_flipper|Flipper Zero (by name)|med|attacker|ble|C1:00:00:00:00:01|Flipper Al|-60" strongest_wins_name_only_control
unset _SW2 _SW2r
