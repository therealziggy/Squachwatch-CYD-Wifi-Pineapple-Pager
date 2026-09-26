# test/signatures_test.sh (sourced by run.sh; SW_ROOT set below)
SW_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../payloads/user/reconnaissance/squachwatch" && pwd)"
_FIX="$(cd "$(dirname "${BASH_SOURCE[0]}")/fixtures" && pwd)"
source "$SW_ROOT/lib/match.sh"; source "$SW_ROOT/lib/ble.sh"
SIGS="$(sw_load_signatures "$SW_ROOT/signatures.db")"

# every non-comment line has exactly 6 pipe-fields, a valid confidence, and a valid threat_class
# (confidence typos like "hgih" would silently downgrade a high-confidence signature to log-only)
bad="$(printf '%s\n' "$SIGS" | awk -F'|' 'NF!=6 || ($5!="high" && $5!="med" && $5!="low") || ($6!="surveillance" && $6!="tracker" && $6!="attacker"){print}')"
assert_empty "$bad" sig_format_valid

# Tier-1 anchors present and firing
assert_contains "$(sw_match_record 'wifi|70:C9:4E:11:22:33||-40' "$SIGS")" "flock" seed_flock
assert_contains "$(sw_match_record 'ble|80:E1:26:00:00:01|Flipper|' "$SIGS")" "flipper" seed_flipper
assert_contains "$(sw_match_record 'wifi|00:00:00:00:00:00|xPineapplex|' "$SIGS")" "pineapple" seed_pineapple

# every match_type is one the matcher implements: a typo (ble_mrf) would otherwise be
# silently ignored by sw_match_record's catch-all arm
_types_awk='$1!="wifi_oui" && $1!="wifi_ssid_sub" && $1!="wifi_ssid_pre" && $1!="ble_name_sub" && $1!="ble_oui" && $1!="ble_mfr" && $1!="ble_uuid" {print}'
assert_empty "$(printf '%s\n' "$SIGS" | awk -F'|' "$_types_awk")" sig_match_types_known
assert_contains "$(printf 'ble_mrf|004c|x|x|med|tracker\n' | awk -F'|' "$_types_awk")" "ble_mrf" sig_match_type_check_catches_typo
assert_empty "$(printf 'wifi_ssid_pre|ab3-|x|x|high|surveillance\n' | awk -F'|' "$_types_awk")" sig_match_type_pre_known

# Tier-3 seeds against the REAL 2026-09-22 capture, through the real parser
_live="$(sw_btmon_parse < "$_FIX/btmon_live_2026-09-22.txt" | sw_match_stream "$SIGS")"
assert_contains "$_live" "tracker_findmy|Apple Find My (separated)|med|tracker|ble|F9:C1:A3:83:F0:48||-96" seed_live_findmy_separated
assert_empty "$(printf '%s\n' "$_live" | grep -E 'FB:E5:3D:E8:87:19|D3:FC:B3:1C:81:E4|6C:E3:68:45:20:97')" seed_live_nearowner_and_nearby_silent
# the Flipper is still caught via the btmon path (OUI rule: its name is "MyFlipper")
assert_contains "$_live" "hacker_flipper|Flipper Zero|high|attacker|ble|80:E1:26:FA:D6:22" seed_live_flipper_via_btmon

# Tier-3 seeds against the synthetic capture
_syn="$(sw_btmon_parse < "$_FIX/btmon_synthetic.txt" | sw_match_stream "$SIGS")"
assert_contains "$_syn" "tracker_smarttag|Samsung SmartTag|med|tracker|ble|AA:00:00:00:00:01" seed_smarttag
assert_contains "$_syn" "tracker_tile|Tile|med|tracker|ble|AA:00:00:00:00:02" seed_tile_uuid
assert_contains "$_syn" "tracker_gfmd|Google Find My (separated)|med|tracker|ble|AA:00:00:00:00:03" seed_gfmd
assert_contains "$_syn" "surveillance_raven|Raven gunshot sensor (possible)|low|surveillance|ble|AA:00:00:00:00:05" seed_raven
assert_empty "$(printf '%s\n' "$_syn" | grep -E 'AA:00:00:00:00:04|AA:00:00:00:00:07')" seed_eddystone_and_out_of_range_silent
unset _types_awk _live _syn _FIX

# Tier-3 seeds against a REAL capture (2026-09-23): the user's Android phone (nRF Connect)
# advertised a SmartTag-, Tile-, Google-Find-My- and Eddystone-shaped packet at once, next to
# live neighbourhood devices. This replaces "synthetic values" with btmon's real rendering.
_PFIX="$(cd "$(dirname "${BASH_SOURCE[0]}")/fixtures" && pwd)/btmon_phone_2026-09-23.txt"
_ph="$(sw_btmon_parse < "$_PFIX" | sw_match_stream "$SIGS")"
assert_contains "$_ph" "tracker_smarttag|Samsung SmartTag|med|tracker|ble|59:02:79:40:BB:92" phone_smarttag_service_data
assert_contains "$_ph" "tracker_tile|Tile|med|tracker|ble|6E:DA:56:72:20:21" phone_tile_uuid16
assert_contains "$_ph" "tracker_gfmd|Google Find My (separated)|med|tracker|ble|75:61:15:76:65:B8" phone_gfmd_frame_41
# the Eddystone packet shares UUID 0xFEAA and MUST stay silent...
assert_empty "$(printf '%s\n' "$_ph" | grep '5F:64:DB:66:E7:27')" phone_eddystone_silent
# ...and that silence is real, not a parse miss: the same device IS in the parsed records
assert_contains "$(sw_btmon_parse < "$_PFIX")" "ble|5F:64:DB:66:E7:27||-63|sd:feaa:10" phone_eddystone_parsed
unset _PFIX _ph

# Apple Proximity Pairing (0x07): an AirTag in setup mode is flagged; AirPods/Beats never are
_PPFIX="$(cd "$(dirname "${BASH_SOURCE[0]}")/fixtures" && pwd)/btmon_apple_pp.txt"
_ppm="$(sw_btmon_parse < "$_PPFIX" | sw_match_stream "$SIGS")"
assert_contains "$_ppm" "tracker_airtag_setup|Apple AirTag (setup mode)|med|tracker|ble|AA:00:00:00:00:A1" seed_airtag_setup
assert_contains "$_ppm" "tracker_airtag_setup|Apple AirTag (setup mode)|med|tracker|ble|AA:00:00:00:00:A6" seed_airtag_setup_multi_tlv
assert_empty "$(printf '%s\n' "$_ppm" | grep -E 'AA:00:00:00:00:A[2345]')" seed_airpods_beats_silent
# control: the silent ones WERE parsed with their 0x07 model tokens (silence is real, not a miss)
assert_eq "$(sw_btmon_parse < "$_PPFIX" | grep -c 'mfr:004c:07:audio:')" "3" seed_airpods_beats_parsed
unset _PPFIX _ppm

# A Flipper matched by its NAME ALONE is med, as in SquachWatch-CYD ("the owner can change
# it"): on 2026-09-23 a BLE Spam flood of random MACs named "Flipper 🐬" raised 9 full
# alerts in one lap. Its hardware prefix still makes a real Flipper high.
assert_contains "$SIGS" "ble_name_sub|flipper|hacker_flipper|Flipper Zero|med|attacker" sig_flipper_name_is_med
assert_eq "$(sw_match_record 'ble|C1:00:00:00:00:01|Flipper 🐬|-55' "$SIGS")" \
  "hacker_flipper|Flipper Zero|med|attacker|ble|C1:00:00:00:00:01|Flipper 🐬|-55" sig_flipper_name_only_med
# guard: a stock Flipper (name AND prefix) is ONE detection, high (Task 1's strongest-wins)
assert_eq "$(sw_match_record 'ble|80:E1:26:00:00:01|Flipper aa|-60' "$SIGS")" \
  "hacker_flipper|Flipper Zero|high|attacker|ble|80:E1:26:00:00:01|Flipper aa|-60" sig_stock_flipper_one_high
