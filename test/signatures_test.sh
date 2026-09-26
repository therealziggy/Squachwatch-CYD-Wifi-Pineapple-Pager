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
assert_contains "$(sw_match_record 'wifi|B4:1E:52:11:22:33||-40' "$SIGS")" "flock_generic|Flock Safety device|high" seed_flock
assert_contains "$(sw_match_record 'ble|80:E1:26:00:00:01|Flipper|' "$SIGS")" "flipper" seed_flipper
assert_contains "$(sw_match_record 'wifi|00:00:00:00:00:00|Pineapple_1A2B|' "$SIGS")" "hacker_pineapple|WiFi Pineapple setup network|med" seed_pineapple

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

# --- the CYD signature port (spec 2026-09-26 §3, §8) ---
_P="$SIGS"   # the real, ACTIVE rule set
_PFX="$(cd "$(dirname "${BASH_SOURCE[0]}")/fixtures" && pwd)"
_pm() { sw_match_record "$1" "$_P"; }
_ptypes='$1!="wifi_oui" && $1!="wifi_ssid_sub" && $1!="wifi_ssid_pre" && $1!="ble_name_sub" && $1!="ble_oui" && $1!="ble_mfr" && $1!="ble_uuid" {print}'
# counts: 83 active rules load, 42 ship switched off
assert_eq "$(printf '%s\n' "$_P" | grep -c .)" "83" port_active_rule_count
assert_eq "$(grep -c '^#off ' "$SW_ROOT/signatures.db")" "42" port_off_rule_count
# every #off line is a complete, valid, low rule once switched on...
_off="$(sed -n 's/^#off //p' "$SW_ROOT/signatures.db")"
assert_empty "$(printf '%s\n' "$_off" | awk -F'|' 'NF!=6 || $5!="low" || ($6!="surveillance" && $6!="tracker" && $6!="attacker") {print}')" port_off_rules_valid_low
assert_empty "$(printf '%s\n' "$_off" | awk -F'|' "$_ptypes")" port_off_rules_known_types
# ...each one hits a device carrying its own prefix (a positive control per rule)...
_miss=""
while IFS='|' read -r _t _pat _c _l _cf _tc; do
  [ "$_t" = wifi_oui ] || { _miss="$_miss $_pat(type)"; continue; }
  [ -n "$(sw_match_record "wifi|$_pat:00:00:01||-50" "$_t|$_pat|$_c|$_l|$_cf|$_tc")" ] || _miss="$_miss $_pat"
done <<< "$_off"
assert_empty "$_miss" port_off_rules_each_hit_when_enabled
# ...and while switched off, none of them loads
assert_empty "$(_pm 'wifi|70:C9:4E:11:22:33||-40')" port_off_chip_prefix_silent
# CYD's rule: a locally administered (self-assigned) address names no vendor, so no ACTIVE
# prefix rule with bit 0x02 of its first octet set may be graded above low
_la=""
while IFS='|' read -r _t _pat _c _l _cf _tc; do
  case "$_t" in wifi_oui|ble_oui) ;; *) continue ;; esac
  [ $(( 16#${_pat:0:2} & 2 )) -ne 0 ] && [ "$_cf" != low ] && _la="$_la $_pat"
done <<< "$_P"
assert_empty "$_la" port_no_active_locally_administered_prefix_above_low
_pat=02:13:37; assert_eq "$(( 16#${_pat:0:2} & 2 ))" "2" port_la_bit_check_control
# the eight chip-vendor prefixes that were "high" Flock rules until 2026-09-26 (Lite-On, USI,
# Silicon Labs blocks, not Flock's) are not active any more
for _o in 70:C9:4E 3C:91:80 D8:F3:BC 14:5A:FC 08:3A:88 58:8E:81 EC:1B:BD 90:35:EA; do
  assert_empty "$(printf '%s\n' "$_P" | grep -F "|$_o|")" "port_regraded_$_o"
done
# Flock
assert_eq "$(_pm 'wifi|B4:1E:52:00:00:01||-50')" "flock_generic|Flock Safety device|high|surveillance|wifi|B4:1E:52:00:00:01||-50" port_flock_registered_prefix
assert_contains "$(_pm 'wifi|00:00:00:00:00:02|FLOCK-7A2C|-50')" "flock_generic|Flock setup network|high" port_flock_setup_ssid
assert_empty "$(_pm 'wifi|00:00:00:00:00:02|myflock-7A2C|-50')" port_flock_setup_ssid_prefix_only
assert_contains "$(_pm 'ble|00:00:00:00:00:03|Flock_Setup|-60')" "flock_generic|Flock setup|high" port_flock_setup_name_high
assert_contains "$(_pm 'ble|00:00:00:00:00:04||-60|mfr:09c8:01:6')" "flock_generic|Flock device (XUNTONG radio)|high" port_flock_xuntong
assert_eq "$(_pm 'ble|00:00:00:00:00:05|Flockhart|-60')" "flock_generic|Flock device|med|surveillance|ble|00:00:00:00:00:05|Flockhart|-60" port_flock_word_stays_med
# Axon
assert_contains "$(_pm 'wifi|00:25:DF:00:00:01||-50')" "surveillance_axon|Axon / Taser device|high" port_axon_prefix
assert_contains "$(_pm 'wifi|00:00:00:00:00:02|AB3-X7Q2|-50')" "surveillance_axon|Axon body camera|high" port_axon_bodycam_ssid
assert_empty "$(_pm 'wifi|00:00:00:00:00:02|LAB2-GUEST|-50')" port_axon_ssid_prefix_only
assert_contains "$(_pm 'ble|00:00:00:00:00:03|Axon Body 3|-60')" "surveillance_axon|Axon device|high" port_axon_name
# plate readers
assert_contains "$(_pm 'wifi|4C:CC:34:00:00:01||-50')" "surveillance_alpr|Motorola plate reader / police|high" port_alpr_motorola
assert_contains "$(_pm 'wifi|0C:BF:15:00:00:01||-50')" "surveillance_alpr|Genetec plate reader|high" port_alpr_genetec
# CYD's old "Vigilant" entry 00:0E:58 is Sonos's block: it must stay out
assert_empty "$(_pm 'wifi|00:0E:58:00:00:01||-50')" port_alpr_not_sonos
# cameras
assert_contains "$(_pm 'wifi|2C:AA:8E:00:00:01||-50')" "surveillance_camera|Wyze camera|high" port_camera_wyze
assert_contains "$(_pm 'wifi|34:D2:70:00:00:01||-50')" "surveillance_camera|Amazon device (possible camera)|med" port_camera_amazon_med
assert_empty "$(_pm 'wifi|00:E0:4C:00:00:01||-50')" port_camera_realtek_switched_off
# Ring
assert_contains "$(_pm 'wifi|50:E4:67:00:00:01||-50')" "surveillance_ring|Ring doorbell / camera|high" port_ring_prefix
assert_contains "$(_pm 'wifi|FC:65:DE:00:00:01||-50')" "surveillance_ring|Amazon / Ring device|med" port_ring_amazon_med
assert_contains "$(_pm 'wifi|00:00:00:00:00:02|Ring-4F2A|-50')" "surveillance_ring|Ring setup network|med" port_ring_setup_ssid
assert_empty "$(_pm 'wifi|00:00:00:00:00:02|Spring-5G|-50')" port_ring_ssid_prefix_only
# card skimmers
assert_contains "$(_pm 'ble|00:00:00:00:00:03|HC-05|-60')" "surveillance_skimmer|Possible card skimmer (HC-05)|high" port_skimmer_hc05
assert_contains "$(_pm 'ble|00:00:00:00:00:03|RN42-1A2B|-60')" "surveillance_skimmer|Possible card skimmer (RN42)|high" port_skimmer_rn42_default_name
assert_contains "$(_pm 'ble|00:00:00:00:00:04||-60|uuid:1101')" "surveillance_skimmer|Possible card skimmer (serial port)|high" port_skimmer_serial_port
# camera glasses
assert_contains "$(_pm 'ble|00:00:00:00:00:04||-60|uuid:fd5f')" "surveillance_glasses|Ray-Ban Meta glasses|med" port_glasses_rayban
assert_contains "$(_pm 'ble|00:00:00:00:00:04||-60|mfr:01ab:02:9')" "surveillance_glasses|Meta device (glasses or headset)|med" port_glasses_meta_company
assert_contains "$(_pm 'ble|00:00:00:00:00:04||-60|mfr:03c2:00:4')" "surveillance_glasses|Snap Spectacles|med" port_glasses_snap
# Raven: CYD's five exact IDs, no longer a range
assert_contains "$(_pm 'ble|00:00:00:00:00:04||-60|uuid:3300')" "surveillance_raven|" port_raven_exact
assert_empty "$(_pm 'ble|00:00:00:00:00:04||-60|uuid:3101')" port_raven_no_longer_a_range
# drones
assert_eq "$(_pm 'ble|00:00:00:00:00:04||-70|sd:fffa:0d')" "surveillance_drone|Drone (Remote ID)|med|surveillance|ble|00:00:00:00:00:04||-70" port_drone_remote_id
# Flipper's exact signatures (its name alone stays med)
assert_contains "$(_pm 'ble|C1:00:00:00:00:01|MyTool|-60|uuid:3083')" "hacker_flipper|Flipper Zero|high" port_flipper_uuid
assert_contains "$(_pm 'ble|C1:00:00:00:00:01||-60|mfr:0e29:01:4')" "hacker_flipper|Flipper Zero|high" port_flipper_company
assert_empty "$(_pm 'ble|C1:00:00:00:00:01||-60|mfr:0fba:01:4')" port_flipper_not_the_copied_wrong_id
assert_empty "$(_pm 'ble|C1:00:00:00:00:01||-60|uuid:3084')" port_flipper_uuid_exact
assert_contains "$(_pm 'wifi|0C:FA:22:00:00:01||-50')" "hacker_flipper|Flipper Devices hardware|high" port_flipper_registered_prefix
# hacker WiFi
assert_eq "$(_pm 'wifi|00:00:00:00:00:02|Pineapple_1A2B|-50')" "hacker_pineapple|WiFi Pineapple setup network|med|attacker|wifi|00:00:00:00:00:02|Pineapple_1A2B|-50" port_pineapple_setup_med
assert_empty "$(_pm 'wifi|00:00:00:00:00:02|MyPineappleNet|-50')" port_pineapple_substring_no_longer_matches
assert_contains "$(_pm 'wifi|00:00:00:00:00:02|pwned|-50')" "hacker_deauther|ESP deauther network|med" port_deauther
assert_empty "$(_pm 'wifi|00:00:00:00:00:02|ipwned|-50')" port_deauther_prefix_only
# the captures give exactly the detections they gave before the port (pinned at 756ac91): none
# of the new IDs appear in them except Flipper's 0x3082, which lands in the same category as
# its 80:E1:26 prefix
_sum() { sw_btmon_parse < "$_PFX/$1.txt" | sw_match_stream "$_P" | cut -d'|' -f1,3 | LC_ALL=C sort | uniq -c | sed 's/^ *//'; }
assert_eq "$(_sum btmon_live_2026-09-22)" "1 hacker_flipper|high
1 tracker_findmy|med" port_real_live_unchanged
assert_eq "$(_sum btmon_phone_2026-09-23)" "1 hacker_flipper|high
1 tracker_findmy|med
1 tracker_gfmd|med
1 tracker_smarttag|med
1 tracker_tile|med" port_real_phone_unchanged
assert_eq "$(_sum btmon_blespam_2026-09-24)" "1 hacker_flipper|high
17 hacker_flipper|med
3 tracker_airtag_setup|med
1 tracker_findmy|med" port_real_blespam_unchanged
assert_eq "$(_sum btmon_apple_pp)" "2 tracker_airtag_setup|med" port_apple_pp_unchanged
assert_eq "$(_sum btmon_synthetic)" "1 flock_battery|high
1 hacker_flipper|high
2 surveillance_raven|low
1 tracker_gfmd|med
2 tracker_smarttag|med
1 tracker_tile|med" port_synthetic_unchanged
assert_eq "$(_sum btmon_hostile)" "1 tracker_findmy|med
1 tracker_tile|med" port_hostile_unchanged
unset _P _PFX _ptypes _off _miss _t _pat _c _l _cf _tc _la _o
unset -f _pm _sum
