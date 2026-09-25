SW_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../payloads/user/reconnaissance/squachwatch" && pwd)"
FIX="$(cd "$(dirname "${BASH_SOURCE[0]}")/fixtures" && pwd)"
source "$SW_ROOT/lib/match.sh"; source "$SW_ROOT/lib/wifi.sh"
source "$SW_ROOT/lib/ble.sh"; source "$SW_ROOT/lib/alert.sh"; source "$SW_ROOT/lib/log.sh"

SIGS='wifi_oui|70:C9:4E|flock_alpr|Flock Falcon camera|high|surveillance
wifi_ssid_sub|pineapple|hacker_pineapple|WiFi Pineapple|high|attacker
ble_name_sub|flipper|hacker_flipper|Flipper Zero|high|attacker
ble_name_sub|penguin|flock_battery|Flock Penguin battery|high|surveillance'

LOOT="$(mktemp -d)"; sw_log_init "$LOOT"; SEEN="$(mktemp)"; : > "$SEEN"; : > "$SW_STUB_LOG"

# WiFi chain
dets_w="$(sw_wifi_records "$FIX/recon.db" | sw_match_stream "$SIGS")"
assert_contains "$dets_w" "flock_alpr|" e2e_wifi_flock
assert_contains "$dets_w" "hacker_pineapple|" e2e_wifi_pine
# BLE chain
dets_b="$(sw_btmon_parse < "$FIX/btmon_synthetic.txt" | sw_match_stream "$SIGS")"
assert_contains "$dets_b" "hacker_flipper|" e2e_ble_flipper
assert_contains "$dets_b" "flock_battery|" e2e_ble_penguin

# emit all, assert ALERTs fired for the high-confidence hits
while IFS= read -r d; do [ -n "$d" ] && sw_emit "$d" 1000 600 "$SEEN" "$LOOT"; done <<< "$dets_w
$dets_b"
assert_contains "$(cat "$SW_STUB_LOG")" "ALERT " e2e_alerted
assert_eq "$(grep -c . "$LOOT/detections.csv")" "5" e2e_logged_rows  # header + 4 detections

# CLEAN control: an environment with only HomeWiFi yields zero detections
clean="$(printf 'wifi|12:34:56:78:9A:BC|HomeWiFi|-60\n' | sw_match_stream "$SIGS")"
assert_empty "$clean" e2e_clean_silent
rm -rf "$LOOT" "$SEEN"
