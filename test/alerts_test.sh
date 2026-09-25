ALERTS="$(cd "$(dirname "${BASH_SOURCE[0]}")/../payloads/alerts" && pwd)"
FIXDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/fixtures" && pwd)"
: > "$SW_STUB_LOG"
_ALERT_DENIAL_SOURCE_MAC_ADDRESS="AA:BB:CC:00:00:01" \
_ALERT_DENIAL_AP_MAC_ADDRESS="DE:AD:BE:EF:00:02" \
  bash "$ALERTS/deauth_flood_detected/squachwatch_deauth/payload.sh"
assert_contains "$(cat "$SW_STUB_LOG")" "ALERT " deauth_alert
assert_contains "$(cat "$SW_STUB_LOG")" "AA:BB:CC:00:00:01" deauth_src

: > "$SW_STUB_LOG"
SW_OUI_FILE="$FIXDIR/oui.txt" \
_ALERT_CLIENT_CONNECTED_CLIENT_MAC_ADDRESS="F0:F5:A5:11:22:33" \
_ALERT_CLIENT_CONNECTED_SSID="Guest" \
  bash "$ALERTS/pineapple_client_connected/squachwatch_client/payload.sh"
cc="$(cat "$SW_STUB_LOG")"
assert_contains "$cc" "ALERT " client_alert
assert_contains "$cc" "Guest" client_ssid
# vendor lookup against real oui.txt format (colon OUI, TAB, field 2): F0:F5:A5 -> Google
assert_contains "$cc" "Google" client_vendor_lookup

# handshake payload: conveys AP mac + type, colored cyan (attacker class, not white)
: > "$SW_STUB_LOG"
_ALERT_HANDSHAKE_TYPE="eapol" _ALERT_HANDSHAKE_AP_MAC_ADDRESS="AA:BB:CC:DD:EE:FF" \
  bash "$ALERTS/handshake_captured/squachwatch_handshake/payload.sh"
hs="$(cat "$SW_STUB_LOG")"
assert_contains "$hs" "ALERT " handshake_alert
assert_contains "$hs" "AA:BB:CC:DD:EE:FF" handshake_ap
assert_contains "$hs" "LOG cyan" handshake_color

# auth payload: must convey the REAL event data (positive control — a static-string
# ALERT or the wrong _ALERT_ variable would not contain the username/summary).
: > "$SW_STUB_LOG"
_ALERT_AUTH_SUMMARY="mschapv2 challenge for corp\\bob" _ALERT_AUTH_TYPE="mschapv2" _ALERT_AUTH_USERNAME="bob" \
  bash "$ALERTS/pineapple_auth_captured/squachwatch_auth/payload.sh"
au="$(cat "$SW_STUB_LOG")"
assert_contains "$au" "ALERT " auth_alert
assert_contains "$au" "bob" auth_conveys_data
