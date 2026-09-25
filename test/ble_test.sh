#!/bin/bash
# test/ble_test.sh — sw_ble_scan end-to-end through test/stubs/{btmon,hcitool,hciconfig}.
SW_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../payloads/user/reconnaissance/squachwatch" && pwd)"
_FIX="$(cd "$(dirname "${BASH_SOURCE[0]}")/fixtures" && pwd)"
source "$SW_ROOT/lib/match.sh"; source "$SW_ROOT/lib/ble.sh"
export SW_TMP_DIR="$(mktemp -d)"            # keep captures out of the dev box's /tmp
export SW_FAKE_BTMON="$_FIX/btmon_synthetic.txt"

_recs="$(sw_ble_scan 1 hci0)"
assert_contains "$_recs" "ble|80:E1:26:00:00:01|Flipper aa|-55|uuid:3082" ble_scan_via_btmon
assert_contains "$_recs" "ble|AA:00:00:00:00:01||-80|sd:fd5a:02" ble_scan_carries_tokens
assert_eq "$(cat "$SW_TMP_DIR/sw_ble.state")" "ok" ble_scan_records_health
# the capture file is removed (positive control: the state file proves this dir was used)
assert_empty "$(ls "$SW_TMP_DIR" | grep -v '^sw_ble.state$')" ble_scan_removes_capture

# a scan that never started: no records, and a WARN (not a silent empty lap)
: > "$SW_STUB_LOG"
_recs="$(SW_FAKE_BTMON="$_FIX/btmon_scan_failed.txt" sw_ble_scan 1 hci0)"
assert_empty "$_recs" ble_scan_failed_no_records
assert_contains "$(cat "$SW_STUB_LOG")" "BLE scan failed to start" ble_scan_failed_warns

# an hcitool that ignores SIGINT must not hang the lap (-k backstop). Outer 12 s guard so
# a regression FAILS instead of hanging the suite; stderr hides bash's "Killed" notice.
SECONDS=0
SW_FAKE_LESCAN_IGNORE_INT=1 timeout 12 bash -c 'source "$1/lib/match.sh"; source "$1/lib/ble.sh"; sw_ble_scan 1 hci0 >/dev/null' _ "$SW_ROOT" 2>/dev/null
_rc=$?; _el=$SECONDS
assert_eq "$([ "$_rc" -ne 124 ] && [ "$_el" -lt 8 ] && echo bounded || echo "hung rc=$_rc ${_el}s")" "bounded" ble_scan_bounded_if_int_ignored

# no temp space (mktemp fails): a loud, change-only WARN, never a silent empty lap every lap.
# Control: the normal scan at the top of this file succeeded in a valid SW_TMP_DIR.
_cf_tmp="$SW_TMP_DIR/no-such-dir"; _cf_state="$SW_TMP_DIR/cf.state"
_cf_msg='WARN: BLE capture failed (no temp space?) — BLE detection OFF'
: > "$SW_STUB_LOG"
_recs="$(SW_TMP_DIR="$_cf_tmp" SW_BLE_STATE_FILE="$_cf_state" sw_ble_scan 1 hci0 2>/dev/null)"; _rc=$?
assert_eq "$_rc" "1" ble_capture_failed_rc
assert_empty "$_recs" ble_capture_failed_no_records
assert_eq "$(grep -cF "$_cf_msg" "$SW_STUB_LOG")" "1" ble_capture_failed_warns
_recs="$(SW_TMP_DIR="$_cf_tmp" SW_BLE_STATE_FILE="$_cf_state" sw_ble_scan 1 hci0 2>/dev/null)"
assert_eq "$(grep -cF "$_cf_msg" "$SW_STUB_LOG")" "1" ble_capture_failed_warns_once

rm -rf "$SW_TMP_DIR"
unset SW_TMP_DIR SW_FAKE_BTMON _FIX _recs _rc _el _cf_tmp _cf_state _cf_msg
