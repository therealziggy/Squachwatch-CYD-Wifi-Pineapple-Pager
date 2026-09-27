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

# The Pager's Stop signals only the payload's main shell (measured 2026-09-27: SIGINT, then
# SIGKILL ~1 s later), so nothing stops the scan's helpers (and payload.sh kills nothing by
# name). Each helper must end on its OWN within the scan's bound. Run a scan in its own shell,
# SIGKILL that shell mid-scan, and watch the helpers' PIDs.
_pids="$SW_TMP_DIR/stub.pids"; : > "$_pids"
SW_STUB_PIDS="$_pids" bash -c 'source "$1/lib/match.sh"; source "$1/lib/ble.sh"; sw_ble_scan 1 hci0 >/dev/null' _ "$SW_ROOT" 2>/dev/null &
_sp=$!
sleep 1.5                     # btmon starts at ~0 s and hcitool at ~1 s (secs=1): both mid-scan
kill -9 "$_sp" 2>/dev/null; wait "$_sp" 2>/dev/null
_sw_alive() { local p n=0; while read -r p; do kill -0 "$p" 2>/dev/null && n=$((n + 1)); done < "$_pids"; echo "$n"; }
# control: both helpers were alive when their shell died, so "none left" below is not vacuous
assert_eq "$(_sw_alive)" "2" ble_orphans_alive_after_kill
# bound for secs=1: hcitool gets INT at 1 s (+2 s kill-after), btmon TERM at 4 s (+2 s)
SECONDS=0; while [ "$(_sw_alive)" != 0 ] && [ "$SECONDS" -lt 10 ]; do sleep 0.2; done
assert_eq "$(_sw_alive)" "0" ble_orphans_end_by_themselves
unset -f _sw_alive; unset _pids _sp

# A lap already running when Stop killed the main shell lives on in its subshells. It must not
# start a scan (a relaunched payload may be using the adapter) or report scan health (that report
# would land on the relaunched payload's screen). SW_MAIN_PID is the test seam for "the main
# shell" ($$ in the payload); a child that has exited and been waited for is certainly gone.
bash -c 'exit 0' & _dead=$!; wait "$_dead"
_pids="$SW_TMP_DIR/stub.pids"; : > "$_pids"; rm -f "$SW_TMP_DIR/sw_ble.state"
_recs="$(SW_MAIN_PID="$_dead" SW_STUB_PIDS="$_pids" sw_ble_scan 1 hci0)"
assert_empty "$_recs" ble_stopped_payload_no_records
assert_empty "$(cat "$_pids")" ble_stopped_payload_starts_no_scan
assert_eq "$([ -e "$SW_TMP_DIR/sw_ble.state" ] && echo written)" "" ble_stopped_payload_no_health_state
# ...and a lap whose main shell dies DURING its scan drops the capture unread. The hcitool stub
# kills the stand-in main shell as the scan starts, as a Stop would. This fixture's scan never
# started, so a lap that went on would WARN "scan failed" (with a live main shell the same
# fixture does: ble_scan_failed_warns).
sleep 30 & _fm=$!
# (the SIGKILL test above leaves its capture behind by design: clear it so only this scan counts)
: > "$_pids"; : > "$SW_STUB_LOG"; rm -f "$SW_TMP_DIR/sw_ble.state" "$SW_TMP_DIR"/sw_ble.??????
_recs="$(SW_MAIN_PID="$_fm" SW_STUB_STOP_ON_LESCAN="$_fm" SW_STUB_PIDS="$_pids" SW_FAKE_BTMON="$_FIX/btmon_scan_failed.txt" sw_ble_scan 1 hci0)"
wait "$_fm" 2>/dev/null
# control: the scan did start (btmon and hcitool both ran), so the checks below are not vacuous
assert_eq "$(wc -l < "$_pids" | tr -d ' ')" "2" ble_stopped_mid_scan_control_scan_started
assert_empty "$(grep -F 'BLE scan failed' "$SW_STUB_LOG")" ble_stopped_mid_scan_no_false_warn
assert_eq "$([ -e "$SW_TMP_DIR/sw_ble.state" ] && echo written)" "" ble_stopped_mid_scan_no_health_state
assert_empty "$(ls "$SW_TMP_DIR" | grep -E '^sw_ble\.[A-Za-z0-9]{6}$')" ble_stopped_mid_scan_drops_capture
# ...and one whose main shell dies while the capture is being PARSED (a Stop at the very end of
# a scan) reports no health either. The parse is wrapped to kill the stand-in main shell first.
sleep 30 & _fm=$!
: > "$SW_STUB_LOG"; rm -f "$SW_TMP_DIR/sw_ble.state"
(
  eval "_sw_real_awk() $(declare -f _sw_btmon_awk | tail -n +2)"
  _sw_btmon_awk() {
    kill "$_fm" 2>/dev/null
    while [ -e "/proc/$_fm" ] && [ "$(cut -d' ' -f3 "/proc/$_fm/stat" 2>/dev/null)" != Z ]; do sleep 0.01; done
    _sw_real_awk
  }
  SW_MAIN_PID="$_fm" SW_FAKE_BTMON="$_FIX/btmon_scan_failed.txt" sw_ble_scan 1 hci0 >/dev/null
)
wait "$_fm" 2>/dev/null; _rc=$?
# control: the wrapped parse ran and killed the stand-in (143 = ended by SIGTERM)
assert_eq "$_rc" "143" ble_stopped_mid_parse_control_parse_ran
assert_empty "$(grep -F 'BLE scan failed' "$SW_STUB_LOG")" ble_stopped_mid_parse_no_false_warn
assert_eq "$([ -e "$SW_TMP_DIR/sw_ble.state" ] && echo written)" "" ble_stopped_mid_parse_no_health_state
# A main shell that has exited but not yet been reaped by the launcher is a zombie, which
# `kill -0` still finds: sw_stopped must count it as gone. python3 forks a child that exits at
# once and leaves it unreaped for 3 s.
_zf="$(mktemp)"
python3 -c 'import os, time
pid = os.fork()
if pid == 0: os._exit(0)
print(pid, flush=True); time.sleep(3)' > "$_zf" &
_zp=$!
for _i in $(seq 50); do [ -s "$_zf" ] && break; sleep 0.05; done
_z="$(cat "$_zf")"; sleep 0.2
# control: it IS a zombie right now, and kill -0 does find it
assert_eq "$(cut -d' ' -f3 "/proc/$_z/stat" 2>/dev/null)/$(kill -0 "$_z" 2>/dev/null && echo found)" "Z/found" ble_stopped_zombie_control
assert_eq "$(SW_MAIN_PID="$_z" sw_stopped && echo stopped || echo alive)" "stopped" ble_stopped_zombie_main_counts_as_gone
assert_eq "$(SW_MAIN_PID="$_zp" sw_stopped && echo stopped || echo alive)" "alive" ble_stopped_live_main_is_alive
kill "$_zp" 2>/dev/null; wait "$_zp" 2>/dev/null; rm -f "$_zf"
unset _dead _fm _pids _rc _zf _zp _z _i

rm -rf "$SW_TMP_DIR"
unset SW_TMP_DIR SW_FAKE_BTMON _FIX _recs _rc _el _cf_tmp _cf_state _cf_msg
