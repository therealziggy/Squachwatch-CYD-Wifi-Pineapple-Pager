SW_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../payloads/user/reconnaissance/squachwatch" && pwd)"
FIX="$(cd "$(dirname "${BASH_SOURCE[0]}")/fixtures" && pwd)"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/helpers/btmon_gen.sh"   # sw_test_btmon_devs
# Point the scanner at fixtures instead of the device, and skip real BLE:
export SW_RECON_DB="$FIX/recon.db"
export SW_BLE_CMD="cat $FIX/btmon_synthetic.txt"     # payload uses SW_BLE_CMD if set (test seam)
export SW_LOOT_DIR="$(mktemp -d)"
export SW_SEEN_FILE="$(mktemp)"; : > "$SW_SEEN_FILE"
export SW_TMP_DIR="$(mktemp -d)"               # RAM-state seam: keeps track.db out of the real /tmp
export SW_TEST_SOURCE=1                      # tells payload.sh not to auto-run main
# The COMMITTED fixture's timestamps age with the repo, so pin the window off for the
# pipeline assertions below. The window itself is tested in wifi_test.sh against a DB
# rebuilt at test time.
export SW_RECENCY_SECS=0
: > "$SW_STUB_LOG"
source "$SW_ROOT/payload.sh"
# The payload's RAM-backed state (track.db) must land in THIS test's temp dir, never in the
# dev box's real /tmp (which would also leak follow state from one run into the next).
assert_contains "$SW_TRACK_FILE" "${SW_TMP_DIR:-unset}/" payload_track_file_in_test_tmp
sw_log_init "$SW_LOOT_DIR"
sw_scan_once
assert_contains "$(cat "$SW_STUB_LOG")" "ALERT " payload_alerts
assert_contains "$(tail -n +2 "$SW_LOOT_DIR/detections.csv")" "flock_generic" payload_logs_flock
# the fixture's Lite-On chip prefix has been a switched-off rule since 2026-09-26: no row for it
# (payload_logs_flock above is the positive control: the same lap wrote the Flock row)
assert_empty "$(grep -F '70:C9:4E' "$SW_LOOT_DIR/detections.csv")" payload_chip_prefix_not_logged
assert_contains "$(cat "$SW_LOOT_DIR/detections.csv")" "hacker_flipper" payload_logs_flipper

# health signal: an unreadable recon DB must warn + report degraded (not silently run WiFi-off)
: > "$SW_STUB_LOG"
SW_RECON_DB=/nonexistent/recon.db sw_healthcheck; hc_rc=$?
hc="$(cat "$SW_STUB_LOG")"
assert_eq "$hc_rc" "1" health_degraded_rc
assert_contains "$hc" "WiFi detection OFF" health_warns
# positive control: readable DB (the fixture) + loaded sigs -> healthy, no WARN
: > "$SW_STUB_LOG"
sw_healthcheck; assert_eq "$?" "0" health_ok_rc
assert_empty "$(grep WARN "$SW_STUB_LOG")" health_ok_no_warn

# health signal: a recon DB that has rows but NONE inside the recency window means the
# DB stopped updating -- WiFi detection is dead and must not read as "all clear".
: > "$SW_STUB_LOG"
SW_STALED="$(mktemp -d)"
python3 "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/tools/build_fixture_db.py" "$SW_STALED/recon.db" >/dev/null
python3 -c "import sqlite3,sys,time; c=sqlite3.connect(sys.argv[1]); c.execute('UPDATE ssid SET time=?',(int(time.time())-86400,)); c.commit()" "$SW_STALED/recon.db"
SW_RECON_DB="$SW_STALED/recon.db" SW_RECENCY_SECS=600 sw_healthcheck; assert_eq "$?" "1" health_stale_rc
assert_contains "$(cat "$SW_STUB_LOG")" "not updating" health_stale_warns
# positive control: same DB, same code path, window OFF -> healthy and silent, proving
# the warning comes from staleness and not merely from pointing at this DB.
: > "$SW_STUB_LOG"
SW_RECON_DB="$SW_STALED/recon.db" SW_RECENCY_SECS=0 sw_healthcheck; assert_eq "$?" "0" health_stale_control_rc
assert_empty "$(grep WARN "$SW_STUB_LOG")" health_stale_control_silent
rm -rf "$SW_STALED"; unset SW_STALED

# sw_cleanup removes the scanner's temp files and kills NOTHING by name: `killall btmon` would
# also stop another program's btmon or hcitool (another payload, an SSH session). The scan's
# own helpers end by themselves (ble_test.sh: ble_orphans_end_by_themselves). killall and
# pkill are stubs that record calls, so the suite never kills real processes on the dev box.
_ct="$(mktemp -d)"; : > "$_ct/sw_ble.AbC123"; : > "$_ct/sw_ble.state"; : > "$_ct/sw_recon.AbC123"; : > "$_ct/keep.me"; : > "$SW_STUB_LOG"
# precondition: here these names resolve to the recording stubs, never to the real tools
_kst="$(command -v killall pkill | sed 's|.*/test/stubs/||' | tr '\n' ' ')"
assert_eq "$_kst" "killall pkill " cleanup_kill_tools_are_stubs
# control: a killall/pkill made from here IS recorded, so an empty record below means "never
# called", not "called but not seen"
[ "$_kst" = "killall pkill " ] && { killall probe-control; pkill probe-control; }
assert_eq "$(grep -cE '^(killall|pkill) probe-control$' "$SW_STUB_LOG")" "2" cleanup_kill_stubs_record_calls
: > "$SW_STUB_LOG"
( SW_TMP_DIR="$_ct" sw_cleanup )
assert_empty "$(grep -E '^(killall|pkill) ' "$SW_STUB_LOG")" cleanup_kills_nothing_by_name
# It removes the BLE health state and any recon DB copy, but leaves a BLE capture to the lap that
# owns it: a lap still running when Stop came reads its capture again (the health check), and
# removes it itself on every path. The next start sweeps anything a lap could not.
assert_empty "$(ls "$_ct" | grep -E '^(sw_ble\.state|sw_recon\.)')" cleanup_removes_state_and_db_copy
assert_eq "$(ls "$_ct" | grep -c '^sw_ble\.AbC123$')" "1" cleanup_leaves_a_live_laps_capture
assert_contains "$(ls "$_ct")" "keep.me" cleanup_leaves_other_files   # control: it is not rm -rf
rm -rf "$_ct"; unset _ct _kst
# ...and nothing in the payloads finds or kills processes by name at all: a startup "kill the
# orphans" would be the same bug, and on BusyBox it is often written `kill $(pidof btmon)`.
# Comment lines are skipped. Proven: the pattern bites on each idiom, and the walk reads the
# payload files (a wrong path would print nothing and pass).
_kn='(^|[^A-Za-z0-9_-])(killall|pkill|pidof|pgrep)([^A-Za-z0-9_-]|$)'
_kp="$(cd "$SW_ROOT/../../.." && pwd)"
assert_eq "$(printf '%s\n' '  killall hcitool btmon' '  kill $(pidof btmon)' 'pgrep -x btmon | xargs kill' | grep -cE "$_kn")" "3" no_kill_by_name_pattern_bites
assert_contains "$(grep -rl 'sw_clear_tmp' "$_kp")" "squachwatch/payload.sh" no_kill_by_name_walk_reads_payloads
assert_empty "$(grep -rnE "$_kn" "$_kp" | grep -vE '^[^:]+:[0-9]+:[[:space:]]*#')" no_kill_by_name_in_payloads
unset _kn _kp

# --- Tier-3 wiring ---
# follow is wired into the lap: with SW_FOLLOW_SECS=0 a tracker escalates on first sight
: > "$SW_STUB_LOG"; : > "$SW_SEEN_FILE"
SW_FOLLOW_SECS=0 sw_scan_once
assert_contains "$(cat "$SW_STUB_LOG")" "following you" payload_follow_alerts
assert_contains "$(cat "$SW_LOOT_DIR/detections.csv")" "tracker_smarttag_follow" payload_follow_logged
# control: with the real default nothing escalates on a first sighting, but presence is logged.
# Fresh CSV: rows left by the scan above would otherwise satisfy this vacuously.
# "${SW_TRACK_FILE:-}" because the variable only exists once Step 3 lands (set -u in RED).
: > "$SW_STUB_LOG"; : > "$SW_SEEN_FILE"; rm -f "${SW_TRACK_FILE:-}"
rm -f "$SW_LOOT_DIR/detections.csv"; sw_log_init "$SW_LOOT_DIR"
sw_scan_once
assert_empty "$(grep 'following you' "$SW_STUB_LOG")" payload_no_follow_on_first_sight
assert_contains "$(cat "$SW_LOOT_DIR/detections.csv")" 'tracker_smarttag,"Samsung SmartTag",med,tracker' payload_presence_logged   # the CSV is comma-delimited with a quoted label

# ignore is wired in before emit AND follow
rm -f "$SW_LOOT_DIR/detections.csv" "${SW_TRACK_FILE:-}"; : > "$SW_SEEN_FILE"; sw_log_init "$SW_LOOT_DIR"
SW_IGNORE_SET=" AA:00:00:00:00:02 " sw_scan_once
assert_empty "$(grep 'AA:00:00:00:00:02' "$SW_LOOT_DIR/detections.csv")" payload_ignore_drops_row
assert_empty "$(grep 'AA:00:00:00:00:02' "${SW_TRACK_FILE:-/dev/null}" 2>/dev/null)" payload_ignore_skips_follow
assert_contains "$(cat "$SW_LOOT_DIR/detections.csv")" "AA:00:00:00:00:01" payload_ignore_control_other_tracker_kept

# btmon missing must be LOUD. The dev box has a real /usr/bin/btmon, so build a PATH with
# only what sw_healthcheck needs and no btmon at all.
_bin="$(mktemp -d)"; _stubs="$(cd "$(dirname "${BASH_SOURCE[0]}")/stubs" && pwd)"
ln -s "$_stubs/LOG" "$_bin/LOG"; ln -s "$_stubs/sqlite3" "$_bin/sqlite3"; ln -s "$(command -v bash)" "$_bin/bash"
: > "$SW_STUB_LOG"
PATH="$_bin" sw_healthcheck; _hc=$?
assert_eq "$_hc" "1" health_btmon_missing_rc
assert_contains "$(cat "$SW_STUB_LOG")" "btmon missing" health_btmon_missing_warns
rm -rf "$_bin"; unset _bin _stubs _hc

# defaults, asserted in a CLEAN process (a lib-level := would otherwise shadow them)
_defs="$(env -u SW_FOLLOW_SECS -u SW_FOLLOW_GAP -u SW_TRACK_FILE -u SW_IGNORE_FILE -u SW_LOOT_DIR -u SW_TMP_DIR \
  bash -c 'SW_TEST_SOURCE=1 . "$1"/payload.sh >/dev/null 2>&1; echo "$SW_FOLLOW_SECS|$SW_FOLLOW_GAP|$SW_TRACK_FILE|$SW_IGNORE_FILE"' _ "$SW_ROOT")"
# track.db is rewritten on every lap for every tracker, so it lives in RAM (/tmp) rather than
# on flash: no flash wear, faster writes. Cost: a reboot restarts the follow clock.
# ignore.txt stays in the loot dir, since it is hand-edited and must survive reboots.
assert_eq "$_defs" "900|300|/tmp/sw_track.db|/root/loot/squachwatch/ignore.txt" payload_default_follow_and_ignore
unset _defs

rm -rf "$SW_LOOT_DIR" "$SW_SEEN_FILE"
# run.sh sources every *_test.sh into one process; unset our exports so they can't
# leak into an alphabetically-later test file (isolation; guards phantom cross-test state).
# --- AUTO SNOOZE wiring: follow alerts only ---
# cooldown 0 + follow_secs 0 => every lap re-emits a fresh follow detection; after 1 free
# alert the SmartTag's follow alert is held on lap 2, while the (non-follow, high) Flipper
# still alerts: the gate is scoped to "following you" alerts, not a blanket mute.
: > "$SW_SEEN_FILE"; rm -f "$SW_TRACK_FILE" "${SW_SNOOZE_FILE:-}"
SW_COOLDOWN=0 SW_KIND_COOLDOWN=0 SW_FOLLOW_SECS=0 SW_SNOOZE_AFTER=1 sw_scan_once
: > "$SW_STUB_LOG"
SW_COOLDOWN=0 SW_KIND_COOLDOWN=0 SW_FOLLOW_SECS=0 SW_SNOOZE_AFTER=1 sw_scan_once
assert_empty "$(grep '^ALERT ' "$SW_STUB_LOG" | grep 'following you')" payload_snooze_holds_follow_alerts
# control: lap 2 DID produce follow detections (their log lines print every lap, ungated)
assert_contains "$(grep '^LOG ' "$SW_STUB_LOG")" "following you" payload_snooze_follow_still_logged
assert_contains "$(grep '^ALERT ' "$SW_STUB_LOG")" "Flipper" payload_snooze_scoped_to_follow

# snooze defaults, in a CLEAN process
_sdefs="$(env -u SW_SNOOZE_AFTER -u SW_SNOOZE_MARGIN_DB -u SW_SNOOZE_RESET_SECS -u SW_SNOOZE_FILE -u SW_TMP_DIR \
  bash -c 'SW_TEST_SOURCE=1 . "$1"/payload.sh >/dev/null 2>&1; echo "$SW_SNOOZE_AFTER|$SW_SNOOZE_MARGIN_DB|$SW_SNOOZE_RESET_SECS|$SW_SNOOZE_FILE"' _ "$SW_ROOT")"
assert_eq "$_sdefs" "3|7|1800|/tmp/sw_snooze.db" payload_default_snooze
unset _sdefs

# --- noise control (spec 2026-09-23-squachwatch-noise-control-design.md) ---
# generator self-check (positive control for every flood test below): the parser reads it
assert_eq "$(sw_test_btmon_devs C1:00:00:00:00 9 'Flipper 🐬' -55 | sw_btmon_parse | grep -c 'Flipper')" "9" noise_gen_parses_9_devices
# A BLE Spam-style flood of name-only "Flipper" devices logs every device but never buzzes.
rm -f "$SW_LOOT_DIR/detections.csv" "${SW_TRACK_FILE:-}"; : > "$SW_SEEN_FILE"; sw_log_init "$SW_LOOT_DIR"; : > "$SW_STUB_LOG"
SW_RECON_DB=/nonexistent/recon.db SW_BLE_CMD="sw_test_btmon_devs C1:00:00:00:00 9 'Flipper 🐬' -55" sw_scan_once
assert_empty "$(grep '^ALERT ' "$SW_STUB_LOG")" noise_name_only_flipper_flood_no_alert
assert_eq "$(grep -c '^[0-9]*,hacker_flipper,"Flipper Zero",med,' "$SW_LOOT_DIR/detections.csv")" "9" noise_name_only_flipper_flood_all_rows
# control: the synthetic capture's stock Flipper (name + 80:E1:26 prefix) still alerts
: > "$SW_SEEN_FILE"; : > "$SW_STUB_LOG"
sw_scan_once
assert_contains "$(grep -A1 '^ALERT Flipper Zero' "$SW_STUB_LOG")" "80:E1:26:00:00:01" noise_stock_flipper_still_alerts
# one alert per kind, through the real lap: 9 new "Penguin" devices (flock_battery, high)
rm -f "$SW_LOOT_DIR/detections.csv"; : > "$SW_SEEN_FILE"; sw_log_init "$SW_LOOT_DIR"; : > "$SW_STUB_LOG"
SW_RECON_DB=/nonexistent/recon.db SW_BLE_CMD="sw_test_btmon_devs C2:00:00:00:00 9 Penguin -60" sw_scan_once
assert_eq "$(grep -c '^ALERT ' "$SW_STUB_LOG")" "1" noise_kind_flood_one_alert
assert_eq "$(grep -c ',flock_battery,' "$SW_LOOT_DIR/detections.csv")" "9" noise_kind_flood_all_rows
# the next lap brings 9 MORE new devices of the same kind: still inside the window, no alert
: > "$SW_STUB_LOG"
SW_RECON_DB=/nonexistent/recon.db SW_BLE_CMD="sw_test_btmon_devs C3:00:00:00:00 9 Penguin -60" sw_scan_once
assert_empty "$(grep '^ALERT ' "$SW_STUB_LOG")" noise_kind_next_lap_quiet
assert_eq "$(grep -c ',flock_battery,' "$SW_LOOT_DIR/detections.csv")" "18" noise_kind_next_lap_rows_kept
# default, asserted in a CLEAN process
assert_eq "$(env -u SW_KIND_COOLDOWN bash -c 'SW_TEST_SOURCE=1 . "$1"/payload.sh >/dev/null 2>&1; echo "$SW_KIND_COOLDOWN"' _ "$SW_ROOT")" "600" payload_default_kind_cooldown

# screen cap: 9 name-only Flippers in one lap -> 3 device lines + "...and 6 more Flipper Zero"
rm -f "$SW_LOOT_DIR/detections.csv"; : > "$SW_SEEN_FILE"; sw_log_init "$SW_LOOT_DIR"; : > "$SW_STUB_LOG"
SW_RECON_DB=/nonexistent/recon.db SW_BLE_CMD="sw_test_btmon_devs C1:00:00:00:00 9 'Flipper 🐬' -55" sw_scan_once
assert_eq "$(grep -c '^LOG cyan Flipper Zero C1:' "$SW_STUB_LOG")" "3" noise_cap_three_device_lines
assert_eq "$(grep -cxF 'LOG cyan ...and 6 more Flipper Zero' "$SW_STUB_LOG")" "1" noise_cap_summary_line
assert_eq "$(grep -c ',hacker_flipper,' "$SW_LOOT_DIR/detections.csv")" "9" noise_cap_every_row_kept
# exactly SW_LOG_PER_KIND devices -> no summary line (control: the 3 lines DID print)
: > "$SW_SEEN_FILE"; : > "$SW_STUB_LOG"
SW_RECON_DB=/nonexistent/recon.db SW_BLE_CMD="sw_test_btmon_devs C5:00:00:00:00 3 'Flipper 🐬' -55" sw_scan_once
assert_eq "$(grep -c '^LOG cyan Flipper Zero C5:' "$SW_STUB_LOG")" "3" noise_cap_exactly_three_shown
assert_empty "$(grep -F '...and' "$SW_STUB_LOG")" noise_cap_no_summary_at_limit
# two kinds are capped separately
: > "$SW_SEEN_FILE"; : > "$SW_STUB_LOG"
SW_RECON_DB=/nonexistent/recon.db SW_BLE_CMD="sw_test_btmon_devs C1:00:00:00:00 5 'Flipper 🐬' -55; sw_test_btmon_devs C2:00:00:00:00 5 Penguin -60" sw_scan_once
assert_eq "$(grep -cxF 'LOG cyan ...and 2 more Flipper Zero' "$SW_STUB_LOG")" "1" noise_cap_kind_a
assert_eq "$(grep -cxF 'LOG magenta ...and 2 more Flock Penguin battery' "$SW_STUB_LOG")" "1" noise_cap_kind_b
# counts restart every lap (same 5 devices again: 3 lines again, not 0)
: > "$SW_STUB_LOG"
SW_RECON_DB=/nonexistent/recon.db SW_BLE_CMD="sw_test_btmon_devs C1:00:00:00:00 5 'Flipper 🐬' -55" sw_scan_once
assert_eq "$(grep -c '^LOG cyan Flipper Zero C1:' "$SW_STUB_LOG")" "3" noise_cap_resets_each_lap
# default, asserted in a CLEAN process
assert_eq "$(env -u SW_LOG_PER_KIND bash -c 'SW_TEST_SOURCE=1 . "$1"/payload.sh >/dev/null 2>&1; echo "$SW_LOG_PER_KIND"' _ "$SW_ROOT")" "3" payload_default_log_per_kind

# screen counters are keyed by category AND confidence (I1, spec §5): a real high-confidence
# Flipper gets its OWN per-lap allowance, separate from a same-category med (name-only) flood,
# so its line is never folded behind the fakes' summary and vice versa.
: > "$SW_SEEN_FILE"; : > "$SW_STUB_LOG"
SW_RECON_DB=/nonexistent/recon.db SW_BLE_CMD="sw_test_btmon_devs 80:E1:26:00:00 5 'Flipper x' -50; sw_test_btmon_devs C1:00:00:00:00 5 'Flipper 🐬' -55" sw_scan_once
assert_eq "$(grep -c '^LOG cyan Flipper Zero 80:E1:26:' "$SW_STUB_LOG")" "3" noise_cap_by_confidence_high_shown
assert_eq "$(grep -c '^LOG cyan Flipper Zero C1:' "$SW_STUB_LOG")" "3" noise_cap_by_confidence_med_shown
assert_eq "$(grep -cxF 'LOG cyan ...and 2 more Flipper Zero' "$SW_STUB_LOG")" "2" noise_cap_by_confidence_two_summaries

# the follow floor is wired into the lap (payload default -85): a weak tracker never follows...
rm -f "$SW_TRACK_FILE"; : > "$SW_SEEN_FILE"; : > "$SW_STUB_LOG"
SW_FOLLOW_SECS=0 SW_RECON_DB=/nonexistent/recon.db SW_BLE_CMD="sw_test_btmon_devs C6:00:00:00:00 1 Tile -95" sw_scan_once
assert_empty "$(grep 'following you' "$SW_STUB_LOG")" noise_floor_weak_tracker_no_follow
assert_contains "$(grep '^LOG ' "$SW_STUB_LOG")" "Tile tracker C6:00:00:00:00:01" noise_floor_weak_tracker_still_logged
# ...control: the same tracker at -70 escalates at once with SW_FOLLOW_SECS=0
rm -f "$SW_TRACK_FILE"; : > "$SW_SEEN_FILE"; : > "$SW_STUB_LOG"
SW_FOLLOW_SECS=0 SW_RECON_DB=/nonexistent/recon.db SW_BLE_CMD="sw_test_btmon_devs C6:00:00:00:00 1 Tile -70" sw_scan_once
assert_contains "$(cat "$SW_STUB_LOG")" "following you" noise_floor_strong_tracker_follows
# default, asserted in a CLEAN process
assert_eq "$(env -u SW_FOLLOW_MIN_RSSI bash -c 'SW_TEST_SOURCE=1 . "$1"/payload.sh >/dev/null 2>&1; echo "$SW_FOLLOW_MIN_RSSI"' _ "$SW_ROOT")" "-85" payload_default_follow_floor
# I6: SET but EMPTY must stay empty (off), not get replaced by the default. payload.sh must
# use ": \"\${VAR=default}\"" (no colon), since ":=" treats empty the same as unset.
assert_eq "$(SW_FOLLOW_MIN_RSSI= bash -c 'SW_TEST_SOURCE=1 . "$1"/payload.sh >/dev/null 2>&1; echo "[$SW_FOLLOW_MIN_RSSI]"' _ "$SW_ROOT")" "[]" payload_follow_floor_empty_stays_empty
# sw_prune_ledger keeps entries for the LONGER of the two windows
_pn="$(date +%s)"
printf '%s\n' "AA:00:00:00:00:01|x|$((_pn - 300))" "AA:00:00:00:00:02|y|$((_pn - 100000))" > "$SW_SEEN_FILE"
SW_COOLDOWN=100 SW_KIND_COOLDOWN=500 sw_prune_ledger
assert_eq "$(cat "$SW_SEEN_FILE")" "AA:00:00:00:00:01|x|$((_pn - 300))" noise_prune_keeps_longer_window
printf '%s\n' "AA:00:00:00:00:01|x|$((_pn - 300))" "AA:00:00:00:00:06|z|$((_pn - 50))" > "$SW_SEEN_FILE"
SW_COOLDOWN=100 SW_KIND_COOLDOWN=0 sw_prune_ledger
# M21: a mutant that used keep="$k" (i.e. SW_KIND_COOLDOWN, ignoring SW_COOLDOWN) survived the
# 300s-only version of this test, since 300s is older than BOTH 100 and 0 either way. The 50s
# line discriminates: kept under the real keep=max(100,0)=100, dropped under the mutant's
# keep=0. One assert_eq checks both the drop and the keep.
assert_eq "$(cat "$SW_SEEN_FILE")" "AA:00:00:00:00:06|z|$((_pn - 50))" noise_prune_cooldown_only_when_kind_off
# sw_main prunes at STARTUP: a real run (SW_TEST_SOURCE emptied so payload.sh auto-runs
# sw_main), stopped by timeout. SW_HEALTH_EVERY=0, so only the startup call can prune.
_mt="$(mktemp -d)"
printf '%s\n' "AA:00:00:00:00:01|old|$((_pn - 100000))" "AA:00:00:00:00:02|new|$(date +%s)" > "$_mt/seen.db"
SW_TEST_SOURCE= SW_SEEN_FILE="$_mt/seen.db" SW_LOOT_DIR="$_mt/loot" SW_TMP_DIR="$_mt" SW_SLEEP=1 SW_HEALTH_EVERY=0 \
  SW_BLE_CMD=true SW_RECON_DB=/nonexistent/recon.db timeout 2 bash "$SW_ROOT/payload.sh" >/dev/null 2>&1
assert_empty "$(grep '|old|' "$_mt/seen.db")" noise_main_prunes_at_startup
assert_contains "$(cat "$_mt/seen.db")" "|new|" noise_main_prune_keeps_recent
# ...and every SW_HEALTH_EVERY laps: an entry young enough to survive the startup prune (keep =
# 2 s) is gone within a few laps
printf '%s\n' "AA:00:00:00:00:03|aging|$(date +%s)" > "$_mt/seen.db"
SW_TEST_SOURCE= SW_SEEN_FILE="$_mt/seen.db" SW_LOOT_DIR="$_mt/loot" SW_TMP_DIR="$_mt" SW_SLEEP=1 SW_HEALTH_EVERY=1 \
  SW_COOLDOWN=2 SW_KIND_COOLDOWN=0 SW_BLE_CMD=true SW_RECON_DB=/nonexistent/recon.db timeout 5 bash "$SW_ROOT/payload.sh" >/dev/null 2>&1
assert_empty "$(grep '|aging|' "$_mt/seen.db")" noise_main_prunes_periodically
rm -rf "$_mt"; unset _mt _pn
# The Pager's Stop ends the payload without running its EXIT/INT/TERM trap (seen on the device
# 2026-09-27: the launcher logged the stop as a kill, and sw_ble.state was still in /tmp
# afterwards), so a stopped run's temp files stay in RAM until sw_main clears them at the next
# start. `timeout -s KILL` ends each run below without its trap too (a TERM would run the trap,
# and the trap would remove the files itself); `2>/dev/null` hides the shell's "Killed" notice.
_kt="$(mktemp -d)"; : > "$_kt/sw_ble.AbC123"; echo scan_failed > "$_kt/sw_ble.state"; : > "$_kt/sw_recon.AbC123"; : > "$_kt/keep.me"
{ SW_TEST_SOURCE= SW_SEEN_FILE="$_kt/seen.db" SW_LOOT_DIR="$_kt/loot" SW_TMP_DIR="$_kt" SW_SLEEP=1 SW_HEALTH_EVERY=0 \
  SW_BLE_CMD=true SW_RECON_DB=/nonexistent/recon.db timeout -s KILL 2 bash "$SW_ROOT/payload.sh" >/dev/null 2>&1; } 2>/dev/null
_rc=$?
# controls: the run was KILLed (137), so its own trap cannot have removed the files; and it did
# start in this dir
assert_eq "$_rc" "137" main_killed_run_control_killed
assert_eq "$([ -f "$_kt/loot/detections.csv" ] && echo started)" "started" main_killed_run_control_started
# the seeded leftovers are gone, checked by name (a fresh copy the KILLed run left itself must
# not count either way)
assert_empty "$(for f in sw_ble.AbC123 sw_ble.state; do [ -e "$_kt/$f" ] && echo "$f"; done)" main_clears_killed_runs_ble_temp
assert_empty "$([ -e "$_kt/sw_recon.AbC123" ] && echo sw_recon.AbC123)" main_clears_killed_runs_recon_copy
assert_contains "$(ls "$_kt")" "keep.me" main_clear_leaves_other_files   # control: not rm -rf
# A restart after such a stop must WARN again about a BLE scan that is still failing. The old
# run's "scan_failed" state would mark that WARN as already shown: the new run would say
# "armed" and never mention BLE. Real scan path (SW_BLE_CMD empty) through the stubs. The old
# state is written by the scanner's own code, so a renamed state file can't make this pass.
_kw='WARN: BLE scan failed to start'
_sw_run_failing_scan() {
  { SW_TEST_SOURCE= SW_SEEN_FILE="$_kt/seen.db" SW_LOOT_DIR="$_kt/loot" SW_TMP_DIR="$_kt" SW_SLEEP=1 SW_HEALTH_EVERY=0 \
    SW_BLE_CMD= SW_BLE_SECONDS=1 SW_FAKE_BTMON="$FIX/btmon_scan_failed.txt" SW_RECON_DB=/nonexistent/recon.db \
    timeout -s KILL 5 bash "$SW_ROOT/payload.sh" >/dev/null 2>&1; } 2>/dev/null
}
# control: with no leftover state the same run WARNs, once (the fixture and path produce it)
rm -rf "${_kt:?}"/*; : > "$SW_STUB_LOG"; _sw_run_failing_scan
assert_eq "$(grep -cF "$_kw" "$SW_STUB_LOG")" "1" main_scan_failed_control_warns
rm -rf "${_kt:?}"/*; ( SW_TMP_DIR="$_kt" sw_ble_health_note scan_failed ); : > "$SW_STUB_LOG"
# control: the seeded state is where the scanner reads it back (the same state again is silent)
( SW_TMP_DIR="$_kt" sw_ble_health_note scan_failed )
assert_empty "$(grep -F "$_kw" "$SW_STUB_LOG")" main_seeded_state_is_read_back
_sw_run_failing_scan
assert_eq "$(grep -cF "$_kw" "$SW_STUB_LOG")" "1" main_rewarns_after_killed_run
rm -rf "$_kt"; unset -f _sw_run_failing_scan; unset _kt _kw _rc
# Name-agnostic: whatever temp files a lap leaves when it dies before its own cleanup (here every
# `rm` is shadowed, so nothing is removed), sw_clear_tmp removes them all. A capture, state or DB
# copy renamed out of the sweep's globs fails this.
_lt="$(mktemp -d)"
(
  export SW_TMP_DIR="$_lt"
  rm() { :; }
  sw_wifi_records "$FIX/recon.db" >/dev/null
  SW_FAKE_BTMON="$FIX/btmon_synthetic.txt" sw_ble_scan 1 hci0 >/dev/null
)
# control: the lap did leave its files (DB copy, BLE capture, BLE state), so "none left" is not vacuous
assert_eq "$(ls -A "$_lt" | wc -l | tr -d ' ')" "3" sweep_lap_leaves_three_temp_files
( SW_TMP_DIR="$_lt" sw_clear_tmp )
assert_empty "$(ls -A "$_lt")" sweep_clears_every_temp_file_a_lap_leaves
rm -rf "$_lt"; unset _lt
# --- the Pager's Stop (measured 2026-09-27 with a probe payload launched from the menu) ---
# Stop sends SIGINT and then SIGKILL, ~1 s later, to the payload's MAIN shell only; the lap's
# subshells get no signal at all. So the trap must run at once, not after the lap, and a lap
# already running must finish without alerting, buzzing, logging or writing CSV rows.
bash -c 'exit 0' & _dead=$!; wait "$_dead"
rm -f "$SW_LOOT_DIR/detections.csv"; : > "$SW_SEEN_FILE"; sw_log_init "$SW_LOOT_DIR"; : > "$SW_STUB_LOG"
SW_MAIN_PID="$_dead" sw_scan_once
assert_empty "$(grep -E '^(ALERT|VIBRATE|RINGTONE|LOG) ' "$SW_STUB_LOG")" stopped_lap_emits_nothing
assert_eq "$(wc -l < "$SW_LOOT_DIR/detections.csv" | tr -d ' ')" "1" stopped_lap_writes_no_csv_row
# control: the same lap with the main shell alive does alert (fresh cooldown ledger, so this does
# not depend on what the lap above wrote)
: > "$SW_SEEN_FILE"; : > "$SW_STUB_LOG"; sw_scan_once
assert_contains "$(grep '^ALERT ' "$SW_STUB_LOG")" "Flipper" stopped_lap_control_alerts
# A SW_MAIN_PID inherited from the environment (a leftover export in an SSH shell) must not
# silence a real run: sw_main sets it to its own PID. Before, a dead one turned all detection off.
_it="$(mktemp -d)"; : > "$SW_STUB_LOG"
{ SW_MAIN_PID="$_dead" SW_TEST_SOURCE= SW_SEEN_FILE="$_it/seen.db" SW_LOOT_DIR="$_it/loot" SW_TMP_DIR="$_it" SW_SLEEP=1 SW_HEALTH_EVERY=0 \
  timeout 3 bash "$SW_ROOT/payload.sh" >/dev/null 2>&1; } 2>/dev/null
assert_contains "$(grep '^ALERT ' "$SW_STUB_LOG")" "Flipper" main_ignores_inherited_main_pid
rm -rf "$_it"; unset _dead _it
# A Stop that lands inside one detection's report must not let that detection's "following you"
# escalation fire. The LOG stub kills the stand-in main shell during the tracker's own screen
# line; SW_FOLLOW_SECS=0 escalates a tracker on first sight. Input: one SmartTag at -80 dBm.
_tag="$(mktemp)"; sed -n 43,52p "$FIX/btmon_synthetic.txt" > "$_tag"
_ft="$(mktemp -d)"
_sw_follow_lap() {   # $1 = the PID the LOG stub kills ("" = none)
  rm -f "$_ft"/* "$SW_LOOT_DIR/detections.csv"; : > "$SW_SEEN_FILE"; sw_log_init "$SW_LOOT_DIR"; : > "$SW_STUB_LOG"
  SW_MAIN_PID="$_fm" SW_STUB_STOP_ON_LOG="$1" SW_FOLLOW_SECS=0 SW_TRACK_FILE="$_ft/track.db" SW_SNOOZE_FILE="$_ft/snooze.db" \
    SW_RECON_DB=/nonexistent/recon.db SW_BLE_CMD="cat '$_tag'" sw_scan_once
}
# control: with the main shell alive, the SmartTag escalates to a full "following" alert
sleep 30 & _fm=$!; _sw_follow_lap ""
assert_contains "$(grep -A1 '^ALERT ' "$SW_STUB_LOG")" "AA:00:00:00:00:01" follow_control_escalates
kill "$_fm" 2>/dev/null; wait "$_fm" 2>/dev/null
sleep 30 & _fm=$!; _sw_follow_lap "$_fm"; wait "$_fm" 2>/dev/null
assert_contains "$(cat "$SW_STUB_LOG")" "Samsung SmartTag" follow_stopped_control_presence_logged
assert_empty "$(grep -E '^(ALERT|VIBRATE) ' "$SW_STUB_LOG")" follow_stopped_mid_report_no_escalation
rm -rf "$_ft" "$_tag"; unset -f _sw_follow_lap; unset _ft _tag _fm
# End to end, the way the Pager does it. python3 restores the default SIGINT before exec'ing the
# payload: a background job of this script starts with SIGINT ignored, and bash can never trap a
# signal ignored at entry. It also restores SIGPIPE and SIGXFSZ, which python itself ignores, so
# the payload starts the way the launcher starts it (only SIGQUIT ignored).
_st="$(mktemp -d)"; _sc="$(mktemp -d)"
_sw_start_real() {   # $1 = the run's dir -> _sp = the payload's main shell
  SW_TEST_SOURCE= SW_SEEN_FILE="$1/seen.db" SW_LOOT_DIR="$1/loot" SW_TMP_DIR="$1" SW_SLEEP=1 SW_HEALTH_EVERY=0 \
    SW_BLE_CMD= SW_BLE_SECONDS=1 SW_FAKE_BTMON="$FIX/btmon_synthetic.txt" SW_RECON_DB=/nonexistent/recon.db \
    python3 -c 'import os, signal as s, sys; [s.signal(n, s.SIG_DFL) for n in (s.SIGINT, s.SIGPIPE, s.SIGXFSZ)]; os.execvp("bash", ["bash"] + sys.argv[1:])' \
    "$SW_ROOT/payload.sh" >/dev/null 2>&1 &
  _sp=$!
}
# control: left alone, the first lap alerts on the fixture's Flipper (through the real scan path)
: > "$SW_STUB_LOG"; _sw_start_real "$_sc"
for _i in $(seq 80); do grep -q '^ALERT Flipper' "$SW_STUB_LOG" && break; sleep 0.1; done
{ kill -KILL "$_sp"; wait "$_sp"; } 2>/dev/null
assert_contains "$(grep '^ALERT ' "$SW_STUB_LOG")" "Flipper" stop_control_first_lap_alerts
sleep 1.5                                 # whatever that run's lap still had to do, it has done
# the Pager's Stop, in the middle of the first lap's BLE scan
: > "$SW_STUB_LOG"; _sw_start_real "$_st"
for _i in $(seq 50); do ls "$_st" | grep -qE '^sw_ble\.[A-Za-z0-9]{6}$' && break; sleep 0.1; done
kill -INT "$_sp"
for _i in $(seq 20); do kill -0 "$_sp" 2>/dev/null || break; sleep 0.05; done    # the ~1 s grace
_alive="$(kill -0 "$_sp" 2>/dev/null && echo yes || echo no)"
{ kill -KILL "$_sp"; wait "$_sp"; } 2>/dev/null; _rc=$?
assert_eq "$_alive/$_rc" "no/0" stop_trap_runs_within_the_grace
sleep 3                                   # the lap that was running: its 1 s scan runs out
assert_empty "$(grep -E '^(ALERT|VIBRATE|RINGTONE) ' "$SW_STUB_LOG")" stop_lap_in_progress_never_alerts
assert_empty "$(grep -F 'Flipper' "$SW_STUB_LOG")" stop_lap_in_progress_logs_nothing
assert_empty "$(ls "$_st" | grep -E '^sw_(ble|recon)\.')" stop_leaves_no_temp_files
# ...and a Stop during the pause between laps (the Pager waits SW_SLEEP=3 s of every ~20 s cycle)
# must not wait for the pause either. A 5 s pause and no scan: poll for the pause's `sleep`, a
# child of the main shell, then Stop.
rm -rf "${_st:?}"/*
SW_TEST_SOURCE= SW_SEEN_FILE="$_st/seen.db" SW_LOOT_DIR="$_st/loot" SW_TMP_DIR="$_st" SW_SLEEP=5 SW_HEALTH_EVERY=0 \
  SW_BLE_CMD=true SW_RECON_DB=/nonexistent/recon.db \
  python3 -c 'import os, signal as s, sys; [s.signal(n, s.SIG_DFL) for n in (s.SIGINT, s.SIGPIPE, s.SIGXFSZ)]; os.execvp("bash", ["bash"] + sys.argv[1:])' \
  "$SW_ROOT/payload.sh" >/dev/null 2>&1 &
_sp=$!
for _i in $(seq 50); do pgrep -P "$_sp" -x sleep >/dev/null && break; sleep 0.1; done
_pz="$(pgrep -P "$_sp" -x sleep)"; _inpause="$([ -n "$_pz" ] && echo yes || echo no)"
kill -INT "$_sp"
for _i in $(seq 20); do kill -0 "$_sp" 2>/dev/null || break; sleep 0.05; done
_alive="$(kill -0 "$_sp" 2>/dev/null && echo yes || echo no)"
{ kill -KILL "$_sp"; wait "$_sp"; } 2>/dev/null; _rc=$?
assert_eq "$_inpause" "yes" stop_pause_control_was_in_the_pause
assert_eq "$_alive/$_rc" "no/0" stop_during_pause_runs_trap_within_the_grace
[ -n "$_pz" ] && kill $_pz 2>/dev/null     # the pause's own sleep, orphaned when the payload exited
rm -rf "$_st" "$_sc"; unset -f _sw_start_real; unset _st _sc _sp _i _alive _rc _inpause _pz
# REAL Flipper BLE Spam capture: name-only "Flipper" adverts from random MACs. Counts come from
# the matcher, so the test pins behaviour, not today's numbers. _nf counts EVERY Flipper-kind
# device (the user's real Flipper, if captured, is the same kind for the screen cap and CSV);
# _nn counts the name-only ones, the flood itself.
_bs="$FIX/btmon_blespam_2026-09-24.txt"
_dets="$(sw_btmon_parse < "$_bs" | sw_match_stream "$SW_SIGS")"
_nf="$(printf '%s\n' "$_dets" | grep -c '^hacker_flipper|')"
_nn="$(printf '%s\n' "$_dets" | grep -c '^hacker_flipper|Flipper Zero|med|')"
assert_eq "$([ "$_nn" -ge 5 ] && echo y)" "y" spam_fixture_is_a_flood
rm -f "$SW_LOOT_DIR/detections.csv"; : > "$SW_SEEN_FILE"; sw_log_init "$SW_LOOT_DIR"; : > "$SW_STUB_LOG"
SW_RECON_DB=/nonexistent/recon.db SW_BLE_CMD="cat '$_bs'" sw_scan_once
# no full alert names a name-only device (only a real 80:E1:26 Flipper may alert)
assert_empty "$(grep -A1 '^ALERT Flipper Zero' "$SW_STUB_LOG" | grep -vE '^(ALERT|--$)' | grep -v '80:E1:26')" spam_no_name_only_alert
# positive control (I5, closes M15): the real Flipper's alert IS present in this same lap --
# proves the check above is a real filter, not an empty log passing vacuously.
assert_contains "$(grep -A1 '^ALERT Flipper Zero' "$SW_STUB_LOG")" "80:E1:26:FA:D6:22" spam_real_flipper_alerts
# screen counters are keyed by category AND confidence (I1): the real high-confidence Flipper
# gets its own allowance, so 3 name-only lines + the real Flipper's own line = 4 cyan lines.
assert_eq "$(grep -c '^LOG cyan Flipper Zero ' "$SW_STUB_LOG")" "4" spam_flipper_lines_3_fake_plus_real
assert_contains "$(grep '^LOG cyan Flipper Zero 80:E1:26:FA:D6:22' "$SW_STUB_LOG")" "80:E1:26:FA:D6:22" spam_real_flipper_line_visible
assert_eq "$(grep -cxF "LOG cyan ...and $((_nn - 3)) more Flipper Zero" "$SW_STUB_LOG")" "1" spam_summary_line
assert_eq "$(grep -c ',hacker_flipper,' "$SW_LOOT_DIR/detections.csv")" "$_nf" spam_every_row_kept
# IMPORTANT (final review 2): a LEADING-ZERO ledger line for one of THIS fixture's real spam
# MACs must not blank the whole lap. Bash reads a leading zero as octal, and "0800" is not
# valid octal (no digit 8 in base 8), so $((now - last)) used to raise a fatal arithmetic error
# that aborted the rest of the lap -- every device's CSV row and log line that lap were lost,
# not just this one MAC's.
printf 'FA:76:9E:C0:52:35|hacker_flipper|0800\n' > "$SW_SEEN_FILE"
rm -f "$SW_LOOT_DIR/detections.csv"; sw_log_init "$SW_LOOT_DIR"; : > "$SW_STUB_LOG"
SW_RECON_DB=/nonexistent/recon.db SW_BLE_CMD="cat '$_bs'" sw_scan_once
assert_eq "$(grep -c ',hacker_flipper,' "$SW_LOOT_DIR/detections.csv")" "$_nf" spam_leading_zero_ledger_still_writes_all_rows
# control: the lap ran end-to-end, not just "happened to count right" -- the real Flipper (a
# different MAC entirely) still alerts in the same lap.
assert_contains "$(grep -A1 '^ALERT Flipper Zero' "$SW_STUB_LOG")" "80:E1:26:FA:D6:22" spam_leading_zero_control_real_flipper_still_alerts
unset _bs _dets _nf _nn
# --- end noise control ---
rm -rf "$SW_LOOT_DIR" "$SW_SEEN_FILE"

rm -rf "$SW_TMP_DIR"
unset SW_RECON_DB SW_BLE_CMD SW_LOOT_DIR SW_SEEN_FILE SW_TEST_SOURCE SW_RECENCY_SECS SW_FOLLOW_SECS SW_FOLLOW_GAP SW_TRACK_FILE SW_IGNORE_FILE SW_IGNORE_SET SW_TMP_DIR SW_SNOOZE_AFTER SW_SNOOZE_MARGIN_DB SW_SNOOZE_RESET_SECS SW_SNOOZE_FILE SW_KIND_COOLDOWN SW_LOG_PER_KIND SW_FOLLOW_MIN_RSSI

# --- config defaults (regression: a lib default must not pre-empt the payload's) ---
# lib/wifi.sh used to run `: "${SW_RECENCY_SECS:=0}"`, and payload.sh sources its libs
# BEFORE its own config block -- so the operational default of 600 never took effect and
# the scanner swept the entire 20k-row history every lap. The tests above pin the window
# explicitly, which is exactly why they could not see it; this asserts the real default
# by sourcing payload.sh in a clean process with nothing preset.
SW_DEFAULTS="$(env -u SW_RECENCY_SECS -u SW_RECON_DB -u SW_BLE_CMD -u SW_LOOT_DIR -u SW_SEEN_FILE \
  bash -c 'SW_TEST_SOURCE=1 . "$1"/payload.sh >/dev/null 2>&1; echo "$SW_RECENCY_SECS"' _ "$SW_ROOT")"
assert_eq "$SW_DEFAULTS" "600" payload_default_recency_window
unset SW_DEFAULTS

# --- launched from the Pager UI (regression, found on-device 2026-09-23) ---
# The Pager does NOT run payload.sh in place: its launcher writes a copy to
# /tmp/payload-<n>.sh (adding a Hak5 header), exports PAYLOAD_HOME=<real dir>/, cds there
# and runs the copy. Finding lib/ via BASH_SOURCE then meant /tmp: all 8 libs failed to
# load, SW_SIGS was empty, and every lap was a silent no-op that only the "no signatures
# loaded" health WARN hinted at. Every earlier on-device run was `bash payload.sh` over
# SSH, so neither it nor the tests (which source the file in place) could see this.
_sw_probe_load() {  # $1 = file to source -> "libs|<signature count>"
  bash -c 'SW_TEST_SOURCE=1 . "$1" >/dev/null 2>&1
    declare -F sw_match_stream >/dev/null && printf libs
    printf "|%s" "$(printf "%s\n" "$SW_SIGS" | grep -c .)"' _ "$1"
}
_lc="$(mktemp -d)"; cp "$SW_ROOT/payload.sh" "$_lc/payload-123.sh"
_direct="$(unset PAYLOAD_HOME; _sw_probe_load "$SW_ROOT/payload.sh")"
# control: the probe can see a healthy load (libs defined, signatures non-empty)
assert_contains "$_direct" "libs|" payload_probe_control_libs
assert_eq "$([ "${_direct#*|}" -gt 0 ] 2>/dev/null && echo y)" "y" payload_probe_control_sigs
_launched="$(cd "$SW_ROOT" && export PAYLOAD_HOME="$SW_ROOT/" && _sw_probe_load "$_lc/payload-123.sh")"
assert_eq "$_launched" "$_direct" payload_launcher_copy_loads_libs_and_sigs
# ...and when it cannot find its files at all it must stop LOUDLY, never loop blind.
_lg="$(mktemp)"
( unset PAYLOAD_HOME; SW_STUB_LOG="$_lg" SW_TEST_SOURCE=1 timeout 20 bash "$_lc/payload-123.sh" >/dev/null 2>&1 ); _rc=$?
assert_eq "$_rc" "1" payload_missing_home_exits_nonzero
assert_contains "$(cat "$_lg")" "LOG red" payload_missing_home_logs_red
assert_contains "$(cat "$_lg")" "NOT running" payload_missing_home_says_not_running
rm -rf "$_lc" "$_lg"; unset _lc _lg _rc _direct _launched; unset -f _sw_probe_load
unset -f sw_test_btmon_devs
