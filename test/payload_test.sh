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
# Laps here do not capture WiFi frames (each would wait out a Remote ID window); the Remote ID lap
# tests below turn it on, and its default (on) is read in a clean process.
export SW_REMOTE_ID=0
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

# health signal: a recon DB that stops recording network security leaves the evil-twin check blind
# (spec 2026-09-29 §7): it would find nothing, forever, and read as "all clear"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/helpers/recon_db.sh"   # sw_test_recon_db
_hb2="$(mktemp -d)"
sw_test_recon_db "$_hb2/null.db" "8,ACDE48000001,,0,-60,30,HomeNet"
: > "$SW_STUB_LOG"
SW_RECON_DB="$_hb2/null.db" SW_RECENCY_SECS=600 sw_healthcheck; assert_eq "$?" "1" health_twin_blind_rc
assert_contains "$(cat "$SW_STUB_LOG")" "evil-twin check is blind" health_twin_blind_warns
# control: the same DB with the check switched off says nothing about it
: > "$SW_STUB_LOG"
SW_EVIL_TWIN=0 SW_RECON_DB="$_hb2/null.db" SW_RECENCY_SECS=600 sw_healthcheck
assert_empty "$(grep -F 'evil-twin' "$SW_STUB_LOG")" health_twin_blind_quiet_when_off
# control: a DB that records security is healthy and silent
sw_test_recon_db "$_hb2/ok.db" "8,ACDE48000001,17184063752,0,-60,30,HomeNet"
: > "$SW_STUB_LOG"
SW_RECON_DB="$_hb2/ok.db" SW_RECENCY_SECS=600 sw_healthcheck; assert_eq "$?" "0" health_twin_ok_rc
assert_empty "$(grep WARN "$SW_STUB_LOG")" health_twin_ok_silent
# ...and leaves no copy behind
assert_empty "$(ls -A "$SW_TMP_DIR" | grep '^sw_recon\.')" health_leaves_no_db_copy
# a quiet spot, one visible network that the Pager recorded without a name (it does that now and
# then), is healthy too: names are judged only with five or more visible rows
sw_test_recon_db "$_hb2/quiet.db" "8,ACDE48000001,17184063752,0,-60,30,"
: > "$SW_STUB_LOG"
SW_RECON_DB="$_hb2/quiet.db" SW_RECENCY_SECS=600 sw_healthcheck; assert_eq "$?" "0" health_quiet_blank_row_rc
assert_empty "$(grep WARN "$SW_STUB_LOG")" health_quiet_blank_row_silent
# control: five visible networks and none of them named is the blind WARN
sw_test_recon_db "$_hb2/noname.db" "8,ACDE48000001,17184063752,0,-60,30," "8,ACDE48000002,17184063752,0,-60,30," \
  "8,ACDE48000003,17184063752,0,-60,30," "8,ACDE48000004,17184063752,0,-60,30," "8,ACDE48000005,17184063752,0,-60,30,"
: > "$SW_STUB_LOG"
SW_RECON_DB="$_hb2/noname.db" SW_RECENCY_SECS=600 sw_healthcheck; assert_eq "$?" "1" health_five_blank_rows_rc
assert_contains "$(cat "$SW_STUB_LOG")" "evil-twin check is blind" health_five_blank_rows_warn
# a copy that can't be made (a full /tmp, say) turns WiFi detection off: that is a WARN too
: > "$SW_STUB_LOG"
SW_TMP_DIR="$_hb2/no-such-dir" SW_RECON_DB="$_hb2/ok.db" SW_RECENCY_SECS=600 sw_healthcheck 2>/dev/null; assert_eq "$?" "1" health_no_copy_rc
assert_contains "$(cat "$SW_STUB_LOG")" "can't copy the recon DB" health_no_copy_warns
# a recon DB damaged for good (here: not a database at all) is a WARN, once a fresh copy reads the same
printf 'this is not a database, only text\n' > "$_hb2/junk.db"
: > "$SW_STUB_LOG"
SW_RECON_DB="$_hb2/junk.db" SW_RECENCY_SECS=600 sw_healthcheck 2>/dev/null; assert_eq "$?" "1" health_damaged_db_rc
assert_contains "$(cat "$SW_STUB_LOG")" "recon DB copy unreadable twice" health_damaged_db_warns
# ...but a copy torn once by a write in progress (the first copy damaged, the next one fine) says nothing
( eval "$(declare -f sw_recon_snapshot | sed '1s/sw_recon_snapshot/_sw_real_snapshot/')"
  sw_recon_snapshot() {
    _sw_real_snapshot "$@" || return 1
    [ -e "$_hb2/torn-once" ] && return 0
    : > "$_hb2/torn-once"; printf 'torn-page-torn-page' | dd of="$REPLY" bs=1 seek=100 conv=notrunc 2>/dev/null
  }
  : > "$SW_STUB_LOG"; SW_RECON_DB="$_hb2/ok.db" SW_RECENCY_SECS=600 sw_healthcheck 2>/dev/null ); assert_eq "$?" "0" health_torn_once_rc
assert_empty "$(grep WARN "$SW_STUB_LOG")" health_torn_once_silent
assert_eq "$([ -e "$_hb2/torn-once" ] && echo yes)" "yes" health_torn_once_control_was_torn
# an unreadable DB gets its own WARN only, not a second, evil-twin one
: > "$SW_STUB_LOG"
SW_RECON_DB=/nonexistent/recon.db sw_healthcheck
assert_contains "$(cat "$SW_STUB_LOG")" "WiFi detection OFF" health_unreadable_control_warns
assert_empty "$(grep -F 'evil-twin' "$SW_STUB_LOG")" health_unreadable_no_twin_warn
# a check left running by a Stop makes no new DB copy
bash -c 'exit 0' & _hbd=$!; wait "$_hbd"
( sw_recon_snapshot() { echo called >> "$_hb2/calls"; return 1; }
  SW_MAIN_PID="$_hbd" SW_RECON_DB="$_hb2/null.db" SW_RECENCY_SECS=600 sw_healthcheck >/dev/null 2>&1 )
assert_eq "$( { cat "$_hb2/calls" 2>/dev/null; } | grep -c called)" "0" health_stopped_check_makes_no_twin_copy
# control: the same check while the payload runs does ask for one
( sw_recon_snapshot() { echo called >> "$_hb2/calls"; return 1; }
  SW_RECON_DB="$_hb2/null.db" SW_RECENCY_SECS=600 sw_healthcheck >/dev/null 2>&1 )
assert_eq "$( { cat "$_hb2/calls" 2>/dev/null; } | grep -c called)" "1" health_running_check_asks_for_a_copy
rm -rf "$_hb2"; unset _hb2 _hbd

# sw_cleanup removes the scanner's temp files and kills NOTHING by name: `killall btmon` would
# also stop another program's btmon or hcitool (another payload, an SSH session). The scan's
# own helpers end by themselves (ble_test.sh: ble_orphans_end_by_themselves). killall and
# pkill are stubs that record calls, so the suite never kills real processes on the dev box.
_ct="$(mktemp -d)"; : > "$_ct/sw_ble.AbC123"; : > "$_ct/sw_ble.state"; : > "$_ct/sw_recon.AbC123"; : > "$_ct/keep.me"; : > "$SW_STUB_LOG"
: > "$_ct/sw_rid.XyZ789"; : > "$_ct/sw_rid.state"
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
# It removes the BLE and Remote ID health states and any recon DB copy, but leaves the BLE and Remote
# ID captures to the lap that owns them: a lap still running when Stop came reads its capture again (the
# health check), and removes it itself on every path. The next start sweeps anything a lap could not.
assert_empty "$(ls "$_ct" | grep -E '^(sw_ble\.state|sw_rid\.state|sw_recon\.)')" cleanup_removes_state_and_db_copy
assert_eq "$(ls "$_ct" | grep -c '^sw_ble\.AbC123$')" "1" cleanup_leaves_a_live_laps_capture
assert_eq "$(ls "$_ct" | grep -c '^sw_rid\.XyZ789$')" "1" cleanup_leaves_a_live_laps_rid_capture
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
# ...and the everyday tools its DB checks use (the health check copies the DB and reads the clock;
# the sqlite3 stand-in runs python3), so btmon is the only thing missing
for _t in cp date mktemp rm python3; do ln -s "$(command -v "$_t")" "$_bin/$_t"; done
: > "$SW_STUB_LOG"
PATH="$_bin" sw_healthcheck; _hc=$?
assert_eq "$_hc" "1" health_btmon_missing_rc
assert_contains "$(cat "$SW_STUB_LOG")" "btmon missing" health_btmon_missing_warns
rm -rf "$_bin"; unset _bin _stubs _hc _t
# A health check left running by a Stop must stay silent (the Stop tests below), so every WARN it
# prints goes through _sw_health_warn, never a bare LOG.
assert_eq "$(declare -f sw_healthcheck | grep -cw LOG)" "0" health_warns_only_through_the_stop_guard
# control: the same grep does see a LOG call in a function body
assert_eq "$(declare -f _sw_health_warn | grep -cw LOG)" "1" health_guard_control_sees_log
# The main shell's own code (startup and the ledger prune: the only loops the Pager's Stop can land
# in) must never `continue` or `break`: bash drops a trapped SIGINT that lands while a loop continues
# or breaks (measured 2026-09-28, bash 5.2: 53 of 300 Stops lost in a `|| continue` loop, 0 of 300 in
# the same loop written with `if`; `break` loses them too), and the run goes on until the SIGKILL.
_mc=0; for _fn in sw_main sw_prune_ledger sw_seen_prune sw_clear_tmp sw_log_init sw_cleanup; do
  declare -F "$_fn" >/dev/null || { _mc="missing $_fn"; break; }
  _mc=$((_mc + $(declare -f "$_fn" | grep -cwE 'continue|break')))
done
assert_eq "$_mc" "0" main_shell_code_never_continues_or_breaks
# control: the same count does see the lap loop's `continue` (it runs in a subshell, which the
# Stop never signals)
assert_eq "$([ "$(declare -f sw_scan_once | grep -cw continue)" -gt 0 ] && echo yes)" "yes" main_shell_continue_probe_control
unset _mc _fn
# ...and the guard itself: silent once the main shell is gone. The Stop tests below cannot show
# this on their own: there the check's DB copy is always gone before it decides, so
# sw_wifi_stale_db already answers "unknown". A WARN that needs no copy (btmon missing, say) is
# decided by this guard alone.
bash -c 'exit 0' & _hd=$!; wait "$_hd"
: > "$SW_STUB_LOG"; SW_MAIN_PID="$_hd" _sw_health_warn "WARN: guard-probe"
assert_empty "$(grep -F guard-probe "$SW_STUB_LOG")" health_warn_silent_once_stopped
# control: the same call with the main shell alive does print
SW_MAIN_PID=$$ _sw_health_warn "WARN: guard-probe"
assert_contains "$(cat "$SW_STUB_LOG")" "guard-probe" health_warn_control_prints_while_running
unset _hd

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
# ...and the ledger prune's temp copy, which lives in the loot dir (on flash, not in RAM), next to
# the ledger itself and files that only look like that temp copy
: > "$_kt/seen.db.sw-prune-tmp.AbC123"; echo keep > "$_kt/seen.db.backup"; echo keep > "$_kt/seen.db.bak"; echo keep > "$_kt/seen.db.prune.before"
printf '%s\n' "AA:00:00:00:00:02|new|$(date +%s)" > "$_kt/seen.db"; _kl="$(cat "$_kt/seen.db")"
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
assert_empty "$([ -e "$_kt/seen.db.sw-prune-tmp.AbC123" ] && echo seen.db.sw-prune-tmp.AbC123)" main_clears_killed_runs_ledger_temp
assert_eq "$(cat "$_kt/seen.db")|$(cat "$_kt/seen.db.backup")|$(cat "$_kt/seen.db.bak")|$(cat "$_kt/seen.db.prune.before")" "$_kl|keep|keep|keep" main_clear_keeps_the_ledger_and_look_alikes
unset _kl
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
_lt="$(mktemp -d)"; _ll="$(mktemp -d)"
(
  export SW_TMP_DIR="$_lt"
  rm() { :; }
  sw_wifi_records "$FIX/recon.db" >/dev/null
  SW_FAKE_BTMON="$FIX/btmon_synthetic.txt" sw_ble_scan 1 hci0 >/dev/null
  export SW_REMOTE_ID=1 SW_RID_SECONDS=1 SW_FAKE_TCPDUMP="$FIX/rid/beacon.txt"
  sw_rid_start 1700000000; SW_RID_FILE= sw_rid_collect 1700000000 "$_ll" >/dev/null
)
# control: the lap did leave its files (DB copy, BLE capture, BLE state, Remote ID capture, its tcpdump
# messages and its state), so "none left" is not vacuous
assert_eq "$(ls -A "$_lt" | wc -l | tr -d ' ')" "6" sweep_lap_leaves_six_temp_files
( SW_TMP_DIR="$_lt" sw_clear_tmp )
assert_empty "$(ls -A "$_lt")" sweep_clears_every_temp_file_a_lap_leaves
rm -rf "$_lt" "$_ll"; unset _lt _ll
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
# ...and a Stop during the health check (review M5), at startup and every SW_HEALTH_EVERY laps. It
# copies the recon DB and counts its rows twice: 0.43-0.56 s on the Pager (33.6k rows, 2026-09-27),
# and each count reads every row, so it grows with the DB. In the foreground a Stop there waited
# for the step under way, and a step longer than the grace ended in the SIGKILL, which left the
# DB copy in RAM until the next start. A test-local sqlite3 answers the check's first count, then
# marks the moment and holds its answer 3 s, on the call chosen by SW_SLOW_AT. The recon DB is
# stale (rows, none in the window), so a check that runs on to its end warns.
_hs="$(mktemp -d)"; mkdir "$_hs/bin"; _hsq="$(command -v sqlite3)"
python3 "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/tools/build_fixture_db.py" "$_hs/recon.db" >/dev/null
python3 -c "import sqlite3,sys,time; c=sqlite3.connect(sys.argv[1]); c.execute('UPDATE ssid SET time=?',(int(time.time())-86400,)); c.commit()" "$_hs/recon.db"
cat > "$_hs/bin/sqlite3" <<'EOF'
#!/usr/bin/env bash
out="$("$SW_SLOW_REAL" "$@")"; rc=$?
if [ "${2:-}" = "SELECT count(*) FROM ssid;" ]; then
  n=$(( $(cat "$SW_SLOW_DIR/calls" 2>/dev/null || echo 0) + 1 )); echo "$n" > "$SW_SLOW_DIR/calls"
  [ "$n" -eq "$SW_SLOW_AT" ] && { : > "$SW_SLOW_DIR/stalled"; sleep 3; }
fi
[ -n "$out" ] && printf '%s\n' "$out"
exit "$rc"
EOF
chmod +x "$_hs/bin/sqlite3"
_sw_start_slow() {   # $1 = which call of the first count stalls, $2 = SW_HEALTH_EVERY -> _sp
  rm -rf "${_hs:?}/run" "$_hs/calls" "$_hs/stalled"; mkdir "$_hs/run"
  PATH="$_hs/bin:$PATH" SW_SLOW_REAL="$_hsq" SW_SLOW_DIR="$_hs" SW_SLOW_AT="$1" \
    SW_TEST_SOURCE= SW_SEEN_FILE="$_hs/run/seen.db" SW_LOOT_DIR="$_hs/run/loot" SW_TMP_DIR="$_hs/run" SW_SLEEP=1 \
    SW_HEALTH_EVERY="$2" SW_BLE_CMD=true SW_RECON_DB="$_hs/recon.db" SW_RECENCY_SECS=600 \
    python3 -c 'import os, signal as s, sys; [s.signal(n, s.SIG_DFL) for n in (s.SIGINT, s.SIGPIPE, s.SIGXFSZ)]; os.execvp("bash", ["bash"] + sys.argv[1:])' \
    "$SW_ROOT/payload.sh" >/dev/null 2>&1 &
  _sp=$!
}
_sw_stop_in_check() {   # the Pager's Stop inside the stalled check -> _inhc _log (before) _alive _rc _kids _left
  for _i in $(seq 80); do [ -e "$_hs/stalled" ] && break; sleep 0.1; done
  _inhc="$([ -e "$_hs/stalled" ] && echo yes || echo no)"
  _kids="$(pgrep -P "$_sp")"
  _log="$(cat "$SW_STUB_LOG")"; : > "$SW_STUB_LOG"
  kill -INT "$_sp"
  for _i in $(seq 20); do kill -0 "$_sp" 2>/dev/null || break; sleep 0.05; done    # the ~1 s grace
  _alive="$(kill -0 "$_sp" 2>/dev/null && echo yes || echo no)"
  { kill -KILL "$_sp"; wait "$_sp"; } 2>/dev/null; _rc=$?
  # the check that was under way goes on by itself: let it end before reading the log
  for _i in $(seq 100); do
    _left=; for _k in $_kids; do kill -0 "$_k" 2>/dev/null && _left=1; done
    [ -z "$_left" ] && break; sleep 0.1
  done
}
# every SW_HEALTH_EVERY laps (here every lap): the second check stalls
: > "$SW_STUB_LOG"; _sw_start_slow 2 1; _sw_stop_in_check
# control: the same run's startup check, on the same DB, did warn, so "nothing after the Stop"
# below is not vacuous
assert_contains "$_log" "not updating" stop_health_control_warns
assert_eq "$_inhc" "yes" stop_periodic_health_control_was_in_the_check
# control: the log below is read only after the check left running has ended (it was found, and
# it is gone), so it had its chance to report
assert_eq "$([ -n "$_kids" ] && [ -z "$_left" ] && echo yes)" "yes" stop_periodic_health_control_waited_for_the_check
assert_eq "$_alive/$_rc" "no/0" stop_during_periodic_health_check_runs_trap_within_the_grace
assert_empty "$(grep -E '^(LOG|ALERT|VIBRATE|RINGTONE) ' "$SW_STUB_LOG")" stop_during_periodic_health_check_reports_nothing
assert_empty "$(ls "$_hs/run" | grep -E '^sw_(ble|recon)\.')" stop_during_periodic_health_check_leaves_no_temp_files
# at startup: the first check stalls
: > "$SW_STUB_LOG"; _sw_start_slow 1 0; _sw_stop_in_check
assert_eq "$_inhc" "yes" stop_startup_health_control_was_in_the_check
assert_eq "$([ -n "$_kids" ] && [ -z "$_left" ] && echo yes)" "yes" stop_startup_health_control_waited_for_the_check
assert_eq "$_alive/$_rc" "no/0" stop_during_startup_health_check_runs_trap_within_the_grace
assert_empty "$(grep -E '^(LOG|ALERT|VIBRATE|RINGTONE) ' "$SW_STUB_LOG")" stop_during_startup_health_check_reports_nothing
assert_empty "$(ls "$_hs/run" | grep -E '^sw_(ble|recon)\.')" stop_during_startup_health_check_leaves_no_temp_files
rm -rf "$_hs"; unset -f _sw_start_slow _sw_stop_in_check; unset _hs _hsq _sp _i _k _kids _left _inhc _log _alive _rc
# ...and a Stop in the first moments, before the first lap. With no trap, bash drops a SIGINT that
# lands during a foreground command (it takes the child's normal exit to mean the child handled
# it), so the run went on until the SIGKILL, or, inside a command substitution, dies from it.
# Test-local `touch` and `mktemp` hold one startup step for 0.3 s, the one whose first argument
# starts with SW_HOLD_ARG, and mark the moment.
_hb="$(mktemp -d)"; mkdir "$_hb/bin" "$_hb/run"; _hbt="$(command -v touch)"; _hbm="$(command -v mktemp)"; _hbg="$(command -v grep)"
cat > "$_hb/bin/touch" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in "${SW_HOLD_ARG:?}"*) : > "$SW_HOLD_MARK"; sleep 0.3 ;; esac
exec "$SW_HOLD_TOUCH" "$@"
EOF
cat > "$_hb/bin/mktemp" <<'EOF'
#!/usr/bin/env bash
out="$("$SW_HOLD_MKTEMP" "$@")"; rc=$?
case "${1:-}" in "${SW_HOLD_ARG:?}"*) : > "$SW_HOLD_MARK"; sleep 0.3 ;; esac
[ -n "$out" ] && printf '%s\n' "$out"
exit "$rc"
EOF
# `grep` holds only on an argument that IS SW_HOLD_ARG: loading the signatures greps their file
cat > "$_hb/bin/grep" <<'EOF'
#!/usr/bin/env bash
for a in "$@"; do [ "$a" = "${SW_HOLD_ARG:?}" ] && { : > "$SW_HOLD_MARK"; sleep 0.3; break; }; done
exec "$SW_HOLD_GREP" "$@"
EOF
chmod +x "$_hb/bin/touch" "$_hb/bin/mktemp" "$_hb/bin/grep"
_sw_start_held() {   # $1 = what the held call gets (touch/mktemp: its start; grep: all of it) -> _sp
  rm -f "$_hb/held"
  SW_HOLD_ARG="$1" SW_HOLD_MARK="$_hb/held" SW_HOLD_TOUCH="$_hbt" SW_HOLD_MKTEMP="$_hbm" SW_HOLD_GREP="$_hbg" PATH="$_hb/bin:$PATH" \
    SW_TEST_SOURCE= SW_SEEN_FILE="$_hb/run/seen.db" SW_LOOT_DIR="$_hb/run/loot" SW_TMP_DIR="$_hb/run" SW_SLEEP=1 \
    SW_HEALTH_EVERY=0 SW_BLE_CMD=true SW_RECON_DB=/nonexistent/recon.db \
    python3 -c 'import os, signal as s, sys; [s.signal(n, s.SIG_DFL) for n in (s.SIGINT, s.SIGPIPE, s.SIGXFSZ)]; os.execvp("bash", ["bash"] + sys.argv[1:])' \
    "$SW_ROOT/payload.sh" >/dev/null 2>&1 &
  _sp=$!
}
_sw_stop_held() {   # the Pager's Stop (or $1, e.g. TERM) during the held step -> _inh _alive _rc
  for _i in $(seq 80); do [ -e "$_hb/held" ] && break; sleep 0.05; done
  _inh="$([ -e "$_hb/held" ] && echo yes || echo no)"
  : > "$SW_STUB_LOG"
  kill -"${1:-INT}" "$_sp"
  for _i in $(seq 20); do kill -0 "$_sp" 2>/dev/null || break; sleep 0.05; done    # the ~1 s grace
  _alive="$(kill -0 "$_sp" 2>/dev/null && echo yes || echo no)"
  { kill -KILL "$_sp"; wait "$_sp"; } 2>/dev/null; _rc=$?
}
# the startup `touch` of the ledger, before the ledger prune and the health check
rm -rf "${_hb:?}/run"; mkdir "$_hb/run"
_sw_start_held "$_hb/run/seen.db"; _sw_stop_held
assert_eq "$_inh" "yes" stop_first_moments_control_was_held
assert_eq "$_alive/$_rc" "no/0" stop_in_first_moments_runs_trap_within_the_grace
assert_empty "$(grep -E '^(LOG|ALERT|VIBRATE|RINGTONE) ' "$SW_STUB_LOG")" stop_in_first_moments_reports_nothing
# ...even earlier, while the libs and signatures load (about a quarter of a second on the Pager),
# before sw_main or its trap exist
rm -rf "${_hb:?}/run"; mkdir "$_hb/run"
_sw_start_held "$SW_ROOT/signatures.db"; _sw_stop_held
assert_eq "$_inh" "yes" stop_while_loading_control_was_held
assert_eq "$_alive/$_rc" "no/0" stop_while_loading_ends_cleanly_within_the_grace
assert_empty "$(grep -E '^(LOG|ALERT|VIBRATE|RINGTONE) ' "$SW_STUB_LOG")" stop_while_loading_reports_nothing
# ...and a TERM there (a shutdown, a kill over SSH) the same way
rm -rf "${_hb:?}/run"; mkdir "$_hb/run"
_sw_start_held "$SW_ROOT/signatures.db"; _sw_stop_held TERM
assert_eq "$_inh/$_alive/$_rc" "yes/no/0" stop_while_loading_term_ends_cleanly
# ...inside the ledger prune's rewrite: the trap ends the run between the prune's mktemp and its mv,
# which left the prune's temp copy of the ledger in the loot dir for good. The ledger holds an
# expired line, so the startup prune rewrites it. Files that only look like that temp copy (a
# hand-made seen.db.backup, say) must survive, and so must the ledger itself, which the prune
# never got to replace.
rm -rf "${_hb:?}/run"; mkdir "$_hb/run"
printf '%s\n' "AA:00:00:00:00:01|old|$(( $(date +%s) - 100000 ))" "AA:00:00:00:00:02|new|$(date +%s)" > "$_hb/run/seen.db"
for _f in seen.db.bak seen.db.backup seen.db.1234567 seen.db.prune.before; do echo keep > "$_hb/run/$_f"; done
_ledger="$(cat "$_hb/run/seen.db")"
_sw_start_held "$_hb/run/seen.db."; _sw_stop_held
assert_eq "$_inh" "yes" stop_in_prune_control_was_held
assert_eq "$_alive/$_rc" "no/0" stop_in_prune_runs_trap_within_the_grace
assert_eq "$(ls "$_hb/run" | LC_ALL=C sort | tr '\n' ' ')" "loot seen.db seen.db.1234567 seen.db.backup seen.db.bak seen.db.prune.before " stop_in_prune_leaves_no_ledger_temp
assert_eq "$(cat "$_hb/run/seen.db")" "$_ledger" stop_in_prune_keeps_the_ledger
assert_eq "$(cat "$_hb/run/seen.db.backup")|$(cat "$_hb/run/seen.db.prune.before")" "keep|keep" stop_in_prune_keeps_look_alikes
rm -rf "$_hb"; unset -f _sw_start_held _sw_stop_held; unset _hb _hbt _hbm _hbg _sp _i _f _inh _alive _rc _ledger
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

# --- evil twin in the lap (spec 2026-09-29) ---
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/helpers/recon_db.sh"   # sw_test_recon_db
_tw="$(mktemp -d)"; _twdb="$_tw/recon.db"
sw_test_recon_db "$_twdb" "8,ACDE48000001,17184063752,0,-60,30,HomeNet" "8,021122334455,0,0,-38,20,HomeNet"
_tw_reset() { rm -f "$SW_LOOT_DIR/detections.csv"; : > "$SW_SEEN_FILE"; sw_log_init "$SW_LOOT_DIR"; : > "$SW_STUB_LOG"; }
# a lap over the twin DB plus one BLE Flipper (proof the lap ran), with a fresh ledger and CSV
_tw_lap() { _tw_reset; SW_RECON_DB="$_twdb" SW_BLE_CMD="sw_test_btmon_devs C1:00:00:00:00 1 'Flipper x' -55" sw_scan_once; }
_tw_lap
assert_contains "$(cat "$SW_STUB_LOG")" "ALERT Evil twin 'HomeNet'" lap_twin_alerts
assert_contains "$(cat "$SW_STUB_LOG")" "LOG cyan Evil twin 'HomeNet' 02:11:22:33:44:55 -38dBm" lap_twin_screen_line
assert_contains "$(cat "$SW_LOOT_DIR/detections.csv")" ',evil_twin,"Evil twin",high,attacker,wifi,02:11:22:33:44:55,"HomeNet",-38,' lap_twin_csv_row
assert_empty "$(ls -A "$SW_TMP_DIR" | grep '^sw_recon\.')" lap_leaves_no_db_copy
# ONE copy per lap: with rm switched off, the copies a lap makes are all still there to count
_tw1="$(mktemp -d)"
( export SW_TMP_DIR="$_tw1"; rm() { :; }; SW_RECON_DB="$_twdb" SW_BLE_CMD=true sw_scan_once >/dev/null 2>&1 )
assert_eq "$(ls -A "$_tw1" | grep -c '^sw_recon\.')" "1" lap_makes_one_db_copy
rm -rf "$_tw1"; unset _tw1
# SW_EVIL_TWIN=0 turns the check off; the same lap still reports the Flipper
SW_EVIL_TWIN=0 _tw_lap
assert_empty "$(grep -F 'Evil twin' "$SW_STUB_LOG")" lap_twin_off_silent
assert_contains "$(cat "$SW_STUB_LOG")" "Flipper" lap_twin_off_control_lap_ran
# a plain ignore.txt address never silences an evil twin (the attacker picks the address; this one
# could be your own Flipper's); only an explicit evil_twin:<MAC> line does
SW_IGNORE_SET=" 02:11:22:33:44:55 " _tw_lap
assert_contains "$(cat "$SW_STUB_LOG")" "ALERT Evil twin 'HomeNet'" lap_twin_not_hidden_by_plain_ignore
SW_IGNORE_SET=" EVIL_TWIN:02:11:22:33:44:55 " _tw_lap
assert_empty "$(grep -F 'Evil twin' "$SW_STUB_LOG")" lap_twin_ignored_by_twin_entry
assert_contains "$(cat "$SW_STUB_LOG")" "Flipper" lap_twin_ignore_control_lap_ran
# three open copies in one lap: every one gets its CSV row, the kind buzzes once
sw_test_recon_db "$_twdb" "8,021122334466,0,0,-50,20,HomeNet" "8,ACDE48000009,17184063752,0,-60,30,Office" "8,021122334477,0,0,-45,20,Office"
_tw_lap
assert_eq "$(grep -c ',evil_twin,' "$SW_LOOT_DIR/detections.csv")" "3" lap_twins_each_get_a_row
assert_eq "$(grep -c '^ALERT Evil twin' "$SW_STUB_LOG")" "1" lap_twins_buzz_once
# decoys cannot hide the real target (the adversarial review's repro): three decoy twins with low
# addresses, then one radio copying two names; every copied name gets its CSV row, the kind buzzes once
sw_test_recon_db "$_tw/decoy.db" "8,000000000001,0,0,-50,20,D1" "8,FEFEFE000001,17184063752,0,-50,20,D1" \
  "8,000000000002,0,0,-50,20,D2" "8,FEFEFE000002,17184063752,0,-50,20,D2" "8,000000000003,0,0,-50,20,D3" \
  "8,FEFEFE000003,17184063752,0,-50,20,D3" "8,021122334455,0,0,-40,10,AAAA" "8,FEFEFE000009,17184063752,0,-50,20,AAAA" \
  "8,ACDE48000001,17184063752,0,-70,20,HomeNet" "8,021122334455,0,0,-40,10,HomeNet"
_tw_reset; SW_RECON_DB="$_tw/decoy.db" SW_BLE_CMD=true sw_scan_once
assert_contains "$(cat "$SW_LOOT_DIR/detections.csv")" ',"HomeNet",' lap_decoys_cannot_hide_the_target
assert_eq "$(grep -c ',evil_twin,' "$SW_LOOT_DIR/detections.csv")" "5" lap_every_copied_name_logged
assert_eq "$(grep -c '^ALERT Evil twin' "$SW_STUB_LOG")" "1" lap_decoys_buzz_once
# a recon DB in WAL mode: a read-only open leaves -wal and -shm files next to its copy, and the lap
# and the health check remove those too (the Pager's recon.db uses a rollback journal today)
sw_test_recon_db "$_tw/wal.db" "8,ACDE48000001,17184063752,0,-60,30,HomeNet" "8,021122334455,0,0,-38,20,HomeNet"
assert_eq "$(python3 -c 'import sqlite3,sys; print(sqlite3.connect(sys.argv[1]).execute("PRAGMA journal_mode=WAL").fetchone()[0])' "$_tw/wal.db")" "wal" lap_wal_control_db_is_wal
_tw_reset; SW_RECON_DB="$_tw/wal.db" SW_BLE_CMD=true sw_scan_once
SW_RECON_DB="$_tw/wal.db" SW_RECENCY_SECS=600 sw_healthcheck >/dev/null 2>&1
SW_TMP_DIR="$SW_TMP_DIR" sw_wifi_records "$_tw/wal.db" >/dev/null
assert_contains "$(cat "$SW_STUB_LOG")" "ALERT Evil twin 'HomeNet'" lap_wal_control_twin_found
assert_empty "$(ls -A "$SW_TMP_DIR" | grep '^sw_recon\.')" lap_wal_leaves_no_files
# the copy is gone before the BLE scan starts (6 MB of RAM freed for the scan's ~12 s)
_tw_reset; SW_RECON_DB="$_twdb" SW_BLE_CMD="ls -A '$SW_TMP_DIR' > '$_tw/during-ble'" sw_scan_once
assert_eq "$([ -e "$_tw/during-ble" ] && echo ran)" "ran" lap_ble_step_control_ran
assert_empty "$(grep '^sw_recon\.' "$_tw/during-ble")" lap_copy_gone_before_ble_scan
# the screen cap: one twin line, then "...and 2 more Evil twin"
SW_LOG_PER_KIND=1 _tw_lap
assert_eq "$(grep -c "^LOG cyan Evil twin '" "$SW_STUB_LOG")" "1" lap_twin_screen_cap
assert_contains "$(cat "$SW_STUB_LOG")" "...and 2 more Evil twin" lap_twin_screen_cap_more_line
# a hostile name reaches the CSV guarded, so a spreadsheet will not run it
sw_test_recon_db "$_tw/hostile.db" "8,ACDE48000001,17184063752,0,-60,30,=HYPERLINK(1)" "8,021122334455,0,0,-38,20,=HYPERLINK(1)"
_tw_reset; SW_RECON_DB="$_tw/hostile.db" SW_BLE_CMD=true sw_scan_once
assert_contains "$(cat "$SW_LOOT_DIR/detections.csv")" ",\"'=HYPERLINK(1)\"," lap_twin_csv_formula_guarded
# a stopped lap reports no twin (the Pager's Stop, above); control: lap_twin_alerts
bash -c 'exit 0' & _twd=$!; wait "$_twd"
_tw_reset; SW_MAIN_PID="$_twd" SW_RECON_DB="$_twdb" SW_BLE_CMD=true sw_scan_once
assert_empty "$(grep -E '^(ALERT|VIBRATE|RINGTONE|LOG) ' "$SW_STUB_LOG")" stopped_lap_reports_no_twin
assert_eq "$(wc -l < "$SW_LOOT_DIR/detections.csv" | tr -d ' ')" "1" stopped_lap_writes_no_twin_row
# the default is ON, read in a clean process (a test that sets a value cannot see its default)
assert_eq "$(env -u SW_EVIL_TWIN bash -c 'SW_TEST_SOURCE=1 . "$1"/payload.sh >/dev/null 2>&1; echo "$SW_EVIL_TWIN"' _ "$SW_ROOT")" "1" payload_default_evil_twin_on
rm -rf "$_tw"; unset _tw _twdb _twd; unset -f _tw_lap _tw_reset
# --- end evil twin ---

# --- Remote ID over WiFi in the lap (spec 2026-10-01) ---
_RFIX2="$(cd "$(dirname "${BASH_SOURCE[0]}")/fixtures" && pwd)/rid"
_rid_reset() { rm -f "$SW_LOOT_DIR/detections.csv" "$SW_LOOT_DIR/remoteid.csv" "$SW_TMP_DIR"/sw_rid.*; : > "$SW_SEEN_FILE"; sw_log_init "$SW_LOOT_DIR"; : > "$SW_STUB_LOG"; }
# _rid_lap FIXTURE: one lap with the capture on (a 1 s window), no recon DB and no BLE devices
_rid_lap() { SW_REMOTE_ID=1 SW_RID_SECONDS=1 SW_FAKE_TCPDUMP="$_RFIX2/$1.txt" SW_RECON_DB=/nonexistent/recon.db SW_BLE_CMD=true sw_scan_once; }
_rid_reset; _rid_lap beacon
# the lap collects its capture once the window ends (it waits for it, in the shell that started it)
assert_contains "$(cat "$SW_STUB_LOG")" "ALERT Drone '0000FSWTEST000000001'" rid_lap_alerts
assert_contains "$(cat "$SW_STUB_LOG")" "LOG magenta   87m up, 12m/s, pilot (live) 47.39800,8.54102" rid_lap_detail_line
assert_contains "$(cat "$SW_LOOT_DIR/remoteid.csv")" ",beacon,80:E1:26:AA:BB:CC,-47,serial," rid_lap_track_row
assert_contains "$(cat "$SW_LOOT_DIR/detections.csv")" ',drone_rid,"Drone",high,surveillance,wifi,80:E1:26:AA:BB:CC,"0000FSWTEST000000001",-47,' rid_lap_detections_row
assert_empty "$(ls -A "$SW_TMP_DIR" | grep '^sw_rid\.' | grep -v '^sw_rid\.state$')" rid_lap_leaves_no_capture
# the next lap: no second alert or detections row (the cooldown), but a second flight-track row
_rid_lap beacon
assert_eq "$(grep -c '^ALERT Drone' "$SW_STUB_LOG")" "1" rid_lap_second_lap_no_second_alert
assert_eq "$(grep -c ',beacon,' "$SW_LOOT_DIR/remoteid.csv")" "2" rid_lap_track_row_every_lap
# the owner's own drone (drone:<ID> in ignore.txt) leaves no trace in the lap either
_rid_reset; SW_IGNORE_SET=" DRONE:0000FSWTEST000000001 " _rid_lap beacon
assert_empty "$(grep -F 'Drone' "$SW_STUB_LOG")" rid_lap_ignored_drone_silent
assert_eq "$([ -e "$SW_LOOT_DIR/remoteid.csv" ] && echo written)" "" rid_lap_ignored_drone_no_track_row
# SW_REMOTE_ID=0: no capture at all (control: rid_lap_alerts, which had one)
_rid_reset; SW_REMOTE_ID=0 SW_FAKE_TCPDUMP="$_RFIX2/beacon.txt" SW_RECON_DB=/nonexistent/recon.db SW_BLE_CMD=true sw_scan_once
assert_empty "$(grep '^tcpdump ' "$SW_STUB_LOG")" rid_lap_off_no_capture
# a lap of a stopped payload starts no capture and reports no drone
bash -c 'exit 0' & _rd=$!; wait "$_rd"
_rid_reset; SW_MAIN_PID="$_rd" _rid_lap beacon
assert_empty "$(grep -E '^(tcpdump|ALERT|LOG) ' "$SW_STUB_LOG")" rid_lap_stopped_no_capture_no_report
# The ignore list against a spoofer (user decision 2026-10-02): a drone is silenced only when EVERY ID heard
# from its address is listed as drone:<ID>. These laps play two frames from one address: hostile/owner_id.txt
# is the reference beacon carrying the owner's ID (0x48-0x5b "0000FSWTEST000000001" -> "0000FSWTESTOWNER001"),
# caa_id.txt sends the reference ID as a CAA registration (0x47 12->22), fake_id.txt a made-up serial
# (0x48-0x5b -> "0000FSWTESTFAKE00001").
_rcat="$(mktemp)"; _rown=" DRONE:0000FSWTESTOWNER001 "
_rid_lapf() { SW_REMOTE_ID=1 SW_RID_SECONDS=1 SW_FAKE_TCPDUMP="$1" SW_RECON_DB=/nonexistent/recon.db SW_BLE_CMD=true sw_scan_once; }
# S1: the owner's ID first, then the real drone: reported (under the first serial heard), both IDs in its row
cat "$_RFIX2/hostile/owner_id.txt" "$_RFIX2/beacon.txt" > "$_rcat"
_rid_reset; SW_IGNORE_SET="$_rown" _rid_lapf "$_rcat"
assert_contains "$(cat "$SW_STUB_LOG")" "ALERT Drone '0000FSWTESTOWNER001'" rid_lap_spoofed_owner_id_hides_nothing
assert_contains "$(cat "$SW_LOOT_DIR/remoteid.csv")" ',serial,"0000FSWTESTOWNER001",serial,"0000FSWTEST000000001",' rid_lap_spoofed_owner_id_row_has_both
# control: with both IDs listed, nothing (and the capture did run)
_rid_reset; SW_IGNORE_SET="$_rown DRONE:0000FSWTEST000000001 " _rid_lapf "$_rcat"
assert_empty "$(grep -F 'Drone' "$SW_STUB_LOG")" rid_lap_both_ids_listed_silent
assert_contains "$(grep '^tcpdump ' "$SW_STUB_LOG")" "tcpdump -i" rid_lap_both_ids_listed_control_captured
# S4: the real drone sends only a CAA registration; the owner's serial, heard after it, still names the drone
# (a serial is preferred), but the drone is reported
cat "$_RFIX2/hostile/caa_id.txt" "$_RFIX2/hostile/owner_id.txt" > "$_rcat"
_rid_reset; SW_IGNORE_SET="$_rown" _rid_lapf "$_rcat"
assert_contains "$(cat "$SW_STUB_LOG")" "ALERT Drone '0000FSWTESTOWNER001'" rid_lap_spoofed_serial_after_caa_hides_nothing
# S2: a spoofer at the owner's own address with a made-up serial, heard first: the owner's drone alerts under it
cat "$_RFIX2/hostile/fake_id.txt" "$_RFIX2/hostile/owner_id.txt" > "$_rcat"
_rid_reset; SW_IGNORE_SET="$_rown" _rid_lapf "$_rcat"
assert_contains "$(cat "$SW_STUB_LOG")" "ALERT Drone '0000FSWTESTFAKE00001'" rid_lap_fake_id_at_owner_address_alerts
# ...while an EMPTY serial heard first (hostile/empty_id.txt: 0x48-0x5b -> 20 zero bytes) is no ID: the only ID
# heard is the owner's, so the owner's drone stays silent
cat "$_RFIX2/hostile/empty_id.txt" "$_RFIX2/hostile/owner_id.txt" > "$_rcat"
_rid_reset; SW_IGNORE_SET="$_rown" _rid_lapf "$_rcat"
assert_empty "$(grep -F 'Drone' "$SW_STUB_LOG")" rid_lap_empty_id_at_owner_address_silent
assert_contains "$(grep '^tcpdump ' "$SW_STUB_LOG")" "tcpdump -i" rid_lap_empty_id_control_captured
# a reference frame with an empty serial and then a CAA registration (gen.c's "emptyserial"): named by the CAA ID
_rid_reset; _rid_lap emptyserial
assert_contains "$(cat "$SW_STUB_LOG")" "ALERT Drone 'FSW-CAA-TEST-0002'" rid_lap_empty_serial_named_by_caa
assert_contains "$(cat "$SW_LOOT_DIR/remoteid.csv")" ',beacon,80:E1:26:FF:00:02,-47,caa,"FSW-CAA-TEST-0002",,"",multirotor,' rid_lap_empty_serial_row
# the defaults, read in a clean process (a test that sets a value cannot see its default)
assert_eq "$(env -u SW_REMOTE_ID -u SW_RID_IFACE -u SW_RID_SECONDS -u SW_RID_MAX_FRAMES -u SW_RID_MAX_DRONES -u SW_RID_FILE -u SW_LOOT_DIR \
  bash -c 'SW_TEST_SOURCE=1 . "$1"/payload.sh >/dev/null 2>&1; echo "$SW_REMOTE_ID|$SW_RID_IFACE|$SW_RID_SECONDS|$SW_RID_MAX_FRAMES|$SW_RID_MAX_DRONES|$SW_RID_FILE"' _ "$SW_ROOT")" \
  "1|wlan1mon|12|1500|32|/root/loot/squachwatch/remoteid.csv" payload_rid_defaults
# health: the capture needs tcpdump and the recon radio's interface (spec 2026-10-01 §7.1). A PATH with
# only what the check needs (the btmon stub too, so tcpdump is the only thing missing).
_rn="$(mktemp -d)"; mkdir "$_rn/net" "$_rn/bin"; : > "$_rn/net/wlan1mon"
_stubs="$(cd "$(dirname "${BASH_SOURCE[0]}")/stubs" && pwd)"
for _t in LOG sqlite3 btmon; do ln -s "$_stubs/$_t" "$_rn/bin/$_t"; done
for _t in bash cp date mktemp rm python3; do ln -s "$(command -v "$_t")" "$_rn/bin/$_t"; done
: > "$SW_STUB_LOG"; PATH="$_rn/bin" SW_REMOTE_ID=1 SW_SYSFS_NET="$_rn/net" sw_healthcheck >/dev/null 2>&1
assert_contains "$(cat "$SW_STUB_LOG")" "WARN: tcpdump missing — Remote ID over WiFi OFF" health_rid_tcpdump_missing
ln -s "$_stubs/tcpdump" "$_rn/bin/tcpdump"
: > "$SW_STUB_LOG"; PATH="$_rn/bin" SW_REMOTE_ID=1 SW_SYSFS_NET="$_rn/net" SW_RID_IFACE=wlan9mon sw_healthcheck >/dev/null 2>&1
assert_contains "$(cat "$SW_STUB_LOG")" "WARN: wlan9mon missing — Remote ID over WiFi OFF" health_rid_iface_missing
# control: both there, no Remote ID WARN
: > "$SW_STUB_LOG"; PATH="$_rn/bin" SW_REMOTE_ID=1 SW_SYSFS_NET="$_rn/net" sw_healthcheck >/dev/null 2>&1
assert_empty "$(grep -F 'Remote ID' "$SW_STUB_LOG")" health_rid_control_all_present
# ...and none when Remote ID is off, even with the interface missing
: > "$SW_STUB_LOG"; PATH="$_rn/bin" SW_REMOTE_ID=0 SW_SYSFS_NET="$_rn/net" SW_RID_IFACE=wlan9mon sw_healthcheck >/dev/null 2>&1
assert_empty "$(grep -F 'Remote ID' "$SW_STUB_LOG")" health_rid_off_silent
rm -rf "$_rn"; unset _rn _stubs _t _rd
# The Pager's Stop during the Remote ID window (spec 2026-10-01 §7.3): the trap runs within the grace,
# and the lap that was running reports nothing when its window ends, and leaves no capture behind.
_rs="$(mktemp -d)"; : > "$SW_STUB_LOG"
SW_TEST_SOURCE= SW_SEEN_FILE="$_rs/seen.db" SW_LOOT_DIR="$_rs/loot" SW_TMP_DIR="$_rs" SW_SLEEP=1 SW_HEALTH_EVERY=0 \
  SW_BLE_CMD=true SW_RECON_DB=/nonexistent/recon.db SW_REMOTE_ID=1 SW_RID_SECONDS=3 SW_FAKE_TCPDUMP="$_RFIX2/beacon.txt" \
  python3 -c 'import os, signal as s, sys; [s.signal(n, s.SIG_DFL) for n in (s.SIGINT, s.SIGPIPE, s.SIGXFSZ)]; os.execvp("bash", ["bash"] + sys.argv[1:])' \
  "$SW_ROOT/payload.sh" >/dev/null 2>&1 &
_sp=$!
for _i in $(seq 80); do ls "$_rs" | grep -qE '^sw_rid\.[A-Za-z0-9]{6}$' && break; sleep 0.1; done
_inwin="$(ls "$_rs" | grep -qE '^sw_rid\.[A-Za-z0-9]{6}$' && echo yes || echo no)"
kill -INT "$_sp"
for _i in $(seq 20); do kill -0 "$_sp" 2>/dev/null || break; sleep 0.05; done    # the ~1 s grace
_alive="$(kill -0 "$_sp" 2>/dev/null && echo yes || echo no)"
{ kill -KILL "$_sp"; wait "$_sp"; } 2>/dev/null; _rc=$?
assert_eq "$_inwin" "yes" stop_rid_control_was_in_the_window
assert_eq "$_alive/$_rc" "no/0" stop_rid_trap_runs_within_the_grace
sleep 4                                   # the lap that was running: its 3 s window runs out
assert_empty "$(grep -E '^(ALERT|VIBRATE|RINGTONE) ' "$SW_STUB_LOG")" stop_rid_lap_never_alerts
assert_empty "$(grep -F 'Drone' "$SW_STUB_LOG")" stop_rid_lap_reports_nothing
assert_empty "$(ls "$_rs" | grep -E '^sw_rid\.')" stop_rid_leaves_no_files
rm -rf "$_rs" "$_rcat"; unset _rs _sp _i _inwin _alive _rc _RFIX2 _rcat _rown; unset -f _rid_reset _rid_lap _rid_lapf
# --- end Remote ID ---

rm -rf "$SW_LOOT_DIR" "$SW_SEEN_FILE"

rm -rf "$SW_TMP_DIR"
unset SW_RECON_DB SW_BLE_CMD SW_LOOT_DIR SW_SEEN_FILE SW_TEST_SOURCE SW_RECENCY_SECS SW_FOLLOW_SECS SW_FOLLOW_GAP SW_TRACK_FILE SW_IGNORE_FILE SW_IGNORE_SET SW_TMP_DIR SW_SNOOZE_AFTER SW_SNOOZE_MARGIN_DB SW_SNOOZE_RESET_SECS SW_SNOOZE_FILE SW_KIND_COOLDOWN SW_LOG_PER_KIND SW_FOLLOW_MIN_RSSI SW_EVIL_TWIN SW_REMOTE_ID SW_RID_IFACE SW_RID_SECONDS SW_RID_MAX_FRAMES SW_RID_MAX_DRONES SW_RID_FILE

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
# Sourcing payload.sh (as these tests do) must not install its early `exit 0` trap in the sourcing
# shell: a Ctrl-C of the suite would then end it with status 0, as if it had passed. (A real run
# does install it: stop_while_loading_ends_cleanly_within_the_grace.) python3 restores the default
# SIGINT/SIGTERM first: a suite started in the background inherits SIGINT ignored, and `trap -p`
# then reports that inherited "ignore" whatever the sourced code does.
_sw_dfl_bash() { python3 -c 'import os, signal as s, sys; [s.signal(n, s.SIG_DFL) for n in (s.SIGINT, s.SIGTERM)]; os.execvp("bash", ["bash"] + sys.argv[1:])' "$@"; }
# The probe prints "sourced" only if the file really loaded (so a failed source cannot pass as
# "no trap"), then any INT/TERM trap it finds.
assert_eq "$(_sw_dfl_bash -c 'SW_TEST_SOURCE=1 . "$1/payload.sh" >/dev/null 2>&1; declare -F sw_main >/dev/null && echo sourced; trap -p INT TERM' _ "$SW_ROOT")" "sourced" payload_sourced_sets_no_signal_trap
# control: the same probe does report a trap the sourced code sets
assert_contains "$(_sw_dfl_bash -c 'trap "exit 0" INT; trap -p INT TERM')" "exit 0" payload_sourced_trap_probe_control
unset -f _sw_dfl_bash

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
