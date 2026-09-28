# test/wifi_test.sh  (sourced by run.sh)
SW_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../payloads/user/reconnaissance/squachwatch" && pwd)"
FIX="$(cd "$(dirname "${BASH_SOURCE[0]}")/fixtures" && pwd)"
source "$SW_ROOT/lib/match.sh"; source "$SW_ROOT/lib/wifi.sh"   # match.sh provides sw_sanitize_ident

# pure formatter
sw_wifi_colonize '70c94e112233'; assert_eq "$REPLY" "70:C9:4E:11:22:33" colonize
assert_eq "$(sw_wifi_row_to_record '70c94e112233' '' '-40')" "wifi|70:C9:4E:11:22:33||-40" row2rec
# Finding-1 sanitize: a '|' in the SSID is stripped when building the record
assert_eq "$(sw_wifi_row_to_record '70c94e112233' 'Ev|il' '-40')" "wifi|70:C9:4E:11:22:33|Evil|-40" row2rec_sanitized

# integration via shim against the fixture DB
recs="$(sw_wifi_records "$FIX/recon.db")"
assert_contains "$recs" "wifi|70:C9:4E:11:22:33||-40" wifi_flock_record
assert_contains "$recs" "wifi|AA:BB:CC:00:11:22|MyPineappleNet|-55" wifi_pine_record
assert_contains "$recs" "wifi|F0:F5:A5:44:55:66||-70" wifi_client_record
# The DB copy lives in ${SW_TMP_DIR:-/tmp}, like the BLE capture: payload.sh clears a copy that
# the Pager's Stop stranded there (5.6 MB each on a real Pager, and growing), and a test can
# keep its copies out of the dev box's /tmp.
SW_TMPC="$(mktemp -d)"
# control: a sweep with a usable temp dir returns records, and leaves no copy behind
assert_contains "$(SW_TMP_DIR="$SW_TMPC" sw_wifi_records "$FIX/recon.db")" "wifi|70:C9:4E:11:22:33||-40" wifi_copy_tmp_dir_control
assert_empty "$(ls "$SW_TMPC")" wifi_copy_removed_after_sweep
# no usable temp dir -> no copy -> no records (the copy used to go to /tmp regardless)
assert_empty "$(SW_TMP_DIR="$SW_TMPC/missing" sw_wifi_records "$FIX/recon.db" 2>/dev/null)" wifi_copy_uses_sw_tmp_dir
rm -rf "$SW_TMPC"; unset SW_TMPC

# --- recency window (SW_RECENCY_SECS) ---
# recon.db keeps months of history (20,294 rows on the real Pager, only 222 of them
# from the last 10 minutes). A detector cares about what is nearby NOW, so the sweep
# filters on ssid.time (P0-confirmed epoch seconds). Build the fixture fresh here so
# these timestamps stay relative to now and the committed fixture can't rot.
SW_TMPD="$(mktemp -d)"
python3 "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/tools/build_fixture_db.py" "$SW_TMPD/recon.db" >/dev/null

SW_RECENCY_SECS=0
recs_all="$(sw_wifi_records "$SW_TMPD/recon.db")"
assert_contains "$recs_all" "wifi|00:11:22:33:44:55|OldAP|-75" recency_off_keeps_old

SW_RECENCY_SECS=600
recs_fresh="$(sw_wifi_records "$SW_TMPD/recon.db")"
assert_empty "$(printf '%s\n' "$recs_fresh" | grep '00:11:22:33:44:55')" recency_filters_old
# POSITIVE CONTROL: the window must not filter EVERYTHING -- if this fails, the
# "old row is gone" assertion above passed vacuously (an empty result satisfies it).
assert_contains "$recs_fresh" "wifi|70:C9:4E:11:22:33||-40" recency_keeps_fresh

# STALE-DB GUARD: a window that filters out every row means the recon DB stopped
# updating (or its clock is wrong) and WiFi detection is silently dead. That must
# never read as "all clear".
cp "$SW_TMPD/recon.db" "$SW_TMPD/stale.db"
python3 -c "import sqlite3,sys,time; c=sqlite3.connect(sys.argv[1]); c.execute('UPDATE ssid SET time=?',(int(time.time())-86400,)); c.commit()" "$SW_TMPD/stale.db"
SW_RECENCY_SECS=600
sw_wifi_stale_db "$SW_TMPD/stale.db"; assert_eq "$?" "0" stale_db_detected
sw_wifi_stale_db "$SW_TMPD/recon.db"; assert_eq "$?" "1" stale_db_not_flagged_when_fresh
SW_RECENCY_SECS=0
sw_wifi_stale_db "$SW_TMPD/stale.db"; assert_eq "$?" "1" stale_db_off_when_window_off
# A copy that vanishes mid-check (after a Stop the exit trap removes it; a relaunch's startup sweep
# can too) must not read as "stale": the second count then opens an EMPTY new file, which the
# sqlite3 CLI creates (the Pager's does too), and a healthy DB used to read as "not updating".
# The function below removes the copy just as the second count opens it, as the trap could: the
# last moment that still changes the answer, so a check made between the two counts misses it.
SW_TMPV="$(mktemp -d)"
( SW_RECENCY_SECS=600
  sqlite3() {
    case "$2" in *"WHERE time"*) rm -f "$1" && : > "$SW_TMPD/vanished" ;; esac
    command sqlite3 "$@"
  }
  SW_TMP_DIR="$SW_TMPV" sw_wifi_stale_db "$SW_TMPD/recon.db" ); assert_eq "$?" "1" stale_db_vanished_copy_not_flagged
# control: the copy really was removed mid-check (else the healthy DB above passes vacuously)
assert_eq "$([ -e "$SW_TMPD/vanished" ] && echo yes)" "yes" stale_db_vanished_copy_control_removed
assert_empty "$(ls -A "$SW_TMPV")" stale_db_vanished_copy_leaves_no_file
rm -rf "$SW_TMPV"; unset SW_TMPV
rm -rf "$SW_TMPD"; unset SW_TMPD recs_all recs_fresh

# --- the test shim behaves like the Pager's sqlite3 3.46.1 (checked on the device 2026-09-29) ---
_ro="$(mktemp -d)"
sqlite3 -readonly "$_ro/missing.db" "SELECT 1;" >/dev/null 2>&1; assert_eq "$?" "1" shim_readonly_missing_fails
assert_eq "$([ -e "$_ro/missing.db" ] && echo created || echo absent)" "absent" shim_readonly_missing_not_created
# control: without -readonly a missing file is created (empty), as the real CLI does
sqlite3 "$_ro/plain.db" "SELECT 1;" >/dev/null 2>&1
assert_eq "$([ -e "$_ro/plain.db" ] && echo created || echo absent)" "created" shim_plain_missing_created
assert_eq "$(sqlite3 -readonly "$FIX/recon.db" "SELECT count(*) FROM ssid;")" "6" shim_readonly_reads_existing
rm -rf "$_ro"; unset _ro

# --- one copy per lap: sw_recon_snapshot + sw_wifi_records_in (spec 2026-09-29 §6.2) ---
_sn="$(mktemp -d)"
SW_TMP_DIR="$_sn" sw_recon_snapshot "$FIX/recon.db"; assert_eq "$?" "0" snapshot_rc
_snap="$REPLY"
assert_contains "$_snap" "$_sn/sw_recon." snapshot_in_sw_tmp_dir
assert_eq "$(cmp -s "$FIX/recon.db" "$_snap" && echo same)" "same" snapshot_is_a_copy
# the reader reads a given copy and leaves it for the next reader (the evil-twin check)
assert_contains "$(sw_wifi_records_in "$_snap")" "wifi|AA:BB:CC:00:11:22|MyPineappleNet|-55" records_in_reads_copy
assert_eq "$([ -e "$_snap" ] && echo kept)" "kept" records_in_keeps_copy
rm -f "$_snap"
# a copy removed under the lap (the exit trap after a Stop) reads as nothing and is NOT recreated
assert_empty "$(sw_wifi_records_in "$_snap")" records_in_vanished_copy_empty
assert_eq "$([ -e "$_snap" ] && echo recreated || echo absent)" "absent" records_in_vanished_copy_not_recreated
# no copy possible: rc 1, REPLY empty, nothing left behind
SW_TMP_DIR="$_sn" sw_recon_snapshot "$_sn/no-such.db"; assert_eq "$?" "1" snapshot_missing_db_rc
assert_empty "$REPLY" snapshot_missing_db_reply_empty
assert_empty "$(ls -A "$_sn")" snapshot_missing_db_leaves_nothing
SW_TMP_DIR="$_sn/missing" sw_recon_snapshot "$FIX/recon.db"; assert_eq "$?" "1" snapshot_no_tmp_dir_rc
rm -rf "$_sn"; unset _sn _snap

# --- a network name cannot forge a second record (reproduced 2026-09-29) ---
# The sqlite3 CLI prints a line break inside a value as it is, so a nearby network named
# "X<LF>B41E52112233<TAB>-10<TAB>Fake" used to add a record for B4:1E:52:11:22:33 -- Flock Safety's
# own block, i.e. a fake full-screen "Flock Safety device" alert at an address the attacker picks.
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/helpers/recon_db.sh"   # sw_test_recon_db
_nl="$(mktemp -d)"
sw_test_recon_db "$_nl/r.db" "8,021122334455,0,0,-60,30,X"$'\n'"B41E52112233"$'\t'"-10"$'\t'"Fake"
# control: the name really holds a line break (else the checks below pass vacuously)
assert_eq "$(python3 -c 'import sqlite3,sys; print(int(b"\n" in sqlite3.connect(sys.argv[1]).execute("SELECT ssid FROM ssid").fetchone()[0]))' "$_nl/r.db")" "1" forge_control_name_has_line_break
_recs="$(sw_wifi_records "$_nl/r.db")"
assert_eq "$(printf '%s\n' "$_recs" | grep -c .)" "1" forge_one_record_per_row
assert_contains "$_recs" "wifi|02:11:22:33:44:55|XB41E52112233-10Fake|-60" forge_real_record_kept
assert_empty "$(printf '%s\n' "$_recs" | grep -F 'B4:1E:52')" forge_no_forged_record
assert_empty "$(printf '%s\n' "$_recs" | sw_match_stream "$(sw_load_signatures "$SW_ROOT/signatures.db")" | grep -F 'flock')" forge_no_fake_flock_detection
rm -rf "$_nl"; unset _nl _recs
