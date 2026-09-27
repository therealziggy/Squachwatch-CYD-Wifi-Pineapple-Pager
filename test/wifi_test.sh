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
# the Pager's Stop stranded there (4.8 MB each on a real Pager), and the suite keeps its copies
# out of the dev box's /tmp.
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
rm -rf "$SW_TMPD"; unset SW_TMPD recs_all recs_fresh
