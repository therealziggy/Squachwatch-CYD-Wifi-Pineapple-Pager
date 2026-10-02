# test/perf_test.sh  (sourced by run.sh)
# Guards the fork-free hot path. Measured on the Pager (2026-09-22): the fork-based
# helpers cost ~1.04 s PER RECORD over 18,098 recon.db rows => ~5.2 h for one sweep,
# against a designed ~15 s lap. The cause was ~45 forks/row (printf|tr|sed helpers,
# plus every signature re-lowered inside the per-record loop). These functions run
# once per record, so they must use bash builtins only -- no pipes, no $( ).
SW_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../payloads/user/reconnaissance/squachwatch" && pwd)"
source "$SW_ROOT/lib/match.sh"; source "$SW_ROOT/lib/wifi.sh"

# Extract a function body, minus full-line comments.
_sw_body() { sed -n "/^$2()/,/^}/p" "$1" | grep -v '^[[:space:]]*#'; }

# 1) Hot-path helpers must be fork-free.
# (each check first proves the body was FOUND: a renamed or reformatted function would
# otherwise extract nothing and pass vacuously)
for _fn in sw_sanitize_ident sw_oui _sw_lower _sw_uuid_hit _sw_candidates _sw_match_prepared; do
  assert_contains "$(_sw_body "$SW_ROOT/lib/match.sh" "$_fn")" "$_fn()" "forkfree_found_$_fn"
  assert_empty "$(_sw_body "$SW_ROOT/lib/match.sh" "$_fn" | grep -nE '\$\([^(]|`|(^|[^a-z_])(tr|sed|cut|awk|grep) ')" "forkfree_$_fn"
done
assert_contains "$(_sw_body "$SW_ROOT/lib/wifi.sh" sw_wifi_colonize)" "sw_wifi_colonize()" forkfree_found_sw_wifi_colonize
assert_empty "$(_sw_body "$SW_ROOT/lib/wifi.sh" sw_wifi_colonize | grep -nE '\$\([^(]|`|(^|[^a-z_])(tr|sed|cut|awk|grep) ')" forkfree_sw_wifi_colonize

# regex self-check: still catches a command substitution, does not flag arithmetic
assert_contains "$(printf 'x="$(date)"\n' | grep -E '\$\([^(]')" 'x=' perf_regex_catches_subshell
assert_empty "$(printf 'x=$((16#ff))\n' | grep -E '\$\([^(]')" perf_regex_allows_arithmetic

# 2) The per-record producers must not fork to call those helpers either.
assert_contains "$(_sw_body "$SW_ROOT/lib/wifi.sh" sw_wifi_row_to_record)" "sw_wifi_row_to_record()" forkfree_found_row_to_record
assert_empty "$(_sw_body "$SW_ROOT/lib/wifi.sh" sw_wifi_row_to_record | grep -nE '\$\([^(]|`')" forkfree_row_to_record
# 3) The one-record wrapper sw_match_record must not fork either (the per-rule loop itself lives in _sw_match_prepared, checked in 1).
assert_contains "$(_sw_body "$SW_ROOT/lib/match.sh" sw_match_record)" "sw_match_record()" forkfree_found_match_record
assert_empty "$(_sw_body "$SW_ROOT/lib/match.sh" sw_match_record | grep -nE '\$\([^(]|`')" forkfree_match_record

# 4) Helpers expose a fork-free result via REPLY (callers must not need $( )).
sw_sanitize_ident 'Ev|il';           assert_eq "$REPLY" "Evil"             reply_sanitize
sw_oui '70:c9:4e:aa:bb:cc';          assert_eq "$REPLY" "70:C9:4E"         reply_oui
_sw_lower 'MiXeD';                   assert_eq "$REPLY" "mixed"            reply_lower
sw_wifi_colonize '70c94e112233';     assert_eq "$REPLY" "70:C9:4E:11:22:33" reply_colonize

# 5) LATENCY BUDGET (the guard that was missing -- correctness probes passed while a
#    sweep took hours). 500 records x the real signature set must finish well inside
#    5 s on any dev box; the fork-based version needs ~20 s+ for the same work.
_sw_sigs="$(sw_load_signatures "$SW_ROOT/signatures.db")"
_sw_bulk="$(i=0; while [ $i -lt 499 ]; do printf 'wifi|AA:BB:CC:00:11:%02X|HomeNet%d|-60\n' $((i%256)) $i; i=$((i+1)); done
            printf 'wifi|B4:1E:52:11:22:33|FlockCam|-40\n')"   # POSITIVE CONTROL row (Flock Safety's own block)
SECONDS=0
_sw_out="$(printf '%s\n' "$_sw_bulk" | sw_match_stream "$_sw_sigs")"
_sw_elapsed=$SECONDS
# positive control first: if this is 0 the matcher did no work and the timing is vacuous.
assert_eq "$(printf '%s\n' "$_sw_out" | grep -c 'flock_generic')" "1" perf_positive_control
if [ "$_sw_elapsed" -lt 5 ]; then pass; else fail "perf_budget: 500 records took ${_sw_elapsed}s (budget 5s)"; fi

# LATENCY BUDGET for token records: 500 BLE records carrying tokens x a rule set that
# includes a RANGE (the most expensive matcher: loops tokens with arithmetic).
_sw_t3sigs='ble_mfr|004c:12:25|tracker_findmy|Apple Find My (separated)|med|tracker
ble_uuid|fd5a|tracker_smarttag|Samsung SmartTag|med|tracker
ble_uuid|feaa:41|tracker_gfmd|Google Find My (separated)|med|tracker
ble_uuid|3100-3500|surveillance_raven|Raven gunshot sensor (possible)|low|surveillance'
_sw_bulk_ble="$(i=0; while [ $i -lt 499 ]; do printf 'ble|AA:BB:CC:00:11:%02X||-60|mfr:004c:10:5 uuid:%04x sd:fcf1:04\n' $((i%256)) $((i+4096)); i=$((i+1)); done
                printf 'ble|F9:C1:A3:83:F0:48||-96|mfr:004c:12:25\n')"   # POSITIVE CONTROL row
SECONDS=0
_sw_out_ble="$(printf '%s\n' "$_sw_bulk_ble" | sw_match_stream "$_sw_t3sigs")"
_sw_el_ble=$SECONDS
assert_eq "$(printf '%s\n' "$_sw_out_ble" | grep -c 'tracker_findmy')" "1" perf_ble_positive_control
if [ "$_sw_el_ble" -lt 5 ]; then pass; else fail "perf_ble_budget: 500 token records took ${_sw_el_ble}s (budget 5s)"; fi
# 6) TEXT-SIZE INDEPENDENCE. On the Pager, handing the signature text to a function costs ~4.5 us per
#    BYTE per call (2026-09-26: 29 ms per record for the shipped 6 KB set), so the stream must prepare
#    ONCE and never pass the text per record. Padding the set with 600 keyed rules that never match
#    must therefore not slow the stream down (before the fix it made it about 3x slower on the dev box).
_sw_pad="$_sw_sigs"
for (( _i = 0; _i < 600; _i++ )); do
  printf -v _l 'wifi_oui|F%01X:%02X:%02X|pad|Pad|low|surveillance' $((_i % 16)) $((_i / 16)) $((_i % 251))
  _sw_pad+=$'\n'"$_l"
done
_t0=${EPOCHREALTIME//[!0-9]/}; _sw_o1="$(printf '%s\n' "$_sw_bulk" | sw_match_stream "$_sw_sigs")"
_t1=${EPOCHREALTIME//[!0-9]/}; _sw_o2="$(printf '%s\n' "$_sw_bulk" | sw_match_stream "$_sw_pad")"
_t2=${EPOCHREALTIME//[!0-9]/}
assert_eq "$_sw_o2" "$_sw_o1" perf_padding_changes_no_result
assert_contains "$_sw_o1" "flock_generic" perf_padding_control_nonempty
# control: the padded set really was loaded (a stream that ignored its text would pass the two
# checks above): a device on a pad prefix must hit a pad rule
assert_contains "$(printf 'wifi|F0:00:00:00:00:01|x|-1\n' | sw_match_stream "$_sw_pad")" "pad|Pad|low" perf_padding_rules_loaded
_plain=$(( _t1 - _t0 )); _padded=$(( _t2 - _t1 ))
if [ "$_padded" -le $(( _plain * 3 / 2 + 100000 )) ]; then pass; else fail "perf_text_size_independent: padded ${_padded}us vs plain ${_plain}us"; fi
# ...by construction: the stream matches prepared records and never re-passes the text
assert_contains "$(_sw_body "$SW_ROOT/lib/match.sh" sw_match_stream)" "_sw_match_prepared" perf_stream_uses_prepared
assert_empty "$(_sw_body "$SW_ROOT/lib/match.sh" sw_match_stream | grep -n 'sw_match_record')" perf_stream_never_repasses_text

# 7) The evil-twin check (spec 2026-09-29 §7) formats its rows with builtins only, reads the recon
#    DB copy read-only, and reads its window once (MATERIALIZED: one pass over the table on the Pager).
source "$SW_ROOT/lib/eviltwin.sh"
for _fn in sw_evil_twin_scan _sw_evil_twin_window _sw_evil_twin_rows; do
  assert_contains "$(_sw_body "$SW_ROOT/lib/eviltwin.sh" "$_fn")" "$_fn()" "forkfree_found_$_fn"
  assert_empty "$(_sw_body "$SW_ROOT/lib/eviltwin.sh" "$_fn" | grep -nE '\$\([^(]|`|(^|[^a-z_])(tr|sed|cut|awk|grep) ')" "forkfree_$_fn"
done
assert_contains "$(_sw_body "$SW_ROOT/lib/eviltwin.sh" sw_evil_twin_scan)" "sqlite3 -readonly" twin_query_read_only
assert_contains "$(_sw_body "$SW_ROOT/lib/eviltwin.sh" sw_evil_twin_scan)" "AS MATERIALIZED" twin_query_one_pass

# 8) Remote ID (spec 2026-10-01): the per-drone bash is builtins only (the frames themselves are read by
#    one awk pass per lap), the decoder keeps its budget, and the capture never touches the interface.
source "$SW_ROOT/lib/remoteid.sh"
for _fn in sw_rid_coord sw_rid_alt sw_rid_m sw_rid_mps sw_rid_mps2 sw_rid_dmps sw_rid_text _sw_rid_name _sw_rid_line_ok _sw_rid_csv_row _sw_rid_keys; do
  assert_contains "$(_sw_body "$SW_ROOT/lib/remoteid.sh" "$_fn")" "$_fn()" "forkfree_found_$_fn"
  assert_empty "$(_sw_body "$SW_ROOT/lib/remoteid.sh" "$_fn" | grep -nE '\$\([^(]|`|(^|[^a-z_])(tr|sed|cut|awk|grep) ')" "forkfree_$_fn"
done
# sw_rid_records runs once per drone: its one fork is the GPS read, done once a lap (for the first drone)
assert_contains "$(_sw_body "$SW_ROOT/lib/remoteid.sh" sw_rid_records)" "sw_rid_records()" forkfree_found_sw_rid_records
assert_eq "$(_sw_body "$SW_ROOT/lib/remoteid.sh" sw_rid_records | grep -oE '\$\([^(]|`' | wc -l | tr -d ' ')" "1" forkfree_sw_rid_records_one_fork
assert_contains "$(_sw_body "$SW_ROOT/lib/remoteid.sh" sw_rid_records | grep -E '\$\([^(]')" 'gps="$(GPS_GET 2>/dev/null' forkfree_sw_rid_records_fork_is_the_gps_read
assert_contains "$(_sw_body "$SW_ROOT/lib/remoteid.sh" sw_rid_start)" " -p -l -t -nn -xx " rid_capture_read_only
assert_empty "$(_sw_body "$SW_ROOT/lib/remoteid.sh" sw_rid_start | grep -nE '(^|[^-])-I( |$)|iw |iwconfig|ifconfig|ip link')" rid_capture_never_reconfigures
# control: the same grep sees a planted -I
assert_contains "$(printf 'tcpdump -I -i wlan1mon\n' | grep -nE '(^|[^-])-I( |$)|iw |iwconfig|ifconfig|ip link')" "-I" rid_reconfigure_grep_works
# LATENCY BUDGET for the decoder: 1,500 frames (1,200 ordinary beacons + 300 Remote ID) in one pass
_rfx="$(cd "$(dirname "${BASH_SOURCE[0]}")/fixtures" && pwd)/rid"; _big="$(mktemp)"
{ for _i in $(seq 1200); do cat "$_rfx/quiet.txt"; done; for _i in $(seq 300); do cat "$_rfx/beacon.txt"; done; } > "$_big"
SECONDS=0; _o="$(_sw_rid_decode_awk < "$_big")"; _el=$SECONDS
# positive control first: every frame was read (else the timing is vacuous)
assert_contains "$_o" "S	1500	1500	300	0" rid_perf_control_all_frames_read
if [ "$_el" -lt 5 ]; then pass; else fail "rid_perf_budget: 1500 frames took ${_el}s (budget 5s)"; fi
# ...and the drone cap's choice at its worst: 1,499 copies of a listed ID, each from its own address (owner_id.txt's
# addr2 rewritten per copy: a text edit), then the real drone, so every address gets its key looked up
awk '{ a[NR] = $0 } END { for (i = 1; i <= 1499; i++) for (j = 1; j <= NR; j++) {
  l = a[j]; h = sprintf("%04x", i)
  if (l ~ /^\t0x0010:  ffff ff80 e126 aabb cc80/) l = "\t0x0010:  ffff ff02 aabb cc" substr(h, 1, 2) " " substr(h, 3, 2) "80 e126 aabb cc00"
  print l } }' "$_rfx/hostile/owner_id.txt" > "$_big"
cat "$_rfx/beacon.txt" >> "$_big"
SECONDS=0; _o="$(SW_IGNORE_SET=" DRONE:0000FSWTESTOWNER001 " _sw_rid_decode_awk < "$_big")"; _el=$SECONDS
# positive control first: every frame was read and the copies were ranked (the weaker real drone is kept, first)
assert_eq "$(printf '%s\n' "$_o" | grep -c '^D')|$(printf '%s\n' "$_o" | grep -m1 '^D' | cut -f2)|$(printf '%s\n' "$_o" | grep '^S')" "32|80e126aabbcc|S	1500	1500	1500	1468" rid_perf_rank_control
if [ "$_el" -lt 5 ]; then pass; else fail "rid_perf_rank_budget: 1500 addresses took ${_el}s (budget 5s)"; fi
# ...and the ignore list's keys, built once per lap, in time linear in the list: 4,000 plain address lines and one
# drone line take well under a second (a pattern that searched the rest of the list for each line took seconds)
_l=" "; for (( _i = 0; _i < 4000; _i++ )); do printf -v _m 'AA:BB:CC:%02X:%02X:%02X ' $(( _i / 65536 % 256 )) $(( _i / 256 % 256 )) $(( _i % 256 )); _l+="$_m"; done
_l+="DRONE:0000FSWTESTOWNER001 "
_t0=${EPOCHREALTIME//[!0-9]/}; SW_IGNORE_SET="$_l" _sw_rid_keys; _t1=${EPOCHREALTIME//[!0-9]/}
assert_eq "$REPLY" " :0000FSWTESTOWNER001 " rid_perf_keys_control
if [ $(( _t1 - _t0 )) -lt 1000000 ]; then pass; else fail "rid_perf_keys_budget: 4000 lines took $(( (_t1 - _t0) / 1000 )) ms (budget 1000 ms)"; fi
rm -f "$_big"; unset _rfx _big _i _o _el _l _m _t0 _t1

unset _fn _sw_body _sw_sigs _sw_bulk _sw_out _sw_elapsed _sw_t3sigs _sw_bulk_ble _sw_out_ble _sw_el_ble _sw_pad _i _l _t0 _t1 _t2 _sw_o1 _sw_o2 _plain _padded
