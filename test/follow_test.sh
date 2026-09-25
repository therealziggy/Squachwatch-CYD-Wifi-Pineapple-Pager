# test/follow_test.sh  (sourced by run.sh) — continuous-presence escalation (spec §5).
SW_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../payloads/user/reconnaissance/squachwatch" && pwd)"
source "$SW_ROOT/lib/follow.sh"
_T="$(mktemp -d)"; _tf="$_T/track.db"
_D='tracker_findmy|Apple Find My (separated)|med|tracker|ble|F9:C1:A3:83:F0:48||-96'
_E='tracker_tile|Tile|med|tracker|ble|AA:00:00:00:00:02||-81'
_W='flock_alpr|Flock Falcon camera|high|surveillance|wifi|70:C9:4E:11:22:33||-40'

assert_empty "$(sw_follow_update "$_D" 1000 "$_tf" 900 300)" follow_first_sighting_silent
sw_follow_update "$_D" 1299 "$_tf" 900 300 >/dev/null
sw_follow_update "$_D" 1599 "$_tf" 900 300 >/dev/null
assert_empty "$(sw_follow_update "$_D" 1899 "$_tf" 900 300)" follow_silent_at_899s
assert_eq "$(sw_follow_update "$_D" 1900 "$_tf" 900 300)" "tracker_findmy_follow|Apple Find My (separated) — following you 15+ min|high|tracker|ble|F9:C1:A3:83:F0:48||-96" follow_escalates_at_900s
assert_eq "$(cat "$_tf")" "F9:C1:A3:83:F0:48|tracker_findmy|1000|1900" follow_state_line

# a gap longer than GAP breaks continuity: the clock restarts
assert_empty "$(sw_follow_update "$_D" 2201 "$_tf" 900 300)" follow_gap_resets
assert_eq "$(cat "$_tf")" "F9:C1:A3:83:F0:48|tracker_findmy|2201|2201" follow_gap_reset_state

# stale entries are pruned on rewrite, so the file stays bounded
: > "$_tf"
sw_follow_update "$_D" 5000 "$_tf" 900 300 >/dev/null
sw_follow_update "$_E" 5000 "$_tf" 900 300 >/dev/null
sw_follow_update "$_D" 5400 "$_tf" 900 300 >/dev/null
assert_empty "$(grep 'AA:00:00:00:00:02' "$_tf")" follow_prunes_stale
assert_eq "$(cat "$_tf")" "F9:C1:A3:83:F0:48|tracker_findmy|5400|5400" follow_keeps_current

# non-trackers never enter follow: with follow_secs=0 a tracker WOULD escalate at once
_before="$(cat "$_tf")"
assert_empty "$(sw_follow_update "$_W" 6000 "$_tf" 0 300)" follow_ignores_non_tracker
assert_eq "$(cat "$_tf")" "$_before" follow_non_tracker_leaves_state
assert_contains "$(sw_follow_update "$_E" 6000 "$_tf" 0 300)" "tracker_tile_follow|Tile — following you 0+ min|high|" follow_zero_secs_escalates_tracker

# unwritable state: loud (rc 1 + WARN), never a false escalation. A missing parent dir
# makes mktemp fail even for root, unlike chmod.
: > "$SW_STUB_LOG"
_out="$(sw_follow_update "$_D" 7000 "$_T/no/such/dir/track.db" 0 300)"; _rc=$?
assert_eq "$_rc" "1" follow_unwritable_rc
assert_empty "$_out" follow_unwritable_no_escalation
assert_contains "$(cat "$SW_STUB_LOG")" "follow state unwritable" follow_unwritable_warns

# atomic rewrite: the live file is only ever replaced by mv, never written in place
_body="$(sed -n '/^sw_follow_update()/,/^}/p' "$SW_ROOT/lib/follow.sh" | grep -v '^[[:space:]]*#')"
assert_empty "$(printf '%s\n' "$_body" | grep -E '>>? *"\$tf"')" follow_never_writes_live_file
assert_contains "$_body" 'mv -f "$tmp" "$tf"' follow_replaces_via_mv   # control: right body

# the mv step failing (disk full / read-only remount AFTER mktemp worked) must be just as
# loud as mktemp failing. A stub mv that always fails, first on PATH for this one call.
_fb="$(mktemp -d)"; printf '#!/bin/sh\nexit 1\n' > "$_fb/mv"; chmod +x "$_fb/mv"
: > "$SW_STUB_LOG"
_out="$(PATH="$_fb:$PATH" sw_follow_update "$_D" 8000 "$_T/mvfail.db" 0 300)"; _rc=$?
assert_eq "$_rc" "1" follow_mv_failure_rc
assert_empty "$_out" follow_mv_failure_no_escalation
assert_contains "$(cat "$SW_STUB_LOG")" "follow state unwritable" follow_mv_failure_warns
assert_empty "$(ls "$_T" | grep '^mvfail\.db\.')" follow_mv_failure_no_temp_left
rm -rf "$_fb"; unset _fb

# --- follow floor (spec 2026-09-23 §6) ---
_F2="$(mktemp -d)"; _tf2="$_F2/track.db"
_weak='tracker_findmy|Apple Find My (separated)|med|tracker|ble|F4:46:D0:F4:1A:D0||-95'
_strong='tracker_findmy|Apple Find My (separated)|med|tracker|ble|F4:46:D0:F4:1A:D0||-70'
# a tracker that stays weak (-95, like the neighbour's device seen 2026-09-23) never escalates
for _t in 1000 1300 1600 1900 2200; do _o="$(SW_FOLLOW_MIN_RSSI=-85 sw_follow_update "$_weak" "$_t" "$_tf2" 900 300)"; done
assert_empty "$_o" floor_weak_never_follows
assert_empty "$(cat "$_tf2" 2>/dev/null)" floor_weak_leaves_no_state
# control: the same device at -70 on the same timeline DOES escalate
for _t in 1000 1300 1600 1900; do _o="$(SW_FOLLOW_MIN_RSSI=-85 sw_follow_update "$_strong" "$_t" "$_tf2" 900 300)"; done
assert_contains "$_o" "tracker_findmy_follow|" floor_strong_follows
# the floor is inclusive: exactly -85 counts
rm -f "$_tf2"
assert_contains "$(SW_FOLLOW_MIN_RSSI=-85 sw_follow_update 'tracker_tile|Tile|med|tracker|ble|AA:00:00:00:00:02||-85' 1000 "$_tf2" 0 300)" "tracker_tile_follow|" floor_inclusive
# a missing reading counts: a missing number must never hide a tracker
assert_contains "$(SW_FOLLOW_MIN_RSSI=-85 sw_follow_update 'tracker_tile|Tile|med|tracker|ble|AA:00:00:00:00:03||' 1000 "$_tf2" 0 300)" "tracker_tile_follow|" floor_missing_rssi_counts
# weak sightings do not keep the clock alive: strong at 1000, weak at 1200/1500/1800, strong at
# 1901. Without the floor the weak ones refresh last_seen (1800 -> 1901 is inside the 300 s gap)
# and it escalates at 901 s. With the floor, last_seen stays 1000, the gap breaks, the clock restarts.
rm -f "$_tf2"
SW_FOLLOW_MIN_RSSI=-85 sw_follow_update "$_strong" 1000 "$_tf2" 900 300 >/dev/null
for _t in 1200 1500 1800; do SW_FOLLOW_MIN_RSSI=-85 sw_follow_update "$_weak" "$_t" "$_tf2" 900 300 >/dev/null; done
assert_empty "$(SW_FOLLOW_MIN_RSSI=-85 sw_follow_update "$_strong" 1901 "$_tf2" 900 300)" floor_weak_does_not_bridge_gap
assert_eq "$(cat "$_tf2")" "F4:46:D0:F4:1A:D0|tracker_findmy|1901|1901" floor_weak_gap_restarts_clock
rm -rf "$_F2"; unset _F2 _tf2 _weak _strong _t _o


# --- follow floor OFF switch (I6): ":=" replaces an EMPTY value with the default too, so
# the documented "empty turns it off" didn't work, and 0 or 85 (positive guesses, since the
# sibling settings use 0 = off) silently disabled follow detection since a -40 dBm tracker
# reads "weaker" than 0 or 85 under a plain "-?[0-9]+" check. The floor now counts ONLY when
# it matches a negative integer; anything else -- 0, positive, empty, garbage -- is off. ---
_F3="$(mktemp -d)"; _tf3="$_F3/track.db"
_strong40='tracker_findmy|Apple Find My (separated)|med|tracker|ble|E0:45:25:FD:3B:5E||-40'
for _t in 1000 1300 1600 1900; do _o="$(SW_FOLLOW_MIN_RSSI=0 sw_follow_update "$_strong40" "$_t" "$_tf3" 900 300)"; done
assert_contains "$_o" "tracker_findmy_follow|" floor_zero_is_off
rm -f "$_tf3"
for _t in 1000 1300 1600 1900; do _o="$(SW_FOLLOW_MIN_RSSI=85 sw_follow_update "$_strong40" "$_t" "$_tf3" 900 300)"; done
assert_contains "$_o" "tracker_findmy_follow|" floor_positive_is_off
# control: a REAL negative floor, same shape, DOES gate a weak tracker -- proves the two
# passes above are because the floor is off, not because escalation itself is broken.
rm -f "$_tf3"
_weak95='tracker_findmy|Apple Find My (separated)|med|tracker|ble|E0:45:25:FD:3B:5E||-95'
for _t in 1000 1300 1600 1900 2200; do _o="$(SW_FOLLOW_MIN_RSSI=-85 sw_follow_update "$_weak95" "$_t" "$_tf3" 900 300)"; done
assert_empty "$_o" floor_negative_85_gates_control
rm -rf "$_F3"; unset _F3 _tf3 _strong40 _weak95 _t _o

rm -rf "$_T"; unset _T _tf _D _E _W _before _out _rc _body
