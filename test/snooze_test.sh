# test/snooze_test.sh  (sourced by run.sh) — AUTO SNOOZE, ported from SquachWatch-CYD
# (include/detection.h, DetectionEngine::alertGate). rc 0 = interrupt, 2 = interrupt (last
# free one), 1 = hold. Args: mac category rssi now statefile after margin_db reset_secs.
SW_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../payloads/user/reconnaissance/squachwatch" && pwd)"
source "$SW_ROOT/lib/snooze.sh"
_S="$(mktemp -d)"; _sf="$_S/snooze.db"; _M=AA:00:00:00:00:02; _C=tracker_tile_follow
_g() { sw_snooze_gate "$_M" "$_C" "$1" "$2" "$_sf" 3 7 1800; echo $?; }

# the first `after` alerts are free; the last free one says so (rc 2)
assert_eq "$(_g -80 1000) $(_g -80 1600) $(_g -80 2200)" "0 0 2" snooze_three_free_last_flagged
# out of free ones: the same strength is held...
assert_eq "$(_g -80 2800)" "1" snooze_holds_after_allowance
# ...6 dB closer is RSSI noise, still held...
assert_eq "$(_g -74 3400)" "1" snooze_noise_margin_holds
# ...7 dB closer than its strongest alert interrupts, and raises the bar to beat
assert_eq "$(_g -73 4000)" "0" snooze_closer_interrupts
assert_eq "$(_g -73 4600)" "1" snooze_bar_raised

# a tracker that STAYS with you stays held: consulted every 10 min for 2 h, never re-armed
# (CYD's literal code resets 30 min after the last ALERT, which would re-arm a 3-alert burst
# every half hour for a follower; we reset on time since last SEEN, CYD's stated intent)
_held=""; _t=4600; for _i in 1 2 3 4 5 6 7 8 9 10 11 12; do _t=$((_t+600)); _held="$_held$(_g -73 $_t)"; done
assert_eq "$_held" "111111111111" snooze_continuous_presence_stays_held
# gone longer than the reset window -> the allowance comes back (positive control for the above)
assert_eq "$(_g -73 $((_t + 1801)))" "0" snooze_resets_after_gone

# the bar is the STRONGEST it ever interrupted at, not the last: -80, -60, -80 -> must beat -60
_M=AA:00:00:00:00:09
_g -80 1000 >/dev/null; _g -60 1600 >/dev/null; _g -80 2200 >/dev/null
assert_eq "$(_g -54 2800) $(_g -53 3400)" "1 0" snooze_bar_is_strongest_ever

# no RSSI -> it cannot be shown to be closer -> held once the allowance is spent
_M=AA:00:00:00:00:10
_g "" 1000 >/dev/null; _g "" 1600 >/dev/null; _g "" 2200 >/dev/null
assert_eq "$(_g "" 2800)" "1" snooze_unknown_rssi_holds

# keys are independent: another category on the same MAC starts with its own allowance
assert_eq "$(sw_snooze_gate "$_M" other_follow -80 2800 "$_sf" 3 7 1800; echo $?)" "0" snooze_independent_keys

# after=0 turns the feature off: always interrupt
sw_snooze_gate "$_M" "$_C" -80 9000 "$_S/off.db" 0 7 1800; assert_eq "$?" "0" snooze_off_always_allows
assert_eq "$(ls "$_S" | grep -c '^off.db')" "0" snooze_off_writes_no_state

# the state stays bounded: entries gone longer than the reset window are dropped
sw_snooze_gate AA:00:00:00:00:99 tracker_x_follow -80 100000 "$_sf" 3 7 1800 >/dev/null
assert_empty "$(grep -F 'AA:00:00:00:00:02|' "$_sf")" snooze_prunes_stale
assert_contains "$(cat "$_sf")" "AA:00:00:00:00:99|tracker_x_follow|1|-80|100000" snooze_state_line
rm -rf "$_S"; unset -f _g; unset _S _sf _M _C _held _t _i
