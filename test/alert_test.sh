SW_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../payloads/user/reconnaissance/squachwatch" && pwd)"
source "$SW_ROOT/lib/alert.sh"

assert_eq "$(sw_color_for surveillance)" "magenta" c_surv
assert_eq "$(sw_color_for tracker)" "yellow" c_track
assert_eq "$(sw_color_for attacker)" "cyan" c_atk
assert_eq "$(sw_color_for weird)" "white" c_default

SEEN="$(mktemp)"; : > "$SEEN"
# Capture rc explicitly (0=alert, 1=suppress). Do NOT use `if fn; then fail; else pass`
# for the suppress case: a missing fn exits 127 (falsy) and would pass it vacuously in RED.
# first sighting -> alert; records t=1000
sw_should_report "AA:BB:CC:00:11:22" flock_alpr 1000 600 "$SEEN"; assert_eq "$?" "0" first_alerts
# same device 100s later, within cooldown 600 -> suppressed
sw_should_report "AA:BB:CC:00:11:22" flock_alpr 1100 600 "$SEEN"; assert_eq "$?" "1" cooldown_suppress
# a SUPPRESSED call must NOT slide the window (reference stays 1000, not 1100). At t=1650
# the correct impl alerts (1650-1000=650>=600); a sliding-window bug (recorded 1100) would
# still suppress (1650-1100=550<600). This assertion discriminates the two. Also = re-alert.
sw_should_report "AA:BB:CC:00:11:22" flock_alpr 1650 600 "$SEEN"; assert_eq "$?" "0" no_window_slide
# the re-alert recorded t=1650, so a call at 1700 (50s later) is suppressed -> proves alert records
sw_should_report "AA:BB:CC:00:11:22" flock_alpr 1700 600 "$SEEN"; assert_eq "$?" "1" suppress_after_realert
# different category, same MAC -> independent -> alert
sw_should_report "AA:BB:CC:00:11:22" other_cat 1100 600 "$SEEN"; assert_eq "$?" "0" independent_category
rm -f "$SEEN"

# --- fail OPEN on clock steps and torn ledger lines (spec 2026-09-23 §8; I4 + m1) ---
# I4: a future-dated line (e.g. after a backward clock step) must not hold anything silent
# until the clock catches up -- validate "last" BEFORE any arithmetic, so a bad stored value
# can only ever make MORE alerts fire, never fewer.
_FO="$(mktemp)"; : > "$_FO"
_now="$(date +%s)"
printf 'AA:00:00:00:00:05|flock_alpr|%s\n' "$((_now + 86400))" > "$_FO"
sw_should_report "AA:00:00:00:00:05" flock_alpr "$_now" 600 "$_FO"; assert_eq "$?" "0" fail_open_future_device_key
# m1: a torn line fused from two concurrent appends (only the LAST field happens to be a
# valid int; the field sw_should_report actually reads for THIS key is not) must not raise a
# bash arithmetic error -- that used to abort the rest of the caller's lap -- and must be
# treated as fresh, same as any other unreadable value.
: > "$_FO"
printf 'X|cat|1790266851C2:00:00:00:00:02|cat2|1790266901\n' > "$_FO"
_out="$(sw_should_report X cat "$_now" 600 "$_FO" 2>&1)"; _rc=$?
assert_eq "$_rc" "0" fail_open_torn_line_fresh
assert_empty "$_out" fail_open_torn_line_no_stderr
# positive control: the fresh call above just appended a REAL line for this key, so the very
# next call, inside its cooldown, IS held -- proving the function isn't simply always-fresh.
sw_should_report X cat "$((_now + 10))" 600 "$_FO"; assert_eq "$?" "1" fail_open_control_still_holds_normally
rm -f "$_FO"; unset _FO _now _out _rc

# final review 2 (IMPORTANT): a LEADING-ZERO timestamp (e.g. a ledger line written when the
# clock read exactly "0800", or a short one like "09") must not reach bash arithmetic at all.
# Bash treats a leading zero as an octal literal, and neither "0800" nor "09" is valid octal
# ("8"/"9" don't exist in base 8), so $((now - last)) used to raise a FATAL "value too great
# for base" error -- proven by hand: it abandons the current top-level command, not merely the
# enclosing function (nested function calls unwind too, final review 3, T3) -- which is why the
# calls below are wrapped in $( ): that subshell is what contains it here, unlike a direct
# top-level call (see the prune tests further down) -- so a leading zero
# must be excluded by the shape check itself, before any arithmetic ever sees it.
_OCT="$(mktemp)"; _now2="$(date +%s)"
printf 'FA:76:9E:C0:52:35|hacker_flipper|0800\n' > "$_OCT"
_out="$(sw_should_report "FA:76:9E:C0:52:35" hacker_flipper "$_now2" 600 "$_OCT" 2>&1)"; _rc=$?
assert_eq "$_rc" "0" leading_zero_0800_fails_open
assert_empty "$_out" leading_zero_0800_no_stderr
: > "$_OCT"
printf 'FA:76:9E:C0:52:35|hacker_flipper|09\n' > "$_OCT"
_out="$(sw_should_report "FA:76:9E:C0:52:35" hacker_flipper "$_now2" 600 "$_OCT" 2>&1)"; _rc=$?
assert_eq "$_rc" "0" leading_zero_09_fails_open
assert_empty "$_out" leading_zero_09_no_stderr
# positive control: the fresh call above just appended a REAL line for this key, so the very
# next call, inside its cooldown, IS held -- proving the check isn't simply always-fresh.
sw_should_report "FA:76:9E:C0:52:35" hacker_flipper "$((_now2 + 10))" 600 "$_OCT"; assert_eq "$?" "1" leading_zero_control_still_holds_normally
rm -f "$_OCT"; unset _OCT _now2 _out _rc

# T4 (final review 3): the {0,11} length cap matters as much as the leading-zero shape -- a
# PLAIN, no-leading-zero integer can still be too LONG (e.g. 20 digits) to fit it. Unlike a
# leading zero (invalid octal) or a torn line (non-integer), an over-long integer is not
# rejected by $(( )) itself; it reaches the "[ -ge ]" comparison on its own terms and overflows
# THAT ("integer expression expected" on stderr, proven by hand), which is falsy anyway -- so rc
# alone is 0 (fresh) whether the cap correctly excludes it by shape or a regression lets it
# through and the comparison merely happens to fail. Only the empty-stderr assertion tells the
# silent, correct rejection apart from a mutated cap leaking that error.
_LONG="$(mktemp)"; _now3="$(date +%s)"
printf 'E1:00:00:00:00:01|hacker_flipper|12345678901234567890\n' > "$_LONG"
_out="$(sw_should_report "E1:00:00:00:00:01" hacker_flipper "$_now3" 600 "$_LONG" 2>&1)"; _rc=$?
assert_eq "$_rc" "0" long_timestamp_fails_open
assert_empty "$_out" long_timestamp_no_stderr
# positive control: same as above, proves the check isn't simply always-fresh.
sw_should_report "E1:00:00:00:00:01" hacker_flipper "$((_now3 + 10))" 600 "$_LONG"; assert_eq "$?" "1" long_timestamp_control_still_holds_normally
rm -f "$_LONG"; unset _LONG _now3 _out _rc

source "$SW_ROOT/lib/log.sh"
LOOT="$(mktemp -d)"; sw_log_init "$LOOT"
SEEN2="$(mktemp)"; : > "$SEEN2"; : > "$SW_STUB_LOG"

# NEW + high confidence surveillance -> LOG magenta + ALERT + hardware notify + logged
sw_emit "flock_alpr|Flock Falcon camera|high|surveillance|wifi|70:C9:4E:11:22:33||-40" 1000 600 "$SEEN2" "$LOOT"
calls="$(cat "$SW_STUB_LOG")"
assert_contains "$calls" "LOG magenta" emit_logcolor
assert_contains "$calls" "ALERT " emit_alert
assert_contains "$calls" "RINGTONE" emit_ring
assert_contains "$calls" "VIBRATE" emit_vibrate
assert_contains "$(tail -1 "$LOOT/detections.csv")" "flock_alpr" emit_logged

# REPEAT within cooldown -> still LOG line, but NO second ALERT
: > "$SW_STUB_LOG"
sw_emit "flock_alpr|Flock Falcon camera|high|surveillance|wifi|70:C9:4E:11:22:33||-40" 1100 600 "$SEEN2" "$LOOT"
calls2="$(cat "$SW_STUB_LOG")"
assert_contains "$calls2" "LOG" emit_repeat_logs
assert_empty "$(printf '%s' "$calls2" | grep '^ALERT ' )" emit_repeat_no_alert

# LOW confidence new -> LOG line only, no ALERT/hardware
: > "$SW_STUB_LOG"
sw_emit "liteon_maybe|Possible Flock chipset|low|surveillance|wifi|74:4C:A1:00:00:01||-80" 2000 600 "$SEEN2" "$LOOT"
calls3="$(cat "$SW_STUB_LOG")"
assert_contains "$calls3" "LOG" emit_low_logs
assert_empty "$(printf '%s' "$calls3" | grep '^ALERT ')" emit_low_no_alert
# CHANGED with the CSV cooldown gate: low confidence now DOES enter the ledger, because
# the ledger is what rate-limits its CSV rows. The invariant that still matters is that a
# low-confidence hit never escalates -- asserted by emit_low_no_alert above, plus this
# control proving no hardware notify fired on a path that did reach the ledger.
assert_contains "$(cat "$SEEN2")" '74:4C:A1:00:00:01|liteon_maybe|' emit_low_recorded
assert_empty "$(printf '%s' "$calls3" | grep -E '^(RINGTONE|VIBRATE)')" emit_low_no_hardware
# The CSV is cooldown-gated: of the 3 emits above, the repeat is inside the cooldown
# and writes nothing, while the new + low-confidence ones each write once.
# -> 2 rows + 1 header = 3 lines.
assert_eq "$(grep -c . "$LOOT/detections.csv")" "3" emit_logs_cooldown_gated
rm -rf "$LOOT" "$SEEN2"

# --- CSV cooldown gate (the loot log used to grow one row per device PER LAP) ---
LOOT3="$(mktemp -d)"; sw_log_init "$LOOT3"; SEEN3="$(mktemp)"; : > "$SEEN3"
D3='flock_alpr|Flock Falcon camera|high|surveillance|wifi|70:C9:4E:11:22:33||-40'
sw_emit "$D3" 1000 600 "$SEEN3" "$LOOT3"
sw_emit "$D3" 1005 600 "$SEEN3" "$LOOT3"
sw_emit "$D3" 1100 600 "$SEEN3" "$LOOT3"
assert_eq "$(grep -c . "$LOOT3/detections.csv")" "2" csv_one_row_per_cooldown   # header + 1
# ...but it must still be a RATE limit, not a write-once: past the cooldown, a new row.
sw_emit "$D3" 2000 600 "$SEEN3" "$LOOT3"
assert_eq "$(grep -c . "$LOOT3/detections.csv")" "3" csv_new_row_after_cooldown
# duplicate-row case: the same mac+category reached twice in one lap (a device matching
# both a name rule and an OUI rule) collapses to a single row.
sw_emit "$D3" 2001 600 "$SEEN3" "$LOOT3"
assert_eq "$(grep -c . "$LOOT3/detections.csv")" "3" csv_dual_match_no_dup
rm -rf "$LOOT3" "$SEEN3"

# --- AUTO SNOOZE in sw_emit (optional args 6-9: statefile after margin_db reset_secs) ---
source "$SW_ROOT/lib/snooze.sh"
_L="$(mktemp -d)"; sw_log_init "$_L"; _sn="$_L/snooze.db"; _se="$(mktemp)"; : > "$_se"
_F='tracker_tile_follow|Tile — following you 15+ min|high|tracker|ble|AA:00:00:00:00:02||-80'
: > "$SW_STUB_LOG"
sw_emit "$_F" 1000 600 "$_se" "$_L" "$_sn" 2 7 1800          # free
sw_emit "$_F" 1600 600 "$_se" "$_L" "$_sn" 2 7 1800          # last free one
sw_emit "$_F" 2200 600 "$_se" "$_L" "$_sn" 2 7 1800          # held
assert_eq "$(grep -c '^ALERT ' "$SW_STUB_LOG")" "2" emit_snooze_holds_third_alert
assert_eq "$(grep -c '^VIBRATE' "$SW_STUB_LOG")" "2" emit_snooze_holds_hardware_too
assert_contains "$(cat "$SW_STUB_LOG")" "snoozing" emit_snooze_last_free_says_so
# NEVER discard data: the held one still wrote its CSV row (3 rows + header)
assert_eq "$(grep -c . "$_L/detections.csv")" "4" emit_snooze_still_logs_row
# control: the same third emit WITHOUT snooze args does alert (the gate is opt-in)
: > "$SW_STUB_LOG"
sw_emit "$_F" 2800 600 "$_se" "$_L"
assert_eq "$(grep -c '^ALERT ' "$SW_STUB_LOG")" "1" emit_without_snooze_alerts
rm -rf "$_L" "$_se"; unset _L _sn _se _F

# --- one full alert per KIND per window (spec 2026-09-23 §4) ---
_L4="$(mktemp -d)"; sw_log_init "$_L4"; _s4="$(mktemp)"; : > "$_s4"; : > "$SW_STUB_LOG"
for _i in 1 2 3 4 5 6 7 8 9; do
  SW_KIND_COOLDOWN=600 sw_emit "flock_battery|Flock Penguin battery|high|surveillance|ble|C2:00:00:00:00:0$_i|Penguin|-60" 1000 600 "$_s4" "$_L4"
done
assert_eq "$(grep -c '^ALERT ' "$SW_STUB_LOG")" "1" kind_flood_one_alert
assert_eq "$(grep -c '^VIBRATE' "$SW_STUB_LOG")" "1" kind_flood_one_buzz
assert_eq "$(grep -c ',flock_battery,' "$_L4/detections.csv")" "9" kind_flood_every_row_kept
# later in the window, another NEW device of that kind stays quiet...
: > "$SW_STUB_LOG"
SW_KIND_COOLDOWN=600 sw_emit "flock_battery|Flock Penguin battery|high|surveillance|ble|C3:00:00:00:00:01|Penguin|-60" 1300 600 "$_s4" "$_L4"
assert_empty "$(grep '^ALERT ' "$SW_STUB_LOG")" kind_quiet_inside_window
assert_contains "$(cat "$SW_STUB_LOG")" "LOG magenta Flock Penguin battery C3:00:00:00:00:01" kind_quiet_still_logs
# ...while a different kind is independent
SW_KIND_COOLDOWN=600 sw_emit "hacker_flipper|Flipper Zero|high|attacker|ble|80:E1:26:00:00:01|Flipper aa|-60" 1300 600 "$_s4" "$_L4"
assert_eq "$(grep -c '^ALERT ' "$SW_STUB_LOG")" "1" kind_other_kind_alerts
# "following you" alerts are exempt: two different followers inside one window both alert
: > "$SW_STUB_LOG"
SW_KIND_COOLDOWN=600 sw_emit "tracker_tile_follow|Tile — following you 15+ min|high|tracker|ble|AA:00:00:00:00:02||-70" 1300 600 "$_s4" "$_L4"
SW_KIND_COOLDOWN=600 sw_emit "tracker_tile_follow|Tile — following you 15+ min|high|tracker|ble|AA:00:00:00:00:0B||-71" 1310 600 "$_s4" "$_L4"
assert_eq "$(grep -c '^ALERT ' "$SW_STUB_LOG")" "2" kind_follow_alerts_exempt
# once the window has passed (1600-1000 = 600), the kind interrupts again
: > "$SW_STUB_LOG"
SW_KIND_COOLDOWN=600 sw_emit "flock_battery|Flock Penguin battery|high|surveillance|ble|C4:00:00:00:00:01|Penguin|-60" 1600 600 "$_s4" "$_L4"
assert_eq "$(grep -c '^ALERT ' "$SW_STUB_LOG")" "1" kind_alerts_again_after_window
# the lib default is OFF: with SW_KIND_COOLDOWN unset every new device alerts (today's behaviour)
: > "$SW_STUB_LOG"; : > "$_s4"
for _i in 1 2 3; do sw_emit "flock_battery|Flock Penguin battery|high|surveillance|ble|C5:00:00:00:00:0$_i|Penguin|-60" 2000 600 "$_s4" "$_L4"; done
assert_eq "$(grep -c '^ALERT ' "$SW_STUB_LOG")" "3" kind_gate_off_when_unset
rm -rf "$_L4" "$_s4"; unset _L4 _s4 _i

# I4: a future-dated "*|<category>" kind-cooldown line (e.g. after a backward clock step) must
# not hold a NEW device of that kind silent for as long as it takes the clock to catch up.
_L4fo="$(mktemp -d)"; sw_log_init "$_L4fo"; _s4fo="$(mktemp)"
_now4fo="$(date +%s)"
printf '*|flock_alpr|%s\n' "$((_now4fo + 86400))" > "$_s4fo"
: > "$SW_STUB_LOG"
SW_KIND_COOLDOWN=600 sw_emit "flock_alpr|Flock Falcon camera|high|surveillance|wifi|70:C9:4E:11:22:44||-40" "$_now4fo" 600 "$_s4fo" "$_L4fo"
assert_eq "$(grep -c '^ALERT ' "$SW_STUB_LOG")" "1" fail_open_future_kind_key_alerts
rm -rf "$_L4fo" "$_s4fo"; unset _L4fo _s4fo _now4fo

# I5 / M15: a fresh MED (or LOW) detection must NEVER stamp the kind ledger -- only a fresh
# HIGH detection may claim the kind's one alert (the gate in sw_emit is nested inside the
# "conf = high" check). Order-independent: it does not matter whether the med device or the
# high device is processed first within the lap: the med one alone must never spend the kind's
# buzz. A mutant that stamps "*|<cat>" for every fresh detection (any confidence) would let an
# earlier med detection silently swallow a later real high one's alert -- the exact shape of
# the real BLE-Spam lap (17 med Flippers, 1 real high Flipper, spam_real_flipper_alerts in
# payload_test.sh is the fixture-level positive control for this).
_M15="$(mktemp -d)"; sw_log_init "$_M15"; _s15="$(mktemp)"; : > "$_s15"
: > "$SW_STUB_LOG"
SW_KIND_COOLDOWN=600 sw_emit "kind_x|Kind X device|med|attacker|ble|C1:00:00:00:00:01|ident|-55" 1000 600 "$_s15" "$_M15"
assert_empty "$(grep '^\*|kind_x|' "$_s15")" m15_fresh_med_no_kind_stamp
: > "$SW_STUB_LOG"
SW_KIND_COOLDOWN=600 sw_emit "kind_x|Kind X device|high|attacker|ble|C1:00:00:00:00:02|ident|-55" 1000 600 "$_s15" "$_M15"
assert_eq "$(grep -c '^ALERT ' "$SW_STUB_LOG")" "1" m15_fresh_high_after_med_alerts
rm -rf "$_M15" "$_s15"; unset _M15 _s15

# SW_EMIT_NOLOG skips ONLY the log line (the lap's screen cap, spec 2026-09-23 §5)
_L5="$(mktemp -d)"; sw_log_init "$_L5"; _s5="$(mktemp)"; : > "$_s5"; : > "$SW_STUB_LOG"
SW_EMIT_NOLOG=1 sw_emit "hacker_flipper|Flipper Zero|high|attacker|ble|80:E1:26:00:00:01|Flipper aa|-60" 1000 600 "$_s5" "$_L5"
assert_empty "$(grep '^LOG ' "$SW_STUB_LOG")" nolog_skips_line
assert_contains "$(cat "$SW_STUB_LOG")" "ALERT Flipper Zero" nolog_keeps_alert
assert_contains "$(cat "$_L5/detections.csv")" "hacker_flipper" nolog_keeps_row
rm -rf "$_L5" "$_s5"; unset _L5 _s5

# An evil twin names the copied network on its screen line and in its alert (spec 2026-09-29 §6.4)
_L6="$(mktemp -d)"; sw_log_init "$_L6"; _s6="$(mktemp)"; : > "$_s6"; : > "$SW_STUB_LOG"
sw_emit "evil_twin|Evil twin|high|attacker|wifi|02:11:22:33:44:55|HomeNet|-38" 1000 600 "$_s6" "$_L6"
assert_contains "$(cat "$SW_STUB_LOG")" "LOG cyan Evil twin 'HomeNet' 02:11:22:33:44:55 -38dBm" twin_line_names_network
assert_contains "$(cat "$SW_STUB_LOG")" "ALERT Evil twin 'HomeNet'" twin_alert_names_network
assert_contains "$(cat "$SW_STUB_LOG")" "LED R 255" twin_alert_red_led
assert_contains "$(tail -1 "$_L6/detections.csv")" ',evil_twin,"Evil twin",high,attacker,wifi,02:11:22:33:44:55,"HomeNet",-38,' twin_csv_row
# control: every other kind keeps its plain label
: > "$SW_STUB_LOG"
sw_emit "hacker_flipper|Flipper Zero|high|attacker|ble|80:E1:26:00:00:09|Flipper aa|-60" 1000 600 "$_s6" "$_L6"
assert_contains "$(cat "$SW_STUB_LOG")" "LOG cyan Flipper Zero 80:E1:26:00:00:09 -60dBm" plain_label_line_unchanged
assert_empty "$(grep -F "'Flipper aa'" "$SW_STUB_LOG")" plain_label_never_quotes_ident
rm -rf "$_L6" "$_s6"; unset _L6 _s6

# Every copied name is reported on its own, even from one radio (spec 2026-09-29, user decision):
# two names from the same MAC inside the cooldown both get a CSV row; the same name again does not
_L7="$(mktemp -d)"; sw_log_init "$_L7"; _s7="$(mktemp)"; : > "$_s7"; : > "$SW_STUB_LOG"
sw_emit "evil_twin|Evil twin|high|attacker|wifi|02:11:22:33:44:55|HomeNet|-38" 1000 600 "$_s7" "$_L7"
sw_emit "evil_twin|Evil twin|high|attacker|wifi|02:11:22:33:44:55|Office|-38" 1010 600 "$_s7" "$_L7"
sw_emit "evil_twin|Evil twin|high|attacker|wifi|02:11:22:33:44:55|HomeNet|-38" 1020 600 "$_s7" "$_L7"
assert_eq "$(grep -c ',evil_twin,' "$_L7/detections.csv")" "2" twin_each_name_gets_a_row
assert_contains "$(cat "$_L7/detections.csv")" '"Office"' twin_second_name_logged
# control: every other kind keeps one row per device per window, whatever its name
sw_emit "hacker_flipper|Flipper Zero|high|attacker|ble|80:E1:26:00:00:0A|Flipper a|-60" 1000 600 "$_s7" "$_L7"
sw_emit "hacker_flipper|Flipper Zero|high|attacker|ble|80:E1:26:00:00:0A|Flipper b|-60" 1010 600 "$_s7" "$_L7"
assert_eq "$(grep -c ',hacker_flipper,' "$_L7/detections.csv")" "1" other_kinds_one_row_per_device
rm -rf "$_L7" "$_s7"; unset _L7 _s7
# a name that is not UTF-8 keeps its cooldown, and the prune keeps its ledger line: the ledger is read
# as bytes (GNU grep hid such a line as "binary", and bash's regex did not match it in UTF-8)
_L8="$(mktemp -d)"; sw_log_init "$_L8"; _s8="$(mktemp)"; : > "$_s8"; : > "$SW_STUB_LOG"
for _t in 1000 1010 1020; do sw_emit "evil_twin|Evil twin|high|attacker|wifi|02:11:22:33:44:55|Caf"$'\xe9'"|-38" "$_t" 600 "$_s8" "$_L8"; done
assert_eq "$(grep -a -c ',evil_twin,' "$_L8/detections.csv")" "1" twin_non_utf8_name_keeps_its_cooldown
sw_seen_prune "$_s8" 1100 600
assert_eq "$(grep -a -c 'evil_twin:Caf' "$_s8")" "1" prune_keeps_non_utf8_name_line
rm -rf "$_L8" "$_s8"; unset _L8 _s8 _t

# A drone is named by its Remote ID, with a detail line and a two-line alert body (spec 2026-10-01 §4)
_L7="$(mktemp -d)"; sw_log_init "$_L7"; _s7="$(mktemp)"; : > "$_s7"; : > "$SW_STUB_LOG"
_drone="drone_rid|Drone|high|surveillance|wifi|80:E1:26:AA:BB:CC|0000FSWTEST000000001|-47|multirotor"$'\t'"87m up, 12m/s"$'\t'"pilot (live) 47.39800,8.54102"
sw_emit "$_drone" 1000 600 "$_s7" "$_L7"
assert_contains "$(cat "$SW_STUB_LOG")" "LOG magenta Drone '0000FSWTEST000000001' 80:E1:26:AA:BB:CC -47dBm" drone_line_names_id
assert_contains "$(cat "$SW_STUB_LOG")" "LOG magenta   87m up, 12m/s, pilot (live) 47.39800,8.54102" drone_detail_line
assert_contains "$(cat "$SW_STUB_LOG")" "ALERT Drone '0000FSWTEST000000001'
multirotor, 87m up, 12m/s
pilot (live) 47.39800,8.54102
80:E1:26:AA:BB:CC -47dBm" drone_alert_body
assert_contains "$(cat "$SW_STUB_LOG")" "LED M 200" drone_alert_magenta_led
assert_contains "$(tail -1 "$_L7/detections.csv")" ',drone_rid,"Drone",high,surveillance,wifi,80:E1:26:AA:BB:CC,"0000FSWTEST000000001",-47,' drone_csv_row_without_detail
# one drone = one Remote ID: the same ID at a new address is the same drone, with no second row or alert...
: > "$SW_STUB_LOG"
sw_emit "drone_rid|Drone|high|surveillance|wifi|80:E1:26:11:22:33|0000FSWTEST000000001|-50|multirotor"$'\t\t'"no pilot location" 1001 600 "$_s7" "$_L7"
assert_eq "$(grep -c ',drone_rid,' "$_L7/detections.csv")" "1" drone_new_address_same_id_no_row
assert_empty "$(grep '^ALERT' "$SW_STUB_LOG")" drone_new_address_same_id_no_alert
# ...though its screen line still prints (the live "still here" signal)
assert_contains "$(cat "$SW_STUB_LOG")" "LOG magenta Drone '0000FSWTEST000000001' 80:E1:26:11:22:33 -50dBm" drone_new_address_still_on_screen
assert_contains "$(cat "$_s7")" "drone|drone_rid:0000FSWTEST000000001|1000" drone_ledger_key_is_the_id
# control: a different ID at that address is a different drone
sw_emit "drone_rid|Drone|high|surveillance|wifi|80:E1:26:11:22:33|0000FSWTEST000000002|-50|multirotor"$'\t\t'"no pilot location" 1002 600 "$_s7" "$_L7"
assert_eq "$(grep -c ',drone_rid,' "$_L7/detections.csv")" "2" drone_other_id_new_row
assert_contains "$(cat "$SW_STUB_LOG")" "ALERT Drone '0000FSWTEST000000002'" drone_other_id_alerts
# a drone that sends no ID says so and is keyed by its address
: > "$SW_STUB_LOG"
sw_emit "drone_rid|Drone|high|surveillance|wifi|80:E1:26:44:55:66||-60|multirotor"$'\t\t'"no pilot location" 1003 600 "$_s7" "$_L7"
assert_contains "$(cat "$SW_STUB_LOG")" "LOG magenta Drone (no ID) 80:E1:26:44:55:66 -60dBm" drone_no_id_line
assert_contains "$(cat "$_s7")" "80:E1:26:44:55:66|drone_rid|1003" drone_no_id_keyed_by_address
# the per-lap screen cap hides both of a drone's lines, never its alert
: > "$SW_STUB_LOG"
SW_EMIT_NOLOG=1 sw_emit "drone_rid|Drone|high|surveillance|wifi|80:E1:26:77:88:99|0000FSWTEST000000003|-55|multirotor"$'\t'"87m up"$'\t'"no pilot location" 1004 600 "$_s7" "$_L7"
assert_empty "$(grep '^LOG ' "$SW_STUB_LOG")" drone_nolog_hides_both_lines
assert_contains "$(cat "$SW_STUB_LOG")" "ALERT Drone '0000FSWTEST000000003'" drone_nolog_alert_unchanged
# control: every other kind keeps one screen line and its two-line alert
: > "$SW_STUB_LOG"
sw_emit "hacker_flipper|Flipper Zero|high|attacker|ble|80:E1:26:00:00:09|Flipper aa|-60" 1005 600 "$_s7" "$_L7"
assert_eq "$(grep -c '^LOG ' "$SW_STUB_LOG")" "1" plain_kind_one_screen_line
assert_contains "$(cat "$SW_STUB_LOG")" "ALERT Flipper Zero
80:E1:26:00:00:09 -60dBm" plain_kind_alert_unchanged
rm -rf "$_L7" "$_s7"; unset _L7 _s7 _drone

# --- ledger pruning (spec 2026-09-23 §7) ---
_P="$(mktemp -d)"; _pf="$_P/seen.db"
printf '%s\n' 'AA:00:00:00:00:01|old_cat|1000' 'AA:00:00:00:00:02|new_cat|1500' '*|kind_old|1000' '*|kind_new|1550' 'garbage-line' 'AA:00:00:00:00:03|bad_ts|12x4' > "$_pf"
sw_seen_prune "$_pf" 2000 600; assert_eq "$?" "0" prune_rc
# ONE assert_eq checks both halves: old + malformed lines dropped, recent lines kept (so an
# emptied file cannot pass), both key shapes (mac|cat and *|cat)
assert_eq "$(cat "$_pf")" 'AA:00:00:00:00:02|new_cat|1500
*|kind_new|1550' prune_keeps_recent_drops_old_and_malformed
# I4 + m1: a future-dated line (clock stepped backward) and a torn line (two appends fused
# into one -- only its LAST field is a plain int) are both dropped, same as any other
# malformed line, while a normal recent line survives (one assert_eq so an emptied file, or
# one that kept the bad lines instead of the good one, both fail this).
# Minor 1 (final review 2): the FIRST torn line's own last field (1790266901) is far in the
# FUTURE relative to now=2000, so the future check alone would drop it even if the whole-line
# shape check were broken -- it never exercises the shape check. The SECOND torn line's last
# field (1990) is RECENT, so only the shape check (exactly two pipes, then a digits-only tail)
# can drop it; a regression to a last-field-only check would keep it and fail this test.
printf '%s\n' 'AA:00:00:00:00:07|cat_ok|1900' "AA:00:00:00:00:08|cat_future|$((2000 + 86400))" \
  'X|cat|1790266851C2:00:00:00:00:02|cat2|1790266901' \
  'X|cat|1850C2:00:00:00:00:02|cat2|1990' > "$_pf"
sw_seen_prune "$_pf" 2000 600
assert_eq "$(cat "$_pf")" 'AA:00:00:00:00:07|cat_ok|1900' prune_drops_future_and_torn_keeps_normal
# final review 2 (IMPORTANT), corrected in final review 3 (T2/T3): the SAME leading-zero shape
# check applies here. A bash arithmetic error only ever abandons the current top-level command
# -- under the OLD, ungrouped code (`sw_seen_prune ...; _prc=$?` as one top-level statement,
# `_after=ok` as the next), that abandoned just the first statement, leaving `_prc` UNSET, while
# `_after=ok` still ran regardless, so that assertion alone could never fail. The suite would
# then die later, at the NEXT reference to the now-unset `_prc`, with "_prc: unbound variable"
# (set -u) and no PASS/FAIL tally at all -- that harsher, whole-process exit is set -u's own
# doing, not the arithmetic error reaching that far by itself. Pre-initialising both sentinels
# to empty and running the call plus both assignments as ONE group (below) fixes this: an
# aborted call now leaves both at their "did not run" empty value, so a regression here
# produces a clean, named `assert_eq` failure and a full tally instead.
printf '%s\n' 'AA:00:00:00:00:16|cat_oct|0800' 'AA:00:00:00:00:17|cat_oct2|09' 'AA:00:00:00:00:18|cat_ok|1900' > "$_pf"
_prc=; _after=
{ sw_seen_prune "$_pf" 2000 600; _prc=$?; _after=ok; }
assert_eq "$_after" "ok" leading_zero_prune_call_returns
assert_eq "$_prc" "0" leading_zero_prune_rc
assert_eq "$(cat "$_pf")" "AA:00:00:00:00:18|cat_ok|1900" leading_zero_prune_drops_octal_keeps_normal
unset _prc _after
# T4 (final review 3): the SAME length cap applies to the prune's shape check. An over-long
# (20-digit) timestamp reaches the "[ -le ]" comparison on a mutated (uncapped) regex and that
# comparison itself errors "integer expression expected" to stderr, even though the line still
# ends up dropped either way (a failed "[ ]" is falsy, same as a rejected shape) -- the correct
# {0,11} cap rejects it silently, before either comparison runs. rc/content alone can't tell
# the two apart; the empty-stderr assertion can.
printf '%s\n' 'AA:00:00:00:00:19|cat_ok2|1900' 'AA:00:00:00:00:23|cat_long|12345678901234567890' > "$_pf"
_out="$(sw_seen_prune "$_pf" 2000 600 2>&1)"; _rc=$?
assert_eq "$_rc" "0" long_timestamp_prune_rc
assert_empty "$_out" long_timestamp_prune_no_stderr
assert_eq "$(cat "$_pf")" "AA:00:00:00:00:19|cat_ok2|1900" long_timestamp_prune_drops_long_keeps_normal
unset _out _rc
# boundary: exactly KEEP seconds old can no longer block (sw_should_report is fresh at >= cooldown)
printf 'AA:00:00:00:00:04|edge|1400\n' > "$_pf"
sw_seen_prune "$_pf" 2000 600
assert_empty "$(cat "$_pf")" prune_boundary_drops
# a missing ledger is fine (nothing to prune)
sw_seen_prune "$_P/none.db" 2000 600; assert_eq "$?" "0" prune_missing_file_ok
# failure is LOUD and harmless: mv fails -> WARN, rc 1, file untouched, no temp left behind
_fb="$(mktemp -d)"; printf '#!/bin/sh\nexit 1\n' > "$_fb/mv"; chmod +x "$_fb/mv"
printf 'AA:00:00:00:00:01|old_cat|1000\n' > "$_pf"; : > "$SW_STUB_LOG"
PATH="$_fb:$PATH" sw_seen_prune "$_pf" 2000 600; _rc=$?
assert_eq "$_rc" "1" prune_mv_failure_rc
assert_contains "$(cat "$SW_STUB_LOG")" "can't prune" prune_mv_failure_warns
assert_eq "$(cat "$_pf")" "AA:00:00:00:00:01|old_cat|1000" prune_mv_failure_leaves_file
assert_empty "$(ls "$_P" | grep '^seen\.db\.')" prune_mv_failure_no_temp_left
# ...and when mktemp itself fails
rm -f "$_fb/mv"; printf '#!/bin/sh\nexit 1\n' > "$_fb/mktemp"; chmod +x "$_fb/mktemp"; : > "$SW_STUB_LOG"
PATH="$_fb:$PATH" sw_seen_prune "$_pf" 2000 600; _rc=$?
assert_eq "$_rc" "1" prune_mktemp_failure_rc
assert_contains "$(cat "$SW_STUB_LOG")" "can't prune" prune_mktemp_failure_warns
assert_eq "$(cat "$_pf")" "AA:00:00:00:00:01|old_cat|1000" prune_mktemp_failure_leaves_file
rm -rf "$_P" "$_fb"; unset _P _pf _fb _rc

# --- m3: no needless rewrite, and write failures are as loud as mv/mktemp failures ---
# when NOTHING would be dropped, sw_seen_prune must not touch the file at all: same inode
# before and after (not just the same content), so there is no flash rewrite for nothing.
_UN="$(mktemp -d)"; _uf="$_UN/seen.db"
printf '%s\n' 'AA:00:00:00:00:09|catq|1900' '*|catr|1950' > "$_uf"
_before_content="$(cat "$_uf")"; _before_inode="$(ls -i "$_uf" | awk '{print $1}')"
sw_seen_prune "$_uf" 2000 600; assert_eq "$?" "0" prune_noop_rc
assert_eq "$(cat "$_uf")" "$_before_content" prune_noop_content_unchanged
assert_eq "$(ls -i "$_uf" | awk '{print $1}')" "$_before_inode" prune_noop_same_inode
# positive control: when a line IS dropped, the inode DOES change -- proves the checks above
# are discriminating a real no-op, not just always true (mv genuinely didn't run vs. did).
printf 'AA:00:00:00:00:10|cats|1000\n' > "$_uf"
_before_inode2="$(ls -i "$_uf" | awk '{print $1}')"
sw_seen_prune "$_uf" 2000 600
assert_empty "$(cat "$_uf")" prune_noop_control_dropped
assert_eq "$([ "$_before_inode2" != "$(ls -i "$_uf" | awk '{print $1}')" ] && echo changed)" "changed" prune_noop_control_inode_changes_on_drop
rm -rf "$_UN"; unset _UN _uf _before_content _before_inode _before_inode2

# Minor 5 (final review 2): a no-op prune must not create a temp file AT ALL. The round-1 test
# above only proved the RENAME was skipped (same inode); sw_seen_prune still created, fully
# wrote, and then unlinked a temp file for nothing. A stub mktemp that logs its own invocation
# (and fails, so a bug that DOES call it is also loud, not silently tolerated) proves the whole
# write pass -- mktemp included -- is skipped by a read-only first pass when there is nothing
# to drop and the ledger already ends in a newline.
_NM="$(mktemp -d)"; _nmf="$_NM/seen.db"; _nmcalls="$_NM/mktemp.calls"
printf '%s\n' 'AA:00:00:00:00:21|catx|1900' > "$_nmf"
_nmstub="$(mktemp -d)"; printf '#!/bin/sh\necho "MKTEMP $*" >> "%s"\nexit 1\n' "$_nmcalls" > "$_nmstub/mktemp"; chmod +x "$_nmstub/mktemp"
_before_nm="$(cat "$_nmf")"
PATH="$_nmstub:$PATH" sw_seen_prune "$_nmf" 2000 600; _rc=$?
assert_eq "$_rc" "0" prune_noop_skips_mktemp_rc
assert_empty "$([ -f "$_nmcalls" ] && cat "$_nmcalls")" prune_noop_skips_mktemp_not_called
assert_eq "$(cat "$_nmf")" "$_before_nm" prune_noop_skips_mktemp_ledger_unchanged
# positive control: the SAME stub, on a ledger that DOES need a rewrite, IS invoked -- proves
# the stub is a working control (it can log a call), not just permanently silent.
printf 'AA:00:00:00:00:22|caty|1000\n' > "$_nmf"
PATH="$_nmstub:$PATH" sw_seen_prune "$_nmf" 2000 600
assert_contains "$(cat "$_nmcalls" 2>/dev/null)" "MKTEMP" prune_noop_control_mktemp_called_when_needed
rm -rf "$_NM" "$_nmstub"; unset _NM _nmf _nmcalls _nmstub _before_nm _rc

# a write failure while rewriting (e.g. ENOSPC) must be just as loud and harmless as an mv or
# mktemp failure: rc 1, WARN, ledger untouched, temp file removed. A stub mktemp hands back a
# symlink to /dev/full instead of a real temp file, so the write into it fails. The ledger
# carries one line that would be KEPT (so its content matters to the unchanged-check) plus one
# old line that would be DROPPED, so the read-only first pass (Minor 5, above) actually decides
# a rewrite is needed and a write into the temp file is attempted at all -- a ledger with
# nothing to drop now skips the temp file entirely and this test would never reach the write.
# (Verified by hand, outside this suite, that the OLD unconditional-mv code fails this in the
# worst possible way: mv succeeds anyway and the real ledger becomes a symlink to /dev/full, so
# a later read of it would hang forever reading zeroes. That is exactly why the write must be
# checked BEFORE any mv is attempted, and why THIS test reads the ledger back through a bound
# (Minor 2): $_wf is asserted to still be a regular file BEFORE it is read at all, and even
# then the read is capped with `head -c`, so if that regression ever comes back, a hung read
# can never take the rest of the suite down with it.)
_WF="$(mktemp -d)"; _wf="$_WF/seen.db"
printf '%s\n' 'AA:00:00:00:00:11|catt|1990' 'AA:00:00:00:00:20|catt_old|1000' > "$_wf"
_wlink="$_WF/devfull_link"; ln -sf /dev/full "$_wlink"
_wstub="$(mktemp -d)"; printf '#!/bin/sh\necho "%s"\n' "$_wlink" > "$_wstub/mktemp"; chmod +x "$_wstub/mktemp"
_before_wf="$(cat "$_wf")"; : > "$SW_STUB_LOG"
PATH="$_wstub:$PATH" timeout 5 bash -c 'source "$1"; sw_seen_prune "$2" 2000 600' _ "$SW_ROOT/lib/alert.sh" "$_wf"; _rc=$?
assert_eq "$_rc" "1" prune_write_failure_rc
assert_contains "$(cat "$SW_STUB_LOG")" "can't prune" prune_write_failure_warns
assert_eq "$([ ! -L "$_wf" ] && echo ok)" "ok" prune_write_failure_ledger_not_symlink
assert_eq "$(timeout 5 head -c 4096 "$_wf")" "$_before_wf" prune_write_failure_ledger_unchanged
assert_empty "$(ls "$_WF" | grep -v '^seen\.db$')" prune_write_failure_temp_removed
rm -rf "$_WF" "$_wstub"; unset _WF _wf _wlink _wstub _before_wf _rc

# Minor 4a: a ledger PATH that exists but is not a plain readable file (here, a directory) must
# WARN + rc 1, not silently read as "nothing to prune": without this check the read loop simply
# never runs (0 lines seen), which looks exactly like an already-clean ledger. A directory is
# used because it fails this check regardless of root or non-root (unlike chmod 000, which root
# can still read).
_DL="$(mktemp -d)"; _dlf="$_DL/seen.db"; mkdir -p "$_dlf"
: > "$SW_STUB_LOG"
sw_seen_prune "$_dlf" 2000 600; _rc=$?
assert_eq "$_rc" "1" prune_unreadable_ledger_rc
assert_contains "$(cat "$SW_STUB_LOG")" "can't prune" prune_unreadable_ledger_warns
assert_eq "$([ -d "$_dlf" ] && echo stilldir)" "stilldir" prune_unreadable_ledger_untouched
# control, same block: a GENUINELY missing ledger (as opposed to one that exists but is
# unusable) is still fine -- rc 0 and silent -- proving the WARN above is about "exists but
# unreadable", not about the path merely being unopenable in some other sense.
: > "$SW_STUB_LOG"
sw_seen_prune "$_DL/genuinely-missing.db" 2000 600; assert_eq "$?" "0" prune_unreadable_ledger_control_missing_is_fine
assert_empty "$(cat "$SW_STUB_LOG")" prune_unreadable_ledger_control_missing_no_warn
rm -rf "$_DL"; unset _DL _dlf _rc

# Minor 4b: the temp file failing to even OPEN (as opposed to a write into an already-open one
# failing, covered above) must be just as loud -- and without this check it is actively
# DANGEROUS, not merely silent. A stub mktemp hands back a path to a DANGLING SYMLINK whose
# target directory does not exist: opening it for writing fails with ENOENT for root and
# non-root alike (final review 3, T1). A chmod-000 file does NOT reproduce this as root: root's
# own DAC override lets it open a permission-000 file for writing anyway, so under `unshare -r`
# the intended rewrite would actually happen and this test would wrongly see rc 0, no WARN, and
# a CHANGED ledger instead of an unchanged one (verified by hand, and the reason for this
# rewrite). But `mv` only needs write permission on the DIRECTORY, not the file itself, and
# happily renames a symlink over the ledger, so an unconditional mv would still "succeed" --
# silently replacing the real ledger with that same dangling symlink (verified by hand: mv's
# own rc is 0, and a later read of the ledger would then follow the symlink to nowhere, rather
# than merely being unpruned).
_TO="$(mktemp -d)"; _tof="$_TO/seen.db"
printf 'AA:00:00:00:00:15|catw|1000\n' > "$_tof"   # old -> a rewrite IS attempted
_before_to="$(cat "$_tof")"
_fake_tmp="$_TO/fake_tmp"; ln -s "$_TO/no-such-dir/x" "$_fake_tmp"
_tostub="$(mktemp -d)"; printf '#!/bin/sh\necho "%s"\n' "$_fake_tmp" > "$_tostub/mktemp"; chmod +x "$_tostub/mktemp"
: > "$SW_STUB_LOG"
PATH="$_tostub:$PATH" sw_seen_prune "$_tof" 2000 600 2>/dev/null; _rc=$?
assert_eq "$_rc" "1" prune_temp_open_failure_rc
assert_contains "$(cat "$SW_STUB_LOG")" "can't prune" prune_temp_open_failure_warns
assert_eq "$(cat "$_tof")" "$_before_to" prune_temp_open_failure_ledger_unchanged
assert_empty "$(ls "$_TO" | grep -v '^seen\.db$')" prune_temp_open_failure_temp_removed
rm -rf "$_TO" "$_tostub"; unset _TO _tof _before_to _fake_tmp _tostub _rc

# Minor 3: a ledger whose last line lacks a trailing newline (a power cut, a hand edit) must
# still be rewritten even when every line would otherwise be KEPT unchanged, or the next
# append fuses onto that last line -- creating exactly the torn-line shape this function exists
# to clean up. `tail -c1 | wc -l` is 1 when the file ends in a newline, 0 otherwise.
_NL="$(mktemp -d)"; _nlf="$_NL/seen.db"
printf 'AA:00:00:00:00:14|catz|1900' > "$_nlf"   # deliberately no trailing newline
assert_eq "$(tail -c1 "$_nlf" | wc -l | tr -d ' ')" "0" prune_missing_newline_control_fixture_lacks_nl
sw_seen_prune "$_nlf" 2000 600; assert_eq "$?" "0" prune_missing_newline_rc
assert_eq "$(tail -c1 "$_nlf" | wc -l | tr -d ' ')" "1" prune_missing_newline_repaired
assert_eq "$(cat "$_nlf")" "AA:00:00:00:00:14|catz|1900" prune_missing_newline_content_intact
rm -rf "$_NL"; unset _NL _nlf
