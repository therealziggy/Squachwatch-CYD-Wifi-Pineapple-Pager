# test/eviltwin_test.sh  (sourced by run.sh) — the evil-twin check, spec 2026-09-29.
SW_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../payloads/user/reconnaissance/squachwatch" && pwd)"
source "$SW_ROOT/lib/match.sh"; source "$SW_ROOT/lib/wifi.sh"; source "$SW_ROOT/lib/eviltwin.sh"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/helpers/recon_db.sh"   # sw_test_recon_db
_et="$(mktemp -d)"; _etn=0
_wpa2=17184063752   # the Pager's most common protected value (a WPA2 personal network); 0 = open
# _et_db ROW... -> REPLY = a new DB holding ROWs;  _et_scan DB -> what the check reports now
_et_db() { _etn=$((_etn + 1)); REPLY="$_et/t$_etn.db"; sw_test_recon_db "$REPLY" "$@"; }
_et_scan() { sw_evil_twin_scan "$1" "$(date +%s)"; }
SW_RECENCY_SECS=600

# the finding: a protected network plus an open copy on another radio -> the OPEN copy is reported
_et_db "8,ACDE48000001,$_wpa2,0,-60,30,HomeNet" "8,021122334455,0,0,-38,20,HomeNet"
assert_eq "$(_et_scan "$REPLY")" "evil_twin|Evil twin|high|attacker|wifi|02:11:22:33:44:55|HomeNet|-38" twin_reports_open_copy
# one line per open copy, with its LATEST signal (an older session's row and the current one)
_et_db "8,ACDE48000001,$_wpa2,0,-60,30,HomeNet" "8,021122334455,0,0,-70,300,HomeNet" "8,021122334455,0,0,-35,10,HomeNet"
assert_eq "$(_et_scan "$REPLY")" "evil_twin|Evil twin|high|attacker|wifi|02:11:22:33:44:55|HomeNet|-35" twin_latest_signal_one_line
# the same radio offering the name both open and protected: a copy under the real router's own address
_et_db "8,ACDE48000007,$_wpa2,0,-74,40,HomeNet" "8,ACDE48000007,0,0,-8,20,HomeNet"
assert_eq "$(_et_scan "$REPLY")" "evil_twin|Evil twin|high|attacker|wifi|AC:DE:48:00:00:07|HomeNet|-8" twin_same_address_copy

# a mesh or dual-band network: every radio protected -> nothing
_et_db "8,ACDE48000001,$_wpa2,0,-60,30,MeshNet" "8,ACDE48000002,$_wpa2,0,-65,30,MeshNet" "8,36DE48000003,$_wpa2,0,-70,30,MeshNet"
_d="$REPLY"; assert_empty "$(_et_scan "$_d")" mesh_all_protected_silent
# control: the same DB plus one open radio fires (the silence is the rule, not a dead query)
sw_test_recon_db "$_d" "8,021122334455,0,0,-40,10,MeshNet"
assert_contains "$(_et_scan "$_d")" "|02:11:22:33:44:55|MeshNet|-40" mesh_control_open_copy_fires
# names that differ only in capitals are different networks
_et_db "8,ACDE48000001,0,0,-60,30,Lobby-WiFi" "8,ACDE48000002,$_wpa2,0,-60,30,LOBBY-WIFI"
_d="$REPLY"; assert_empty "$(_et_scan "$_d")" capitals_are_different_names
sw_test_recon_db "$_d" "8,021122334455,0,0,-40,10,LOBBY-WIFI"
assert_eq "$(_et_scan "$_d")" "evil_twin|Evil twin|high|attacker|wifi|02:11:22:33:44:55|LOBBY-WIFI|-40" capitals_control_exact_name_fires
# an Enhanced Open network: a visible open radio plus a HIDDEN protected radio with the same name
_et_db "8,ACDE48000001,0,0,-60,30,CafeNet" "8,ACDE48000002,$_wpa2,1,-60,30,CafeNet"
_d="$REPLY"; assert_empty "$(_et_scan "$_d")" hidden_protected_radio_skipped
sw_test_recon_db "$_d" "8,ACDE48000003,$_wpa2,0,-60,30,CafeNet"
assert_contains "$(_et_scan "$_d")" "|AC:DE:48:00:00:01|CafeNet|-60" hidden_control_visible_protected_fires

# the window: both sides must have been seen in it
_et_db "8,ACDE48000001,$_wpa2,0,-60,30,HomeNet" "8,021122334455,0,0,-38,700,HomeNet"
assert_empty "$(_et_scan "$REPLY")" window_open_copy_too_old
_et_db "8,ACDE48000001,$_wpa2,0,-60,700,HomeNet" "8,021122334455,0,0,-38,20,HomeNet"
assert_empty "$(_et_scan "$REPLY")" window_protected_side_too_old
_et_db "8,ACDE48000001,$_wpa2,0,-60,30,HomeNet" "8,021122334455,0,0,-38,500,HomeNet"
_d="$REPLY"; assert_contains "$(_et_scan "$_d")" "|02:11:22:33:44:55|HomeNet|" window_inside_fires
SW_RECENCY_SECS=120; assert_empty "$(_et_scan "$_d")" window_custom_honoured
# 0 (the WiFi sweep then reads the whole DB), a leading zero (octal: 0600 = 384) or junk mean 600,
# never "all of history": the copy seen 500 s ago counts, the one seen 700 s ago does not
_et_db "8,ACDE48000001,$_wpa2,0,-60,30,OldNet" "8,021122334455,0,0,-38,700,OldNet"; _old="$REPLY"
for _w in 0 0600 abc ""; do
  SW_RECENCY_SECS="$_w"
  assert_contains "$(_et_scan "$_d")" "|HomeNet|" "window_fallback_600_inside_[$_w]"
  assert_empty "$(_et_scan "$_old")" "window_fallback_600_not_whole_db_[$_w]"
done
SW_RECENCY_SECS=600

# rows with no security value say nothing
_et_db "8,ACDE48000001,,0,-60,30,HomeNet" "8,021122334455,0,0,-38,20,HomeNet"
assert_empty "$(_et_scan "$REPLY")" null_security_ignored
# blank names (empty, or only zero bytes) are hidden networks too
_et_db "8,ACDE48000001,$_wpa2,0,-60,30," "8,021122334455,0,0,-38,20,"
assert_empty "$(_et_scan "$REPLY")" empty_name_skipped
_et_db "8,ACDE48000001,$_wpa2,0,-60,30,hex:0000" "8,021122334455,0,0,-38,20,hex:0000"
assert_empty "$(_et_scan "$REPLY")" zero_byte_name_skipped
# control: a name made of the digit 0 (byte 0x30) is a real name
_et_db "8,ACDE48000001,$_wpa2,0,-60,30,0" "8,021122334455,0,0,-38,20,0"
assert_eq "$(_et_scan "$REPLY")" "evil_twin|Evil twin|high|attacker|wifi|02:11:22:33:44:55|0|-38" digit_zero_name_is_a_name

# hostile names: the attacker picks the name, so it can neither split the line nor forge another one
_et_db "8,ACDE48000001,$_wpa2,0,-60,30,Ev|il"$'\t'"Net" "8,021122334455,0,0,-38,20,Ev|il"$'\t'"Net"
assert_eq "$(_et_scan "$REPLY")" "evil_twin|Evil twin|high|attacker|wifi|02:11:22:33:44:55|EvilNet|-38" hostile_pipe_and_tab_removed
_fake="X"$'\n'"B41E52112233"$'\t'"-10"$'\t'"Fake"
_et_db "8,ACDE48000001,$_wpa2,0,-60,30,$_fake" "8,021122334455,0,0,-38,20,$_fake"
_o="$(_et_scan "$REPLY")"
assert_eq "$(printf '%s\n' "$_o" | grep -c .)" "1" hostile_line_break_one_detection
assert_empty "$(printf '%s\n' "$_o" | grep -F 'B4:1E:52')" hostile_line_break_forges_nothing
assert_contains "$_o" "|02:11:22:33:44:55|XB41E52112233-10Fake|-38" hostile_line_break_control_real_copy
# only well-formed rows become detections (twin_reports_open_copy is the same shape, valid)
_et_db "8,ACDE48000001,$_wpa2,0,-60,30,HomeNet" "8,XYZ,0,0,-38,20,HomeNet" "8,0211223344,0,0,-38,20,HomeNet"
assert_empty "$(_et_scan "$REPLY")" malformed_mac_skipped

# two open copies of one name, and a second twinned name: every open copy is reported
_et_db "8,ACDE48000001,$_wpa2,0,-60,30,HomeNet" "8,021122334455,0,0,-38,20,HomeNet" "8,021122334466,0,0,-50,20,HomeNet" \
       "8,ACDE48000009,$_wpa2,0,-60,30,Office" "8,021122334477,0,0,-45,20,Office"
_o="$(_et_scan "$REPLY")"
assert_eq "$(printf '%s\n' "$_o" | grep -c '^evil_twin|')" "3" two_copies_and_two_names
assert_contains "$_o" "|02:11:22:33:44:66|HomeNet|-50" second_copy_reported
assert_contains "$_o" "|02:11:22:33:44:77|Office|-45" second_name_reported

# a copy that vanished (the exit trap after a Stop) reads as nothing and is NOT recreated
_et_db "8,ACDE48000001,$_wpa2,0,-60,30,HomeNet" "8,021122334455,0,0,-38,20,HomeNet"; _d="$REPLY"
rm -f "$_d"
assert_empty "$(_et_scan "$_d")" vanished_copy_reports_nothing
assert_eq "$([ -e "$_d" ] && echo recreated || echo absent)" "absent" vanished_copy_not_recreated
# the replay argument: rows last seen after it are left out; bad times give nothing, never a full sweep
_et_db "8,ACDE48000001,$_wpa2,0,-60,30,HomeNet" "8,021122334455,0,0,-38,20,HomeNet"; _d="$REPLY"
_n="$(date +%s)"
assert_empty "$(sw_evil_twin_scan "$_d" "$_n" "$((_n - 25))")" until_leaves_out_later_rows
assert_contains "$(sw_evil_twin_scan "$_d" "$_n" "$_n")" "|HomeNet|" until_control_keeps_rows
assert_empty "$(sw_evil_twin_scan "$_d" "soon")" bad_now_gives_nothing
assert_empty "$(sw_evil_twin_scan "$_d" "$_n" "x")" bad_until_gives_nothing
# the check changes nothing on disk
_before="$(cksum < "$_d")"; _et_scan "$_d" >/dev/null
assert_eq "$(cksum < "$_d")" "$_before" scan_leaves_copy_unchanged

# a clock that stepped back cannot turn old history into "right now" (the adversarial review's
# repro): an open copy and a protected network seen 100 s apart, 13 days ago
_et_db "8,021122334455,0,0,-60,$((13*86400)),Cafe" "8,ACDE48000001,$_wpa2,0,-60,$((13*86400 - 100)),Cafe"; _d="$REPLY"
_n="$(date +%s)"
assert_empty "$(sw_evil_twin_scan "$_d" "$(( _n - 14*86400 ))")" clock_step_back_fabricates_no_twin
# control: a lap that ran back then, when both were in range, does pair them
assert_contains "$(sw_evil_twin_scan "$_d" "$(( _n - 13*86400 + 100 ))")" "|02:11:22:33:44:55|Cafe|-60" clock_control_pair_was_real_then
# a line break inside the stored address cannot forge a line either (defence in depth: pineapd writes hex)
_et_db "8,ACDE48000001,$_wpa2,0,-60,30,HomeNet" "8,021122334455"$'\n'"B41E52112233,0,0,-38,20,HomeNet" "8,021122334466,0,0,-40,20,HomeNet"
_o="$(_et_scan "$REPLY")"
assert_empty "$(printf '%s\n' "$_o" | grep -F 'B4:1E:52')" address_line_break_forges_nothing
assert_contains "$_o" "|02:11:22:33:44:66|HomeNet|-40" address_line_break_control_valid_copy
# a name that is not UTF-8 is still a name, and never costs another twin its report
_et_db "8,ACDE48000001,$_wpa2,0,-60,30,hex:436166e9" "8,021122334455,0,0,-38,20,hex:436166e9" \
       "8,ACDE48000002,$_wpa2,0,-60,30,HomeNet" "8,021122334466,0,0,-38,20,HomeNet"
_o="$(_et_scan "$REPLY")"
assert_contains "$_o" "|02:11:22:33:44:66|HomeNet|-38" non_utf8_name_costs_no_other_twin
assert_contains "$_o" "|02:11:22:33:44:55|Caf"$'\xe9'"|-38" non_utf8_name_reported
# the address must be hex, not just 12 characters long
_et_db "8,ACDE48000001,$_wpa2,0,-60,30,HomeNet" "8,GGGGGGGGGGGG,0,0,-38,20,HomeNet" "8,021122334466,0,0,-40,20,HomeNet"
_o="$(_et_scan "$REPLY")"
assert_empty "$(printf '%s\n' "$_o" | grep -F 'GG:GG')" address_must_be_hex
assert_contains "$_o" "|02:11:22:33:44:66|HomeNet|-40" address_hex_control_valid_copy
# a NUL inside a name: the Pager's CLI prints up to it (C strings), and so does the test stand-in
_et_db "8,ACDE48000001,$_wpa2,0,-60,30,hex:486f6d65004e6574" "8,021122334455,0,0,-38,20,hex:486f6d65004e6574"
assert_eq "$(_et_scan "$REPLY")" "evil_twin|Evil twin|high|attacker|wifi|02:11:22:33:44:55|Home|-38" nul_in_name_cut_like_the_cli

rm -rf "$_et"; unset _et _etn _d _o _w _old _fake _n _before _wpa2; unset -f _et_db _et_scan
unset SW_RECENCY_SECS

# --- the blind-spot check (spec 2026-09-29 §7) ---
_eb="$(mktemp -d)"; SW_RECENCY_SECS=600
sw_test_recon_db "$_eb/ok.db" "8,ACDE48000001,17184063752,0,-60,30,HomeNet" "8,021122334455,0,0,-38,20,Cafe"
SW_TMP_DIR="$_eb" sw_evil_twin_blind "$_eb/ok.db"; assert_eq "$?" "1" blind_no_on_healthy_db
sw_test_recon_db "$_eb/null.db" "8,ACDE48000001,,0,-60,30,HomeNet" "8,021122334455,,0,-38,20,Cafe"
SW_TMP_DIR="$_eb" sw_evil_twin_blind "$_eb/null.db"; assert_eq "$?" "0" blind_yes_without_security_values
# a recon DB whose ssid table has no encryption column any more (a firmware change)
python3 - "$_eb/nocol.db" <<'PY'
import sqlite3, sys, time
c = sqlite3.connect(sys.argv[1])
c.execute("CREATE TABLE ssid(hash INT PRIMARY KEY, type INT, bssid TEXT, ssid BLOB, hidden INT, time INT, signal INT)")
c.execute("INSERT INTO ssid VALUES(1, 8, ?, ?, 0, ?, -60)", (b"ACDE48000001", b"HomeNet", int(time.time()) - 30))
c.commit()
PY
SW_TMP_DIR="$_eb" sw_evil_twin_blind "$_eb/nocol.db"; assert_eq "$?" "0" blind_yes_when_column_gone
# no rows in the window: no verdict (the stale-DB check reports that one)
sw_test_recon_db "$_eb/old.db" "8,ACDE48000001,,0,-60,5000,HomeNet"
SW_TMP_DIR="$_eb" sw_evil_twin_blind "$_eb/old.db"; assert_eq "$?" "1" blind_no_verdict_without_rows
# every column the check reads counts (the final review's cases): a renamed address or signal
# column, NULL addresses, text in the security column or NULL hidden flags all blind it
python3 - "$_eb" <<'PY'
import sqlite3, sys, time
d, now = sys.argv[1], int(time.time())
std = "hash INT PRIMARY KEY, type INT, bssid TEXT, ssid BLOB, hidden INT, time INT, signal INT, encryption INT"
def mk(name, cols, row):
    c = sqlite3.connect(d + "/" + name)
    c.execute("CREATE TABLE ssid(%s)" % cols)
    c.execute("INSERT INTO ssid VALUES(%s)" % ",".join("?" * len(row)), row)
    c.commit()
mk("nobssid.db", std.replace("bssid TEXT", "mac TEXT"), (1, 8, b"ACDE48000001", b"HomeNet", 0, now - 30, -60, 0))
mk("nosignal.db", std.replace("signal INT", "rssi INT"), (1, 8, b"ACDE48000001", b"HomeNet", 0, now - 30, -60, 0))
mk("nullbssid.db", std, (1, 8, None, b"HomeNet", 0, now - 30, -60, 0))
mk("textenc.db", std, (1, 8, b"ACDE48000001", b"HomeNet", 0, now - 30, -60, "WPA2"))
mk("nullhidden.db", std, (1, 8, b"ACDE48000001", b"HomeNet", None, now - 30, -60, 0))
mk("good.db", std, (1, 8, b"ACDE48000001", b"HomeNet", 0, now - 30, -60, 0))
mk("realsignal.db", std, (1, 8, b"ACDE48000001", b"HomeNet", 0, now - 30, -60.5, 0))
mk("noname.db", std, (1, 8, b"ACDE48000001", b"", 0, now - 30, -60, 0))
mk("hiddenonly.db", std, (1, 8, b"ACDE48000001", b"", 1, now - 30, -60, 0))
mk("future.db", std, (1, 8, b"ACDE48000001", b"HomeNet", 0, now + 1000, -60, None))
PY
for _b in nobssid nosignal nullbssid textenc nullhidden realsignal noname; do
  sw_evil_twin_blind "$_eb/$_b.db"; assert_eq "$?" "0" "blind_yes_$_b"
done
# control: the same shape with every column usable is fine
sw_evil_twin_blind "$_eb/good.db"; assert_eq "$?" "1" blind_no_on_good_shape
# control for noname: hidden radios without names are normal
sw_evil_twin_blind "$_eb/hiddenonly.db"; assert_eq "$?" "1" blind_no_on_hidden_unnamed_rows
# rows last seen after the lap (a clock that stepped back) are outside the window: no verdict
sw_evil_twin_blind "$_eb/future.db"; assert_eq "$?" "1" blind_no_verdict_on_future_rows
# hidden radios count too: a window of hidden rows with no security value means the field is gone
sw_test_recon_db "$_eb/hid.db" "8,ACDE48000001,,1,-60,30,HomeNet"
sw_evil_twin_blind "$_eb/hid.db"; assert_eq "$?" "0" blind_yes_when_even_hidden_rows_lack_security
# a torn copy of a DB that was being written reads as damaged (2), not blind: the health check
# looks at a fresh copy before it says anything
cp "$_eb/ok.db" "$_eb/torn.db"; printf 'torn-page-torn-page' | dd of="$_eb/torn.db" bs=1 seek=100 conv=notrunc 2>/dev/null
sw_evil_twin_blind "$_eb/torn.db"; assert_eq "$?" "2" blind_torn_copy_reads_as_damaged
# control: that copy really is damaged (else "unknown" above passes vacuously)
assert_contains "$(sqlite3 -readonly "$_eb/torn.db" "SELECT count(*) FROM ssid;" 2>&1)" "malformed" blind_torn_control_is_damaged
# no DB: no verdict (the health check's unreadable-DB WARN covers it)
SW_TMP_DIR="$_eb" sw_evil_twin_blind "$_eb/missing.db"; assert_eq "$?" "1" blind_no_verdict_without_db
# A copy that vanishes during the check (the exit trap after a Stop) is "unknown", never "blind":
# this sqlite3 removes the copy just before the probe opens it. The DB would read as blind otherwise.
( sqlite3() { case "$*" in *"typeof(encryption)"*) rm -f "$2"; : > "$_eb/vanished" ;; esac; command sqlite3 "$@"; }
  sw_evil_twin_blind "$_eb/null.db" ); assert_eq "$?" "1" blind_vanished_copy_is_unknown
assert_eq "$([ -e "$_eb/vanished" ] && echo yes)" "yes" blind_vanished_control_removed
rm -rf "$_eb"; unset _eb SW_RECENCY_SECS

# --- tools/replay_evil_twin.sh (spec 2026-09-29 §8) replays history through the real check ---
_rp="$(mktemp -d)"; _rpt="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/tools/replay_evil_twin.sh"
sw_test_recon_db "$_rp/twin.db" "8,ACDE48000001,17184063752,0,-60,30,HomeNet" "8,021122334455,0,0,-38,20,HomeNet"
_out="$(bash "$_rpt" "$_rp/twin.db")"
assert_contains "$_out" "open copies found: 1" replay_finds_the_twin
assert_contains "$_out" "02:11:22:33:44:55  'HomeNet'" replay_names_the_copy
# control: a history where every radio is protected finds nothing
sw_test_recon_db "$_rp/mesh.db" "8,ACDE48000001,17184063752,0,-60,30,MeshNet" "8,ACDE48000002,17184063752,0,-60,30,MeshNet"
assert_contains "$(bash "$_rpt" "$_rp/mesh.db")" "open copies found: 0" replay_control_mesh_finds_nothing
# a file that is not a recon DB is an error, not an empty history
printf 'not a database, just text\n' > "$_rp/junk.db"
_out="$(bash "$_rpt" "$_rp/junk.db" 2>&1)"; assert_eq "$?" "1" replay_unreadable_history_fails
assert_contains "$_out" "can't read the history" replay_unreadable_history_says_so
rm -rf "$_rp"; unset _rp _rpt _out
