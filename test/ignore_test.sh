# test/ignore_test.sh  (sourced by run.sh) — the owner's own devices (spec §6).
SW_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../payloads/user/reconnaissance/squachwatch" && pwd)"
source "$SW_ROOT/lib/ignore.sh"
_T="$(mktemp -d)"
printf 'f9:c1:a3:83:f0:48  # my AirTag\n\n# a comment line\nAA:BB:CC:DD:EE:FF\r\n' > "$_T/ignore.txt"
_set="$(sw_load_ignore "$_T/ignore.txt")"
assert_eq "$_set" " F9:C1:A3:83:F0:48 AA:BB:CC:DD:EE:FF " ignore_load_normalises
_D='tracker_findmy|Apple Find My (separated)|med|tracker|ble|F9:C1:A3:83:F0:48||-96'
sw_ignored "$_D" "$_set"; assert_eq "$?" "0" ignore_listed_mac_dropped
# control: the identical detection from an unlisted MAC is kept
sw_ignored "${_D/F9:C1:A3:83:F0:48/CA:B6:53:B5:3B:D5}" "$_set"; assert_eq "$?" "1" ignore_unlisted_kept
assert_eq "$(sw_load_ignore "$_T/missing.txt")" " " ignore_missing_file_empty_set
# an EXISTING zero-byte file is the same empty set (control: ignore_load_normalises above)
: > "$_T/empty.txt"
assert_eq "$(sw_load_ignore "$_T/empty.txt")" " " ignore_empty_existing_file
sw_ignored "$_D" " "; assert_eq "$?" "1" ignore_empty_set_keeps_all
# only the MAC column counts: a listed MAC appearing as an advertised NAME is not a match
_X='hacker_flipper|Flipper Zero|high|attacker|ble|80:E1:26:00:00:01|F9:C1:A3:83:F0:48|-60'
sw_ignored "$_X" "$_set"; assert_eq "$?" "1" ignore_matches_mac_column_only
# a hand-edited file often lacks a final newline: its last MAC must still count
printf 'AA:BB:CC:DD:EE:FF\nCC:CC:CC:CC:CC:CC' > "$_T/noeol.txt"
assert_eq "$(sw_load_ignore "$_T/noeol.txt")" " AA:BB:CC:DD:EE:FF CC:CC:CC:CC:CC:CC " ignore_last_line_without_newline
printf 'CC:CC:CC:CC:CC:CC' > "$_T/single_noeol.txt"
assert_eq "$(sw_load_ignore "$_T/single_noeol.txt")" " CC:CC:CC:CC:CC:CC " ignore_single_line_without_newline
# An evil twin is dropped only by an explicit "evil_twin:<MAC>" line: the attacker chooses its
# address, so a plain line for one of your own devices must not silence a copy made under it.
printf '02:11:22:33:44:55\nevil_twin:02:11:22:33:44:66  # my Pager, testing its open AP\n' > "$_T/twins.txt"
_tset="$(sw_load_ignore "$_T/twins.txt")"
assert_eq "$_tset" " 02:11:22:33:44:55 EVIL_TWIN:02:11:22:33:44:66 " ignore_load_keeps_twin_entries
sw_ignored 'evil_twin|Evil twin|high|attacker|wifi|02:11:22:33:44:55|HomeNet|-38' "$_tset"; assert_eq "$?" "1" ignore_plain_mac_never_hides_a_twin
sw_ignored 'evil_twin|Evil twin|high|attacker|wifi|02:11:22:33:44:66|HomeNet|-38' "$_tset"; assert_eq "$?" "0" ignore_twin_entry_hides_that_twin
# the twin entry is for evil twins only; a plain entry still hides every other kind
sw_ignored 'hacker_flipper|Flipper Zero|high|attacker|ble|02:11:22:33:44:66|Flipper|-60' "$_tset"; assert_eq "$?" "1" ignore_twin_entry_only_for_twins
sw_ignored 'hacker_flipper|Flipper Zero|high|attacker|ble|02:11:22:33:44:55|Flipper|-60' "$_tset"; assert_eq "$?" "0" ignore_plain_entry_still_hides_other_kinds
rm -rf "$_T"; unset _T _set _D _X _tset

# A drone is silenced only by "drone:<its Remote ID>", or "drone:<MAC>" when it sends no ID (spec 2026-10-01
# §4): any case, spaces ignored, as sw_load_ignore stores every line. A plain address never silences one.
_igf="$(mktemp)"; printf '%s\n' '# my own drone' 'drone:0000fswtest000000001' 'drone:80:e1:26:44:55:66' '80:E1:26:AA:BB:CC' > "$_igf"
_igs="$(sw_load_ignore "$_igf")"
assert_eq "$(sw_ignored "drone_rid|Drone|high|surveillance|wifi|80:E1:26:99:99:99|0000FSWTEST000000001|-47|a	b	c" "$_igs" && echo drop || echo keep)" "drop" drone_ignored_by_id_at_any_address
assert_eq "$(sw_ignored "drone_rid|Drone|high|surveillance|wifi|80:E1:26:AA:BB:CC|0000FSWTEST000000002|-47|a	b	c" "$_igs" && echo drop || echo keep)" "keep" drone_plain_mac_never_silences
assert_eq "$(sw_ignored "drone_rid|Drone|high|surveillance|wifi|80:E1:26:44:55:66||-60|a	b	c" "$_igs" && echo drop || echo keep)" "drop" drone_no_id_ignored_by_address
assert_eq "$(sw_ignored "drone_rid|Drone|high|surveillance|wifi|80:E1:26:99:99:99|0000 FSWTEST 000000001|-47|a	b	c" "$_igs" && echo drop || echo keep)" "drop" drone_id_spaces_ignored
# control: the plain address line still silences an ordinary device at that address
assert_eq "$(sw_ignored "hacker_flipper|Flipper Zero|high|attacker|ble|80:E1:26:AA:BB:CC|x|-60" "$_igs" && echo drop || echo keep)" "drop" drone_control_plain_mac_still_works
rm -f "$_igf"; unset _igf _igs
