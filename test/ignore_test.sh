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
rm -rf "$_T"; unset _T _set _D _X
