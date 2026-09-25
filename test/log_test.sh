#!/bin/bash
SW_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../payloads/user/reconnaissance/squachwatch" && pwd)"
source "$SW_ROOT/lib/log.sh"
D="$(mktemp -d)"
sw_log_init "$D"
assert_contains "$(head -1 "$D/detections.csv")" "time,category,label,confidence,threat_class,radio,mac,ident,rssi,gps" csv_header

export SW_FAKE_GPS="37.77,-122.41"
sw_log_write "$D" "flock_alpr|Flock Falcon camera|high|surveillance|wifi|70:C9:4E:11:22:33||-40" "1700000000"
row="$(tail -1 "$D/detections.csv")"
assert_contains "$row" "flock_alpr" csv_cat
assert_contains "$row" "70:C9:4E:11:22:33" csv_mac
assert_contains "$row" "37.77,-122.41" csv_gps

# --- coverage / positive controls: real-shape GPS (multi-value) + ident with comma & quote ---
# real device GPS_GET returns space-separated "lat lon alt acc"; ident may hold commas/quotes.
export SW_FAKE_GPS="37.77 -122.41 15.2 5.0"
sw_log_write "$D" "cat|lbl|high|surveillance|wifi|AA:BB:CC:00:11:22|Bob's \"Guest, Net\"|-50" "1700000001"
row2="$(tail -1 "$D/detections.csv")"
# the row must still be EXACTLY 10 CSV columns (real CSV parse, not substring)
ncols="$(printf '%s\n' "$row2" | python3 -c 'import csv,sys; print(len(next(csv.reader(sys.stdin))))')"
assert_eq "$ncols" "10" csv_ten_columns
# multi-value GPS survives as ONE field (col 10, 0-indexed 9)
gpsfield="$(printf '%s\n' "$row2" | python3 -c 'import csv,sys; print(next(csv.reader(sys.stdin))[9])')"
assert_eq "$gpsfield" "37.77,-122.41,15.2,5.0" csv_gps_one_field
# ident with comma + quote round-trips intact (col 8, 0-indexed 7)
identfield="$(printf '%s\n' "$row2" | python3 -c 'import csv,sys; print(next(csv.reader(sys.stdin))[7])')"
assert_eq "$identfield" "Bob's \"Guest, Net\"" csv_ident_roundtrip

# formula-injection guard: an SSID starting with '=' must be neutralized with a leading
# apostrophe so a spreadsheet treats it as text (not a live =HYPERLINK/DDE formula), and
# must still occupy exactly one CSV cell.
sw_log_write "$D" 'cat|lbl|high|surveillance|wifi|AA:BB:CC:00:11:22|=HYPERLINK("http://x")|-50' "1700000002"
row3="$(tail -1 "$D/detections.csv")"
identf3="$(printf '%s\n' "$row3" | python3 -c 'import csv,sys; print(next(csv.reader(sys.stdin))[7])')"
assert_eq "${identf3:0:1}" "'" csv_formula_neutralized
assert_eq "$(printf '%s\n' "$row3" | python3 -c 'import csv,sys; print(len(next(csv.reader(sys.stdin))))')" "10" csv_formula_ten_cols
rm -rf "$D"
