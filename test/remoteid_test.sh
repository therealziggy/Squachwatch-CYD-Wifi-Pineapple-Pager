#!/bin/bash
# test/remoteid_test.sh — Remote ID over WiFi (spec 2026-10-01). Reads the committed fixtures in
# test/fixtures/rid/ (made by tools/rid_fixtures/build.sh from opendroneid-core-c).
SW_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../payloads/user/reconnaissance/squachwatch" && pwd)"
_RFIX="$(cd "$(dirname "${BASH_SOURCE[0]}")/fixtures" && pwd)/rid"

# --- the fixtures: tcpdump -t -nn -xx text, radiotap with a signal, no clock times ---
for _f in beacon nan parrot multi unknowns equator order quiet truncated badlink; do
  assert_eq "$([ -s "$_RFIX/$_f.txt" ] && echo ok)" "ok" "rid_fixture_present_$_f"
done
assert_contains "$(cat "$_RFIX/beacon.txt")" "-47dBm signal Beacon (TEST-DRONE)" rid_fixture_signal_header
assert_empty "$(grep -lE '^[0-9]{2}:[0-9]{2}:[0-9]{2}\.' "$_RFIX"/*.txt)" rid_fixtures_no_clock_times
# control: the same check does see a clock time at the start of a line
assert_contains "$(printf '22:13:20.000000 Beacon\n' | grep -E '^[0-9]{2}:[0-9]{2}:[0-9]{2}\.')" "22:13:20" rid_fixture_clock_check_works
unset _f

