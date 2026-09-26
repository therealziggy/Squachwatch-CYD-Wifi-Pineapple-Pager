#!/bin/bash
# tools/bench_match.sh — time the matcher on THIS machine (meant to run on the Pager).
# Usage: bash bench_match.sh <payload dir> [signatures file]
# Builds 100 WiFi + 100 BLE records from a fixed seed (every run times the same records) and
# times sw_match_stream over them. Spec 2026-09-26 §6.3: the shipped rule set must not be
# slower than the pre-index matcher with 27 rules.
dir="${1:?usage: bench_match.sh <payload dir> [signatures file]}"
sigfile="${2:-$dir/signatures.db}"
source "$dir/lib/match.sh"
SIGS="$(sw_load_signatures "$sigfile")"
RANDOM=42
recs="" line=""
for (( i = 0; i < 100; i++ )); do
  # RANDOM is read here, in this shell: a $( ) subshell may reseed it
  printf -v line 'wifi|%02X:%02X:%02X:11:22:33|SomeNetwork%d|-70' $((RANDOM % 256)) $((RANDOM % 256)) $((RANDOM % 256)) "$i"
  recs+="$line"$'\n'
  printf -v line 'ble|%02X:%02X:%02X:44:55:66|Device%d|-80|mfr:004c:10:5 uuid:fe9f sd:fe2c:00' $((RANDOM % 256)) $((RANDOM % 256)) $((RANDOM % 256)) "$i"
  recs+="$line"$'\n'
done
echo "rules: $(printf '%s\n' "$SIGS" | grep -c .)  records: $(printf '%s' "$recs" | grep -c .)"
time (printf '%s' "$recs" | sw_match_stream "$SIGS" > /dev/null)
