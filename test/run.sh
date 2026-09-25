#!/usr/bin/env bash
# test/run.sh — zero-dependency bash test runner. Run: bash test/run.sh
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export SW_STUB_LOG="$(mktemp)"
export PATH="$ROOT/test/stubs:$PATH"
PASS=0; FAIL=0
pass(){ PASS=$((PASS+1)); }
fail(){ FAIL=$((FAIL+1)); echo "  FAIL: $*"; }
assert_eq(){ if [ "$1" = "$2" ]; then pass; else fail "${3:-eq}: expected [$2] got [$1]"; fi; }
assert_contains(){ case "$1" in *"$2"*) pass;; *) fail "${3:-contains}: [$1] lacks [$2]";; esac; }
assert_empty(){ if [ -z "$1" ]; then pass; else fail "${2:-empty}: expected empty got [$1]"; fi; }
for t in "$ROOT"/test/*_test.sh; do
  [ -e "$t" ] || continue
  echo "== $(basename "$t") =="
  : > "$SW_STUB_LOG"
  # shellcheck disable=SC1090
  source "$t"
done
echo "-----------------------------"
echo "PASS=$PASS FAIL=$FAIL"
[ "$FAIL" -eq 0 ]
