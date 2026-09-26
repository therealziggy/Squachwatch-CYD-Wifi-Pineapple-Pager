# SquachWatch-Pager CYD Signature Port Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Port SquachWatch-CYD's current device signatures (83 active rules + 42 shipped switched off), fix our over-graded rules, and add a matcher index so a scan lap on the Pager is no slower than today.

**Architecture:**
- A new match type, `wifi_ssid_pre` (case-insensitive SSID prefix), sits next to `wifi_ssid_sub` in `sw_match_record`.
- `sw_prepare_sigs` additionally builds an index. Keyed rules (OUI, BLE company, 16-bit UUID) go into one associative array, `SW_IX`, and rules no key can narrow go into two per-radio scan lists.
- A new helper, `_sw_candidates`, fills `SW_CAND` with only the rules that could hit a record. `sw_match_record` loops over those in file order, with its per-rule body unchanged.
- `signatures.db` is rewritten with the spec's rule set. Weak rules ship as `#off ` comment lines.

**Tech Stack:**
- bash 5.2 payloads on the Hak5 WiFi Pineapple Pager (MT7628AN MIPS, BusyBox userland), btmon 5.72 / hcitool.
- Offline test harness: `bash test/run.sh` (sourced `*_test.sh` files and `test/stubs/`), with python3 only for the sqlite3 shim and fixture builder.

**Spec:** `docs/superpowers/specs/2026-09-26-squachwatch-cyd-signature-port-design.md`. Read §3, §6 and §8 before your task.

**Base commit:** `13dda44` (the spec commit on `main`; no code has changed yet).

**Who runs what:**
- **Task 1** runs first, on branch `cyd-signature-port`.
- **Tasks 2 and 3** run IN PARALLEL, each in its own git worktree branched from Task 1's commit. Their files do not overlap, except `test/perf_test.sh`, where they touch different lines.
- **Task 4** (integration), **Task 5** (the Pager) and **Task 6** (final review + merge) are run by the orchestrating session.

## Global Constraints

**Repo, branches, commits**
- Repo: this repository (the checkout or worktree named in your dispatch). It is a PUBLIC GitHub repo. **Never `git push`, never touch `.git/hooks` or git config.**
- Work only in the checkout or worktree named in your dispatch, on the branch named there.
- Every commit uses this exact form (UTC timestamps and the noreply identity are required, because the repo is public), with the message in a quoted heredoc:
  `TZ=UTC git -c user.name=Ziggy commit -F - <<'EOF'` … message … `EOF`
- Every commit message ends with the line `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. After each commit:
  - `git log -1 --format=%B | grep -cF 'Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>'` must print `1`;
  - `git log -1 --format=%ad --date=iso` must end in `+0000`.
  An earlier implementer replaced the trailer with its own model name. Do not.

**Privacy (public repo)**
- Use only synthetic device addresses in anything you commit: `AA:00:00:00:00:xx`, `C1:00:00:00:00:xx`, `00:00:00:00:00:0x`, or a registry prefix + `00:00:01`-style tail.
- Never commit real captures, clock times, epochs next to local dates, or any filesystem path of the machine you work on.

**Test harness**
- Run tests with `bash test/run.sh`. It prints `PASS=N FAIL=M` and exits non-zero on any failure.
- Test files are *sourced* into one shell running `set -u`:
  - prefix helper variables with `_` and `unset` them at the end of your block;
  - `unset -f` helper functions you define;
  - never `exit` in a test file.
- Assertions: `assert_eq ACTUAL EXPECTED NAME`, `assert_contains HAYSTACK NEEDLE NAME`, `assert_empty VALUE NAME`, `pass`, `fail "msg"`.

**Test discipline**
- **TDD is mandatory:** write the test, run the suite, and see it FAIL for the expected reason before writing code. Quote the failing assertion NAMES in your report.
- **Positive controls are mandatory:** pair every assertion that something is absent or empty with one proving the same path produced something.

**Code rules**
- **Hot-path contract** (header of `lib/match.sh`): `sw_match_record` and every helper it calls per record use bash builtins only. That means no pipes, no `$( )`, no backticks, and no `tr`/`sed`/`cut`/`awk`/`grep`. Arithmetic `(( ))` is fine. `test/perf_test.sh` enforces this.
- Libraries never assign config defaults with `:=`.
- **Formats are unchanged:**
  - detections: `category|label|confidence|threat_class|radio|mac|ident|rssi` (8 fields);
  - records: `radio|mac|ident|rssi[|tokens]`;
  - signature lines: `match_type|pattern|category|label|confidence|threat_class`.
- Only `high` raises a full-screen alert. `med`/`low` log only (existing behaviour, do not change).

## File Structure

| File | Responsibility | Task |
|---|---|---|
| `payloads/user/reconnaissance/squachwatch/lib/match.sh` | `wifi_ssid_pre` arm (T1); index in `sw_prepare_sigs`, new `_sw_candidates`, candidate loop in `sw_match_record` (T2) | 1, 2 |
| `payloads/user/reconnaissance/squachwatch/signatures.db` | the ported rule set (spec §3) | 3 |
| `test/match_test.sh` | `wifi_ssid_pre` unit tests | 1 |
| `test/index_test.sh` | **new**: index == full scan (differential), candidate counts, hostile tokens | 2, 4 |
| `test/signatures_test.sh` | known-types list (T1); updated seeds + port tests (T3) | 1, 3 |
| `test/perf_test.sh` | `_sw_candidates` fork-free (T2); positive control uses an active prefix (T3) | 2, 3 |
| `test/payload_test.sh` | Flock row now comes from `B4:1E:52` | 3 |
| `tools/build_fixture_db.py`, `test/fixtures/recon.db` | add a `B4:1E:52` AP row; `SW_FIXTURE_NOW` for deterministic builds | 3 |
| `README.md` | match types (T1); signatures, status, credits (T3); test count (T4); Pager timings (T5) | 1, 3, 4, 5 |
| `tools/bench_match.sh` | **new**: on-device matcher benchmark | 5 |
| `docs/superpowers/P0-findings.md` | on-device results | 5 |

---

### Task 1: The `wifi_ssid_pre` match type

**Files:**
- Modify: `payloads/user/reconnaissance/squachwatch/lib/match.sh` (the `case "$mtype"` in `sw_match_record`)
- Modify: `test/signatures_test.sh:19` (known match types)
- Modify: `README.md` (the `match_type` bullet)
- Test: `test/match_test.sh` (append)

**Interfaces:**
- Consumes: nothing new.
- Produces: signature lines of type `wifi_ssid_pre` match when `radio` is `wifi` and the lowercased, sanitized SSID **starts with** the lowercased pattern. Empty SSID or empty pattern never match. Tasks 2 and 3 rely on the name `wifi_ssid_pre`.

- [ ] **Step 1: Write the failing tests.** Append to `test/match_test.sh`:

```bash
# --- wifi_ssid_pre: case-insensitive SSID PREFIX (spec 2026-09-26 §6.1) ---
_PRE='wifi_ssid_pre|ab3-|surveillance_axon|Axon body camera|high|surveillance
wifi_ssid_pre|Pineapple_|hacker_pineapple|WiFi Pineapple setup network|med|attacker'
assert_eq "$(sw_match_record 'wifi|00:00:00:00:00:01|AB3-X7Q2|-50' "$_PRE")" \
  "surveillance_axon|Axon body camera|high|surveillance|wifi|00:00:00:00:00:01|AB3-X7Q2|-50" pre_hit_case_insensitive
assert_contains "$(sw_match_record 'wifi|00:00:00:00:00:02|pineapple_1A2B|-60' "$_PRE")" "hacker_pineapple|" pre_hit_pattern_case_folded
assert_empty "$(sw_match_record 'wifi|00:00:00:00:00:01|LAB3-GUEST|-50' "$_PRE")" pre_not_a_substring_match
assert_empty "$(sw_match_record 'wifi|00:00:00:00:00:02|MyPineapple_Net|-60' "$_PRE")" pre_not_mid_string
assert_empty "$(sw_match_record 'wifi|00:00:00:00:00:03||-60' "$_PRE")" pre_empty_ssid_silent
assert_empty "$(sw_match_record 'ble|00:00:00:00:00:04|AB3-X7Q2|-60' "$_PRE")" pre_wifi_only
assert_empty "$(sw_match_record 'wifi|AA:BB:CC:00:11:22|anything|-50' 'wifi_ssid_pre||x|X|low|attacker')" pre_empty_pattern_guard
# control: the same near-miss SSID DOES hit a substring rule, so the silence above comes from
# the prefix rule and not from the record
assert_contains "$(sw_match_record 'wifi|00:00:00:00:00:01|LAB3-GUEST|-50' 'wifi_ssid_sub|ab3-|x|X|low|attacker')" "x|X|low" pre_control_substring_does_hit
unset _PRE
```

In `test/signatures_test.sh`, replace line 19:

```bash
_types_awk='$1!="wifi_oui" && $1!="wifi_ssid_sub" && $1!="ble_name_sub" && $1!="ble_oui" && $1!="ble_mfr" && $1!="ble_uuid" {print}'
```

with:

```bash
_types_awk='$1!="wifi_oui" && $1!="wifi_ssid_sub" && $1!="wifi_ssid_pre" && $1!="ble_name_sub" && $1!="ble_oui" && $1!="ble_mfr" && $1!="ble_uuid" {print}'
```

and add directly after line 21 (the `sig_match_type_check_catches_typo` assertion):

```bash
assert_empty "$(printf 'wifi_ssid_pre|ab3-|x|x|high|surveillance\n' | awk -F'|' "$_types_awk")" sig_match_type_pre_known
```

- [ ] **Step 2: Run the suite to verify the new tests fail.**

Run: `bash test/run.sh 2>&1 | grep -E 'FAIL|PASS='`
Expected: FAIL for `pre_hit_case_insensitive` and `pre_hit_pattern_case_folded`, because the unknown type is ignored, so both come out empty. `sig_match_type_pre_known` passes already (the awk list was just edited), which is fine. Every other test passes.

- [ ] **Step 3: Implement.** In `lib/match.sh`, `sw_match_record`, add this arm directly after the `wifi_ssid_sub)` arm:

```bash
      wifi_ssid_pre) if [ "$radio" = wifi ] && [ -n "$ident" ] && [ -n "$norm" ]; then case "$lident" in "$norm"*) hit=0;; esac; fi ;;
```

(`sw_prepare_sigs` already lowercases every non-OUI pattern, so no change is needed there.)

In `README.md`, replace the line

```
- `match_type`: `wifi_oui` · `wifi_ssid_sub` · `ble_name_sub` · `ble_oui` · `ble_mfr` · `ble_uuid`
```

with

```
- `match_type`: `wifi_oui` · `wifi_ssid_sub` · `wifi_ssid_pre` · `ble_name_sub` · `ble_oui` · `ble_mfr` · `ble_uuid` (`wifi_ssid_sub` matches anywhere in the network name, `wifi_ssid_pre` only at its start; both ignore case)
```

- [ ] **Step 4: Run the suite.**

Run: `bash test/run.sh 2>&1 | tail -1`
Expected: `PASS=435 FAIL=0` (426 + 8 new in match_test + 1 new in signatures_test).

- [ ] **Step 5: Commit.**

```bash
git add payloads/user/reconnaissance/squachwatch/lib/match.sh test/match_test.sh test/signatures_test.sh README.md
TZ=UTC git -c user.name=Ziggy commit -F - <<'EOF'
match: add wifi_ssid_pre (case-insensitive SSID prefix)

SquachWatch-CYD matches setup networks by prefix (AB3-, Pineapple_, pwned).
A substring rule would also hit LAB3-GUEST or MyPineapple_Net.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
git log -1 --format=%B | grep -cF 'Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>'   # 1
git log -1 --format=%ad --date=iso                                                           # ends +0000
```

---

### Task 2: The matcher index

**Runs in its own worktree, in parallel with Task 3.**

**Files:**
- Modify: `payloads/user/reconnaissance/squachwatch/lib/match.sh` (header comment, a top-level `declare`, `sw_prepare_sigs`, new `_sw_candidates`, the loop header in `sw_match_record`)
- Create: `test/index_test.sh`
- Modify: `test/perf_test.sh:14` (fork-free list)

**Interfaces:**
- Consumes: `wifi_ssid_pre` (Task 1). The prepared arrays `SW_SIG_TYPE/CAT/LABEL/CONF/CLASS/NORM` are unchanged.
- Produces, built by `sw_prepare_sigs` (Task 4 relies on these exact names):
  - `SW_IX`: global associative array. Keys `w:<OUI>`, `b:<OUI>`, `m:<4hex company>`, `u:<4hex uuid>`; each value is a space-separated list of rule numbers.
  - `SW_SCAN_WIFI` / `SW_SCAN_BLE`: space-separated rule numbers.
- Produces: `_sw_candidates RADIO OUI TOKENS`, which sets the global sparse indexed array `SW_CAND`. Its INDICES are the candidate rule numbers.
- `sw_match_record` output is byte-identical to before for every input (the property `test/index_test.sh` checks).

- [ ] **Step 1: Write the failing tests.** Create `test/index_test.sh`:

```bash
# test/index_test.sh  (sourced by run.sh) — the matcher's index (spec 2026-09-26 §6.2, §8).
# The index decides which rules sw_match_record even looks at. The one way it can go wrong is
# by leaving out a rule that would have hit, so these tests compare the indexed matcher with a
# FULL scan of every rule (exactly what the matcher did before the index), byte for byte.
SW_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../payloads/user/reconnaissance/squachwatch" && pwd)"
_IFIX="$(cd "$(dirname "${BASH_SOURCE[0]}")/fixtures" && pwd)"
source "$SW_ROOT/lib/match.sh"; source "$SW_ROOT/lib/ble.sh"; source "$SW_ROOT/lib/wifi.sh"

# Synthetic rules: every match type, including shapes the index must NOT key (ranges, bad
# companies and UUIDs, empty patterns) and a type the matcher does not know.
_IX_SYN='wifi_oui|aa:bb:cc|x_oui|OUI (lowercase in file)|high|attacker
wifi_oui||x_oui_empty|Empty OUI|low|attacker
ble_oui|C1:00:00|x_boui|BLE OUI|med|attacker
wifi_ssid_sub|net|x_sub|SSID substring|low|surveillance
wifi_ssid_pre|home|x_pre|SSID prefix|med|surveillance
wifi_ssid_pre||x_pre_empty|Empty prefix|low|surveillance
ble_name_sub|flip|x_name|Name|low|attacker
ble_mfr|004C|x_mfr_co|Apple any|low|tracker
ble_mfr|004c:12|x_mfr_type|Find My any|med|tracker
ble_mfr|004c:12:25|x_mfr_full|Find My separated|high|tracker
ble_mfr|zz:12|x_mfr_bad|Bad company|low|tracker
ble_mfr||x_mfr_empty|Empty mfr|low|tracker
ble_uuid|FD5A|x_uuid|SmartTag (uppercase in file)|med|tracker
ble_uuid|feaa:41|x_uuid_fb|Google Find My|med|tracker
ble_uuid|feaa:4|x_uuid_badfb|Short first byte|low|tracker
ble_uuid|3100-3500|x_range|Range|low|surveillance
ble_uuid|zzzz|x_uuid_bad|Bad UUID|low|surveillance
ble_uuid||x_uuid_empty|Empty UUID|low|surveillance
ble_company|0x004C|x_unknown|Unknown type|high|tracker'

# Records: every fixture capture, the recon fixture, and hand-made / hostile records.
_ix_recs="$(for _f in "$_IFIX"/btmon_*.txt; do sw_btmon_parse < "$_f"; done
  SW_RECENCY_SECS=0 sw_wifi_records "$_IFIX/recon.db"
  printf '%s\n' \
    'wifi|AA:BB:CC:00:00:01|HomeNet|-50' \
    'wifi|AA:BB:CC:00:00:02||-50' \
    'wifi|12:34:56:00:00:03|home-office|-51' \
    'wifi|12:34:56:00:00:04|MyNet|-52' \
    'wifi|||-1' \
    'wifi|B4:1E:52:00:00:05|flock-7A2C|-40' \
    'wifi|70:C9:4E:11:22:33|AB3-X7Q2|-41' \
    'wifi|02:13:37:00:00:06|Pineapple_1A2B|-42' \
    'wifi|00:25:DF:00:00:07|pwned|-43' \
    'ble|C1:00:00:00:00:01|Flipper Bob|-55' \
    'ble|C1:00:00:00:00:02||-56|mfr:004c:12:25 sd:feaa:41 uuid:fd5a' \
    'ble|80:E1:26:00:00:03|flipper|-57|uuid:3082 mfr:0e29:01:4' \
    'ble|AA:00:00:00:00:66||-80|sd::41 uuid:zzzz' \
    'ble|AA:00:00:00:00:67||-80|uuid:* sd:feaa:4 mfr:zz:12:1 mfr:' \
    'ble|AA:00:00:00:00:68|HC-05|-81|uuid:1101 uuid:fffa uuid:fd5f mfr:01ab:02:3 mfr:09c8:00:6' \
    'ble|||' \
    'ble|AA:00:00:00:00:69||-82|uuid:3150 uuid:3100 sd:3200:01' \
    'ble|80:e1:26:00:00:0a|lower mac|-60|uuid:FD5A mfr:004C:12:25' \
    'zzz|70:C9:4E:11:22:33|x|1')"
unset _f

_ix_run() {  # $1 = signature text -> every record's detections, in record order
  local _r
  while IFS= read -r _r; do [ -n "$_r" ] && sw_match_record "$_r" "$1"; done <<< "$_ix_recs"
}
# Full scan: every rule is a candidate, which is what the matcher did before the index.
_ix_fullscan() {
  _sw_candidates() { SW_CAND=(); local k; for (( k = 0; k < ${#SW_SIG_TYPE[@]}; k++ )); do SW_CAND[k]=1; done; }
}
_ix_compare() {  # $1 = signature text, $2 = test name: the indexed output must equal the full scan's
  local _idx _full
  _idx="$(_ix_run "$1")"
  _ix_fullscan; _full="$(_ix_run "$1")"
  source "$SW_ROOT/lib/match.sh"    # restores the real _sw_candidates
  assert_eq "$_idx" "$_full" "$2"
  _IX_LAST="$_idx"
}

_ix_real="$(sw_load_signatures "$SW_ROOT/signatures.db")"
_ix_all="$(sed 's/^#off //' "$SW_ROOT/signatures.db" | grep -v '^[[:space:]]*#' | grep -v '^[[:space:]]*$')"
_ix_compare "$_IX_SYN" index_equals_fullscan_synthetic
# non-vacuity: the synthetic comparison exercised keyed, scanned, range and unkeyable rules
assert_contains "$_IX_LAST" "x_mfr_full|Find My separated|high" index_syn_keyed_mfr_hit
assert_contains "$_IX_LAST" "x_range|Range|low" index_syn_range_hit
assert_contains "$_IX_LAST" "x_pre|SSID prefix|med" index_syn_prefix_hit
assert_contains "$_IX_LAST" "x_uuid_bad|Bad UUID|low" index_syn_unkeyed_uuid_hit
_ix_compare "$_ix_real" index_equals_fullscan_real
assert_contains "$_IX_LAST" "hacker_flipper|Flipper Zero|high" index_real_nonvacuous
_ix_compare "$_ix_all" index_equals_fullscan_real_with_off_rules

# POSITIVE CONTROL: the comparison can fail. Drop one key from a prepared index and the
# indexed matcher loses the Apple rules, so it must now DIFFER from the full scan.
sw_prepare_sigs "$_IX_SYN"; SW_SIGS_CACHE="$_IX_SYN"
unset 'SW_IX[m:004c]'
_ix_broken="$(_ix_run "$_IX_SYN")"
_ix_fullscan; _ix_ok="$(_ix_run "$_IX_SYN")"; source "$SW_ROOT/lib/match.sh"
assert_eq "$([ "$_ix_broken" != "$_ix_ok" ] && echo differs)" "differs" index_compare_can_fail
unset SW_SIGS_CACHE    # the index above is broken: force the next caller to re-prepare

# Candidate counts: the speed property, deterministic and machine-independent. The synthetic
# set scans rules 3,4,5 (WiFi) and 6,10,11,14,15,16,17 (BLE); everything else is keyed.
sw_prepare_sigs "$_IX_SYN"; SW_SIGS_CACHE="$_IX_SYN"
_sw_candidates wifi "12:34:56" "";  assert_eq "${#SW_CAND[@]}" "3" index_wifi_scans_ssid_rules_only
_sw_candidates wifi "AA:BB:CC" "";  assert_eq "${#SW_CAND[@]}" "4" index_wifi_adds_its_oui_rule
_sw_candidates ble "12:34:56" "";   assert_eq "${#SW_CAND[@]}" "7" index_ble_scans_unkeyable_rules_only
_sw_candidates ble "C1:00:00" "mfr:004c:12:25 sd:feaa:41 uuid:fd5a"
assert_eq "${!SW_CAND[*]}" "2 6 7 8 9 10 11 12 13 14 15 16 17" index_ble_candidates_in_file_order
_sw_candidates zzz "12:34:56" "uuid:fd5a"; assert_eq "${#SW_CAND[@]}" "0" index_unknown_radio_no_candidates
# hostile tokens: no error, and nothing keyed
assert_empty "$( { _sw_candidates ble "12:34:56" "sd::41 uuid:zzzz mfr: uuid:"; } 2>&1 )" index_hostile_tokens_no_error
_sw_candidates ble "12:34:56" "sd::41 uuid:zzzz mfr: uuid:"; assert_eq "${#SW_CAND[@]}" "7" index_hostile_tokens_add_nothing
# a token is never a file pattern: in a folder holding a file named "uuid:fd5a", the token
# "uuid:*" must not expand to it (which would add the SmartTag rule)
_ixg="$(mktemp -d)"; : > "$_ixg/uuid:fd5a"
assert_eq "$(cd "$_ixg" && set -- uuid:*; echo "$1")" "uuid:fd5a" index_glob_control_would_expand
assert_eq "$(cd "$_ixg" && _sw_candidates ble "12:34:56" "uuid:*" && echo "${#SW_CAND[@]}")" "7" index_tokens_never_glob
rm -rf "$_ixg"
unset SW_SIGS_CACHE
unset _IX_SYN _IX_LAST _ix_recs _ix_real _ix_all _ix_broken _ix_ok _ixg _IFIX
unset -f _ix_run _ix_fullscan _ix_compare
```

In `test/perf_test.sh`, replace line 14:

```bash
for _fn in sw_sanitize_ident sw_oui _sw_lower _sw_uuid_hit; do
```

with:

```bash
for _fn in sw_sanitize_ident sw_oui _sw_lower _sw_uuid_hit _sw_candidates; do
```

- [ ] **Step 2: Run the suite to verify the new tests fail.**

Run: `bash test/run.sh 2>&1 | grep -E 'FAIL|PASS=' | head -30`
Expected:
- The differential tests pass or error out: `_ix_fullscan` defines `_sw_candidates`, but the real one does not exist yet, so `sw_match_record` never calls it.
- These FAIL: `index_compare_can_fail` (`SW_IX` does not exist, so nothing differs), every `index_*` count assertion (`_sw_candidates: command not found`), and `index_tokens_never_glob`.
- `forkfree__sw_candidates` passes vacuously: the function is missing, so its body is empty. It becomes meaningful once the function exists.

Record the failing names in your report.

- [ ] **Step 3: Implement.** In `lib/match.sh`:

(a) Replace the header comment (lines 2–7) with:

```bash
# lib/match.sh — signature loading, OUI extraction, and match dispatch.
#
# PERF CONTRACT (see test/perf_test.sh): every function below runs once per record,
# and a real sweep is ~18k records on a 580MHz MIPS CPU. They must use bash builtins
# only — no pipes, no $( ). The fork-based version measured ~1.04 s/record on the
# Pager (~5.2 h per sweep). Helpers return via REPLY so callers need no subshell.
#
# THE INDEX (spec 2026-09-26 §6.2): even fork-free, each rule costs ~2 ms per record on the
# Pager, so a record only meets the rules that could hit it. sw_prepare_sigs files each rule
# under the key a record must carry for it to hit (SW_IX), and lists the rules no key can
# narrow (substrings, prefixes, ranges, odd shapes) per radio; _sw_candidates combines them.

# SW_IX exists from the moment the library loads, so a lookup is always an associative one
# (on an undeclared name bash would evaluate the key "w:AA:BB:CC" as arithmetic).
declare -gA SW_IX 2>/dev/null
```

(b) Replace the whole `sw_prepare_sigs` function with:

```bash
sw_prepare_sigs() {
  # $1 = signatures text. Parses ONCE into parallel arrays and pre-normalizes each
  # pattern to the case its matcher needs. Previously this normalization happened
  # per record PER signature (~40 forks/record) — the dominant cost of a sweep.
  # Also builds the index (header): SW_IX maps "w:<OUI>" (wifi_oui), "b:<OUI>" (ble_oui),
  # "m:<company>" (ble_mfr) and "u:<uuid16>" (ble_uuid, exact or first-byte form) to the
  # numbers of the rules filed there; SW_SCAN_WIFI / SW_SCAN_BLE list the rest. A pattern
  # whose shape fits no key is scanned, so it still gets exactly the check it always got.
  SW_SIG_TYPE=(); SW_SIG_CAT=(); SW_SIG_LABEL=(); SW_SIG_CONF=(); SW_SIG_CLASS=(); SW_SIG_NORM=()
  unset SW_IX; declare -gA SW_IX=()
  SW_SCAN_WIFI=""; SW_SCAN_BLE=""
  local mtype pat cat label conf tclass norm key n=0
  while IFS='|' read -r mtype pat cat label conf tclass; do
    [ -n "$mtype" ] || continue
    case "$mtype" in
      wifi_oui|ble_oui) norm="${pat^^}" ;;
      *)                norm="${pat,,}" ;;
    esac
    SW_SIG_TYPE+=("$mtype"); SW_SIG_CAT+=("$cat"); SW_SIG_LABEL+=("$label")
    SW_SIG_CONF+=("$conf"); SW_SIG_CLASS+=("$tclass"); SW_SIG_NORM+=("$norm")
    key=""
    case "$mtype" in
      wifi_oui) key="w:$norm" ;;
      ble_oui)  key="b:$norm" ;;
      wifi_ssid_sub|wifi_ssid_pre) SW_SCAN_WIFI+=" $n" ;;
      ble_name_sub) SW_SCAN_BLE+=" $n" ;;
      ble_mfr)
        case "${norm%%:*}" in
          [0-9a-f][0-9a-f][0-9a-f][0-9a-f]) key="m:${norm%%:*}" ;;
          *) SW_SCAN_BLE+=" $n" ;;
        esac ;;
      ble_uuid)
        case "$norm" in
          [0-9a-f][0-9a-f][0-9a-f][0-9a-f]|[0-9a-f][0-9a-f][0-9a-f][0-9a-f]:[0-9a-f][0-9a-f]) key="u:${norm:0:4}" ;;
          *) SW_SCAN_BLE+=" $n" ;;
        esac ;;
    esac
    [ -z "$key" ] || SW_IX["$key"]+=" $n"
    n=$((n + 1))
  done <<HEREDOC
$1
HEREDOC
}

_sw_candidates() {
  # $1 = radio, $2 = OUI (upper, "AA:BB:CC"), $3 = advertisement tokens -> SW_CAND, a sparse
  # indexed array whose INDICES are the numbers of the rules worth checking (bash lists them
  # in ascending, i.e. file, order). It holds every rule that could hit the record: an OUI
  # rule can only hit its own OUI, a ble_mfr rule only a token of its company, and a ble_uuid
  # rule only a token of its UUID. Fork-free (perf contract). Keys are namespaced, so none is
  # ever empty (an empty subscript is a "bad array subscript" error). Globbing is off, so a
  # hostile token such as "uuid:*" stays a string instead of becoming a file pattern.
  local -
  set -f
  local IFS=$' \t\n' k t u
  SW_CAND=()
  case "$1" in
    wifi) for k in ${SW_IX["w:$2"]-} ${SW_SCAN_WIFI-}; do SW_CAND[k]=1; done ;;
    ble)
      for k in ${SW_IX["b:$2"]-} ${SW_SCAN_BLE-}; do SW_CAND[k]=1; done
      for t in $3; do
        case "$t" in
          mfr:*)  u="${t#mfr:}"; u="${u%%:*}"; for k in ${SW_IX["m:$u"]-}; do SW_CAND[k]=1; done ;;
          uuid:*) u="${t#uuid:}";              for k in ${SW_IX["u:$u"]-}; do SW_CAND[k]=1; done ;;
          sd:*)   u="${t#sd:}";  u="${u%%:*}"; for k in ${SW_IX["u:$u"]-}; do SW_CAND[k]=1; done ;;
        esac
      done ;;
  esac
}
```

(c) In `sw_match_record`, replace the single loop-header line

```bash
  for (( i=0; i<${#SW_SIG_TYPE[@]}; i++ )); do
```

with

```bash
  # Only the rules that could hit this record (spec 2026-09-26 §6.2), in file order.
  _sw_candidates "$radio" "$oui" "$adv"
  for i in "${!SW_CAND[@]}"; do
```

Change nothing else in `sw_match_record`: the per-rule `case`, the strongest-per-category bookkeeping and the output loop stay exactly as they are.

- [ ] **Step 4: Run the suite.**

Run: `bash test/run.sh 2>&1 | tail -1`
Expected: `FAIL=0`. PASS = the Task-1 total (435) + 18 new assertions in `index_test.sh` + 1 new in `perf_test.sh` (`forkfree__sw_candidates`) = `PASS=454`. If your count differs, list the new assertion names in your report.

Then prove the positive control can bite on the real code. Temporarily change `SW_IX["$key"]+=" $n"` to `[ "$mtype" = ble_uuid ] || SW_IX["$key"]+=" $n"` and run `bash test/run.sh 2>&1 | grep FAIL`. Expected: `index_equals_fullscan_synthetic`, `index_equals_fullscan_real` and several count assertions FAIL. Revert the change, re-run, confirm `FAIL=0`. Quote both runs in your report.

- [ ] **Step 5: Commit.**

```bash
git add payloads/user/reconnaissance/squachwatch/lib/match.sh test/index_test.sh test/perf_test.sh
TZ=UTC git -c user.name=Ziggy commit -F - <<'EOF'
match: index the rules so a record only meets rules that could hit it

Each rule costs ~2 ms per record on the Pager, so 4x the rules would make a
lap ~3.5x slower. OUI, BLE company and 16-bit UUID rules are filed under
their key; substring/prefix/range rules stay in a per-radio scan list.
test/index_test.sh checks the indexed matcher against a full scan, byte for
byte, over every fixture record and hostile records.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
git log -1 --format=%B | grep -cF 'Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>'   # 1
git log -1 --format=%ad --date=iso                                                           # ends +0000
```

---

### Task 3: The ported rule set

**Runs in its own worktree, in parallel with Task 2.**

**Files:**
- Modify (full rewrite): `payloads/user/reconnaissance/squachwatch/signatures.db`
- Modify: `test/signatures_test.sh` (two seeds; append the port block)
- Modify: `test/perf_test.sh:38-44` (positive control)
- Modify: `test/payload_test.sh:23` (Flock row)
- Modify: `tools/build_fixture_db.py`; regenerate: `test/fixtures/recon.db`
- Modify: `README.md` (Signatures section, Status & roadmap, Credits)

**Interfaces:**
- Consumes: `wifi_ssid_pre` (Task 1). It does NOT need Task 2: the index changes speed, not results.
- Produces: `signatures.db` with exactly 83 active rules and 42 `#off ` lines (Task 4 asserts candidate counts on it: 9 WiFi scan rules, 13 BLE scan rules).

- [ ] **Step 1: Write the failing tests.**

(a) In `test/signatures_test.sh`, replace line 13:

```bash
assert_contains "$(sw_match_record 'wifi|70:C9:4E:11:22:33||-40' "$SIGS")" "flock" seed_flock
```

with

```bash
assert_contains "$(sw_match_record 'wifi|B4:1E:52:11:22:33||-40' "$SIGS")" "flock_generic|Flock Safety device|high" seed_flock
```

and replace line 15:

```bash
assert_contains "$(sw_match_record 'wifi|00:00:00:00:00:00|xPineapplex|' "$SIGS")" "pineapple" seed_pineapple
```

with

```bash
assert_contains "$(sw_match_record 'wifi|00:00:00:00:00:00|Pineapple_1A2B|' "$SIGS")" "hacker_pineapple|WiFi Pineapple setup network|med" seed_pineapple
```

(b) Append to the end of `test/signatures_test.sh`:

```bash
# --- the CYD signature port (spec 2026-09-26 §3, §8) ---
_P="$SIGS"   # the real, ACTIVE rule set
_PFX="$(cd "$(dirname "${BASH_SOURCE[0]}")/fixtures" && pwd)"
_pm() { sw_match_record "$1" "$_P"; }
_ptypes='$1!="wifi_oui" && $1!="wifi_ssid_sub" && $1!="wifi_ssid_pre" && $1!="ble_name_sub" && $1!="ble_oui" && $1!="ble_mfr" && $1!="ble_uuid" {print}'
# counts: 83 active rules load, 42 ship switched off
assert_eq "$(printf '%s\n' "$_P" | grep -c .)" "83" port_active_rule_count
assert_eq "$(grep -c '^#off ' "$SW_ROOT/signatures.db")" "42" port_off_rule_count
# every #off line is a complete, valid, low rule once switched on...
_off="$(sed -n 's/^#off //p' "$SW_ROOT/signatures.db")"
assert_empty "$(printf '%s\n' "$_off" | awk -F'|' 'NF!=6 || $5!="low" || ($6!="surveillance" && $6!="tracker" && $6!="attacker") {print}')" port_off_rules_valid_low
assert_empty "$(printf '%s\n' "$_off" | awk -F'|' "$_ptypes")" port_off_rules_known_types
# ...each one hits a device carrying its own prefix (a positive control per rule)...
_miss=""
while IFS='|' read -r _t _pat _c _l _cf _tc; do
  [ "$_t" = wifi_oui ] || { _miss="$_miss $_pat(type)"; continue; }
  [ -n "$(sw_match_record "wifi|$_pat:00:00:01||-50" "$_t|$_pat|$_c|$_l|$_cf|$_tc")" ] || _miss="$_miss $_pat"
done <<< "$_off"
assert_empty "$_miss" port_off_rules_each_hit_when_enabled
# ...and while switched off, none of them loads
assert_empty "$(_pm 'wifi|70:C9:4E:11:22:33||-40')" port_off_chip_prefix_silent
# CYD's rule: a locally administered (self-assigned) address names no vendor, so no ACTIVE
# prefix rule with bit 0x02 of its first octet set may be graded above low
_la=""
while IFS='|' read -r _t _pat _c _l _cf _tc; do
  case "$_t" in wifi_oui|ble_oui) ;; *) continue ;; esac
  [ $(( 16#${_pat:0:2} & 2 )) -ne 0 ] && [ "$_cf" != low ] && _la="$_la $_pat"
done <<< "$_P"
assert_empty "$_la" port_no_active_locally_administered_prefix_above_low
_pat=02:13:37; assert_eq "$(( 16#${_pat:0:2} & 2 ))" "2" port_la_bit_check_control
# the eight chip-vendor prefixes that were "high" Flock rules until 2026-09-26 (Lite-On, USI,
# Silicon Labs blocks, not Flock's) are not active any more
for _o in 70:C9:4E 3C:91:80 D8:F3:BC 14:5A:FC 08:3A:88 58:8E:81 EC:1B:BD 90:35:EA; do
  assert_empty "$(printf '%s\n' "$_P" | grep -F "|$_o|")" "port_regraded_$_o"
done
# Flock
assert_eq "$(_pm 'wifi|B4:1E:52:00:00:01||-50')" "flock_generic|Flock Safety device|high|surveillance|wifi|B4:1E:52:00:00:01||-50" port_flock_registered_prefix
assert_contains "$(_pm 'wifi|00:00:00:00:00:02|FLOCK-7A2C|-50')" "flock_generic|Flock setup network|high" port_flock_setup_ssid
assert_empty "$(_pm 'wifi|00:00:00:00:00:02|myflock-7A2C|-50')" port_flock_setup_ssid_prefix_only
assert_contains "$(_pm 'ble|00:00:00:00:00:03|Flock_Setup|-60')" "flock_generic|Flock setup|high" port_flock_setup_name_high
assert_contains "$(_pm 'ble|00:00:00:00:00:04||-60|mfr:09c8:01:6')" "flock_generic|Flock device (XUNTONG radio)|high" port_flock_xuntong
assert_eq "$(_pm 'ble|00:00:00:00:00:05|Flockhart|-60')" "flock_generic|Flock device|med|surveillance|ble|00:00:00:00:00:05|Flockhart|-60" port_flock_word_stays_med
# Axon
assert_contains "$(_pm 'wifi|00:25:DF:00:00:01||-50')" "surveillance_axon|Axon / Taser device|high" port_axon_prefix
assert_contains "$(_pm 'wifi|00:00:00:00:00:02|AB3-X7Q2|-50')" "surveillance_axon|Axon body camera|high" port_axon_bodycam_ssid
assert_empty "$(_pm 'wifi|00:00:00:00:00:02|LAB2-GUEST|-50')" port_axon_ssid_prefix_only
assert_contains "$(_pm 'ble|00:00:00:00:00:03|Axon Body 3|-60')" "surveillance_axon|Axon device|high" port_axon_name
# plate readers
assert_contains "$(_pm 'wifi|4C:CC:34:00:00:01||-50')" "surveillance_alpr|Motorola plate reader / police|high" port_alpr_motorola
assert_contains "$(_pm 'wifi|0C:BF:15:00:00:01||-50')" "surveillance_alpr|Genetec plate reader|high" port_alpr_genetec
# CYD's old "Vigilant" entry 00:0E:58 is Sonos's block: it must stay out
assert_empty "$(_pm 'wifi|00:0E:58:00:00:01||-50')" port_alpr_not_sonos
# cameras
assert_contains "$(_pm 'wifi|2C:AA:8E:00:00:01||-50')" "surveillance_camera|Wyze camera|high" port_camera_wyze
assert_contains "$(_pm 'wifi|34:D2:70:00:00:01||-50')" "surveillance_camera|Amazon device (possible camera)|med" port_camera_amazon_med
assert_empty "$(_pm 'wifi|00:E0:4C:00:00:01||-50')" port_camera_realtek_switched_off
# Ring
assert_contains "$(_pm 'wifi|50:E4:67:00:00:01||-50')" "surveillance_ring|Ring doorbell / camera|high" port_ring_prefix
assert_contains "$(_pm 'wifi|FC:65:DE:00:00:01||-50')" "surveillance_ring|Amazon / Ring device|med" port_ring_amazon_med
assert_contains "$(_pm 'wifi|00:00:00:00:00:02|Ring-4F2A|-50')" "surveillance_ring|Ring setup network|med" port_ring_setup_ssid
assert_empty "$(_pm 'wifi|00:00:00:00:00:02|Spring-5G|-50')" port_ring_ssid_prefix_only
# card skimmers
assert_contains "$(_pm 'ble|00:00:00:00:00:03|HC-05|-60')" "surveillance_skimmer|Possible card skimmer (HC-05)|high" port_skimmer_hc05
assert_contains "$(_pm 'ble|00:00:00:00:00:03|RN42-1A2B|-60')" "surveillance_skimmer|Possible card skimmer (RN42)|high" port_skimmer_rn42_default_name
assert_contains "$(_pm 'ble|00:00:00:00:00:04||-60|uuid:1101')" "surveillance_skimmer|Possible card skimmer (serial port)|high" port_skimmer_serial_port
# camera glasses
assert_contains "$(_pm 'ble|00:00:00:00:00:04||-60|uuid:fd5f')" "surveillance_glasses|Ray-Ban Meta glasses|med" port_glasses_rayban
assert_contains "$(_pm 'ble|00:00:00:00:00:04||-60|mfr:01ab:02:9')" "surveillance_glasses|Meta device (glasses or headset)|med" port_glasses_meta_company
assert_contains "$(_pm 'ble|00:00:00:00:00:04||-60|mfr:03c2:00:4')" "surveillance_glasses|Snap Spectacles|med" port_glasses_snap
# Raven: CYD's five exact IDs, no longer a range
assert_contains "$(_pm 'ble|00:00:00:00:00:04||-60|uuid:3300')" "surveillance_raven|" port_raven_exact
assert_empty "$(_pm 'ble|00:00:00:00:00:04||-60|uuid:3101')" port_raven_no_longer_a_range
# drones
assert_eq "$(_pm 'ble|00:00:00:00:00:04||-70|sd:fffa:0d')" "surveillance_drone|Drone (Remote ID)|med|surveillance|ble|00:00:00:00:00:04||-70" port_drone_remote_id
# Flipper's exact signatures (its name alone stays med)
assert_contains "$(_pm 'ble|C1:00:00:00:00:01|MyTool|-60|uuid:3083')" "hacker_flipper|Flipper Zero|high" port_flipper_uuid
assert_contains "$(_pm 'ble|C1:00:00:00:00:01||-60|mfr:0e29:01:4')" "hacker_flipper|Flipper Zero|high" port_flipper_company
assert_empty "$(_pm 'ble|C1:00:00:00:00:01||-60|mfr:0fba:01:4')" port_flipper_not_the_copied_wrong_id
assert_empty "$(_pm 'ble|C1:00:00:00:00:01||-60|uuid:3084')" port_flipper_uuid_exact
assert_contains "$(_pm 'wifi|0C:FA:22:00:00:01||-50')" "hacker_flipper|Flipper Devices hardware|high" port_flipper_registered_prefix
# hacker WiFi
assert_eq "$(_pm 'wifi|00:00:00:00:00:02|Pineapple_1A2B|-50')" "hacker_pineapple|WiFi Pineapple setup network|med|attacker|wifi|00:00:00:00:00:02|Pineapple_1A2B|-50" port_pineapple_setup_med
assert_empty "$(_pm 'wifi|00:00:00:00:00:02|MyPineappleNet|-50')" port_pineapple_substring_no_longer_matches
assert_contains "$(_pm 'wifi|00:00:00:00:00:02|pwned|-50')" "hacker_deauther|ESP deauther network|med" port_deauther
assert_empty "$(_pm 'wifi|00:00:00:00:00:02|ipwned|-50')" port_deauther_prefix_only
# the captures give exactly the detections they gave before the port (pinned at 756ac91): none
# of the new IDs appear in them except Flipper's 0x3082, which lands in the same category as
# its 80:E1:26 prefix
_sum() { sw_btmon_parse < "$_PFX/$1.txt" | sw_match_stream "$_P" | cut -d'|' -f1,3 | LC_ALL=C sort | uniq -c | sed 's/^ *//'; }
assert_eq "$(_sum btmon_live_2026-09-22)" "1 hacker_flipper|high
1 tracker_findmy|med" port_real_live_unchanged
assert_eq "$(_sum btmon_phone_2026-09-23)" "1 hacker_flipper|high
1 tracker_findmy|med
1 tracker_gfmd|med
1 tracker_smarttag|med
1 tracker_tile|med" port_real_phone_unchanged
assert_eq "$(_sum btmon_blespam_2026-09-24)" "1 hacker_flipper|high
17 hacker_flipper|med
3 tracker_airtag_setup|med
1 tracker_findmy|med" port_real_blespam_unchanged
assert_eq "$(_sum btmon_apple_pp)" "2 tracker_airtag_setup|med" port_apple_pp_unchanged
assert_eq "$(_sum btmon_synthetic)" "1 flock_battery|high
1 hacker_flipper|high
2 surveillance_raven|low
1 tracker_gfmd|med
2 tracker_smarttag|med
1 tracker_tile|med" port_synthetic_unchanged
assert_eq "$(_sum btmon_hostile)" "1 tracker_findmy|med
1 tracker_tile|med" port_hostile_unchanged
unset _P _PFX _ptypes _off _miss _t _pat _c _l _cf _tc _la _o
unset -f _pm _sum
```

(c) In `test/perf_test.sh`, replace lines 38–39:

```bash
_sw_bulk="$(i=0; while [ $i -lt 499 ]; do printf 'wifi|AA:BB:CC:00:11:%02X|HomeNet%d|-60\n' $((i%256)) $i; i=$((i+1)); done
            printf 'wifi|70:C9:4E:11:22:33|FlockCam|-40\n')"   # POSITIVE CONTROL row
```

with

```bash
_sw_bulk="$(i=0; while [ $i -lt 499 ]; do printf 'wifi|AA:BB:CC:00:11:%02X|HomeNet%d|-60\n' $((i%256)) $i; i=$((i+1)); done
            printf 'wifi|B4:1E:52:11:22:33|FlockCam|-40\n')"   # POSITIVE CONTROL row (Flock Safety's own block)
```

and line 44:

```bash
assert_eq "$(printf '%s\n' "$_sw_out" | grep -c 'flock_alpr')" "1" perf_positive_control
```

with

```bash
assert_eq "$(printf '%s\n' "$_sw_out" | grep -c 'flock_generic')" "1" perf_positive_control
```

(d) In `test/payload_test.sh`, replace line 23:

```bash
assert_contains "$(tail -n +2 "$SW_LOOT_DIR/detections.csv")" "flock_alpr" payload_logs_flock
```

with

```bash
assert_contains "$(tail -n +2 "$SW_LOOT_DIR/detections.csv")" "flock_generic" payload_logs_flock
# the fixture's Lite-On chip prefix has been a switched-off rule since 2026-09-26: no row for it
# (payload_logs_flock above is the positive control: the same lap wrote the Flock row)
assert_empty "$(grep -F '70:C9:4E' "$SW_LOOT_DIR/detections.csv")" payload_chip_prefix_not_logged
```

- [ ] **Step 2: Run the suite to verify the new tests fail.**

Run: `bash test/run.sh 2>&1 | grep -E 'FAIL|PASS='`
Expected FAILs (old rule set still in place), among them:
- `seed_flock`, `seed_pineapple`
- `port_active_rule_count`, `port_off_rule_count`
- `port_flock_registered_prefix`, `port_axon_prefix`
- `port_raven_no_longer_a_range`, `port_pineapple_substring_no_longer_matches`
- `port_regraded_70:C9:4E`, `perf_positive_control`, `payload_logs_flock`

All six `port_*_unchanged` summaries PASS already: they pin today's behaviour. Record the failing names.

- [ ] **Step 3: Rewrite `signatures.db`** with exactly this content:

```
# SquachWatch-Pager signatures — match_type|pattern|category|label|confidence|threat_class
#
# Only "high" raises the full-screen alert + buzz; "med" and "low" log a colored line and a
# CSV row. Grades follow SquachWatch-CYD's rule (include/signatures.h, docs/DETECTIONS.md):
#   high = the ID is registered to the company that makes the product, or is an exact
#          self-identifying signature;
#   med  = registered to a parent far broader than the product, or a name anyone can type;
#   low  = a chip/module vendor inside everything, an unregistered block, or a locally
#          administered (self-assigned) address.
# Ported from SquachWatch-CYD at commit ecaff618 (GPL-3.0). Every MAC prefix was checked
# against the IEEE MA-L registry, every company ID and service UUID against the Bluetooth SIG.
#
# SWITCHED-OFF RULES: a line starting "#off " is a complete rule that ships disabled: weak,
# generic-chip evidence that, switched on, would log every nearby gadget built on that chip
# (one row per device every SW_COOLDOWN). To switch one on, delete the leading "#off ".
# test/signatures_test.sh keeps every #off line valid.

# ---- Flock Safety (surveillance) ----
# B4:1E:52 is the only MAC block registered to Flock Safety. Flock builds on commodity chips,
# so the other prefixes seen on Flock hardware belong to the chip makers; they are listed
# below, switched off.
wifi_oui|B4:1E:52|flock_generic|Flock Safety device|high|surveillance
wifi_ssid_pre|flock-|flock_generic|Flock setup network|high|surveillance
ble_name_sub|penguin|flock_battery|Flock Penguin battery|high|surveillance
ble_name_sub|pigvision|flock_alpr|Flock Pigvision device|high|surveillance
ble_name_sub|fs ext battery|flock_battery|Flock external battery|high|surveillance
ble_name_sub|flock_setup|flock_generic|Flock setup|high|surveillance
# The bare word "flock" is too common for a full alert (SquachWatch-CYD grades it high).
ble_name_sub|flock|flock_generic|Flock device|med|surveillance
# 0x09C8 (XUNTONG) is the Bluetooth radio supplier in Flock hardware (flock-you, via CYD). It
# names a module supplier, so drop it to med if it ever false-alarms.
ble_mfr|09c8|flock_generic|Flock device (XUNTONG radio)|high|surveillance
# Switched off: chip-vendor prefixes seen on Flock hardware (15 Espressif ESP32 blocks, 10
# Lite-On, and others). Until 2026-09-26 eight of these were "high" Flock rules here.
#off wifi_oui|24:0A:C4|flock_chip|Possible Flock (ESP32 chip)|low|surveillance
#off wifi_oui|30:AE:A4|flock_chip|Possible Flock (ESP32 chip)|low|surveillance
#off wifi_oui|24:6F:28|flock_chip|Possible Flock (ESP32 chip)|low|surveillance
#off wifi_oui|CC:50:E3|flock_chip|Possible Flock (ESP32 chip)|low|surveillance
#off wifi_oui|DC:54:75|flock_chip|Possible Flock (ESP32 chip)|low|surveillance
#off wifi_oui|E8:9F:6D|flock_chip|Possible Flock (ESP32 chip)|low|surveillance
#off wifi_oui|8C:AA:B5|flock_chip|Possible Flock (ESP32 chip)|low|surveillance
#off wifi_oui|34:85:18|flock_chip|Possible Flock (ESP32 chip)|low|surveillance
#off wifi_oui|AC:67:B2|flock_chip|Possible Flock (ESP32 chip)|low|surveillance
#off wifi_oui|84:F3:EB|flock_chip|Possible Flock (ESP32 chip)|low|surveillance
#off wifi_oui|B4:E6:2D|flock_chip|Possible Flock (ESP32 chip)|low|surveillance
#off wifi_oui|CC:DB:A7|flock_chip|Possible Flock (ESP32 chip)|low|surveillance
#off wifi_oui|94:B9:7E|flock_chip|Possible Flock (ESP32 chip)|low|surveillance
#off wifi_oui|A4:CF:12|flock_chip|Possible Flock (ESP32 chip)|low|surveillance
#off wifi_oui|C0:49:EF|flock_chip|Possible Flock (ESP32 chip)|low|surveillance
#off wifi_oui|70:C9:4E|flock_chip|Possible Flock (Lite-On chip)|low|surveillance
#off wifi_oui|3C:91:80|flock_chip|Possible Flock (Lite-On chip)|low|surveillance
#off wifi_oui|D8:F3:BC|flock_chip|Possible Flock (Lite-On chip)|low|surveillance
#off wifi_oui|14:5A:FC|flock_chip|Possible Flock (Lite-On chip)|low|surveillance
#off wifi_oui|80:30:49|flock_chip|Possible Flock (Lite-On chip)|low|surveillance
#off wifi_oui|74:4C:A1|flock_chip|Possible Flock (Lite-On chip)|low|surveillance
#off wifi_oui|24:B2:B9|flock_chip|Possible Flock (Lite-On chip)|low|surveillance
#off wifi_oui|D0:39:57|flock_chip|Possible Flock (Lite-On chip)|low|surveillance
#off wifi_oui|00:F4:8D|flock_chip|Possible Flock (Lite-On chip)|low|surveillance
#off wifi_oui|E0:0A:F6|flock_chip|Possible Flock (Lite-On chip)|low|surveillance
#off wifi_oui|D4:AD:FC|flock_chip|Possible Flock (Intellirocks chip)|low|surveillance
#off wifi_oui|08:3A:88|flock_chip|Possible Flock (USI chip)|low|surveillance
#off wifi_oui|58:8E:81|flock_chip|Possible Flock battery (Silicon Labs chip)|low|surveillance
#off wifi_oui|EC:1B:BD|flock_chip|Possible Flock battery (Silicon Labs chip)|low|surveillance
#off wifi_oui|90:35:EA|flock_chip|Possible Flock battery (Silicon Labs chip)|low|surveillance
#off wifi_oui|00:A0:D8|flock_chip|Possible Flock (Spectra-Tek prefix)|low|surveillance
#off wifi_oui|B8:35:32|flock_chip|Possible Flock (unregistered prefix)|low|surveillance
#off wifi_oui|82:6B:F2|flock_chip|Possible Flock (self-assigned MAC)|low|surveillance

# ---- Axon body cameras / Taser (surveillance) ----
# 00:25:DF is Taser International (Axon's former name). Body cameras put up an AB2-/AB3-/AB4-
# network while pairing (Axon's admin documentation).
wifi_oui|00:25:DF|surveillance_axon|Axon / Taser device|high|surveillance
wifi_ssid_pre|ab2-|surveillance_axon|Axon body camera|high|surveillance
wifi_ssid_pre|ab3-|surveillance_axon|Axon body camera|high|surveillance
wifi_ssid_pre|ab4-|surveillance_axon|Axon body camera|high|surveillance
wifi_ssid_pre|axon-|surveillance_axon|Axon device network|high|surveillance
ble_name_sub|axon|surveillance_axon|Axon device|high|surveillance
# Switched off: E4:05:40 is not in the IEEE registry; 28:24:FF is Wistron NeWeb, an ODM.
#off wifi_oui|E4:05:40|surveillance_axon|Possible Axon (unregistered prefix)|low|surveillance
#off wifi_oui|28:24:FF|surveillance_axon|Possible Axon (Wistron NeWeb chip)|low|surveillance

# ---- Licence-plate readers (surveillance) ----
# Motorola Solutions (owns Vigilant) and Genetec (AutoVu) blocks, read from the IEEE registry.
# CYD dropped its old "Vigilant" entry 00:0E:58: that block is Sonos's, so every Sonos speaker
# had been logged as a plate reader.
wifi_oui|00:04:7D|surveillance_alpr|Motorola plate reader / police|high|surveillance
wifi_oui|00:18:85|surveillance_alpr|Motorola plate reader / police|high|surveillance
wifi_oui|00:1F:92|surveillance_alpr|Motorola plate reader / police|high|surveillance
wifi_oui|4C:CC:34|surveillance_alpr|Motorola plate reader / police|high|surveillance
wifi_oui|B8:E2:8C|surveillance_alpr|Motorola plate reader / police|high|surveillance
wifi_oui|00:BF:15|surveillance_alpr|Genetec plate reader|high|surveillance
wifi_oui|0C:BF:15|surveillance_alpr|Genetec plate reader|high|surveillance

# ---- Cameras (surveillance) ----
wifi_oui|2C:AA:8E|surveillance_camera|Wyze camera|high|surveillance
wifi_oui|D0:3F:27|surveillance_camera|Wyze camera|high|surveillance
wifi_oui|7C:78:B2|surveillance_camera|Wyze camera|high|surveillance
wifi_oui|C0:56:E3|surveillance_camera|Hikvision camera|high|surveillance
wifi_oui|44:19:B6|surveillance_camera|Hikvision camera|high|surveillance
wifi_oui|28:57:BE|surveillance_camera|Hikvision camera|high|surveillance
wifi_oui|E0:A7:00|surveillance_camera|Verkada camera|high|surveillance
wifi_oui|70:1A:D5|surveillance_camera|Avigilon Alta device|high|surveillance
wifi_oui|00:40:8C|surveillance_camera|Axis camera|high|surveillance
wifi_oui|B8:A4:4F|surveillance_camera|Axis camera|high|surveillance
# Amazon Technologies blocks are shared with Echo, Fire TV and Kindle, hence med.
wifi_oui|34:D2:70|surveillance_camera|Amazon device (possible camera)|med|surveillance
wifi_oui|F0:27:2D|surveillance_camera|Amazon device (possible camera)|med|surveillance
# Switched off: chips inside every kind of gadget, or unregistered blocks.
#off wifi_oui|B8:D7:AF|surveillance_camera|Possible Wyze camera (Murata chip)|low|surveillance
#off wifi_oui|00:E0:4C|surveillance_camera|Possible camera (Realtek chip)|low|surveillance
#off wifi_oui|BC:DD:C2|surveillance_camera|Possible Arlo camera (ESP32 chip)|low|surveillance
#off wifi_oui|4C:69:05|surveillance_camera|Possible Blink camera (unregistered prefix)|low|surveillance
#off wifi_oui|A4:C1:38|surveillance_camera|Possible camera (Telink chip)|low|surveillance

# ---- Ring doorbells / cameras (surveillance) ----
# Ring LLC's registered blocks (high), two Amazon Technologies blocks Ring also uses (med), and
# the network a Ring device puts up while it is being installed ("Ring-...").
wifi_oui|AC:9F:C3|surveillance_ring|Ring doorbell / camera|high|surveillance
wifi_oui|18:7F:88|surveillance_ring|Ring doorbell / camera|high|surveillance
wifi_oui|34:3E:A4|surveillance_ring|Ring doorbell / camera|high|surveillance
wifi_oui|54:E0:19|surveillance_ring|Ring doorbell / camera|high|surveillance
wifi_oui|5C:47:5E|surveillance_ring|Ring doorbell / camera|high|surveillance
wifi_oui|64:9A:63|surveillance_ring|Ring doorbell / camera|high|surveillance
wifi_oui|90:48:6C|surveillance_ring|Ring doorbell / camera|high|surveillance
wifi_oui|9C:76:13|surveillance_ring|Ring doorbell / camera|high|surveillance
wifi_oui|CC:3B:FB|surveillance_ring|Ring doorbell / camera|high|surveillance
wifi_oui|C4:DB:AD|surveillance_ring|Ring doorbell / camera|high|surveillance
wifi_oui|24:2B:D6|surveillance_ring|Ring doorbell / camera|high|surveillance
wifi_oui|00:B4:63|surveillance_ring|Ring doorbell / camera|high|surveillance
wifi_oui|50:E4:67|surveillance_ring|Ring doorbell / camera|high|surveillance
wifi_oui|FC:65:DE|surveillance_ring|Amazon / Ring device|med|surveillance
wifi_oui|68:37:E9|surveillance_ring|Amazon / Ring device|med|surveillance
wifi_ssid_pre|ring-|surveillance_ring|Ring setup network|med|surveillance

# ---- Card skimmers (surveillance) ----
# Serial-Bluetooth modules that skimmers are built from, by their default names, plus the
# serial-port service ID (SparkFun Skimmer Scanner, ESP32 Marauder, via CYD). Most of these
# modules are Bluetooth Classic, which a BLE scan cannot hear; this catches the BLE-capable ones.
ble_name_sub|hc-03|surveillance_skimmer|Possible card skimmer (HC-03)|high|surveillance
ble_name_sub|hc-05|surveillance_skimmer|Possible card skimmer (HC-05)|high|surveillance
ble_name_sub|hc-06|surveillance_skimmer|Possible card skimmer (HC-06)|high|surveillance
ble_name_sub|rn42|surveillance_skimmer|Possible card skimmer (RN42)|high|surveillance
ble_name_sub|bt04-a|surveillance_skimmer|Possible card skimmer (BT04-A)|high|surveillance
ble_uuid|1101|surveillance_skimmer|Possible card skimmer (serial port)|high|surveillance

# ---- Camera glasses (surveillance) ----
# 0xFD5F is Ray-Ban Meta's own service ID. The company IDs are Meta, Meta Platforms
# Technologies, Luxottica (who make Ray-Ban) and Snap (Spectacles). Meta's IDs also ship on
# Quest headsets, so a hit means "a Meta radio", hence med.
ble_uuid|fd5f|surveillance_glasses|Ray-Ban Meta glasses|med|surveillance
ble_mfr|01ab|surveillance_glasses|Meta device (glasses or headset)|med|surveillance
ble_mfr|058e|surveillance_glasses|Meta device (glasses or headset)|med|surveillance
ble_mfr|0d53|surveillance_glasses|Luxottica (Ray-Ban) device|med|surveillance
ble_mfr|03c2|surveillance_glasses|Snap Spectacles|med|surveillance

# ---- Raven gunshot sensors (surveillance) ----
# SquachWatch-CYD's five exact service IDs (flock-you's datasets). They are not verified on a
# real Raven, hence low (log only), and they replace our earlier 3100-3500 range. Hobby devices
# live nearby: a Flipper advertises 0x3081-0x3083.
ble_uuid|3100|surveillance_raven|Raven gunshot sensor (possible)|low|surveillance
ble_uuid|3200|surveillance_raven|Raven gunshot sensor (possible)|low|surveillance
ble_uuid|3300|surveillance_raven|Raven gunshot sensor (possible)|low|surveillance
ble_uuid|3400|surveillance_raven|Raven gunshot sensor (possible)|low|surveillance
ble_uuid|3500|surveillance_raven|Raven gunshot sensor (possible)|low|surveillance

# ---- Drones (surveillance) ----
# ASTM F3411 Remote ID over Bluetooth (legacy advertising). Presence only: decoding the drone's
# serial and the pilot's position belongs with Remote ID over WiFi, a later phase.
ble_uuid|fffa|surveillance_drone|Drone (Remote ID)|med|surveillance

# ---- Trackers (Tier 3: raw BLE advertisements via btmon, spec 2026-09-22) ----
# Trackers log at med (colored line + CSV row). lib/follow.sh escalates one that STAYS
# with you to a high "<category>_follow" alert. Your own devices: loot dir ignore.txt.
# Only Find My (004c:12:25) and Google Find My (feaa:41) are separation-aware. The SmartTag
# and Tile rules match EVERY SmartTag/Tile, owner nearby or not, so a companion's tag that
# stays with you escalates too: silence a known companion's tag via ignore.txt.
ble_name_sub|tile|tracker_tile|Tile tracker|med|tracker
# Apple Find My, separated from its owner: type 0x12, 25-byte payload (seen live
# 2026-09-22). The near-owner form (2-byte payload) deliberately does NOT match.
ble_mfr|004c:12:25|tracker_findmy|Apple Find My (separated)|med|tracker
# Apple Proximity Pairing (0x07) from a NON-audio model = an AirTag in setup mode: freshly
# powered, e.g. right after a battery swap (SquachWatch-CYD saw a real separated AirTag send 0x07
# before it switched to Find My 0x12). AirPods/Beats send 0x07 too, but every published model
# code for them ends in 0x20, so the parser tags those "audio" and they never match here.
# CYD matches EVERY 0x07 and accepts the AirPods noise; this keeps the catch without it.
ble_mfr|004c:07:other|tracker_airtag_setup|Apple AirTag (setup mode)|med|tracker
ble_uuid|fd5a|tracker_smarttag|Samsung SmartTag|med|tracker
ble_uuid|feed|tracker_tile|Tile|med|tracker
ble_uuid|feec|tracker_tile|Tile|med|tracker
# Google Find My: service data 0xFEAA with frame 0x41 = separated (inferred from Google's
# spec). The first-byte check keeps Eddystone beacons (also 0xFEAA) out.
ble_uuid|feaa:41|tracker_gfmd|Google Find My (separated)|med|tracker

# ---- Hacker tools (attacker) ----
# A Flipper matched by its NAME ALONE is med, as in SquachWatch-CYD (src/detection.cpp:
# matchedByName ? MED_CONF : HIGH_CONF; "the owner can change it"). On 2026-09-23 a BLE Spam
# flood of random MACs named "Flipper 🐬" hit this rule 9 times in one lap. The exact
# signatures below still make a real Flipper high (strongest match wins, lib/match.sh).
ble_name_sub|flipper|hacker_flipper|Flipper Zero|med|attacker
# 80:E1:26 is not an IEEE registration (CYD leaves it out for that reason): Flipper firmware
# builds its BLE address from the STM32's device ID (0x26) and ST's company-ID bytes (E1, 80),
# see furi_hal_version.c, so every Flipper Zero's address starts 80:E1:26. Seen on real hardware.
ble_oui|80:E1:26|hacker_flipper|Flipper Zero|high|attacker
# Flipper's three service IDs (one per case colour) and its Bluetooth SIG company ID 0x0E29.
# The 0x0FBA that other projects copied belongs to a headset maker.
ble_uuid|3081|hacker_flipper|Flipper Zero|high|attacker
ble_uuid|3082|hacker_flipper|Flipper Zero|high|attacker
ble_uuid|3083|hacker_flipper|Flipper Zero|high|attacker
ble_mfr|0e29|hacker_flipper|Flipper Zero|high|attacker
# 0C:FA:22 is Flipper Devices' own registered block.
wifi_oui|0C:FA:22|hacker_flipper|Flipper Devices hardware|high|attacker
# Default setup networks: a WiFi Pineapple's management AP ("Pineapple_XXXX") and the
# ESP8266/ESP32 deauther family's control AP ("pwned"). Anyone can name their WiFi this: med.
wifi_ssid_pre|pineapple_|hacker_pineapple|WiFi Pineapple setup network|med|attacker
wifi_ssid_pre|pwned|hacker_deauther|ESP deauther network|med|attacker
wifi_ssid_sub|pager_open|hacker_pager|WiFi Pineapple Pager|med|attacker
# Switched off: Hak5's locally administered (self-assigned) MACs, which anyone can set.
#off wifi_oui|02:C0:CA|hacker_pineapple|Possible Hak5 device (self-assigned MAC)|low|attacker
#off wifi_oui|02:13:37|hacker_pineapple|Possible Hak5 device (self-assigned MAC)|low|attacker
```

- [ ] **Step 4: Give the fixture recon.db an active Flock row.**

In `tools/build_fixture_db.py`:
- change `import sqlite3, sys, time` to `import os, sqlite3, sys, time`;
- change `now = int(time.time())` to `now = int(os.environ.get("SW_FIXTURE_NOW") or time.time())  # fixed epoch = reproducible committed fixture`.

In `devs`, replace the line `devs = [("h_flock","70c94e112233",1200),` with:

```python
devs = [("h_flock","70c94e112233",1200),
        ("h_flocksafe","b41e52112233",900),
```

In `rows`, replace the line
` ("70c94e112233","",8,6,2437,-40,0,0,now,"h_flock"),          # Flock camera AP`
with:

```python
 ("70c94e112233","",8,6,2437,-40,0,0,now,"h_flock"),          # Lite-On chip prefix: a switched-off rule since 2026-09-26
 ("b41e52112233","",8,6,2437,-45,0,0,now,"h_flocksafe"),      # Flock Safety's own registered block
```

Regenerate the committed fixture into a FRESH file (SQLite keeps freed pages, so never rebuild in place), with the fixed epoch the committed file already uses:

```bash
_t="$(mktemp -d)" && SW_FIXTURE_NOW=1700000000 python3 tools/build_fixture_db.py "$_t/recon.db" && mv "$_t/recon.db" test/fixtures/recon.db && rmdir "$_t"
python3 -c "import sqlite3; c=sqlite3.connect('test/fixtures/recon.db'); print(sorted(c.execute('SELECT s.bssid, CAST(s.ssid AS TEXT), s.time FROM ssid s')))"
```

Expected: 6 rows, including `('b41e52112233', '', 1700000000)`. Every time is `1700000000` except the `OldAP` row's `1699996400`.

- [ ] **Step 5: Update README.md.**

Replace the line

```
- `pattern`: e.g. `70:C9:4E` (an OUI), `pineapple` (an SSID substring), `Penguin-` (a BLE name substring)
```

with

```
- `pattern`: e.g. `B4:1E:52` (an OUI), `pineapple_` (an SSID prefix), `Penguin` (a BLE name substring)
```

Replace the whole `- \`confidence\`: …` bullet (the line starting `` - `confidence`: ``) with

```
- `confidence`: `high` | `med` | `low` (only `high` raises a full-screen alert; others just log a colored line). Grades follow SquachWatch-CYD's rule, checked against the IEEE MAC registry and the Bluetooth SIG lists: **high** when the ID is registered to the company that makes the product (or is an exact self-identifying signature), **med** when it belongs to a much broader parent (Amazon's blocks also cover Echo and Kindle) or is a name anyone can type, **low** for chips inside everything (ESP32, Lite-On, Realtek…), unregistered blocks and self-assigned addresses. So a **Flipper Zero** matched by its advertised name alone is `med` (BLE Spam floods fake that name), while its hardware signatures make it `high`. When one device matches several rules of the same category, only its strongest match counts.
```

Replace the line starting `Add a detection by adding a line` with

```
Add a detection by adding a line — no code changes. Lines starting with `#` are comments. **Switched-off rules:** a line starting `#off ` is a complete rule shipped disabled: weak, generic-chip evidence that would log every nearby gadget built on that chip. Delete the `#off ` to switch it on. Signatures never contain `|`; observed device names have `|` and control characters stripped before matching, so a device can't split a token to evade a signature.
```

Replace the line starting `The seed set covers Tier-1 targets` with

```
**What it detects** (83 active rules, 42 switched off): Flock Safety devices, Axon body cameras, Motorola and Genetec plate readers, Wyze/Hikvision/Verkada/Avigilon/Axis cameras and Amazon devices, Ring doorbells, Bluetooth card-skimmer modules, camera glasses (Ray-Ban Meta, Snap), Raven gunshot sensors, drones broadcasting Remote ID, personal trackers (Apple Find My and AirTags in setup mode, Samsung SmartTag, Tile, Google Find My) and hacker tools (Flipper Zero, WiFi Pineapple and Pager, ESP deauthers). Each family's comment in `signatures.db` names its source.
```

In `## Status & roadmap`, insert this paragraph directly before the line `Deferred to their own phases:`:

```
**Signature port** (2026-09-26): SquachWatch-CYD's current fingerprints, graded the way CYD grades them, by who the ID is registered to. That audit also demoted eight of our own "Flock" prefixes that turned out to belong to chip makers (Lite-On, USI, Silicon Labs), so they no longer raise alerts. Weak generic-chip rules ship switched off. The matcher now indexes its rules, so each device is only checked against the rules that could fit it.
```

Replace the `## Credits` paragraph with

```
Homage to **SquachWatch-CYD** by skizzophrenic (https://github.com/skizzophrenic/SquachWatch-CYD, GPL-3.0): this project ports ideas, rules and logic from it, such as AUTO SNOOZE, rating a hacker tool matched by name alone as medium, and its signature set and grading (ported at commit `ecaff61`; CYD credits colonelpanichacks/flock-you, ESP32 Marauder, Eye Spy, the SparkFun Skimmer Scanner and others). MAC prefixes checked against the IEEE registry, Bluetooth IDs against the Bluetooth SIG assigned numbers. Detection patterns and data adapted from Hak5 community payloads: Flock_Detect (colonelpanichacks et al.), flipper_detector (nemanjan00), find_hackers (NULLFaceNoCase), SkimmerScanner (Adam Glenn), device_profiler (z3r0l1nk), recondb_reporting (Digs). Native alert event schemas from the official Hak5 example payloads.
```

- [ ] **Step 6: Run the suite.**

Run: `bash test/run.sh 2>&1 | tail -1`
Expected: `FAIL=0`. Every assertion from Step 1 passes, including the six `port_*_unchanged` summaries. `PASS` = 435 (the Task-1 total) + 60 new assertions in the port block (54 + the 6 unchanged summaries) + 1 new payload assertion = `PASS=496`. If the count differs, list the new assertion names in your report.

Then prove the per-rule `#off` check can fail: temporarily change one `#off` line's grade from `low` to `lw` and re-run. Expected: `port_off_rules_valid_low` FAILs. Revert and re-run to `FAIL=0`. Quote both.

- [ ] **Step 7: Commit.**

```bash
git add payloads/user/reconnaissance/squachwatch/signatures.db test/signatures_test.sh test/perf_test.sh test/payload_test.sh tools/build_fixture_db.py test/fixtures/recon.db README.md
TZ=UTC git -c user.name=Ziggy commit -F - <<'EOF'
signatures: port SquachWatch-CYD's rule set, graded by registrant

83 active rules + 42 weak ones shipped switched off ("#off "). New: Flock
Safety's own block, Axon body cameras, Motorola/Genetec plate readers, cameras,
Ring, card skimmers, camera glasses, drones (Remote ID), Flipper's exact IDs.
Eight of our "high" Flock prefixes were Lite-On/USI/Silicon Labs blocks: now
switched off. Pineapple: setup-network prefix at med (was any SSID containing
pineapple, high). Raven: CYD's five exact IDs instead of a range.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
git log -1 --format=%B | grep -cF 'Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>'   # 1
git log -1 --format=%ad --date=iso                                                           # ends +0000
```

---

### Task 4: Integration (orchestrating session)

**Files:**
- Modify: `test/index_test.sh` (real-set candidate counts)
- Modify: `README.md` (test count)

- [ ] **Step 1: Bring Tasks 2 and 3 onto `cyd-signature-port`.** Cherry-pick each worktree branch's commits in order (Task 2, then Task 3) with `TZ=UTC git -c user.name=Ziggy cherry-pick <sha>`. Resolve any `test/perf_test.sh` conflict by keeping both changes. Run `bash test/run.sh`; expected `FAIL=0`.

- [ ] **Step 2: Add the real-set candidate counts.** In `test/index_test.sh`, insert directly before the line `unset SW_SIGS_CACHE` that precedes the final `unset _IX_SYN …` line:

```bash
# with the SHIPPED rule set, a record meets only the rules that could fit it (spec §6.3):
# 9 WiFi prefix/substring rules, 13 BLE name rules, plus whatever its OUI and tokens key
sw_prepare_sigs "$_ix_real"; SW_SIGS_CACHE="$_ix_real"
assert_eq "${#SW_SIG_TYPE[@]}" "83" index_real_rule_count
_sw_candidates wifi "12:34:56" "";  assert_eq "${#SW_CAND[@]}" "9" index_real_wifi_candidates
_sw_candidates wifi "B4:1E:52" "";  assert_eq "${#SW_CAND[@]}" "10" index_real_wifi_oui_candidates
_sw_candidates ble "12:34:56" "";   assert_eq "${#SW_CAND[@]}" "13" index_real_ble_candidates
_sw_candidates ble "80:E1:26" "uuid:3082 mfr:004c:12:25"; assert_eq "${#SW_CAND[@]}" "17" index_real_flipper_candidates
```

Run `bash test/run.sh`; expected `FAIL=0` with 5 more passes: `PASS=520` (435 + 19 from Task 2 + 61 from Task 3 + these 5).

- [ ] **Step 3: One-time independent check (recorded in the SDD ledger, not committed).** Run the matcher as of Task 1's commit (a full scan, independent code) and the final matcher over every fixture record, with three rule sets: the active set, the set with every `#off` enabled, and the synthetic set from `test/index_test.sh`. Compare the outputs with `cmp` and record `SAME` or the diff.

- [ ] **Step 4: Full suite as the normal user AND as root** (`unshare -r bash test/run.sh`). Record both `PASS=` lines. Replace the README's `**426 assertions, all passing**` with the new total, then commit (`TZ=UTC`, trailer).

---

### Task 5: On the Pager (orchestrating session; install approved by the user for this job)

**Files:**
- Create: `tools/bench_match.sh`
- Modify: `docs/superpowers/P0-findings.md`, `README.md` (Status & roadmap timing sentence)

- [ ] **Step 1: Create `tools/bench_match.sh`:**

```bash
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
recs=""
for (( i = 0; i < 100; i++ )); do
  recs+="$(printf 'wifi|%02X:%02X:%02X:11:22:33|SomeNetwork%d|-70' $((RANDOM % 256)) $((RANDOM % 256)) $((RANDOM % 256)) "$i")"$'\n'
  recs+="$(printf 'ble|%02X:%02X:%02X:44:55:66|Device%d|-80|mfr:004c:10:5 uuid:fe9f sd:fe2c:00' $((RANDOM % 256)) $((RANDOM % 256)) $((RANDOM % 256)) "$i")"$'\n'
done
echo "rules: $(printf '%s\n' "$SIGS" | grep -c .)  records: $(printf '%s' "$recs" | grep -c .)"
time (printf '%s' "$recs" | sw_match_stream "$SIGS" > /dev/null)
```

- [ ] **Step 2: Back up, install and verify.**
  - Back up the installed scanner to `/root/squachwatch-backup-2026-09-26/`. It must sit outside `/root/payloads`, so the UI shows no duplicate.
  - `scp` the payload folder over the installed one.
  - Compare `sha256sum` of every payload file on both sides.
- [ ] **Step 3: Launcher-faithful silent lap.** Build a copy of `payload.sh` with the launcher's header injected after line 1, plus shell functions that shadow `LOG ALERT LED RINGTONE VIBRATE TITLE START_SPINNER STOP_SPINNER` (they write to a temp log instead of the screen, speaker and LEDs). Source it with only `PAYLOAD_HOME` plus temp loot/seen/tmp paths and `SW_TEST_SOURCE=1`. Then run `sw_log_init`, `sw_healthcheck` and one timed `sw_scan_once`. Expected: 83 signatures, health rc 0, no errors, a lap time comparable to before (18 s on 2026-09-26 with 27 rules).
- [ ] **Step 4: Benchmark.** Run `tools/bench_match.sh` on the Pager three ways:
  - against the backup (old matcher, 27 rules);
  - against the new install (83 rules);
  - against the new install with every `#off` rule enabled (125 rules).

  Acceptance: new ≤ old, and all-enabled within 10% of new.
- [ ] **Step 5: Record and clean up.**
  - Add a P0-findings table: aggregate results only, no device MACs.
  - Add the timing sentence to README's Status & roadmap.
  - Remove the temp files on the Pager.
  - Commit (`TZ=UTC`, trailer).

---

### Task 6: Final review and merge (orchestrating session)

- [ ] **Step 1:** Final whole-branch review on the most capable model, with the review package `main..cyd-signature-port`, the spec, and the Minor-findings list from the ledger.
- [ ] **Step 2:** One fix subagent for all Critical/Important findings, then a re-review.
- [ ] **Step 3:** `git checkout main && git merge --ff-only cyd-signature-port`. No push. Remove the worktrees and their branches, then update the memory files.

---

## Notes after execution (2026-09-26)

- **Task 2, Step 4:** the mutation line as written also dropped the `[ -z "$key" ]` guard, so it crashed on an empty key instead of silently dropping one. The meaningful mutation is `[ -z "$key" ] || [ "$mtype" = ble_uuid ] || SW_IX["$key"]+=" $n"`. It makes the three full-scan comparisons and the order test fail.
- **Tasks 4b and 4c were added** after measuring on the Pager. Handing the signature text to a bash function costs ~4.5 µs per byte per call, so the stream now prepares once (`_sw_match_prepared`). `sw_prepare_sigs` records the prepared text itself, and an unset cache counts as "nothing prepared". Results: `docs/superpowers/P0-findings.md`.
- **Task 5, Step 1:** `$( )` reseeds `RANDOM` in the subshell, so the committed `tools/bench_match.sh` builds its records with `printf -v` in the parent shell.
- **After the final review,** the `axon` name rule became `med` (spec §4 item 7).
