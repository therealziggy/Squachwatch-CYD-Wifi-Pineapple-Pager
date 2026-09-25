# SquachWatch-Pager Noise Control Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keep the Pager usable when many devices of one kind appear at once, keep the screen readable during floods, stop weak stationary trackers escalating to "following you", and stop the cooldown ledger growing forever, without dropping any CSV row.

**Architecture:** Approach A from the spec: small gates in the existing code paths.
- `sw_match_record` emits one detection per category (the strongest match wins), and the Flipper name rule drops to `med`.
- `sw_emit` gains a per-kind cooldown, stored as a `*|<category>` key in the existing ledger, and a call-scoped `SW_EMIT_NOLOG`.
- `sw_scan_once` keeps per-lap counters and prints `...and N more`.
- `sw_follow_update` ignores sightings weaker than `SW_FOLLOW_MIN_RSSI`.
- `sw_seen_prune` bounds `seen.db`. `sw_main` calls it at startup and every `SW_HEALTH_EVERY` laps.

**Tech Stack:**
- bash 5.2 payloads on the Hak5 WiFi Pineapple Pager (MIPS, BusyBox userland, but GNU `timeout`), with btmon 5.72 and hcitool.
- Offline test harness: `bash test/run.sh` (sourced `*_test.sh` files, plus stubs in `test/stubs/`).

**Spec:** `docs/superpowers/specs/2026-09-23-squachwatch-noise-control-design.md`. Read it first.

**Base commit for differentials:** `0630b64` (the spec commit; no code has changed yet).

**Who runs what:**
- **Tasks 1–6** are self-contained code tasks, suitable for subagents.
- **Tasks 7–8** need the user's Flipper and the Pager, so the orchestrating session runs them together with the user.

## Global Constraints

**Repo and commits**
- Repo: `<repo>`, branch `master`, no remote.
- Every commit message ends with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. After each commit, `git log -1 --format=%B | grep -cF 'Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>'` must print `1`. An earlier implementer replaced this line with its own model name.

**Test harness**
- Run tests with `bash test/run.sh`. It prints `PASS=N FAIL=M` and exits non-zero on any failure.
- Test files are *sourced* into one shell running `set -u`:
  - prefix helper variables with `_` and `unset` them at the end of your block;
  - `unset -f` helper functions you define;
  - never `exit` in a test file.
- Assertions available: `assert_eq ACTUAL EXPECTED NAME`, `assert_contains HAYSTACK NEEDLE NAME`, `assert_empty VALUE NAME`, `pass`, `fail "msg"`.
- Stubs log one line per call to `$SW_STUB_LOG` as `<VERB> <args>` (for example `LOG cyan Flipper Zero C1:00:00:00:00:01 -55dBm`).
  - `ALERT`'s argument contains a newline, so the MAC lands on the line *after* `ALERT <label>`. To assert on it, use `grep -A1 '^ALERT <label>'`.

**Test discipline**
- **TDD is mandatory:** write the test, run the suite, and see it FAIL for the expected reason before writing code. Quote the failing assertion NAMES in your report, not just the summary line.
- **Positive controls are mandatory:** pair every assertion that something is absent, empty or zero with one that proves the same code path produced something.

**Code rules**
- **Hot-path contract** (header of `lib/match.sh`): `sw_match_record` runs once per record and must use bash builtins only. That means no pipes, no `$( )` and no backticks; arithmetic `(( ))` is fine. `test/perf_test.sh` enforces this.
- **Config defaults live ONLY in `payload.sh`'s config block** (`: "${VAR:=default}"`).
  - Libraries never use `:=`. They read `${VAR:-off}` at the point of use, where "off" means today's behaviour.
  - Each new payload default gets a clean-process test (`env -u VAR bash -c 'SW_TEST_SOURCE=1 . payload.sh; echo "$VAR"'`), because a test that pins a value cannot see its default.
- **BusyBox:** `mktemp` templates end in `XXXXXX` with no suffix, and `tr` has no `[:class:]`. Bash glob classes and `[[ =~ ]]` are fine: the payload runs under `/bin/bash`.
- **Formats are unchanged:**
  - detections: `category|label|confidence|threat_class|radio|mac|ident|rssi` (8 fields);
  - the loot CSV: 10 columns;
  - ledger lines: `key|timestamp`, where the key is `mac|category`, or (new) `*|category`.
- **Screen text is plain ASCII `...`**, never `…`. The Pager's font rendered `—` as `-`, and `…` is untested.

**Invariants (asserted by tests)**
1. `low`/`med` never ALERT or buzz.
2. Every fresh device gets its CSV row.
3. A `*_follow` alert is never held by the kind cooldown.

**Device**
- `root@172.16.52.1`, passwordless ssh. The ssh login shell is BusyBox `ash`, and the device has no `diff`, `paste` or `stat`.
- The Pager's menu launcher runs a **copy** of `payload.sh` from `/tmp` (passing the real folder in `PAYLOAD_HOME`), so on-device checks must go through the menu, not `bash payload.sh`.
- `LOG` run from ANY shell, SSH included, prints on the running payload's screen.
- The Pager's `/tmp/TZ` can hold a POSIX zone string such as `UTC-N`, so `date` may show local time labelled "UTC". Epochs are correct; convert them on the desktop with `date -d @N`.

## File Structure

| File | Responsibility |
|---|---|
| `payloads/user/reconnaissance/squachwatch/lib/match.sh` | modify `sw_match_record`: one detection per category, strongest wins (Task 1) |
| `payloads/user/reconnaissance/squachwatch/signatures.db` | modify: the Flipper name rule becomes `med` (Task 2) |
| `payloads/user/reconnaissance/squachwatch/lib/alert.sh` | modify `sw_emit`: kind cooldown (Task 3), `SW_EMIT_NOLOG` (Task 4). New `sw_seen_prune` (Task 6) |
| `payloads/user/reconnaissance/squachwatch/lib/follow.sh` | modify `sw_follow_update`: the follow floor (Task 5) |
| `payloads/user/reconnaissance/squachwatch/payload.sh` | modify: 3 new defaults (Tasks 3–5), `_sw_emit_capped` + per-lap counters in `sw_scan_once` (Task 4), `sw_prune_ledger` + `sw_main` wiring (Task 6) |
| `test/helpers/btmon_gen.sh` | **new**: `sw_test_btmon_devs`, which prints btmon text for N devices (Task 2) |
| `test/fixtures/btmon_blespam_<capture-date>.txt` | **new**: a real Flipper BLE Spam capture (Task 7) |
| `test/match_test.sh`, `test/signatures_test.sh`, `test/alert_test.sh`, `test/follow_test.sh`, `test/payload_test.sh` | tests |
| `README.md`, `docs/superpowers/P0-findings.md` | docs |

**`test/payload_test.sh` layout.** Task 2 creates a marked section. Tasks 3–6 insert their pipeline blocks **immediately before** the line `# --- end noise control ---`:

```
... existing tests ...
# --- noise control (spec 2026-09-23-squachwatch-noise-control-design.md) ---
   (Task 2 block, then Task 3, 4, 5, 6 blocks in order)
# --- end noise control ---
rm -rf "$SW_LOOT_DIR" "$SW_SEEN_FILE"
rm -rf "$SW_TMP_DIR"
unset SW_RECON_DB SW_BLE_CMD ...
```

---

### Task 1: One detection per record per category, strongest wins

**Files:**
- Modify: `payloads/user/reconnaissance/squachwatch/lib/match.sh` (function `sw_match_record`)
- Test: `test/match_test.sh` (append)

**Interfaces:**
- Consumes: the prepared signature arrays `SW_SIG_TYPE/CAT/LABEL/CONF/CLASS/NORM` (from `sw_prepare_sigs`, unchanged).
- Produces: `sw_match_record RECORD SIGS` prints **at most one** 8-field detection per category, keeping the highest confidence (`high` > `med` > `low`); on a tie it keeps the rule listed first. Categories print in first-hit order. Tasks 2–7 rely on this: a device matching the Flipper name rule (`med`) *and* the `80:E1:26` prefix rule (`high`) yields exactly one `high` detection.

- [ ] **Step 1: Write the failing tests.** Append to `test/match_test.sh`:

```bash
# --- one detection per record per category: strongest wins (spec 2026-09-23 §3.1) ---
# A device matching two rules of ONE category used to print twice, and the first (maybe
# weaker) hit took its cooldown slot: a med name hit would then swallow a high prefix alert.
_SW2='ble_name_sub|flipper|hacker_flipper|Flipper Zero (by name)|med|attacker
ble_oui|80:E1:26|hacker_flipper|Flipper Zero|high|attacker
ble_name_sub|tile|tracker_tile|Tile tracker|med|tracker
ble_uuid|feed|tracker_tile|Tile|med|tracker
ble_name_sub|bob|flock_generic|Flock device|med|surveillance'
_SW2r='ble_oui|80:E1:26|hacker_flipper|Flipper Zero|high|attacker
ble_name_sub|flipper|hacker_flipper|Flipper Zero (by name)|med|attacker'
# weaker rule first, stronger later -> ONE line, the strong one (assert_eq: no second line)
assert_eq "$(sw_match_record 'ble|80:E1:26:00:00:01|Flipper Al|-60' "$_SW2")" \
  "hacker_flipper|Flipper Zero|high|attacker|ble|80:E1:26:00:00:01|Flipper Al|-60" strongest_wins_later_high
# stronger rule first, weaker later -> the weaker one must not replace it
assert_eq "$(sw_match_record 'ble|80:E1:26:00:00:01|Flipper Al|-60' "$_SW2r")" \
  "hacker_flipper|Flipper Zero|high|attacker|ble|80:E1:26:00:00:01|Flipper Al|-60" strongest_wins_first_high_kept
# a tie keeps the FIRST rule (its label)
assert_eq "$(sw_match_record 'ble|AA:00:00:00:00:02|Tile Mate|-70|uuid:feed' "$_SW2")" \
  "tracker_tile|Tile tracker|med|tracker|ble|AA:00:00:00:00:02|Tile Mate|-70" strongest_wins_tie_first_rule
# different categories on one device are independent: both print, in first-hit order
assert_eq "$(sw_match_record 'ble|80:E1:26:00:00:01|Flipper Bob|-60' "$_SW2")" \
  "hacker_flipper|Flipper Zero|high|attacker|ble|80:E1:26:00:00:01|Flipper Bob|-60
flock_generic|Flock device|med|surveillance|ble|80:E1:26:00:00:01|Flipper Bob|-60" strongest_wins_categories_independent
# control: the name rule alone still matches (the dedupe did not just drop name hits)
assert_eq "$(sw_match_record 'ble|C1:00:00:00:00:01|Flipper Al|-60' "$_SW2")" \
  "hacker_flipper|Flipper Zero (by name)|med|attacker|ble|C1:00:00:00:00:01|Flipper Al|-60" strongest_wins_name_only_control
unset _SW2 _SW2r
```

- [ ] **Step 2: Run the suite and confirm RED.**

Run: `bash test/run.sh 2>&1 | grep -E 'FAIL|PASS='`
Expected: exactly these 4 fail. Each gets two or three lines where one is expected. `strongest_wins_name_only_control` passes.
```
FAIL: strongest_wins_later_high: ...
FAIL: strongest_wins_first_high_kept: ...
FAIL: strongest_wins_tie_first_rule: ...
FAIL: strongest_wins_categories_independent: ...
```

- [ ] **Step 3: Implement.** Replace the whole `sw_match_record` function in `lib/match.sh` with:

```bash
sw_match_record() {
  # $1 = record "radio|mac|ident|rssi"  $2 = signatures text
  # Prints at most ONE detection per category: the hit with the strongest confidence
  # (high > med > low); on a tie, the rule listed first. Two rules of one category used to
  # print twice, and the first (maybe weaker) hit took the device's cooldown slot, so a med
  # name match could swallow a high hardware-prefix alert (spec 2026-09-23 §3.1).
  local rec="$1" sigs="$2"
  # Re-prepare only when the signature set actually changes (a plain string compare,
  # no fork), so a stream of records prepares once no matter which caller drives it.
  [ "${SW_SIGS_CACHE-}" = "$sigs" ] || { sw_prepare_sigs "$sigs"; SW_SIGS_CACHE="$sigs"; }
  # Split the fields with parameter expansion (ident is sanitized, so it holds no '|').
  # BLE records carry an optional 5th field of advertisement tokens (lib/ble.sh).
  local radio="${rec%%|*}" _r="${rec#*|}"
  local mac="${_r%%|*}" _r2="${_r#*|}"
  local ident="${_r2%%|*}" _r3="${_r2#*|}"
  local rssi="${_r3%%|*}" adv=""
  [ "$_r3" = "$rssi" ] || adv="${_r3#*|}"
  local oui="${mac:0:8}"; oui="${oui^^}"
  local lident="${ident,,}"
  local i j hit mtype norm rank
  local -a best_cat=() best_rank=() best_i=()   # one slot per category hit, first-hit order
  for (( i=0; i<${#SW_SIG_TYPE[@]}; i++ )); do
    hit=1; mtype="${SW_SIG_TYPE[i]}"; norm="${SW_SIG_NORM[i]}"
    case "$mtype" in
      wifi_oui)      [ "$radio" = wifi ] && [ "$norm" = "$oui" ] && hit=0 ;;
      ble_oui)       [ "$radio" = ble  ] && [ "$norm" = "$oui" ] && hit=0 ;;
      wifi_ssid_sub) if [ "$radio" = wifi ] && [ -n "$ident" ] && [ -n "$norm" ]; then case "$lident" in *"$norm"*) hit=0;; esac; fi ;;
      ble_name_sub)  if [ "$radio" = ble  ] && [ -n "$ident" ] && [ -n "$norm" ]; then case "$lident" in *"$norm"*) hit=0;; esac; fi ;;
      # Tier-3 (spec §4). ble_mfr is a WHOLE-SEGMENT prefix: equal, or followed by ':'.
      # A plain string prefix would let 004c:12:2 (near owner) match 004c:12:25 (separated).
      ble_mfr)       if [ "$radio" = ble ] && [ -n "$adv" ]; then case " $adv " in *" mfr:$norm "*|*" mfr:$norm:"*) hit=0;; esac; fi ;;
      ble_uuid)      [ "$radio" = ble ] && [ -n "$adv" ] && _sw_uuid_hit "$norm" "$adv" && hit=0 ;;
      *) : ;;   # unknown match_type: ignored (test/signatures_test.sh rejects unknown types)
    esac
    [ "$hit" -eq 0 ] || continue
    case "${SW_SIG_CONF[i]}" in high) rank=3 ;; med) rank=2 ;; low) rank=1 ;; *) rank=0 ;; esac
    for (( j=0; j<${#best_cat[@]}; j++ )); do [ "${best_cat[j]}" = "${SW_SIG_CAT[i]}" ] && break; done
    if [ "$j" -eq "${#best_cat[@]}" ]; then
      best_cat+=("${SW_SIG_CAT[i]}"); best_rank+=("$rank"); best_i+=("$i")
    elif [ "$rank" -gt "${best_rank[j]}" ]; then
      best_rank[j]="$rank"; best_i[j]="$i"
    fi
  done
  for (( j=0; j<${#best_i[@]}; j++ )); do
    i="${best_i[j]}"
    printf '%s|%s|%s|%s|%s|%s|%s|%s\n' \
      "${SW_SIG_CAT[i]}" "${SW_SIG_LABEL[i]}" "${SW_SIG_CONF[i]}" "${SW_SIG_CLASS[i]}" \
      "$radio" "$mac" "$ident" "$rssi"
  done
}
```

- [ ] **Step 4: Run the suite and confirm GREEN.**

Run: `bash test/run.sh 2>&1 | tail -1`
Expected: `PASS=<previous+5> FAIL=0`. That includes `forkfree_match_record` and both `perf_*budget` checks: the hot path must stay fork-free and inside budget.

- [ ] **Step 5: Differential. Prove that no `(device, category)` pair was lost or gained.** Run from the repo root:

```bash
_d="$(mktemp -d)"; git show 0630b64:payloads/user/reconnaissance/squachwatch/lib/match.sh > "$_d/match.sh"
_run() { PATH="$PWD/test/stubs:$PATH" SW_STUB_LOG=/dev/null bash -c '
  D=payloads/user/reconnaissance/squachwatch; . "$1"; . $D/lib/wifi.sh; . $D/lib/ble.sh
  S="$(sw_load_signatures $D/signatures.db)"
  { SW_RECENCY_SECS=0 sw_wifi_records test/fixtures/recon.db
    for f in test/fixtures/btmon_*.txt; do sw_btmon_parse < "$f"; done; } | sw_match_stream "$S"' _ "$1"; }
_run "$_d/match.sh" > "$_d/old.txt"; _run payloads/user/reconnaissance/squachwatch/lib/match.sh > "$_d/new.txt"
echo "old lines: $(wc -l < "$_d/old.txt")  new lines: $(wc -l < "$_d/new.txt")"
cut -d'|' -f1,6 "$_d/old.txt" | sort -u > "$_d/old.pairs"; cut -d'|' -f1,6 "$_d/new.txt" | sort -u > "$_d/new.pairs"
echo "pairs: $(wc -l < "$_d/old.pairs")"; diff "$_d/old.pairs" "$_d/new.pairs" && echo "DIFFERENTIAL OK: identical (category, mac) sets"
rm -rf "$_d"; unset -f _run; unset _d
```
Expected:
- `pairs:` is well above 0 (the positive control: the probe matched real fixtures).
- `DIFFERENTIAL OK` is printed.
- `new lines` is less than `old lines`, by exactly the number of same-category duplicates. The synthetic capture's Flipper is one of them.

Record the three numbers for the commit message.

- [ ] **Step 6: Commit.**

```bash
git add payloads/user/reconnaissance/squachwatch/lib/match.sh test/match_test.sh
git commit -F - <<'EOF'
fix(match): one detection per device per kind, strongest match wins

sw_match_record printed one detection per matching RULE, so a device hit by
two rules of one category (a stock Flipper: its name AND its 80:E1:26
prefix) was reported twice, and the first hit took the device's cooldown
slot. Once the Flipper name rule becomes med, that first hit would swallow
the high prefix alert. Now each category prints once, with the strongest
confidence (a tie keeps the first rule).

Differential over every fixture vs 0630b64: identical (category, mac) sets
(<pairs> pairs); <old lines> -> <new lines> detections (duplicates removed).

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
git log -1 --format=%B | grep -cF 'Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>'
```
Replace `<pairs>`, `<old lines>` and `<new lines>` with the numbers from Step 5 before committing. Expected last output: `1`.

---

### Task 2: A Flipper matched by name alone is `med` (from CYD)

**Files:**
- Modify: `payloads/user/reconnaissance/squachwatch/signatures.db` (the Flipper name rule and its comment)
- Create: `test/helpers/btmon_gen.sh`
- Modify: `test/signatures_test.sh` (append), `test/payload_test.sh` (source the helper, create the noise section, `unset -f` at the end), `README.md` (Signatures section)

**Interfaces:**
- Consumes: Task 1's strongest-wins `sw_match_record`.
- Produces: `sw_test_btmon_devs PREFIX COUNT NAME RSSI` (in `test/helpers/btmon_gen.sh`, sourced by `test/payload_test.sh`).
  - It prints btmon-5.72-shaped text for COUNT devices, `PREFIX:01` … `PREFIX:<COUNT as 2 hex digits>`. PREFIX is 5 octets, e.g. `C1:00:00:00:00`.
  - Every device gets the complete name NAME and RSSI RSSI.
  - Use it in a lap as `SW_BLE_CMD="sw_test_btmon_devs C1:00:00:00:00 9 'Flipper 🐬' -55" sw_scan_once`. `_sw_ble_records` `eval`s `SW_BLE_CMD`, and several calls can be joined with `;`.
  - Tasks 3–6 use it.
- Produces: the noise-control section in `test/payload_test.sh`, delimited by `# --- noise control (…) ---` and `# --- end noise control ---`.

- [ ] **Step 1: Create the generator** `test/helpers/btmon_gen.sh`:

```bash
# test/helpers/btmon_gen.sh — sourced by tests (NOT by run.sh, which sources only *_test.sh).
# sw_test_btmon_devs PREFIX COUNT NAME RSSI -> btmon 5.72-shaped text: COUNT advertising
# reports from PREFIX:01 .. PREFIX:<COUNT in hex>, each with the given complete name and RSSI.
# The layout follows test/fixtures/btmon_synthetic.txt, which was copied from a real capture.
sw_test_btmon_devs() {
  local prefix="$1" count="$2" name="$3" rssi="$4" i
  for (( i = 1; i <= count; i++ )); do
    printf '> HCI Event: LE Meta Event (0x3e) plen 30                    #%d [hci0] 1.%06d\n' "$i" "$i"
    printf '      LE Advertising Report (0x02)\n'
    printf '        Num reports: 1\n'
    printf '        Address type: Random (0x01)\n'
    printf '        Address: %s:%02X (Static)\n' "$prefix" "$i"
    printf '        Name (complete): %s\n' "$name"
    printf '        RSSI: %s dBm (0xc4)\n' "$rssi"
  done
}
```

- [ ] **Step 2: Write the failing tests.**

(a) Append to `test/signatures_test.sh`:

```bash
# A Flipper matched by its NAME ALONE is med, as in SquachWatch-CYD ("the owner can change
# it"): on 2026-09-23 a BLE Spam flood of random MACs named "Flipper 🐬" raised 9 full
# alerts in one lap. Its hardware prefix still makes a real Flipper high.
assert_contains "$SIGS" "ble_name_sub|flipper|hacker_flipper|Flipper Zero|med|attacker" sig_flipper_name_is_med
assert_eq "$(sw_match_record 'ble|C1:00:00:00:00:01|Flipper 🐬|-55' "$SIGS")" \
  "hacker_flipper|Flipper Zero|med|attacker|ble|C1:00:00:00:00:01|Flipper 🐬|-55" sig_flipper_name_only_med
# guard: a stock Flipper (name AND prefix) is ONE detection, high (Task 1's strongest-wins)
assert_eq "$(sw_match_record 'ble|80:E1:26:00:00:01|Flipper aa|-60' "$SIGS")" \
  "hacker_flipper|Flipper Zero|high|attacker|ble|80:E1:26:00:00:01|Flipper aa|-60" sig_stock_flipper_one_high
```

(b) In `test/payload_test.sh`, add this line directly after line 2 (`FIX="$(cd …/fixtures" && pwd)"`):

```bash
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/helpers/btmon_gen.sh"   # sw_test_btmon_devs
```

(c) In `test/payload_test.sh`, insert this block **immediately before** the line `rm -rf "$SW_TMP_DIR"`. It is the only such line; today it is line 123.

```bash
# --- noise control (spec 2026-09-23-squachwatch-noise-control-design.md) ---
# generator self-check (positive control for every flood test below): the parser reads it
assert_eq "$(sw_test_btmon_devs C1:00:00:00:00 9 'Flipper 🐬' -55 | sw_btmon_parse | grep -c 'Flipper')" "9" noise_gen_parses_9_devices
# A BLE Spam-style flood of name-only "Flipper" devices logs every device but never buzzes.
rm -f "$SW_LOOT_DIR/detections.csv" "${SW_TRACK_FILE:-}"; : > "$SW_SEEN_FILE"; sw_log_init "$SW_LOOT_DIR"; : > "$SW_STUB_LOG"
SW_RECON_DB=/nonexistent/recon.db SW_BLE_CMD="sw_test_btmon_devs C1:00:00:00:00 9 'Flipper 🐬' -55" sw_scan_once
assert_empty "$(grep '^ALERT ' "$SW_STUB_LOG")" noise_name_only_flipper_flood_no_alert
assert_eq "$(grep -c '^[0-9]*,hacker_flipper,"Flipper Zero",med,' "$SW_LOOT_DIR/detections.csv")" "9" noise_name_only_flipper_flood_all_rows
# control: the synthetic capture's stock Flipper (name + 80:E1:26 prefix) still alerts
: > "$SW_SEEN_FILE"; : > "$SW_STUB_LOG"
sw_scan_once
assert_contains "$(grep -A1 '^ALERT Flipper Zero' "$SW_STUB_LOG")" "80:E1:26:00:00:01" noise_stock_flipper_still_alerts
# --- end noise control ---
rm -rf "$SW_LOOT_DIR" "$SW_SEEN_FILE"
```

(d) Append as the very last line of `test/payload_test.sh`:

```bash
unset -f sw_test_btmon_devs
```

- [ ] **Step 3: Run the suite and confirm RED.**

Run: `bash test/run.sh 2>&1 | grep -E 'FAIL|PASS='`
Expected failures:
- `sig_flipper_name_is_med`, `sig_flipper_name_only_med`;
- `noise_name_only_flipper_flood_no_alert` (9 ALERTs today);
- `noise_name_only_flipper_flood_all_rows` (the rows say `high`).

These pass already and are guards: `sig_stock_flipper_one_high`, `noise_gen_parses_9_devices`, `noise_stock_flipper_still_alerts`.

- [ ] **Step 4: Implement.** In `signatures.db`, replace these two lines:

```
# ---- Tier 1: hacker tools ----
ble_name_sub|flipper|hacker_flipper|Flipper Zero|high|attacker
```

with:

```
# ---- Tier 1: hacker tools ----
# A Flipper matched by its NAME ALONE is med, as in SquachWatch-CYD (src/detection.cpp:
# matchedByName ? MED_CONF : HIGH_CONF; "the owner can change it"). On 2026-09-23 a BLE Spam
# flood of random MACs named "Flipper 🐬" hit this rule 9 times in one lap. The hardware
# prefix below still makes a real Flipper high (strongest match wins, lib/match.sh).
ble_name_sub|flipper|hacker_flipper|Flipper Zero|med|attacker
```

In `README.md`'s Signatures section, replace:

```
- `confidence`: `high` | `med` | `low` (only `high` raises a full-screen alert; others just log a colored line)
```

with:

```
- `confidence`: `high` | `med` | `low` (only `high` raises a full-screen alert; others just log a colored line). A hacker tool matched by its advertised **name alone** is `med`, because names are trivial to fake (BLE Spam floods them); a hardware match (e.g. the Flipper's `80:E1:26` prefix) makes it `high`. When one device matches several rules of the same category, only its strongest match counts.
```

- [ ] **Step 5: Run the suite and confirm GREEN.** Run: `bash test/run.sh 2>&1 | tail -1`. Expected: `FAIL=0`.

- [ ] **Step 6: Commit.**

```bash
git add payloads/user/reconnaissance/squachwatch/signatures.db test/helpers/btmon_gen.sh test/signatures_test.sh test/payload_test.sh README.md
git commit -F - <<'EOF'
feat(signatures): a Flipper matched by name alone logs, it doesn't buzz

Ported from SquachWatch-CYD (matchedByName ? MED_CONF : HIGH_CONF). A BLE
Spam flood of random MACs named "Flipper 🐬" raised 9 full-screen alerts in
one lap on 2026-09-23. Name-only matches are now med: every device still
gets its log line and CSV row. A real Flipper still alerts through its
80:E1:26 prefix, including a stock one whose name also matches.

Adds test/helpers/btmon_gen.sh (sw_test_btmon_devs) for flood tests.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
git log -1 --format=%B | grep -cF 'Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>'
```

---

### Task 3: One full alert per kind per window (`SW_KIND_COOLDOWN`)

**Files:**
- Modify: `payloads/user/reconnaissance/squachwatch/lib/alert.sh` (`sw_emit`'s alert block)
- Modify: `payloads/user/reconnaissance/squachwatch/payload.sh` (config block)
- Test: `test/alert_test.sh` (append), `test/payload_test.sh` (snooze scans, noise section, final `unset` line)
- Modify: `README.md` (settings list)

**Interfaces:**
- Consumes: `sw_should_report MAC CATEGORY NOW COOLDOWN SEENFILE`. It returns 0 = fresh (and appends `MAC|CATEGORY|NOW`) or 1 = cooling. Here it is called with MAC `*`.
- Produces: `sw_emit` reads `${SW_KIND_COOLDOWN:-0}`. With a value above 0, a fresh `high` detection whose category does not end in `_follow` ALERTs only if the ledger holds no `*|<category>` entry newer than the window, and the ALERT records one. `payload.sh` default: `: "${SW_KIND_COOLDOWN:=600}"`. Task 6 reads `SW_KIND_COOLDOWN` to size the prune window.

- [ ] **Step 1: Write the failing tests.**

(a) Append to `test/alert_test.sh`:

```bash
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
```

(b) In `test/payload_test.sh`, the AUTO SNOOZE wiring section runs two back-to-back scans and expects the Flipper to ALERT again on lap 2. The kind cooldown would now hold that alert, so pin it off for exactly those two scans; the real default is covered in (c). Replace both occurrences of:

```bash
SW_COOLDOWN=0 SW_FOLLOW_SECS=0 SW_SNOOZE_AFTER=1 sw_scan_once
```

with:

```bash
SW_COOLDOWN=0 SW_KIND_COOLDOWN=0 SW_FOLLOW_SECS=0 SW_SNOOZE_AFTER=1 sw_scan_once
```

(c) In `test/payload_test.sh`, insert immediately before `# --- end noise control ---`:

```bash
# one alert per kind, through the real lap: 9 new "Penguin" devices (flock_battery, high)
rm -f "$SW_LOOT_DIR/detections.csv"; : > "$SW_SEEN_FILE"; sw_log_init "$SW_LOOT_DIR"; : > "$SW_STUB_LOG"
SW_RECON_DB=/nonexistent/recon.db SW_BLE_CMD="sw_test_btmon_devs C2:00:00:00:00 9 Penguin -60" sw_scan_once
assert_eq "$(grep -c '^ALERT ' "$SW_STUB_LOG")" "1" noise_kind_flood_one_alert
assert_eq "$(grep -c ',flock_battery,' "$SW_LOOT_DIR/detections.csv")" "9" noise_kind_flood_all_rows
# the next lap brings 9 MORE new devices of the same kind: still inside the window, no alert
: > "$SW_STUB_LOG"
SW_RECON_DB=/nonexistent/recon.db SW_BLE_CMD="sw_test_btmon_devs C3:00:00:00:00 9 Penguin -60" sw_scan_once
assert_empty "$(grep '^ALERT ' "$SW_STUB_LOG")" noise_kind_next_lap_quiet
assert_eq "$(grep -c ',flock_battery,' "$SW_LOOT_DIR/detections.csv")" "18" noise_kind_next_lap_rows_kept
# default, asserted in a CLEAN process
assert_eq "$(env -u SW_KIND_COOLDOWN bash -c 'SW_TEST_SOURCE=1 . "$1"/payload.sh >/dev/null 2>&1; echo "$SW_KIND_COOLDOWN"' _ "$SW_ROOT")" "600" payload_default_kind_cooldown
```

(d) In `test/payload_test.sh`'s cleanup line (it starts with `unset SW_RECON_DB SW_BLE_CMD`), append ` SW_KIND_COOLDOWN` to the end of the line.

- [ ] **Step 2: Run the suite and confirm RED.**

Run: `bash test/run.sh 2>&1 | grep -E 'FAIL|PASS='`

Expected failures:
- `kind_flood_one_alert` (9), `kind_flood_one_buzz` (9), `kind_quiet_inside_window`;
- `noise_kind_flood_one_alert` (9), `noise_kind_next_lap_quiet`;
- `payload_default_kind_cooldown` (empty).

Expected passes (with no gate, everything alerts): `kind_follow_alerts_exempt`, `kind_alerts_again_after_window`, `kind_gate_off_when_unset`, and the row counts. Step 5 mutation-proves the exemption.

- [ ] **Step 3: Implement.**

(a) In `lib/alert.sh`, inside `sw_emit`, replace this block:

```bash
  if [ "$fresh" -eq 0 ] && [ "$conf" = high ]; then
    local gate=0 note=""
    if [ -n "$snz" ]; then
      sw_snooze_gate "$mac" "$cat" "$rssi" "$now" "$snz" "$snz_after" "$snz_margin" "$snz_reset"
      gate=$?
    fi
    if [ "$gate" -ne 1 ]; then
```

with:

```bash
  if [ "$fresh" -eq 0 ] && [ "$conf" = high ]; then
    local gate=0 note=""
    if [ -n "$snz" ]; then
      sw_snooze_gate "$mac" "$cat" "$rssi" "$now" "$snz" "$snz_after" "$snz_margin" "$snz_reset"
      gate=$?
    fi
    # One full alert per KIND per window (spec 2026-09-23 §4): a flood of new devices of one
    # category (BLE Spam's random MACs, a room of real Flippers) interrupts once. The kind is
    # a "*|<category>" key in the same ledger. This is the LAST gate, so that key is recorded
    # only when an alert really fires. "Following you" alerts are exempt: each follower is its
    # own possible stalker, and AUTO SNOOZE already limits it. 0 or unset = off (the lib
    # default; payload.sh owns the 600).
    local kind_cd="${SW_KIND_COOLDOWN:-0}"
    case "$kind_cd" in ''|*[!0-9]*) kind_cd=0 ;; esac
    if [ "$gate" -ne 1 ] && [ "$kind_cd" -gt 0 ]; then
      case "$cat" in
        *_follow) ;;
        *) sw_should_report "*" "$cat" "$now" "$kind_cd" "$sf" || gate=1 ;;
      esac
    fi
    if [ "$gate" -ne 1 ]; then
```

Everything after that `if [ "$gate" -ne 1 ]; then` line stays as it is.

(b) In `payload.sh`'s config block, insert directly after the line `: "${SW_SNOOZE_FILE:=${SW_TMP_DIR:-/tmp}/sw_snooze.db}"`:

```bash
# One full alert + buzz per KIND of device (category) per window, so a flood of new devices of
# one kind (BLE Spam's random MACs, a hacker con full of Flippers) interrupts once. Every device
# still gets its log line and CSV row. "Following you" alerts are exempt. 0 turns it off.
: "${SW_KIND_COOLDOWN:=600}"
```

(c) In `README.md`'s settings list, insert this bullet directly after the `SW_SNOOZE_AFTER` bullet:

```
- `SW_KIND_COOLDOWN` (default 600): one full-screen alert + buzz per *kind* of device (e.g. "Flipper Zero") per window. A flood of new devices of one kind, such as a Flipper running BLE Spam with random addresses or a room full of Flippers, buzzes once; every device still gets its log line and CSV row. "Following you" alerts are exempt (they have AUTO SNOOZE). Set `0` to turn it off.
```

- [ ] **Step 4: Run the suite and confirm GREEN.** Run: `bash test/run.sh 2>&1 | tail -1`. Expected: `FAIL=0`.

- [ ] **Step 5: Mutation-prove the two load-bearing parts.** Restore the file after each mutant.

```bash
F=payloads/user/reconnaissance/squachwatch/lib/alert.sh; cp "$F" /tmp/sw_alert.bak
sed -i 's/^        \*_follow) ;;$/        *_follow_DISABLED) ;;/' "$F"; bash test/run.sh 2>&1 | grep -E 'FAIL|PASS='; cp /tmp/sw_alert.bak "$F"
sed -i 's/sw_should_report "\*" "\$cat" "\$now" "\$kind_cd" "\$sf" || gate=1/: /' "$F"; bash test/run.sh 2>&1 | grep -E 'FAIL|PASS='; cp /tmp/sw_alert.bak "$F"
git diff --stat "$F"; rm -f /tmp/sw_alert.bak
```

Expected:
- The first mutant fails `kind_follow_alerts_exempt`.
- The second fails `kind_flood_one_alert`, `kind_flood_one_buzz`, `kind_quiet_inside_window`, `noise_kind_flood_one_alert` and `noise_kind_next_lap_quiet`.
- `git diff --stat` shows the file changed only by this task's edit, identical to before the mutants.

- [ ] **Step 6: Commit.**

```bash
git add payloads/user/reconnaissance/squachwatch/lib/alert.sh payloads/user/reconnaissance/squachwatch/payload.sh test/alert_test.sh test/payload_test.sh README.md
git commit -F - <<'EOF'
feat(alert): one full alert per kind of device per 10 min

The cooldown was keyed per MAC, so every random address in a BLE Spam flood
counted as a new device: 9 buzzes in one lap. sw_emit now also consults a
"*|<category>" key in the same ledger (SW_KIND_COOLDOWN, default 600 s), as
the LAST gate, so it is recorded only when an alert fires. Every device
still gets its log line and CSV row. "Following you" alerts are exempt:
each follower is its own possible stalker and AUTO SNOOZE limits it.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
git log -1 --format=%B | grep -cF 'Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>'
```

---

### Task 4: Screen cap: first `SW_LOG_PER_KIND` lines per kind per lap, then `...and N more`

**Files:**
- Modify: `payloads/user/reconnaissance/squachwatch/lib/alert.sh` (`sw_emit`'s LOG line)
- Modify: `payloads/user/reconnaissance/squachwatch/payload.sh` (config block, new `_sw_emit_capped`, `sw_scan_once`)
- Test: `test/alert_test.sh` (append), `test/payload_test.sh` (noise section, final `unset` line)
- Modify: `README.md` (settings list)

**Interfaces:**
- Consumes: `sw_emit` (all its existing arguments), `sw_color_for THREAT_CLASS` (it echoes a colour).
- Produces: `sw_emit` skips **only** its `LOG` line when `SW_EMIT_NOLOG` is non-empty (a call-scoped variable). CSV row, cooldown and alert are unchanged.
- Produces: `_sw_emit_capped` (payload.sh) takes the same arguments as `sw_emit`. It is only called from `sw_scan_once`'s lap loop, whose per-lap arrays `_lap_shown` / `_lap_hidden` / `_lap_label` / `_lap_class` / `_lap_order` it updates. `payload.sh` default: `: "${SW_LOG_PER_KIND:=3}"`.

- [ ] **Step 1: Write the failing tests.**

(a) Append to `test/alert_test.sh`:

```bash
# SW_EMIT_NOLOG skips ONLY the log line (the lap's screen cap, spec 2026-09-23 §5)
_L5="$(mktemp -d)"; sw_log_init "$_L5"; _s5="$(mktemp)"; : > "$_s5"; : > "$SW_STUB_LOG"
SW_EMIT_NOLOG=1 sw_emit "hacker_flipper|Flipper Zero|high|attacker|ble|80:E1:26:00:00:01|Flipper aa|-60" 1000 600 "$_s5" "$_L5"
assert_empty "$(grep '^LOG ' "$SW_STUB_LOG")" nolog_skips_line
assert_contains "$(cat "$SW_STUB_LOG")" "ALERT Flipper Zero" nolog_keeps_alert
assert_contains "$(cat "$_L5/detections.csv")" "hacker_flipper" nolog_keeps_row
rm -rf "$_L5" "$_s5"; unset _L5 _s5
```

(b) In `test/payload_test.sh`, insert immediately before `# --- end noise control ---`:

```bash
# screen cap: 9 name-only Flippers in one lap -> 3 device lines + "...and 6 more Flipper Zero"
rm -f "$SW_LOOT_DIR/detections.csv"; : > "$SW_SEEN_FILE"; sw_log_init "$SW_LOOT_DIR"; : > "$SW_STUB_LOG"
SW_RECON_DB=/nonexistent/recon.db SW_BLE_CMD="sw_test_btmon_devs C1:00:00:00:00 9 'Flipper 🐬' -55" sw_scan_once
assert_eq "$(grep -c '^LOG cyan Flipper Zero C1:' "$SW_STUB_LOG")" "3" noise_cap_three_device_lines
assert_eq "$(grep -cxF 'LOG cyan ...and 6 more Flipper Zero' "$SW_STUB_LOG")" "1" noise_cap_summary_line
assert_eq "$(grep -c ',hacker_flipper,' "$SW_LOOT_DIR/detections.csv")" "9" noise_cap_every_row_kept
# exactly SW_LOG_PER_KIND devices -> no summary line (control: the 3 lines DID print)
: > "$SW_SEEN_FILE"; : > "$SW_STUB_LOG"
SW_RECON_DB=/nonexistent/recon.db SW_BLE_CMD="sw_test_btmon_devs C5:00:00:00:00 3 'Flipper 🐬' -55" sw_scan_once
assert_eq "$(grep -c '^LOG cyan Flipper Zero C5:' "$SW_STUB_LOG")" "3" noise_cap_exactly_three_shown
assert_empty "$(grep -F '...and' "$SW_STUB_LOG")" noise_cap_no_summary_at_limit
# two kinds are capped separately
: > "$SW_SEEN_FILE"; : > "$SW_STUB_LOG"
SW_RECON_DB=/nonexistent/recon.db SW_BLE_CMD="sw_test_btmon_devs C1:00:00:00:00 5 'Flipper 🐬' -55; sw_test_btmon_devs C2:00:00:00:00 5 Penguin -60" sw_scan_once
assert_eq "$(grep -cxF 'LOG cyan ...and 2 more Flipper Zero' "$SW_STUB_LOG")" "1" noise_cap_kind_a
assert_eq "$(grep -cxF 'LOG magenta ...and 2 more Flock Penguin battery' "$SW_STUB_LOG")" "1" noise_cap_kind_b
# counts restart every lap (same 5 devices again: 3 lines again, not 0)
: > "$SW_STUB_LOG"
SW_RECON_DB=/nonexistent/recon.db SW_BLE_CMD="sw_test_btmon_devs C1:00:00:00:00 5 'Flipper 🐬' -55" sw_scan_once
assert_eq "$(grep -c '^LOG cyan Flipper Zero C1:' "$SW_STUB_LOG")" "3" noise_cap_resets_each_lap
# default, asserted in a CLEAN process
assert_eq "$(env -u SW_LOG_PER_KIND bash -c 'SW_TEST_SOURCE=1 . "$1"/payload.sh >/dev/null 2>&1; echo "$SW_LOG_PER_KIND"' _ "$SW_ROOT")" "3" payload_default_log_per_kind
```

(c) In `test/payload_test.sh`'s cleanup line (it starts with `unset SW_RECON_DB SW_BLE_CMD`), append ` SW_LOG_PER_KIND`.

- [ ] **Step 2: Run the suite and confirm RED.**

Run: `bash test/run.sh 2>&1 | grep -E 'FAIL|PASS='`

Expected failures:
- `nolog_skips_line`;
- `noise_cap_three_device_lines` (9), `noise_cap_summary_line` (0);
- `noise_cap_kind_a`, `noise_cap_kind_b`;
- `noise_cap_resets_each_lap` (5);
- `payload_default_log_per_kind`.

The row counts and the at-limit checks pass.

- [ ] **Step 3: Implement.**

(a) In `lib/alert.sh`, inside `sw_emit`, replace:

```bash
  # The colored log line still prints every lap: it is the operator's live "still here"
  # signal, and unlike the CSV it does not accumulate on disk.
  LOG "$color" "$label $mac$rssitag" 2>/dev/null
```

with:

```bash
  # The colored log line still prints every lap: it is the operator's live "still here"
  # signal, and unlike the CSV it does not accumulate on disk. A lap loop that has already
  # shown enough lines of this kind sets SW_EMIT_NOLOG=1 for the call (spec 2026-09-23 §5):
  # only this line is skipped, never the CSV row or the alert.
  [ -n "${SW_EMIT_NOLOG:-}" ] || LOG "$color" "$label $mac$rssitag" 2>/dev/null
```

(b) In `payload.sh`'s config block, insert directly after the `: "${SW_KIND_COOLDOWN:=600}"` line (added by Task 3):

```bash
# Per lap, at most this many screen lines per kind of device, then one "...and N more <label>"
# line, so a flood cannot scroll everything else off the screen. The CSV keeps every row.
# 0 = no cap.
: "${SW_LOG_PER_KIND:=3}"
```

(c) In `payload.sh`, replace the whole `sw_scan_once` function with the two functions below:

```bash
# Emit one detection under the lap's screen cap (spec 2026-09-23 §5). Called ONLY from
# sw_scan_once's lap loop: it updates that loop's per-lap arrays (bash dynamic scope).
_sw_emit_capped() {
  local c="${1%%|*}" r="${1#*|}" lab tc cap="${SW_LOG_PER_KIND:-0}"
  lab="${r%%|*}"; r="${r#*|}"; r="${r#*|}"; tc="${r%%|*}"
  case "$cap" in ''|*[!0-9]*) cap=0 ;; esac
  if [ -z "${_lap_shown[$c]+x}" ]; then
    _lap_order+=("$c"); _lap_shown[$c]=0; _lap_hidden[$c]=0; _lap_label[$c]="$lab"; _lap_class[$c]="$tc"
  fi
  if [ "$cap" -gt 0 ] && [ "${_lap_shown[$c]}" -ge "$cap" ]; then
    _lap_hidden[$c]=$(( ${_lap_hidden[$c]} + 1 ))
    SW_EMIT_NOLOG=1 sw_emit "$@"
  else
    _lap_shown[$c]=$(( ${_lap_shown[$c]} + 1 ))
    sw_emit "$@"
  fi
}

sw_scan_once() {
  local now; now="$(date +%s)"
  { sw_wifi_records "$SW_RECON_DB"; _sw_ble_records; } \
    | sw_match_stream "$SW_SIGS" \
    | {
        # Per-lap screen counters (spec 2026-09-23 §5). They live in this pipeline subshell,
        # so they reset every lap.
        local -A _lap_shown=() _lap_hidden=() _lap_label=() _lap_class=()
        local -a _lap_order=()
        local det fdet c
        while IFS= read -r det; do
          [ -n "$det" ] || continue
          sw_ignored "$det" "$SW_IGNORE_SET" && continue
          _sw_emit_capped "$det" "$now" "$SW_COOLDOWN" "$SW_SEEN_FILE" "$SW_LOOT_DIR"
          # A tracker that has stayed with us escalates to its own high-confidence detection.
          fdet="$(sw_follow_update "$det" "$now" "$SW_TRACK_FILE" "$SW_FOLLOW_SECS" "$SW_FOLLOW_GAP")"
          [ -n "$fdet" ] && _sw_emit_capped "$fdet" "$now" "$SW_COOLDOWN" "$SW_SEEN_FILE" "$SW_LOOT_DIR" \
            "$SW_SNOOZE_FILE" "$SW_SNOOZE_AFTER" "$SW_SNOOZE_MARGIN_DB" "$SW_SNOOZE_RESET_SECS"
        done
        for c in "${_lap_order[@]}"; do
          [ "${_lap_hidden[$c]}" -gt 0 ] || continue
          LOG "$(sw_color_for "${_lap_class[$c]}")" "...and ${_lap_hidden[$c]} more ${_lap_label[$c]}" 2>/dev/null
        done
      }
}
```

(d) In `README.md`'s settings list, insert directly after the `SW_KIND_COOLDOWN` bullet:

```
- `SW_LOG_PER_KIND` (default 3): per lap, at most this many screen lines per kind of device, then one `...and N more <label>` line, so a flood can't scroll everything else off the screen. Every device still gets its CSV row. `0` = no cap.
```

- [ ] **Step 4: Run the suite and confirm GREEN.** Run: `bash test/run.sh 2>&1 | tail -1`. Expected: `FAIL=0`. That includes every earlier `payload_*` test: they go through the new loop.

- [ ] **Step 5: Mutation-prove the cap.** Make `_sw_emit_capped` never hide a line, run, then restore.

```bash
F=payloads/user/reconnaissance/squachwatch/payload.sh; cp "$F" /tmp/sw_payload.bak
sed -i 's/if \[ "\$cap" -gt 0 \] && \[ "\${_lap_shown\[\$c\]}" -ge "\$cap" \]; then/if false; then/' "$F"
bash test/run.sh 2>&1 | grep -E 'FAIL|PASS='; cp /tmp/sw_payload.bak "$F"; rm -f /tmp/sw_payload.bak; git diff --stat "$F"
```

Expected: the mutant fails `noise_cap_three_device_lines`, `noise_cap_summary_line`, `noise_cap_kind_a`, `noise_cap_kind_b` and `noise_cap_resets_each_lap`. The file is restored afterwards.

- [ ] **Step 6: Commit.**

```bash
git add payloads/user/reconnaissance/squachwatch/lib/alert.sh payloads/user/reconnaissance/squachwatch/payload.sh test/alert_test.sh test/payload_test.sh README.md
git commit -F - <<'EOF'
feat(screen): at most 3 lines per kind per lap, then "...and N more"

A flood of one kind (BLE Spam) filled the Pager's screen with 9+ lines every
lap and scrolled everything else away. sw_scan_once now keeps per-lap
counters: past SW_LOG_PER_KIND (default 3) lines of a kind, it calls sw_emit
with SW_EMIT_NOLOG=1, which skips only the log line, and ends the lap with
one "...and N more <label>" line. Every CSV row, cooldown, alert and follow
update is unchanged. Plain ASCII "...": the Pager font is unproven with "…".

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
git log -1 --format=%B | grep -cF 'Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>'
```

---

### Task 5: Follow floor (`SW_FOLLOW_MIN_RSSI`)

**Files:**
- Modify: `payloads/user/reconnaissance/squachwatch/lib/follow.sh` (`sw_follow_update`)
- Modify: `payloads/user/reconnaissance/squachwatch/payload.sh` (config block)
- Test: `test/follow_test.sh` (append), `test/payload_test.sh` (noise section, final `unset` line)
- Modify: `README.md` (settings list)

**Interfaces:**
- Produces: `sw_follow_update` reads `${SW_FOLLOW_MIN_RSSI:-}` (empty = off).
  - When the floor and the detection's RSSI are both integers and RSSI < floor, it returns 0 immediately: no output, and the state is neither read nor written.
  - Exactly the floor counts. A missing or non-numeric RSSI counts.
- `payload.sh` default: `: "${SW_FOLLOW_MIN_RSSI:=-85}"`.

- [ ] **Step 1: Write the failing tests.**

(a) Append to `test/follow_test.sh`:

```bash
# --- follow floor (spec 2026-09-23 §6) ---
_F2="$(mktemp -d)"; _tf2="$_F2/track.db"
_weak='tracker_findmy|Apple Find My (separated)|med|tracker|ble|F4:46:D0:F4:1A:D0||-95'
_strong='tracker_findmy|Apple Find My (separated)|med|tracker|ble|F4:46:D0:F4:1A:D0||-70'
# a tracker that stays weak (-95, like the neighbour's device seen 2026-09-23) never escalates
for _t in 1000 1300 1600 1900 2200; do _o="$(SW_FOLLOW_MIN_RSSI=-85 sw_follow_update "$_weak" "$_t" "$_tf2" 900 300)"; done
assert_empty "$_o" floor_weak_never_follows
assert_empty "$(cat "$_tf2" 2>/dev/null)" floor_weak_leaves_no_state
# control: the same device at -70 on the same timeline DOES escalate
for _t in 1000 1300 1600 1900; do _o="$(SW_FOLLOW_MIN_RSSI=-85 sw_follow_update "$_strong" "$_t" "$_tf2" 900 300)"; done
assert_contains "$_o" "tracker_findmy_follow|" floor_strong_follows
# the floor is inclusive: exactly -85 counts
rm -f "$_tf2"
assert_contains "$(SW_FOLLOW_MIN_RSSI=-85 sw_follow_update 'tracker_tile|Tile|med|tracker|ble|AA:00:00:00:00:02||-85' 1000 "$_tf2" 0 300)" "tracker_tile_follow|" floor_inclusive
# a missing reading counts: a missing number must never hide a tracker
assert_contains "$(SW_FOLLOW_MIN_RSSI=-85 sw_follow_update 'tracker_tile|Tile|med|tracker|ble|AA:00:00:00:00:03||' 1000 "$_tf2" 0 300)" "tracker_tile_follow|" floor_missing_rssi_counts
# weak sightings do not keep the clock alive: strong at 1000, weak at 1200/1500/1800, strong at
# 1901. Without the floor the weak ones refresh last_seen (1800 -> 1901 is inside the 300 s gap)
# and it escalates at 901 s. With the floor, last_seen stays 1000, the gap breaks, the clock restarts.
rm -f "$_tf2"
SW_FOLLOW_MIN_RSSI=-85 sw_follow_update "$_strong" 1000 "$_tf2" 900 300 >/dev/null
for _t in 1200 1500 1800; do SW_FOLLOW_MIN_RSSI=-85 sw_follow_update "$_weak" "$_t" "$_tf2" 900 300 >/dev/null; done
assert_empty "$(SW_FOLLOW_MIN_RSSI=-85 sw_follow_update "$_strong" 1901 "$_tf2" 900 300)" floor_weak_does_not_bridge_gap
assert_eq "$(cat "$_tf2")" "F4:46:D0:F4:1A:D0|tracker_findmy|1901|1901" floor_weak_gap_restarts_clock
rm -rf "$_F2"; unset _F2 _tf2 _weak _strong _t _o
```

The earlier `follow_escalates_at_900s` test, which escalates a −96 dBm tracker with the floor unset, is the control proving the lib default is OFF.

(b) In `test/payload_test.sh`, insert immediately before `# --- end noise control ---`:

```bash
# the follow floor is wired into the lap (payload default -85): a weak tracker never follows...
rm -f "$SW_TRACK_FILE"; : > "$SW_SEEN_FILE"; : > "$SW_STUB_LOG"
SW_FOLLOW_SECS=0 SW_RECON_DB=/nonexistent/recon.db SW_BLE_CMD="sw_test_btmon_devs C6:00:00:00:00 1 Tile -95" sw_scan_once
assert_empty "$(grep 'following you' "$SW_STUB_LOG")" noise_floor_weak_tracker_no_follow
assert_contains "$(grep '^LOG ' "$SW_STUB_LOG")" "Tile tracker C6:00:00:00:00:01" noise_floor_weak_tracker_still_logged
# ...control: the same tracker at -70 escalates at once with SW_FOLLOW_SECS=0
rm -f "$SW_TRACK_FILE"; : > "$SW_SEEN_FILE"; : > "$SW_STUB_LOG"
SW_FOLLOW_SECS=0 SW_RECON_DB=/nonexistent/recon.db SW_BLE_CMD="sw_test_btmon_devs C6:00:00:00:00 1 Tile -70" sw_scan_once
assert_contains "$(cat "$SW_STUB_LOG")" "following you" noise_floor_strong_tracker_follows
# default, asserted in a CLEAN process
assert_eq "$(env -u SW_FOLLOW_MIN_RSSI bash -c 'SW_TEST_SOURCE=1 . "$1"/payload.sh >/dev/null 2>&1; echo "$SW_FOLLOW_MIN_RSSI"' _ "$SW_ROOT")" "-85" payload_default_follow_floor
```

(c) In `test/payload_test.sh`'s cleanup line (it starts with `unset SW_RECON_DB SW_BLE_CMD`), append ` SW_FOLLOW_MIN_RSSI`.

- [ ] **Step 2: Run the suite and confirm RED.**

Run: `bash test/run.sh 2>&1 | grep -E 'FAIL|PASS='`

Expected failures:
- `floor_weak_never_follows`, `floor_weak_leaves_no_state`;
- `floor_weak_does_not_bridge_gap`, `floor_weak_gap_restarts_clock`;
- `noise_floor_weak_tracker_no_follow`;
- `payload_default_follow_floor`.

The controls (`floor_strong_follows`, `floor_inclusive`, `floor_missing_rssi_counts`, `noise_floor_strong_tracker_follows`, `noise_floor_weak_tracker_still_logged`) pass.

- [ ] **Step 3: Implement.**

(a) In `lib/follow.sh`, inside `sw_follow_update`, directly after the line `[ "$tclass" = tracker ] || return 0`, insert:

```bash
  # Follow floor (spec 2026-09-23 §6): a sighting weaker than SW_FOLLOW_MIN_RSSI does not count,
  # so a stationary neighbour's tracker heard through a wall never "follows" you at home. It
  # does not refresh last_seen either: weak for longer than the gap and the clock restarts.
  # A missing or non-numeric RSSI still counts, so a missing reading never hides a tracker.
  local floor="${SW_FOLLOW_MIN_RSSI:-}" num='^-?[0-9]+$'
  if [[ "$floor" =~ $num ]] && [[ "$rssi" =~ $num ]] && [ "$rssi" -lt "$floor" ]; then return 0; fi
```

(b) In `payload.sh`'s config block, insert directly after the `: "${SW_FOLLOW_GAP:=300}"` line:

```bash
# The follow timer ignores tracker sightings weaker than this (dBm): a tracker on you or in your
# car reads far stronger, and a neighbour's heard through a wall (-95 on 2026-09-23) must not
# "follow" you at home. The tracker is still logged. Empty turns the floor off.
: "${SW_FOLLOW_MIN_RSSI:=-85}"
```

(c) In `README.md`'s settings list, insert directly after the `SW_FOLLOW_SECS` / `SW_FOLLOW_GAP` bullet:

```
- `SW_FOLLOW_MIN_RSSI` (default -85): the "following you" timer ignores tracker sightings weaker than this (dBm), so a neighbour's tracker heard through a wall doesn't "follow" you at home. Weak trackers are still logged. It's a judgment call from close-range readings of -52 to -75 dBm: a tracker hidden far from you could read weaker and not escalate, so tune it if needed. Empty turns it off.
```

- [ ] **Step 4: Run the suite and confirm GREEN.** Run: `bash test/run.sh 2>&1 | tail -1`. Expected: `FAIL=0`.

- [ ] **Step 5: Mutation-prove the floor.** Disable the early return, run, then restore.

```bash
F=payloads/user/reconnaissance/squachwatch/lib/follow.sh; cp "$F" /tmp/sw_follow.bak
sed -i 's/\[ "\$rssi" -lt "\$floor" \]; then return 0; fi/false; then return 0; fi/' "$F"
bash test/run.sh 2>&1 | grep -E 'FAIL|PASS='; cp /tmp/sw_follow.bak "$F"; rm -f /tmp/sw_follow.bak; git diff --stat "$F"
```

Expected: the mutant fails `floor_weak_never_follows`, `floor_weak_does_not_bridge_gap` and `noise_floor_weak_tracker_no_follow`. The file is restored afterwards.

- [ ] **Step 6: Commit.**

```bash
git add payloads/user/reconnaissance/squachwatch/lib/follow.sh payloads/user/reconnaissance/squachwatch/payload.sh test/follow_test.sh test/payload_test.sh README.md
git commit -F - <<'EOF'
feat(follow): weak trackers (< -85 dBm) never count toward "following you"

follow.sh was time-only, so a stationary neighbour's separated Find My (seen
at -95 dBm every lap on 2026-09-23) would escalate to "following you" after
15 min at home. Sightings weaker than SW_FOLLOW_MIN_RSSI (default -85) no
longer count and no longer keep the clock alive. Exactly the floor counts;
a missing reading counts. The tracker is still logged.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
git log -1 --format=%B | grep -cF 'Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>'
```

---

### Task 6: Prune the cooldown ledger (`seen.db`)

**Files:**
- Modify: `payloads/user/reconnaissance/squachwatch/lib/alert.sh` (new `sw_seen_prune`)
- Modify: `payloads/user/reconnaissance/squachwatch/payload.sh` (new `sw_prune_ledger`; `sw_main` calls it)
- Test: `test/alert_test.sh` (append), `test/payload_test.sh` (noise section)
- Modify: `README.md` (the `SW_COOLDOWN` bullet)

**Interfaces:**
- Consumes: `SW_COOLDOWN`, `SW_KIND_COOLDOWN` (Task 3), `SW_SEEN_FILE`, `SW_HEALTH_EVERY`.
- Produces: `sw_seen_prune SEENFILE NOW KEEP_SECS` → rc 0, or rc 1 on failure.
  - It keeps only lines containing `|` whose last field is an integer `ts` with `NOW - ts < KEEP_SECS`.
  - It rewrites via `mktemp "$sf.XXXXXX"` + `mv`.
  - On failure it leaves the file untouched, removes the temp file and logs `LOG yellow "WARN: can't prune <file> — it will keep growing"`.
  - A missing file is rc 0 (there's nothing to prune).
- Produces: `sw_prune_ledger` (payload.sh) calls `sw_seen_prune "$SW_SEEN_FILE" <now> <max(SW_COOLDOWN, SW_KIND_COOLDOWN)>`. `sw_main` calls it after `touch "$SW_SEEN_FILE"` and inside the `SW_HEALTH_EVERY` block.

- [ ] **Step 1: Write the failing tests.**

(a) Append to `test/alert_test.sh`:

```bash
# --- ledger pruning (spec 2026-09-23 §7) ---
_P="$(mktemp -d)"; _pf="$_P/seen.db"
printf '%s\n' 'AA:00:00:00:00:01|old_cat|1000' 'AA:00:00:00:00:02|new_cat|1500' '*|kind_old|1000' '*|kind_new|1550' 'garbage-line' 'AA:00:00:00:00:03|bad_ts|12x4' > "$_pf"
sw_seen_prune "$_pf" 2000 600; assert_eq "$?" "0" prune_rc
# ONE assert_eq checks both halves: old + malformed lines dropped, recent lines kept (so an
# emptied file cannot pass), both key shapes (mac|cat and *|cat)
assert_eq "$(cat "$_pf")" 'AA:00:00:00:00:02|new_cat|1500
*|kind_new|1550' prune_keeps_recent_drops_old_and_malformed
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
```

(b) In `test/payload_test.sh`, insert immediately before `# --- end noise control ---`:

```bash
# sw_prune_ledger keeps entries for the LONGER of the two windows
_pn="$(date +%s)"
printf '%s\n' "AA:00:00:00:00:01|x|$((_pn - 300))" "AA:00:00:00:00:02|y|$((_pn - 100000))" > "$SW_SEEN_FILE"
SW_COOLDOWN=100 SW_KIND_COOLDOWN=500 sw_prune_ledger
assert_eq "$(cat "$SW_SEEN_FILE")" "AA:00:00:00:00:01|x|$((_pn - 300))" noise_prune_keeps_longer_window
printf '%s\n' "AA:00:00:00:00:01|x|$((_pn - 300))" > "$SW_SEEN_FILE"
SW_COOLDOWN=100 SW_KIND_COOLDOWN=0 sw_prune_ledger
assert_empty "$(cat "$SW_SEEN_FILE")" noise_prune_cooldown_only_when_kind_off
# sw_main prunes at STARTUP: a real run (SW_TEST_SOURCE emptied so payload.sh auto-runs
# sw_main), stopped by timeout. SW_HEALTH_EVERY=0, so only the startup call can prune.
_mt="$(mktemp -d)"
printf '%s\n' "AA:00:00:00:00:01|old|$((_pn - 100000))" "AA:00:00:00:00:02|new|$(date +%s)" > "$_mt/seen.db"
SW_TEST_SOURCE= SW_SEEN_FILE="$_mt/seen.db" SW_LOOT_DIR="$_mt/loot" SW_TMP_DIR="$_mt" SW_SLEEP=1 SW_HEALTH_EVERY=0 \
  SW_BLE_CMD=true SW_RECON_DB=/nonexistent/recon.db timeout 2 bash "$SW_ROOT/payload.sh" >/dev/null 2>&1
assert_empty "$(grep '|old|' "$_mt/seen.db")" noise_main_prunes_at_startup
assert_contains "$(cat "$_mt/seen.db")" "|new|" noise_main_prune_keeps_recent
# ...and every SW_HEALTH_EVERY laps: an entry young enough to survive the startup prune (keep =
# 2 s) is gone within a few laps
printf '%s\n' "AA:00:00:00:00:03|aging|$(date +%s)" > "$_mt/seen.db"
SW_TEST_SOURCE= SW_SEEN_FILE="$_mt/seen.db" SW_LOOT_DIR="$_mt/loot" SW_TMP_DIR="$_mt" SW_SLEEP=1 SW_HEALTH_EVERY=1 \
  SW_COOLDOWN=2 SW_KIND_COOLDOWN=0 SW_BLE_CMD=true SW_RECON_DB=/nonexistent/recon.db timeout 5 bash "$SW_ROOT/payload.sh" >/dev/null 2>&1
assert_empty "$(grep '|aging|' "$_mt/seen.db")" noise_main_prunes_periodically
rm -rf "$_mt"; unset _mt _pn
```

- [ ] **Step 2: Run the suite and confirm RED.**

Run: `bash test/run.sh 2>&1 | grep -E 'FAIL|PASS='`

Expected: every new `prune_*` and `noise_prune_*` / `noise_main_*` assertion fails, except those that hold without pruning: `prune_missing_file_ok`, `noise_main_prune_keeps_recent`, and the `*_leaves_file` checks.
- With `sw_seen_prune` undefined, the calls return 127 and nothing is pruned.
- The `sw_main` runs exit through `timeout`.

- [ ] **Step 3: Implement.**

(a) Append to `lib/alert.sh`:

```bash
sw_seen_prune() {
  # $1=seenfile $2=now $3=keep_secs. Drop ledger lines older than keep_secs (spec 2026-09-23
  # §7): sw_should_report holds only while now - last < cooldown, so an older line can never
  # block anything again. Lines that are not "key|<integer>" go too. Rewrites via temp + mv
  # (like the follow and snooze state); on failure the ledger is left untouched and a WARN
  # says so, because a ledger that silently stops shrinking grows forever. rc 1 on failure.
  local sf="$1" now="$2" keep="$3" tmp line ts num='^[0-9]+$'
  [ -f "$sf" ] || return 0
  if ! tmp="$(mktemp "$sf.XXXXXX" 2>/dev/null)"; then
    LOG yellow "WARN: can't prune $sf — it will keep growing" 2>/dev/null; return 1
  fi
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in *'|'*) ;; *) continue ;; esac
    ts="${line##*|}"
    [[ "$ts" =~ $num ]] || continue
    [ $((now - ts)) -lt "$keep" ] && printf '%s\n' "$line" >> "$tmp"
  done < "$sf"
  if ! mv -f "$tmp" "$sf" 2>/dev/null; then
    rm -f "$tmp"; LOG yellow "WARN: can't prune $sf — it will keep growing" 2>/dev/null; return 1
  fi
  return 0
}
```

(b) In `payload.sh`, insert directly above `sw_main() {`:

```bash
# Drop cooldown-ledger lines too old to block anything (spec 2026-09-23 §7), keeping the
# LONGER of the two windows that read the ledger. Called at startup and every SW_HEALTH_EVERY
# laps, so seen.db stays at "what was reported in the last window" instead of growing forever.
sw_prune_ledger() {
  local keep="$SW_COOLDOWN" k="${SW_KIND_COOLDOWN:-0}"
  case "$k" in ''|*[!0-9]*) k=0 ;; esac
  [ "$k" -gt "$keep" ] && keep="$k"
  sw_seen_prune "$SW_SEEN_FILE" "$(date +%s)" "$keep"
}
```

(c) In `payload.sh`'s `sw_main`, replace:

```bash
  mkdir -p "$(dirname "$SW_SEEN_FILE")"; touch "$SW_SEEN_FILE"
```

with:

```bash
  mkdir -p "$(dirname "$SW_SEEN_FILE")"; touch "$SW_SEEN_FILE"
  sw_prune_ledger
```

Then replace:

```bash
      sw_healthcheck || LOG yellow "SquachWatch DEGRADED — some detection is OFF" 2>/dev/null
```

with:

```bash
      sw_healthcheck || LOG yellow "SquachWatch DEGRADED — some detection is OFF" 2>/dev/null
      sw_prune_ledger
```

(d) In `README.md`, replace the `SW_COOLDOWN` bullet:

```
- `SW_COOLDOWN` (default 600) — one alert *and* one CSV row per device per category per window, so the loot file grows with distinct sightings rather than with uptime.
```

with:

```
- `SW_COOLDOWN` (default 600) — one alert *and* one CSV row per device per category per window, so the loot file grows with distinct sightings rather than with uptime. The cooldown ledger (`seen.db`) is pruned at startup and every `SW_HEALTH_EVERY` laps, so it only holds what was reported within the window.
```

- [ ] **Step 4: Run the suite and confirm GREEN.** Run: `bash test/run.sh 2>&1 | tail -1`. Expected: `FAIL=0`. The two `sw_main` runs add about 7 s to the suite.

- [ ] **Step 5: Mutation-prove the wiring.** Remove each `sw_main` call in turn, run, then restore.

```bash
F=payloads/user/reconnaissance/squachwatch/payload.sh; cp "$F" /tmp/sw_payload.bak
awk '/touch "\$SW_SEEN_FILE"/{print; getline; if ($0 ~ /sw_prune_ledger/) next} {print}' /tmp/sw_payload.bak > "$F"
bash test/run.sh 2>&1 | grep -E 'noise_main|PASS='; cp /tmp/sw_payload.bak "$F"
awk '/SquachWatch DEGRADED — some detection is OFF" 2>\/dev\/null$/{print; getline; if ($0 ~ /sw_prune_ledger/) next} {print}' /tmp/sw_payload.bak > "$F"
bash test/run.sh 2>&1 | grep -E 'noise_main|PASS='; cp /tmp/sw_payload.bak "$F"; rm -f /tmp/sw_payload.bak; git diff --stat "$F"
```

Expected:
- Without the startup call, `noise_main_prunes_at_startup` fails.
- Without the periodic call, `noise_main_prunes_periodically` fails.
- The file is restored afterwards.

- [ ] **Step 6: Commit.**

```bash
git add payloads/user/reconnaissance/squachwatch/lib/alert.sh payloads/user/reconnaissance/squachwatch/payload.sh test/alert_test.sh test/payload_test.sh README.md
git commit -F - <<'EOF'
feat(ledger): prune seen.db at startup and every SW_HEALTH_EVERY laps

sw_should_report only ever appended, so seen.db grew one line per fresh
report forever: in a BLE Spam flood, one per random MAC. sw_seen_prune drops
lines older than max(SW_COOLDOWN, SW_KIND_COOLDOWN), which can no longer
block anything, plus malformed lines. It rewrites via temp + mv. On failure
the ledger is left untouched and a yellow WARN says so.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
git log -1 --format=%B | grep -cF 'Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>'
```

---

### Task 7: Real BLE Spam fixture (orchestrator + user)

**Needs the user:** their Flipper runs the same BLE Spam mode as on 2026-09-23, briefly and away from other people, because it can trigger pop-ups on nearby phones. SquachWatch must NOT be running on the Pager (its per-lap `hciconfig reset` would disturb the capture). Ask the user to stop it from the menu first.

**Files:**
- Create: `test/fixtures/btmon_blespam_<capture-date>.txt`, named with the date of capture, e.g. `btmon_blespam_2026-09-24.txt`
- Test: `test/payload_test.sh` (noise section)

- [ ] **Step 1: Capture** while the user's BLE Spam is running. This mirrors `sw_ble_scan`'s sequence with a 15 s scan:

```bash
ssh root@172.16.52.1 'ps w | grep -q "[/]tmp/payload-" && echo "STOP: a payload is running" && exit 1; hciconfig hci0 down; hciconfig hci0 reset; hciconfig hci0 up; timeout -k 2 18 btmon > /tmp/sw_spam_cap.txt 2>&1 & bpid=$!; sleep 1; timeout -s INT -k 2 15 hcitool -i hci0 lescan --duplicates >/dev/null 2>&1; kill $bpid 2>/dev/null; wait $bpid 2>/dev/null; wc -l /tmp/sw_spam_cap.txt'
scp root@172.16.52.1:/tmp/sw_spam_cap.txt test/fixtures/btmon_blespam_$(date +%F).txt && ssh root@172.16.52.1 'rm -f /tmp/sw_spam_cap.txt'
```

Expected: several thousand lines. If the payload guard prints STOP, ask the user to stop SquachWatch and retry.
The guard uses `grep "[/]tmp/payload-"` on purpose. Over SSH, `pgrep -f "/tmp/payload-"` matches the ssh command's OWN
command line, so it always reports STOP. That misfire happened on 2026-09-23.

- [ ] **Step 2: Positive control on the capture itself.** The capture must actually contain a flood. Run:

```bash
bash -c 'D=payloads/user/reconnaissance/squachwatch; . $D/lib/match.sh; . $D/lib/ble.sh; sw_btmon_parse < "$1" | sw_match_stream "$(sw_load_signatures $D/signatures.db)" | grep -c "^hacker_flipper|Flipper Zero|med|"' _ test/fixtures/btmon_blespam_$(date +%F).txt
```

Expected: at least `5` name-only Flipper detections (distinct devices). If it is lower, the spam mode did not send named adverts. Ask the user which BLE Spam mode they used, then retry with the one that produced `Flipper 🐬` on 2026-09-23.

- [ ] **Step 3: Pin it.** In `test/payload_test.sh`, insert immediately before `# --- end noise control ---` (set `_bs` to the file you created):

```bash
# REAL Flipper BLE Spam capture: name-only "Flipper" adverts from random MACs. Counts come from
# the matcher, so the test pins behaviour, not today's numbers. _nf counts EVERY Flipper-kind
# device (the user's real Flipper, if captured, is the same kind for the screen cap and CSV);
# _nn counts the name-only ones, the flood itself.
_bs="$FIX/btmon_blespam_<capture-date>.txt"
_dets="$(sw_btmon_parse < "$_bs" | sw_match_stream "$SW_SIGS")"
_nf="$(printf '%s\n' "$_dets" | grep -c '^hacker_flipper|')"
_nn="$(printf '%s\n' "$_dets" | grep -c '^hacker_flipper|Flipper Zero|med|')"
assert_eq "$([ "$_nn" -ge 5 ] && echo y)" "y" spam_fixture_is_a_flood
rm -f "$SW_LOOT_DIR/detections.csv"; : > "$SW_SEEN_FILE"; sw_log_init "$SW_LOOT_DIR"; : > "$SW_STUB_LOG"
SW_RECON_DB=/nonexistent/recon.db SW_BLE_CMD="cat '$_bs'" sw_scan_once
# no full alert names a name-only device (only a real 80:E1:26 Flipper may alert)
assert_empty "$(grep -A1 '^ALERT Flipper Zero' "$SW_STUB_LOG" | grep -vE '^(ALERT|--$)' | grep -v '80:E1:26')" spam_no_name_only_alert
assert_eq "$(grep -c '^LOG cyan Flipper Zero ' "$SW_STUB_LOG")" "3" spam_three_flipper_lines
assert_eq "$(grep -cxF "LOG cyan ...and $((_nf - 3)) more Flipper Zero" "$SW_STUB_LOG")" "1" spam_summary_line
assert_eq "$(grep -c ',hacker_flipper,' "$SW_LOOT_DIR/detections.csv")" "$_nf" spam_every_row_kept
unset _bs _dets _nf _nn
```

Replace `<capture-date>` with the real date in the file name.

- [ ] **Step 4: Differential including the new fixture.** Re-run Task 1 Step 5 against base `0630b64`. The loop picks up the new `btmon_*.txt` automatically. Expected: `DIFFERENTIAL OK`.

- [ ] **Step 5: Run the suite (GREEN), then commit.**

```bash
bash test/run.sh 2>&1 | tail -1
git add test/fixtures/btmon_blespam_*.txt test/payload_test.sh
git commit -F - <<'EOF'
test(noise): pin a REAL Flipper BLE Spam capture

Captured on the Pager with the payload's own scan sequence while the user's
Flipper ran BLE Spam. Through a real lap: no Flipper alert, 3 screen lines +
"...and N more Flipper Zero", and one CSV row per spam address. It is the
positive control shaped like the real threat.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
git log -1 --format=%B | grep -cF 'Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>'
```

---

### Task 8: Docs, deploy, on-device verification through the Pager menu (orchestrator + user)

**Files:**
- Modify: `README.md` (Tests count; Status paragraph), `docs/superpowers/P0-findings.md` (new section)

- [ ] **Step 1: Full suite and docs.**

Run: `bash test/run.sh 2>&1 | tail -1` → `PASS=<N> FAIL=0`.

In `README.md`, replace `As of this writing: **296 assertions, all passing**.` with `As of this writing: **<N> assertions, all passing**.`, using the real `<N>`. In the "Status & roadmap" section, add this paragraph after the Tier 3 paragraph:

```
**Noise control** (2026-09-23): a flood of one kind of device — a Flipper running BLE Spam, a room full of Flippers — buzzes once per 10 minutes (`SW_KIND_COOLDOWN`), the screen shows at most 3 lines per kind per lap plus "...and N more", a Flipper matched by name alone only logs, weak trackers (< -85 dBm) never count toward "following you", and the cooldown ledger is pruned. Every device still gets its CSV row.
```

- [ ] **Step 2: Deploy and prove that device == HEAD.**

```bash
scp -r payloads/user/reconnaissance/squachwatch root@172.16.52.1:/root/payloads/user/reconnaissance/
ssh root@172.16.52.1 'chmod 755 /root/payloads/user/reconnaissance/squachwatch/payload.sh; cd /root/payloads/user/reconnaissance/squachwatch && for f in payload.sh signatures.db lib/*.sh; do echo "$(md5sum < $f | cut -c1-32)  $f"; done' > /tmp/sw_dev.md5
for f in payload.sh signatures.db lib/alert.sh lib/ble.sh lib/follow.sh lib/ignore.sh lib/log.sh lib/match.sh lib/snooze.sh lib/wifi.sh; do echo "$(git show HEAD:payloads/user/reconnaissance/squachwatch/$f | md5sum | cut -c1-32)  $f"; done > /tmp/sw_head.md5
diff <(sort -k2 /tmp/sw_head.md5) <(sort -k2 /tmp/sw_dev.md5) && echo "DEVICE == HEAD"; rm -f /tmp/sw_dev.md5 /tmp/sw_head.md5
```

Expected: `DEVICE == HEAD`.

- [ ] **Step 3: Smoke-test bash associative arrays on the device.** This is the first use of `local -A` inside a pipeline `{ }` group on the Pager. Run:

```bash
ssh root@172.16.52.1 'bash -c '"'"'g(){ _a[$1]=$(( ${_a[$1]:-0} + 1 )); }; f(){ printf "x\nx\ny\n" | { local -A _a=(); local d; while read -r d; do g "$d"; done; echo "x=${_a[x]} y=${_a[y]}"; }; }; f'"'"''
```

Expected: `x=2 y=1`.

- [ ] **Step 4: The user relaunches from Payloads → reconnaissance → SquachWatch.** This must NOT be `bash payload.sh` over SSH: the menu runs a `/tmp` copy. Expected screen: the green `SquachWatch armed — watching WiFi + BLE`. For this test the user's own Flipper is deliberately NOT in `ignore.txt`.

- [ ] **Step 5: The real Flipper ALONE first.** Turn its Bluetooth on, with no BLE Spam. Expected: exactly **one** buzz, `Flipper Zero 80:E1:26:…`. (Review I3: the real Flipper also advertises its own address during Spam, so it must be tested first. After this it is inside both its own cooldown and the kind cooldown.)

- [ ] **Step 6: Then BLE Spam for about 30 s.** Expected:
  - **no further buzz**: the name-only flood is `med`, and the real Flipper is in cooldown;
  - per lap, at most 3 name-only `Flipper Zero …` lines plus `...and N more Flipper Zero`;
  - the real Flipper's own line (`80:E1:26:…`), in its separate high-confidence allowance, never folded behind the fakes.

  Then over SSH, confirm that the CSV gained rows for the spam addresses and that no ALERT named a random address.

```bash
ssh root@172.16.52.1 'tail -n 60 /root/loot/squachwatch/detections.csv | grep -c ",hacker_flipper,\"Flipper Zero\",med,"'
```

- [ ] **Step 7: Check the ledger over SSH** after the run has done at least 20 laps (about 10 min). Expected: `oldest_age_s` below about 1200 (the 600 s window plus up to 20 laps between prunes).

```bash
ssh root@172.16.52.1 'now=$(date +%s); awk -F"|" -v now="$now" "{a=now-\$NF; if (a>m) m=a} END {print \"entries=\" NR \" oldest_age_s=\" m+0}" /root/loot/squachwatch/seen.db'
```

- [ ] **Step 8: Record and commit.** Append a section `## Noise control on-device (<date>)` to `docs/superpowers/P0-findings.md`. For each of Steps 3–7, record the expected and observed result and anything that differed. Then commit README + P0-findings:

```bash
git add README.md docs/superpowers/P0-findings.md
git commit -F - <<'EOF'
docs: noise control verified on the Pager (menu launch)

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
git log -1 --format=%B | grep -cF 'Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>'
```
