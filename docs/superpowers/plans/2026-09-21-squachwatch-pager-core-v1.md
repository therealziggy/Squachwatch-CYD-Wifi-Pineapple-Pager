# SquachWatch-Pager Core v1 — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the always-on SquachWatch scanner for the WiFi Pineapple Pager — one user payload that watches the WiFi recon database and name-based BLE against a shared signature file and raises native alerts — plus 4 event-triggered alert payloads, with a fully offline test harness.

**Architecture:** A main `payload.sh` loop sources small single-responsibility bash libs (`match`, `wifi`, `ble`, `alert`, `log`). Both radios are reduced to a uniform *record* line; the matcher turns records + signatures into *detection* lines; the alert layer dedupes and emits via the Pager's DuckyScript verbs. All DuckyScript verbs and `sqlite3` are external executables, so local tests shim them on `PATH` and exercise the real code paths on this dev box.

**Tech Stack:** Bash (device: BusyBox+bash; dev: bash 5.2), `sqlite3` (device CLI; local: python3-backed shim), `hcitool`/`bluetoothctl` (device BLE), DuckyScript verbs (`ALERT`, `LOG`, `RINGTONE`, `VIBRATE`, `LED`, `GPS_GET`, `PAYLOAD_*_CONFIG`).

## Global Constraints

- Payloads run under **bash**; every script starts `#!/bin/bash` and every test runs under `bash` explicitly (dev shell is zsh — never rely on the interactive shell).
- **No `grep -P`** (PCRE unavailable on device). Case-folding via `tr '[:upper:]' '[:lower:]'`, not `${var,,}`, for BusyBox safety.
- Every payload **ends with `exit 0`**; long-running payloads rely on the Pager's built-in cancel button and install a `trap` cleanup (kill `hcitool`, remove temp).
- Interfaces: BLE = `hci0`; WiFi monitor = `wlan1mon` (never `wlan1`).
- Recon DB path = `/root/recon/recon.db`; always query a **`/tmp` copy** to avoid `"database is locked"`.
- OUI vendor DB = `/lib/hak5/oui.txt` (fallback `/rom/lib/hak5/oui.txt`).
- Loot dir = `/root/loot/squachwatch/`.
- Signature line format: `match_type|pattern|category|label|confidence|threat_class`.
- Record line format: `radio|mac|ident|rssi` (mac = UPPER colon form `AA:BB:CC:DD:EE:FF`; ident/rssi may be empty).
- `ident` (SSID / BLE name) is the only attacker-controlled field. Producers MUST pass it through `sw_sanitize_ident` (in `lib/match.sh`) before building a record: it **removes** `|` and all control chars (CR/LF/TAB/…). Remove, don't replace — so a split token like `fli|pper` rejoins to `flipper` and cannot evade a signature. Signatures never contain `|`.
- Detection line format: `category|label|confidence|threat_class|radio|mac|ident|rssi`.
- `threat_class` ∈ {`surveillance`,`tracker`,`attacker`}; color map surveillance→magenta, tracker→yellow, attacker→cyan.
- v1 matcher handles `wifi_oui`, `wifi_ssid_sub`, `ble_name_sub`, `ble_oui`. It **ignores** `ble_company`/`ble_uuid` (Tier-3, separate plan) — those need raw-adv parsing.
- Do NOT auto-push; this is a fresh local repo with no remote. Commit locally per task.

---

## File Structure

```
payloads/user/reconnaissance/squachwatch/
  payload.sh                 # main loop (Task 12)
  signatures.db              # seed fingerprints (Task 11)
  lib/match.sh               # signature load + OUI + match dispatch (Task 3)
  lib/wifi.sh                # recon.db read + row→record (Task 5)
  lib/ble.sh                 # hcitool scan + line→record (Task 6)
  lib/alert.sh               # dedupe + color + emit + hw notify (Tasks 8-9)
  lib/log.sh                 # CSV + human log + GPS tag (Task 7)
payloads/alerts/
  deauth_flood_detected/squachwatch_deauth/payload.sh       # Task 13
  handshake_captured/squachwatch_handshake/payload.sh       # Task 13
  pineapple_client_connected/squachwatch_client/payload.sh  # Task 13
  pineapple_auth_captured/squachwatch_auth/payload.sh        # Task 13
tools/
  p0-verify.sh               # on-device verification (Task 1)
  build_fixture_db.py        # python builder for fixture recon.db (Task 4)
test/
  run.sh                     # pure-bash test runner (Task 2)
  stubs/                     # sqlite3 shim + DuckyScript stubs (Task 2)
  fixtures/                  # sample rows, hcitool dumps, signatures
  match_test.sh  wifi_test.sh  ble_test.sh  alert_test.sh  log_test.sh
README.md                    # Task 14
```

---

### Task 1: Phase-0 on-device verification (spike, not TDD)

Confirms every environment assumption over SSH before engine code is trusted. Deliverable = a runnable probe script + a committed findings doc. This is discovery: each probe has an **expected positive result**; a negative result is recorded and, where it blocks v1, flagged.

**Files:**
- Create: `tools/p0-verify.sh`
- Create: `docs/superpowers/P0-findings.md` (filled from the run)

- [ ] **Step 1: Write the probe script**

```bash
#!/bin/bash
# p0-verify.sh — run ON THE PAGER (scp over, or paste). Prints a labeled report.
# Usage: bash p0-verify.sh
line(){ echo "==== $* ===="; }

line "recon.db present + schema"
ls -l /root/recon/recon.db
cp /root/recon/recon.db /tmp/p0.db 2>&1 && echo "copy_ok"
sqlite3 /tmp/p0.db ".tables" 2>&1
sqlite3 /tmp/p0.db "SELECT count(*) AS beacons FROM ssid WHERE type=8;" 2>&1
sqlite3 /tmp/p0.db "SELECT count(*) AS clients FROM ssid WHERE type=4;" 2>&1
sqlite3 /tmp/p0.db "PRAGMA table_info(ssid);" 2>&1
sqlite3 /tmp/p0.db "PRAGMA table_info(wifi_device);" 2>&1

line "_pineap RECON APS json (alt enumeration)"
_pineap RECON APS format=json 2>&1 | head -c 400; echo

line "sqlite3 / jq presence"
which sqlite3 jq 2>&1

line "BLE tooling"
which hcitool bluetoothctl btmon 2>&1
hciconfig -a 2>&1 | head -20
timeout 6 hcitool lescan --duplicates 2>&1 | head -5

line "raw-adv capability (Tier-3 gate)"
which btmon 2>&1 && echo "btmon_present" || echo "btmon_absent"
timeout 4 btmon 2>&1 | head -5

line "DuckyScript verbs on PATH"
for c in ALERT LOG RINGTONE VIBRATE LED GPS_GET TITLE START_SPINNER STOP_SPINNER PAYLOAD_GET_CONFIG PAYLOAD_SET_CONFIG; do
  printf '%s: ' "$c"; command -v "$c" 2>/dev/null || echo MISSING
done

line "LED syntax probe (observe device reaction)"
LED B 50 2>&1; sleep 1; LED OFF 2>&1; echo "led_probe_done"

line "sysfs hardware paths (fallback)"
ls /sys/class/leds/ 2>&1
ls -l /sys/class/gpio/vibrator/value 2>&1
ls /sys/class/vtconsole/ 2>&1

line "bash version + interfaces + space"
bash --version | head -1
iw dev 2>&1 | grep Interface
df -h /root 2>&1 | tail -1
```

- [ ] **Step 2: Run on the Pager and capture output**

Run (from dev box): `scp tools/p0-verify.sh root@172.16.42.1:/tmp/ && ssh root@172.16.42.1 'bash /tmp/p0-verify.sh' | tee /tmp/p0-out.txt`
Expected: `copy_ok`; `.tables` lists `ssid`, `wifi_device`, `scan`; beacon/client counts ≥ 0; `hcitool`/`bluetoothctl` resolve; DuckyScript verbs resolve (not MISSING).

- [ ] **Step 3: Record findings**

Write `docs/superpowers/P0-findings.md` with a table: assumption → confirmed value → notes. **Explicitly record the Tier-3 gate result** (`btmon_present`/`btmon_absent`) and the exact `LED`/`RINGTONE`/`VIBRATE` syntax that worked. If a v1-critical verb is MISSING or the schema differs, note it as a blocker and stop for a design touch-up before Task 3.

- [ ] **Step 4: Commit**

```bash
git add tools/p0-verify.sh docs/superpowers/P0-findings.md
git commit -m "chore(p0): on-device verification probe + findings"
```

---

### Task 2: Test harness + stubs (offline runner)

**Files:**
- Create: `test/run.sh`
- Create: `test/stubs/sqlite3`
- Create: `test/stubs/ALERT` `LOG` `RINGTONE` `VIBRATE` `LED` `GPS_GET` `TITLE` `START_SPINNER` `STOP_SPINNER` `PAYLOAD_GET_CONFIG` `PAYLOAD_SET_CONFIG`

**Interfaces:**
- Produces: `assert_eq`, `assert_contains`, `assert_empty`, `fail`, `pass` (used by all `*_test.sh`); env `SW_STUB_LOG` (file every DuckyScript stub appends `VERB arg1 arg2...` to); `PATH` with `test/stubs` first.

- [ ] **Step 1: Write the runner (this is the harness; its "test" is that it runs and reports)**

```bash
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
```

- [ ] **Step 2: Write the python-backed `sqlite3` shim**

```bash
#!/usr/bin/env bash
# test/stubs/sqlite3 — emulate the CLI forms the engine uses:
#   sqlite3 DB ".tables" | "PRAGMA ..." | "SELECT ... "
# Delegates to python3 stdlib sqlite3. Tab-separated output (like -separator).
exec python3 - "$@" <<'PY'
import sqlite3, sys
db = sys.argv[1]; sql = sys.argv[2] if len(sys.argv) > 2 else sys.stdin.read()
con = sqlite3.connect(db)
try:
    cur = con.execute(sql)
    rows = cur.fetchall()
    for r in rows:
        print("\t".join("" if v is None else str(v) for v in r))
except sqlite3.OperationalError as e:
    sys.stderr.write("Error: %s\n" % e); sys.exit(1)
PY
```

- [ ] **Step 3: Write one DuckyScript stub, then replicate for all verbs**

```bash
#!/usr/bin/env bash
# test/stubs/ALERT  (chmod +x). Every verb stub is identical except its name.
echo "${0##*/} $*" >> "${SW_STUB_LOG:-/dev/null}"
# GPS_GET must print a coord for log tests; override only in GPS_GET:
```

For `GPS_GET`, the body instead is: `echo "${0##*/} $*" >> "${SW_STUB_LOG:-/dev/null}"; echo "${SW_FAKE_GPS:-}"`.
For `PAYLOAD_GET_CONFIG`, body prints nothing (empty = use default).

- [ ] **Step 4: Make executable and smoke-test the runner**

Run:
```bash
chmod +x test/stubs/* test/run.sh
printf '%s\n' 'assert_eq "a" "a" smoke' > test/smoke_test.sh
bash test/run.sh; echo "rc=$?"
rm test/smoke_test.sh
```
Expected: `PASS=1 FAIL=0` then `rc=0`.

- [ ] **Step 5: Commit**

```bash
git add test/run.sh test/stubs
git commit -m "test: offline harness with sqlite3 shim and DuckyScript stubs"
```

---

### Task 3: Signature loading + OUI + match dispatch (`lib/match.sh`)

**Files:**
- Create: `payloads/user/reconnaissance/squachwatch/lib/match.sh`
- Test: `test/match_test.sh`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `sw_load_signatures <file>` → stdout: signature lines with comments (`#…`) and blank lines stripped.
  - `sw_oui <mac>` → stdout: uppercase `AA:BB:CC` (first three octets).
  - `sw_match_record <record> <sigtext>` → stdout: 0+ detection lines.
  - `sw_match_stream <sigtext>` → reads records on stdin, writes detections on stdout.

- [ ] **Step 1: Write the failing test**

```bash
# test/match_test.sh  (sourced by run.sh; SW_ROOT set below)
SW_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../payloads/user/reconnaissance/squachwatch" && pwd)"
source "$SW_ROOT/lib/match.sh"
SIGS='wifi_oui|70:C9:4E|flock_alpr|Flock Falcon camera|high|surveillance
wifi_ssid_sub|pineapple|hacker_pineapple|WiFi Pineapple|high|attacker
ble_name_sub|flipper|hacker_flipper|Flipper Zero|high|attacker'

# OUI extraction
assert_eq "$(sw_oui '70:c9:4e:aa:bb:cc')" "70:C9:4E" oui_upper

# POSITIVE: a Flock OUI wifi record must produce exactly one detection
det="$(sw_match_record 'wifi|70:C9:4E:11:22:33||-40' "$SIGS")"
assert_contains "$det" "flock_alpr|Flock Falcon camera|high|surveillance|wifi|70:C9:4E:11:22:33||-40" flock_hit

# POSITIVE: ssid substring (case-insensitive) hits pineapple
det2="$(sw_match_record 'wifi|AA:BB:CC:00:11:22|MyPineappleNet|-55' "$SIGS")"
assert_contains "$det2" "hacker_pineapple|WiFi Pineapple|high|attacker|wifi" pineapple_hit

# POSITIVE: ble name hits flipper
det3="$(sw_match_record 'ble|80:E1:26:00:00:01|Flipper aa|' "$SIGS")"
assert_contains "$det3" "hacker_flipper|Flipper Zero|high|attacker|ble" flipper_hit

# NEGATIVE (clean control): unrelated device produces nothing
assert_empty "$(sw_match_record 'wifi|12:34:56:78:9A:BC|HomeWiFi|-60' "$SIGS")" clean_silent

# NON-VACUITY control: remove the Flock sig -> the Flock record now matches nothing
SIGS_NOFLOCK="$(printf '%s\n' "$SIGS" | grep -v flock_alpr)"
assert_empty "$(sw_match_record 'wifi|70:C9:4E:11:22:33||-40' "$SIGS_NOFLOCK")" nonvacuous

# ble_company is Tier-3: must be ignored by v1 matcher
SIG_CO='ble_company|0x004C|apple_findmy|AirTag/Find My|med|tracker'
assert_empty "$(sw_match_record 'ble|DE:AD:BE:EF:00:01||' "$SIG_CO")" tier3_ignored
```

- [ ] **Step 2: Run to verify it fails**

Run: `bash test/run.sh`
Expected: FAIL lines for match_test (functions not defined / no output).

- [ ] **Step 3: Write minimal implementation**

```bash
#!/bin/bash
# lib/match.sh — signature loading, OUI extraction, and match dispatch.
# No grep -P. Case-insensitive via tr.

sw_load_signatures() {
  # $1 = signatures file. Strips comment/blank lines.
  grep -v '^[[:space:]]*#' "$1" 2>/dev/null | grep -v '^[[:space:]]*$'
}

sw_oui() {
  # $1 = MAC (any case, colon form). Echo UPPER first 3 octets.
  printf '%s' "$1" | cut -d: -f1-3 | tr '[:lower:]' '[:upper:]'
}

_sw_lower() { printf '%s' "$1" | tr '[:upper:]' '[:lower:]'; }

sw_match_record() {
  # $1 = record "radio|mac|ident|rssi"  $2 = signatures text
  local rec="$1" sigs="$2"
  local radio mac ident rssi
  IFS='|' read -r radio mac ident rssi <<EOF
$rec
EOF
  local oui; oui="$(sw_oui "$mac")"
  local lident; lident="$(_sw_lower "$ident")"
  local line mtype pat cat label conf tclass
  while IFS='|' read -r mtype pat cat label conf tclass; do
    [ -n "$mtype" ] || continue
    local hit=1
    case "$mtype" in
      wifi_oui)      [ "$radio" = wifi ] && [ "$(printf '%s' "$pat" | tr '[:lower:]' '[:upper:]')" = "$oui" ] && hit=0 ;;
      ble_oui)       [ "$radio" = ble  ] && [ "$(printf '%s' "$pat" | tr '[:lower:]' '[:upper:]')" = "$oui" ] && hit=0 ;;
      wifi_ssid_sub) if [ "$radio" = wifi ] && [ -n "$ident" ]; then case "$lident" in *"$(_sw_lower "$pat")"*) hit=0;; esac; fi ;;
      ble_name_sub)  if [ "$radio" = ble  ] && [ -n "$ident" ]; then case "$lident" in *"$(_sw_lower "$pat")"*) hit=0;; esac; fi ;;
      *) hit=1 ;;   # ble_company / ble_uuid / unknown: Tier-3, ignored in v1
    esac
    [ "$hit" -eq 0 ] && printf '%s|%s|%s|%s|%s|%s|%s|%s\n' "$cat" "$label" "$conf" "$tclass" "$radio" "$mac" "$ident" "$rssi"
  done <<EOF
$sigs
EOF
}

sw_match_stream() {
  # $1 = signatures text; reads records on stdin
  local sigs="$1" rec
  while IFS= read -r rec; do
    [ -n "$rec" ] && sw_match_record "$rec" "$sigs"
  done
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `bash test/run.sh`
Expected: match_test asserts all PASS; `FAIL=0`.

- [ ] **Step 5: Commit**

```bash
git add payloads/user/reconnaissance/squachwatch/lib/match.sh test/match_test.sh
git commit -m "feat(match): signature load, OUI, and match dispatch with positive controls"
```

---

### Task 4: Fixture recon.db builder (`tools/build_fixture_db.py`)

**Files:**
- Create: `tools/build_fixture_db.py`
- Create: `test/fixtures/` (output dir)

**Interfaces:**
- Produces: a recon.db-shaped SQLite file (tables `ssid`, `wifi_device`, `scan`) matching the columns used by `lib/wifi.sh`. Used by Task 5's test.

- [ ] **Step 1: Write the builder**

```python
#!/usr/bin/env python3
"""Build a recon.db-shaped fixture. Usage: build_fixture_db.py OUT.db"""
import sqlite3, sys, time
out = sys.argv[1]
con = sqlite3.connect(out)
con.executescript("""
DROP TABLE IF EXISTS ssid; DROP TABLE IF EXISTS wifi_device; DROP TABLE IF EXISTS scan;
CREATE TABLE scan(id INTEGER PRIMARY KEY, name TEXT, time INT);
CREATE TABLE wifi_device(hash TEXT PRIMARY KEY, mac TEXT, packets INT);
CREATE TABLE ssid(bssid TEXT, ssid TEXT, type INT, channel INT, freq INT,
                  signal INT, encryption INT, hidden INT, time INT, wifi_device TEXT);
""")
now = int(time.time())
con.execute("INSERT INTO scan VALUES(1,'fixture',?)", (now,))
# wifi_device rows keyed by hash (bssid stored as 12 hex chars, no colons, like recon.db)
devs = [("h_flock","70c94e112233",1200),
        ("h_pine","aabbcc001122",300),
        ("h_home","1234569abcde",50),
        ("c_phone","f0f5a5445566",80)]
con.executemany("INSERT INTO wifi_device VALUES(?,?,?)", devs)
# ssid rows: type 8 = AP/beacon, 4 = client probe
rows = [
 ("70c94e112233","",8,6,2437,-40,0,0,now,"h_flock"),          # Flock camera AP
 ("aabbcc001122","MyPineappleNet",8,11,2462,-55,8,0,now,"h_pine"), # pineapple SSID
 ("1234569abcde","HomeWiFi",8,1,2412,-60,8,0,now,"h_home"),    # clean AP
 ("f0f5a5445566","",4,0,2437,-70,0,0,now,"c_phone"),           # client probe
]
con.executemany("INSERT INTO ssid VALUES(?,?,?,?,?,?,?,?,?,?)", rows)
con.commit(); con.close()
print("wrote", out)
```

- [ ] **Step 2: Generate the fixture and verify shape (via the shim so it mirrors device)**

Run:
```bash
mkdir -p test/fixtures
python3 tools/build_fixture_db.py test/fixtures/recon.db
PATH="test/stubs:$PATH" sqlite3 test/fixtures/recon.db "SELECT bssid,ssid,type,signal FROM ssid WHERE type IN (4,8) ORDER BY type DESC;"
```
Expected (tab-separated): four rows incl. `70c94e112233  ` (empty ssid) type 8 signal -40, and `f0f5a5445566` type 4.

- [ ] **Step 3: Commit**

```bash
git add tools/build_fixture_db.py test/fixtures/recon.db
git commit -m "test(fixture): python builder for recon.db-shaped fixtures"
```

---

### Task 5: WiFi read + row→record (`lib/wifi.sh`)

**Files:**
- Create: `payloads/user/reconnaissance/squachwatch/lib/wifi.sh`
- Test: `test/wifi_test.sh`

**Interfaces:**
- Consumes: `sqlite3` (real or shim), a recon.db path.
- Produces:
  - `sw_wifi_colonize <12hex>` → `AA:BB:CC:DD:EE:FF` (upper).
  - `sw_wifi_row_to_record <bssid_hex> <ssid> <signal>` → `wifi|MAC|ssid|signal`.
  - `sw_wifi_records <db_path>` → copies DB to `/tmp`, queries `ssid` type 4/8, prints record lines.

- [ ] **Step 1: Write the failing test**

```bash
SW_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../payloads/user/reconnaissance/squachwatch" && pwd)"
FIX="$(cd "$(dirname "${BASH_SOURCE[0]}")/fixtures" && pwd)"
source "$SW_ROOT/lib/match.sh"; source "$SW_ROOT/lib/wifi.sh"   # match.sh provides sw_sanitize_ident

# pure formatter
assert_eq "$(sw_wifi_colonize '70c94e112233')" "70:C9:4E:11:22:33" colonize
assert_eq "$(sw_wifi_row_to_record '70c94e112233' '' '-40')" "wifi|70:C9:4E:11:22:33||-40" row2rec
# Finding-1 sanitize: a '|' in the SSID is stripped when building the record
assert_eq "$(sw_wifi_row_to_record '70c94e112233' 'Ev|il' '-40')" "wifi|70:C9:4E:11:22:33|Evil|-40" row2rec_sanitized

# integration via shim against the fixture DB
recs="$(sw_wifi_records "$FIX/recon.db")"
assert_contains "$recs" "wifi|70:C9:4E:11:22:33||-40" wifi_flock_record
assert_contains "$recs" "wifi|AA:BB:CC:00:11:22|MyPineappleNet|-55" wifi_pine_record
assert_contains "$recs" "wifi|F0:F5:A5:44:55:66||-70" wifi_client_record
```

- [ ] **Step 2: Run to verify it fails**

Run: `bash test/run.sh`
Expected: wifi_test FAILs (functions undefined).

- [ ] **Step 3: Write minimal implementation**

```bash
#!/bin/bash
# lib/wifi.sh — read recon.db, emit wifi records. Query a /tmp copy (lock-safe).
: "${SW_RECON_DB:=/root/recon/recon.db}"

sw_wifi_colonize() {
  # $1 = 12 hex chars. -> AA:BB:CC:DD:EE:FF upper
  printf '%s' "$1" | tr '[:lower:]' '[:upper:]' \
    | sed 's/\(..\)\(..\)\(..\)\(..\)\(..\)\(..\)/\1:\2:\3:\4:\5:\6/'
}

sw_wifi_row_to_record() {
  # $1=bssid_hex $2=ssid $3=signal. ssid sanitized (Finding-1) via sw_sanitize_ident
  # from lib/match.sh (payload.sh + the test source match.sh before wifi.sh).
  printf 'wifi|%s|%s|%s\n' "$(sw_wifi_colonize "$1")" "$(sw_sanitize_ident "$2")" "$3"
}

sw_wifi_records() {
  # $1 = db path (default SW_RECON_DB). Copies to /tmp then queries.
  local db="${1:-$SW_RECON_DB}" tmp
  tmp="$(mktemp /tmp/sw_recon.XXXXXX.db)" || return 1
  cp "$db" "$tmp" 2>/dev/null || { rm -f "$tmp"; return 1; }
  # tab-separated: bssid, ssid, signal. The { } runs in ONE subshell (pipe RHS).
  # DO NOT use `IFS=$'\t' read -r bssid ssid signal`: tab is IFS-whitespace, so an empty
  # middle field (empty SSID) collapses and shifts signal into ssid. Parse by hand.
  sqlite3 "$tmp" "SELECT bssid, ssid, signal FROM ssid WHERE type IN (4,8);" 2>/dev/null | {
    local line bssid rest ssid signal
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      bssid="${line%%$'\t'*}"; [ -z "$bssid" ] && continue
      rest="${line#*$'\t'}"; ssid="${rest%%$'\t'*}"; signal="${rest#*$'\t'}"
      sw_wifi_row_to_record "$bssid" "$ssid" "$signal"
    done
  }
  rm -f "$tmp"
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `bash test/run.sh`
Expected: wifi_test all PASS.

- [ ] **Step 5: Commit**

```bash
git add payloads/user/reconnaissance/squachwatch/lib/wifi.sh test/wifi_test.sh
git commit -m "feat(wifi): recon.db read (lock-safe copy) and row->record"
```

---

### Task 6: BLE scan + line→record (`lib/ble.sh`)

**Files:**
- Create: `payloads/user/reconnaissance/squachwatch/lib/ble.sh`
- Test: `test/ble_test.sh`

**Interfaces:**
- Consumes: `hcitool` (device only), fixture text (tests).
- Produces:
  - `sw_ble_line_to_record <line>` → `ble|MAC|name|` (empty name if line is a MAC only; skips `LE Scan …` headers and dup `(unknown)`).
  - `sw_ble_parse < file` → reads lescan output on stdin, prints one record per MAC (deduped; keeps a name if any sighting of that MAC carried one).
  - `sw_ble_scan <seconds> <iface>` → device: resets `hci0`, runs `hcitool lescan --duplicates`, pipes through `sw_ble_parse`.

- [ ] **Step 1: Create BLE fixture + failing test**

Create `test/fixtures/lescan.txt`:
```
LE Scan ...
80:E1:26:00:00:01 Flipper aa
80:E1:26:00:00:01 (unknown)
58:8E:81:12:34:56 Penguin-1234
12:34:56:78:9A:BC (unknown)
```

```bash
# test/ble_test.sh
SW_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../payloads/user/reconnaissance/squachwatch" && pwd)"
FIX="$(cd "$(dirname "${BASH_SOURCE[0]}")/fixtures" && pwd)"
source "$SW_ROOT/lib/match.sh"; source "$SW_ROOT/lib/ble.sh"   # match.sh provides sw_sanitize_ident

assert_eq "$(sw_ble_line_to_record '80:E1:26:00:00:01 Flipper aa')" "ble|80:E1:26:00:00:01|Flipper aa|" line_named
assert_eq "$(sw_ble_line_to_record '12:34:56:78:9A:BC (unknown)')"  "ble|12:34:56:78:9A:BC||" line_unknown
assert_empty "$(sw_ble_line_to_record 'LE Scan ...')" header_skipped
# Finding-1 sanitize: a '|' in the advertised name is stripped (rejoins the token)
assert_eq "$(sw_ble_line_to_record '80:E1:26:00:00:01 Fli|pper')" "ble|80:E1:26:00:00:01|Flipper|" line_sanitized

recs="$(sw_ble_parse < "$FIX/lescan.txt")"
assert_contains "$recs" "ble|80:E1:26:00:00:01|Flipper aa|" ble_flipper
assert_contains "$recs" "ble|58:8E:81:12:34:56|Penguin-1234|" ble_penguin
# dedupe: the flipper MAC appears once (named wins over later (unknown))
assert_eq "$(printf '%s\n' "$recs" | grep -c '80:E1:26:00:00:01')" "1" ble_dedup
```

- [ ] **Step 2: Run to verify it fails**

Run: `bash test/run.sh`
Expected: ble_test FAILs.

- [ ] **Step 3: Write minimal implementation**

```bash
#!/bin/bash
# lib/ble.sh — parse hcitool lescan output into ble records.
: "${SW_BLE_IFACE:=hci0}"

sw_ble_line_to_record() {
  # $1 = one lescan line "MAC name..." or "MAC (unknown)" or a header.
  local line="$1" mac rest
  mac="${line%% *}"
  case "$mac" in
    [0-9A-Fa-f][0-9A-Fa-f]:*) : ;;   # looks like a MAC
    *) return 0 ;;                    # header / junk -> skip
  esac
  rest="${line#"$mac"}"; rest="${rest# }"
  [ "$rest" = "(unknown)" ] && rest=""
  # name sanitized (Finding-1) via sw_sanitize_ident from lib/match.sh (sourced first)
  printf 'ble|%s|%s|\n' "$(printf '%s' "$mac" | tr '[:lower:]' '[:upper:]')" "$(sw_sanitize_ident "$rest")"
}

sw_ble_parse() {
  # stdin = lescan output. Reuse the per-line formatter, then dedupe by MAC,
  # keeping a name if ANY sighting of that MAC carried one (lescan often shows
  # "(unknown)" first, then the name on a later advertisement).
  local line
  while IFS= read -r line; do sw_ble_line_to_record "$line"; done \
  | awk -F'|' '
      $1=="ble" {
        mac=$2; name=$3
        if (!(mac in seen) || (name!="" && nameof[mac]=="")) { seen[mac]=1; nameof[mac]=name }
      }
      END { for (m in seen) printf "ble|%s|%s|\n", m, nameof[m] }
    '
}

sw_ble_scan() {
  # $1 = seconds (default 12), $2 = iface (default hci0). Device only.
  local secs="${1:-12}" iface="${2:-$SW_BLE_IFACE}" out
  hciconfig "$iface" down 2>/dev/null; hciconfig "$iface" reset 2>/dev/null; hciconfig "$iface" up 2>/dev/null
  out="$(mktemp /tmp/sw_ble.XXXXXX)"
  timeout "$secs" hcitool -i "$iface" lescan --duplicates > "$out" 2>/dev/null
  sw_ble_parse < "$out"
  rm -f "$out"
}
```

- [ ] **Step 4: Run to verify it passes**

Run: `bash test/run.sh`
Expected: ble_test all PASS.

- [ ] **Step 5: Commit**

```bash
git add payloads/user/reconnaissance/squachwatch/lib/ble.sh test/ble_test.sh test/fixtures/lescan.txt
git commit -m "feat(ble): lescan parse with dedupe and positive controls"
```

---

### Task 7: Logging + GPS tag (`lib/log.sh`)

**Files:**
- Create: `payloads/user/reconnaissance/squachwatch/lib/log.sh`
- Test: `test/log_test.sh`

**Interfaces:**
- Consumes: `GPS_GET` (stub), a detection line, a loot dir.
- Produces:
  - `sw_log_init <dir>` → makes dir, writes CSV header if absent.
  - `sw_log_write <dir> <detection> <now_epoch>` → appends one CSV row `time,category,label,confidence,threat_class,radio,mac,ident,rssi,gps`.

- [ ] **Step 1: Write the failing test**

```bash
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
rm -rf "$D"
```

- [ ] **Step 2: Run to verify it fails** — Run: `bash test/run.sh` — Expected: log_test FAILs.

- [ ] **Step 3: Write minimal implementation**

```bash
#!/bin/bash
# lib/log.sh — CSV detection log with optional GPS tag.
sw_log_init() {
  local dir="$1"; mkdir -p "$dir"
  local csv="$dir/detections.csv"
  [ -f "$csv" ] || echo "time,category,label,confidence,threat_class,radio,mac,ident,rssi,gps" > "$csv"
}
sw_log_write() {
  # $1=dir $2=detection $3=now_epoch
  local dir="$1" det="$2" now="$3" gps
  gps="$(GPS_GET 2>/dev/null | tr ' ' ',' )"   # stub prints SW_FAKE_GPS; device prints coords
  local cat label conf tclass radio mac ident rssi
  IFS='|' read -r cat label conf tclass radio mac ident rssi <<EOF
$det
EOF
  # CSV-escape free-text fields (may contain commas/quotes): quote-wrap, double internal quotes.
  # gps MUST be quoted too — real GPS_GET returns space-separated lat lon alt acc that the tr
  # above turns into commas; unquoted, a GPS row would overflow the 10-column header.
  local qident qgps
  qident="\"$(printf '%s' "$ident" | sed 's/"/""/g')\""
  qgps="\"$(printf '%s' "$gps" | sed 's/"/""/g')\""
  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$now" "$cat" "$label" "$conf" "$tclass" "$radio" "$mac" "$qident" "$rssi" "$qgps" \
    >> "$dir/detections.csv"
}
```

- [ ] **Step 4: Run to verify it passes** — Run: `bash test/run.sh` — Expected: log_test all PASS.

- [ ] **Step 5: Commit**

```bash
git add payloads/user/reconnaissance/squachwatch/lib/log.sh test/log_test.sh
git commit -m "feat(log): CSV detection log with GPS tagging"
```

---

### Task 8: Dedupe/cooldown logic (`lib/alert.sh` part 1)

**Files:**
- Create: `payloads/user/reconnaissance/squachwatch/lib/alert.sh`
- Test: `test/alert_test.sh`

**Interfaces:**
- Produces:
  - `sw_color_for <threat_class>` → `magenta|yellow|cyan|white`.
  - `sw_should_alert <mac> <category> <now> <cooldown> <seenfile>` → return 0 (alert) and update seenfile, or return 1 (suppressed within cooldown).

- [ ] **Step 1: Write the failing test (cooldown + colors)**

```bash
SW_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../payloads/user/reconnaissance/squachwatch" && pwd)"
source "$SW_ROOT/lib/alert.sh"

assert_eq "$(sw_color_for surveillance)" "magenta" c_surv
assert_eq "$(sw_color_for tracker)" "yellow" c_track
assert_eq "$(sw_color_for attacker)" "cyan" c_atk
assert_eq "$(sw_color_for weird)" "white" c_default

SEEN="$(mktemp)"; : > "$SEEN"
# first sighting -> alert (rc 0)
if sw_should_alert "AA:BB:CC:00:11:22" flock_alpr 1000 600 "$SEEN"; then pass; else fail first_alerts; fi
# same device 100s later, cooldown 600 -> suppressed (rc 1)
if sw_should_alert "AA:BB:CC:00:11:22" flock_alpr 1100 600 "$SEEN"; then fail cooldown_suppress; else pass; fi
# same device after cooldown expiry -> alert again (rc 0)
if sw_should_alert "AA:BB:CC:00:11:22" flock_alpr 1700 600 "$SEEN"; then pass; else fail realert_after_cooldown; fi
# different category, same MAC -> independent -> alert (rc 0)
if sw_should_alert "AA:BB:CC:00:11:22" other_cat 1100 600 "$SEEN"; then pass; else fail independent_category; fi
rm -f "$SEEN"
```

- [ ] **Step 2: Run to verify it fails** — Run: `bash test/run.sh` — Expected: alert_test FAILs.

- [ ] **Step 3: Write minimal implementation (part 1 only)**

```bash
#!/bin/bash
# lib/alert.sh — color map, cooldown dedupe, and (Task 9) emit.
sw_color_for() {
  case "$1" in
    surveillance) echo magenta ;;
    tracker)      echo yellow ;;
    attacker)     echo cyan ;;
    *)            echo white ;;
  esac
}

sw_should_alert() {
  # $1=mac $2=category $3=now $4=cooldown_secs $5=seenfile
  local mac="$1" cat="$2" now="$3" cd="$4" sf="$5" key="$1|$2" last
  last="$(grep -F "$key|" "$sf" 2>/dev/null | tail -1 | cut -d'|' -f3)"
  if [ -n "$last" ] && [ $((now - last)) -lt "$cd" ]; then
    return 1
  fi
  # record this alert time (append; last-wins on read)
  printf '%s|%s\n' "$key" "$now" >> "$sf"
  return 0
}
```

- [ ] **Step 4: Run to verify it passes** — Run: `bash test/run.sh` — Expected: alert_test all PASS.

- [ ] **Step 5: Commit**

```bash
git add payloads/user/reconnaissance/squachwatch/lib/alert.sh test/alert_test.sh
git commit -m "feat(alert): color map and cooldown dedupe with positive controls"
```

---

### Task 9: Emit + hardware notify (`lib/alert.sh` part 2)

**Files:**
- Modify: `payloads/user/reconnaissance/squachwatch/lib/alert.sh` (append functions)
- Test: `test/alert_test.sh` (append cases)

**Interfaces:**
- Consumes: `LOG`, `ALERT`, `RINGTONE`, `VIBRATE`, `LED` (stubs); `sw_log_write` (Task 7); `sw_should_alert`, `sw_color_for` (Task 8).
- Produces:
  - `sw_hw_notify <threat_class>` → `LED`+`RINGTONE`+`VIBRATE` for a high-severity hit (syntax per P0 findings; default observed forms below).
  - `sw_emit <detection> <now> <cooldown> <seenfile> <lootdir>` → always logs; always `LOG`-colors a line; on new+high-confidence also full `ALERT` + `sw_hw_notify`.

> **P0 gate:** LED/RINGTONE/VIBRATE argument forms below are the community-observed syntax (`LED B 50`/`LED OFF`, `RINGTONE alert`). If Task-1 findings show different forms, edit ONLY `sw_hw_notify` — no other code changes.

- [ ] **Step 1: Append failing tests**

```bash
# --- append to test/alert_test.sh ---
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
rm -rf "$LOOT" "$SEEN2"
```

- [ ] **Step 2: Run to verify it fails** — Run: `bash test/run.sh` — Expected: new emit_* asserts FAIL.

- [ ] **Step 3: Append implementation to `lib/alert.sh`**

```bash
sw_hw_notify() {
  # $1 = threat_class. Observed-syntax hardware alert; see P0 gate.
  case "$1" in
    surveillance) LED M 200 2>/dev/null ;;
    tracker)      LED Y 200 2>/dev/null ;;
    attacker)     LED R 255 2>/dev/null ;;
    *)            LED B 100 2>/dev/null ;;
  esac
  RINGTONE alert 2>/dev/null
  VIBRATE alert 2>/dev/null
  LED OFF 2>/dev/null
}

sw_emit() {
  # $1=detection $2=now $3=cooldown $4=seenfile $5=lootdir
  local det="$1" now="$2" cd="$3" sf="$4" loot="$5"
  local cat label conf tclass radio mac ident rssi
  IFS='|' read -r cat label conf tclass radio mac ident rssi <<EOF
$det
EOF
  local color; color="$(sw_color_for "$tclass")"
  local rssitag=""; [ -n "$rssi" ] && rssitag=" ${rssi}dBm"
  # Always: persist + colored log line
  sw_log_write "$loot" "$det" "$now"
  LOG "$color" "$label $mac$rssitag" 2>/dev/null
  # New (past cooldown) AND high confidence -> full alert + hardware
  if [ "$conf" = high ] && sw_should_alert "$mac" "$cat" "$now" "$cd" "$sf"; then
    ALERT "$label
$mac$rssitag" 2>/dev/null
    sw_hw_notify "$tclass"
  fi
}
```

- [ ] **Step 4: Run to verify it passes** — Run: `bash test/run.sh` — Expected: all alert_test PASS.

- [ ] **Step 5: Commit**

```bash
git add payloads/user/reconnaissance/squachwatch/lib/alert.sh test/alert_test.sh
git commit -m "feat(alert): emit with colored log, gated full ALERT, and hardware notify"
```

---

### Task 10: End-to-end pipeline test (WiFi + BLE → detections → emit)

Proves the libs compose. No new production code — an integration test that wires fixtures through the whole chain, with a clean-input control.

**Files:**
- Test: `test/e2e_test.sh`

- [ ] **Step 1: Write the integration test**

```bash
SW_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../payloads/user/reconnaissance/squachwatch" && pwd)"
FIX="$(cd "$(dirname "${BASH_SOURCE[0]}")/fixtures" && pwd)"
source "$SW_ROOT/lib/match.sh"; source "$SW_ROOT/lib/wifi.sh"
source "$SW_ROOT/lib/ble.sh"; source "$SW_ROOT/lib/alert.sh"; source "$SW_ROOT/lib/log.sh"

SIGS='wifi_oui|70:C9:4E|flock_alpr|Flock Falcon camera|high|surveillance
wifi_ssid_sub|pineapple|hacker_pineapple|WiFi Pineapple|high|attacker
ble_name_sub|flipper|hacker_flipper|Flipper Zero|high|attacker
ble_name_sub|penguin|flock_battery|Flock Penguin battery|high|surveillance'

LOOT="$(mktemp -d)"; sw_log_init "$LOOT"; SEEN="$(mktemp)"; : > "$SEEN"; : > "$SW_STUB_LOG"

# WiFi chain
dets_w="$(sw_wifi_records "$FIX/recon.db" | sw_match_stream "$SIGS")"
assert_contains "$dets_w" "flock_alpr|" e2e_wifi_flock
assert_contains "$dets_w" "hacker_pineapple|" e2e_wifi_pine
# BLE chain
dets_b="$(sw_ble_parse < "$FIX/lescan.txt" | sw_match_stream "$SIGS")"
assert_contains "$dets_b" "hacker_flipper|" e2e_ble_flipper
assert_contains "$dets_b" "flock_battery|" e2e_ble_penguin

# emit all, assert ALERTs fired for the high-confidence hits
while IFS= read -r d; do [ -n "$d" ] && sw_emit "$d" 1000 600 "$SEEN" "$LOOT"; done <<< "$dets_w
$dets_b"
assert_contains "$(cat "$SW_STUB_LOG")" "ALERT " e2e_alerted
assert_eq "$(grep -c . "$LOOT/detections.csv")" "5" e2e_logged_rows  # header + 4 detections

# CLEAN control: an environment with only HomeWiFi yields zero detections
clean="$(printf 'wifi|12:34:56:78:9A:BC|HomeWiFi|-60\n' | sw_match_stream "$SIGS")"
assert_empty "$clean" e2e_clean_silent
rm -rf "$LOOT" "$SEEN"
```

- [ ] **Step 2: Run** — Run: `bash test/run.sh` — Expected: all e2e_* PASS (fails first if any lib regressed).

- [ ] **Step 3: Commit**

```bash
git add test/e2e_test.sh
git commit -m "test(e2e): full wifi+ble pipeline through emit with clean control"
```

---

### Task 11: Seed signature database (`signatures.db`)

**Files:**
- Create: `payloads/user/reconnaissance/squachwatch/signatures.db`
- Test: `test/signatures_test.sh`

**Interfaces:** consumed by `payload.sh`; validated for format + that seed entries hit known fixtures.

- [ ] **Step 1: Write the failing format+content test**

```bash
SW_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../payloads/user/reconnaissance/squachwatch" && pwd)"
source "$SW_ROOT/lib/match.sh"
SIGS="$(sw_load_signatures "$SW_ROOT/signatures.db")"

# every non-comment line has exactly 6 pipe-fields and a valid threat_class
bad="$(printf '%s\n' "$SIGS" | awk -F'|' 'NF!=6 || ($6!="surveillance" && $6!="tracker" && $6!="attacker"){print}')"
assert_empty "$bad" sig_format_valid

# Tier-1 anchors present and firing
assert_contains "$(sw_match_record 'wifi|70:C9:4E:11:22:33||-40' "$SIGS")" "flock" seed_flock
assert_contains "$(sw_match_record 'ble|80:E1:26:00:00:01|Flipper|' "$SIGS")" "flipper" seed_flipper
assert_contains "$(sw_match_record 'wifi|00:00:00:00:00:00|xPineapplex|' "$SIGS")" "pineapple" seed_pineapple
```

- [ ] **Step 2: Run to verify it fails** — Run: `bash test/run.sh` — Expected: signatures_test FAILs (file absent).

- [ ] **Step 3: Write the seed file (Tier-1 + starter Tier-2; grow later)**

```
# SquachWatch-Pager signatures — match_type|pattern|category|label|confidence|threat_class
# ---- Tier 1: Flock (WiFi OUIs verified via WiGLE, from Flock_Detect) ----
wifi_oui|70:C9:4E|flock_alpr|Flock Falcon camera|high|surveillance
wifi_oui|3C:91:80|flock_alpr|Flock Falcon camera|high|surveillance
wifi_oui|D8:F3:BC|flock_alpr|Flock Falcon camera|high|surveillance
wifi_oui|08:3A:88|flock_alpr|Flock Falcon camera|high|surveillance
wifi_oui|14:5A:FC|flock_alpr|Flock Falcon camera|high|surveillance
wifi_oui|58:8E:81|flock_battery|Flock external battery|high|surveillance
wifi_oui|EC:1B:BD|flock_battery|Flock external battery|high|surveillance
wifi_oui|90:35:EA|flock_battery|Flock external battery|high|surveillance
# Lite-On chipset used by Flock Falcon V2 — broad vendor, LOW confidence
wifi_oui|74:4C:A1|flock_liteon|Possible Flock (Lite-On chipset)|low|surveillance
wifi_oui|80:30:49|flock_liteon|Possible Flock (Lite-On chipset)|low|surveillance
# ---- Tier 1: Flock BLE names ----
ble_name_sub|penguin|flock_battery|Flock Penguin battery|high|surveillance
ble_name_sub|pigvision|flock_alpr|Flock Pigvision device|high|surveillance
ble_name_sub|fs ext battery|flock_battery|Flock external battery|high|surveillance
ble_name_sub|flock|flock_generic|Flock device|med|surveillance
# ---- Tier 1: hacker tools ----
ble_name_sub|flipper|hacker_flipper|Flipper Zero|high|attacker
ble_oui|80:E1:26|hacker_flipper|Flipper Zero|high|attacker
wifi_ssid_sub|pineapple|hacker_pineapple|WiFi Pineapple|high|attacker
wifi_ssid_sub|pager_open|hacker_pager|WiFi Pineapple Pager|med|attacker
# ---- Tier 2 starters (expand in a later task) ----
ble_name_sub|tile|tracker_tile|Tile tracker|med|tracker
wifi_ssid_sub|ring-|surveillance_ring|Ring doorbell|med|surveillance
```

- [ ] **Step 4: Run to verify it passes** — Run: `bash test/run.sh` — Expected: signatures_test PASS.

- [ ] **Step 5: Commit**

```bash
git add payloads/user/reconnaissance/squachwatch/signatures.db test/signatures_test.sh
git commit -m "feat(signatures): Tier-1 + starter Tier-2 seed fingerprints"
```

---

### Task 12: Main scanner payload (`payload.sh`)

**Files:**
- Create: `payloads/user/reconnaissance/squachwatch/payload.sh`
- Test: `test/payload_test.sh`

**Interfaces:**
- Consumes: all libs + `signatures.db`.
- Produces: `sw_scan_once` (one WiFi+BLE sweep → emit), and a guarded `main` loop that only runs when executed (not when sourced), so the test can source and call `sw_scan_once` without looping forever.

- [ ] **Step 1: Write the failing test (single sweep, sourcing guard)**

```bash
SW_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../payloads/user/reconnaissance/squachwatch" && pwd)"
FIX="$(cd "$(dirname "${BASH_SOURCE[0]}")/fixtures" && pwd)"
# Point the scanner at fixtures instead of the device, and skip real BLE:
export SW_RECON_DB="$FIX/recon.db"
export SW_BLE_CMD="cat $FIX/lescan.txt"     # payload uses SW_BLE_CMD if set (test seam)
export SW_LOOT_DIR="$(mktemp -d)"
export SW_SEEN_FILE="$(mktemp)"; : > "$SW_SEEN_FILE"
export SW_TEST_SOURCE=1                      # tells payload.sh not to auto-run main
: > "$SW_STUB_LOG"
source "$SW_ROOT/payload.sh"
sw_scan_once
assert_contains "$(cat "$SW_STUB_LOG")" "ALERT " payload_alerts
assert_contains "$(tail -n +2 "$SW_LOOT_DIR/detections.csv")" "flock_alpr" payload_logs_flock
assert_contains "$(cat "$SW_LOOT_DIR/detections.csv")" "hacker_flipper" payload_logs_flipper
rm -rf "$SW_LOOT_DIR" "$SW_SEEN_FILE"
```

- [ ] **Step 2: Run to verify it fails** — Run: `bash test/run.sh` — Expected: payload_test FAILs.

- [ ] **Step 3: Write the payload**

```bash
#!/bin/bash
# Title: SquachWatch
# Description: Always-on detector for surveillance devices, trackers, and hacker tools.
# Author: ziggy
# Version: 1.0
# Category: reconnaissance
# Homage to SquachWatch-CYD (skizzophrenic); reuses Hak5 community payload patterns.

SW_HOME="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
for l in match wifi ble alert log; do . "$SW_HOME/lib/$l.sh"; done

# --- config (overridable via env / PAYLOAD_GET_CONFIG on device) ---
: "${SW_RECON_DB:=/root/recon/recon.db}"
: "${SW_BLE_IFACE:=hci0}"
: "${SW_BLE_SECONDS:=12}"
: "${SW_COOLDOWN:=600}"
: "${SW_LOOT_DIR:=/root/loot/squachwatch}"
: "${SW_SEEN_FILE:=$SW_LOOT_DIR/seen.db}"
: "${SW_SLEEP:=3}"

SW_SIGS="$(sw_load_signatures "$SW_HOME/signatures.db")"

# BLE source seam: tests set SW_BLE_CMD; device uses real scan.
_sw_ble_records() {
  if [ -n "${SW_BLE_CMD:-}" ]; then eval "$SW_BLE_CMD" | sw_ble_parse
  else sw_ble_scan "$SW_BLE_SECONDS" "$SW_BLE_IFACE"; fi
}

sw_scan_once() {
  local now; now="$(date +%s)"
  { sw_wifi_records "$SW_RECON_DB"; _sw_ble_records; } \
    | sw_match_stream "$SW_SIGS" \
    | while IFS= read -r det; do
        [ -n "$det" ] && sw_emit "$det" "$now" "$SW_COOLDOWN" "$SW_SEEN_FILE" "$SW_LOOT_DIR"
      done
}

sw_cleanup() { killall hcitool 2>/dev/null; exit 0; }

sw_main() {
  sw_log_init "$SW_LOOT_DIR"
  mkdir -p "$(dirname "$SW_SEEN_FILE")"; touch "$SW_SEEN_FILE"
  trap sw_cleanup EXIT INT TERM
  LOG green "SquachWatch armed — watching WiFi + BLE" 2>/dev/null
  while true; do
    sw_scan_once
    sleep "$SW_SLEEP"
  done
}

# Auto-run unless sourced by a test.
[ -n "${SW_TEST_SOURCE:-}" ] || sw_main
```

- [ ] **Step 4: Run to verify it passes** — Run: `bash test/run.sh` — Expected: payload_test PASS (and all prior).

- [ ] **Step 5: Commit**

```bash
git add payloads/user/reconnaissance/squachwatch/payload.sh test/payload_test.sh
git commit -m "feat(payload): main SquachWatch scanner loop with test seam"
```

---

### Task 13: Native alert payloads (4 free events)

**Files:**
- Create: `payloads/alerts/deauth_flood_detected/squachwatch_deauth/payload.sh`
- Create: `payloads/alerts/handshake_captured/squachwatch_handshake/payload.sh`
- Create: `payloads/alerts/pineapple_client_connected/squachwatch_client/payload.sh`
- Create: `payloads/alerts/pineapple_auth_captured/squachwatch_auth/payload.sh`
- Test: `test/alerts_test.sh`

**Interfaces:**
- Consumes: alert-event env vars (`$_ALERT_*`), stubs for `ALERT`/`LOG`/`RINGTONE`.
- Produces: each script emits an `ALERT` + colored `LOG` from the event. The client one derives vendor from `/lib/hak5/oui.txt` when readable (falls back to "Unknown"), matching device_profiler's pattern.

- [ ] **Step 1: Write the failing test**

```bash
ALERTS="$(cd "$(dirname "${BASH_SOURCE[0]}")/../payloads/alerts" && pwd)"
: > "$SW_STUB_LOG"
_ALERT_DENIAL_SOURCE_MAC_ADDRESS="AA:BB:CC:00:00:01" \
_ALERT_DENIAL_AP_MAC_ADDRESS="DE:AD:BE:EF:00:02" \
  bash "$ALERTS/deauth_flood_detected/squachwatch_deauth/payload.sh"
assert_contains "$(cat "$SW_STUB_LOG")" "ALERT " deauth_alert
assert_contains "$(cat "$SW_STUB_LOG")" "AA:BB:CC:00:00:01" deauth_src

: > "$SW_STUB_LOG"
_ALERT_CLIENT_CONNECTED_CLIENT_MAC_ADDRESS="F0:F5:A5:11:22:33" \
_ALERT_CLIENT_CONNECTED_SSID="Guest" \
  bash "$ALERTS/pineapple_client_connected/squachwatch_client/payload.sh"
assert_contains "$(cat "$SW_STUB_LOG")" "ALERT " client_alert
assert_contains "$(cat "$SW_STUB_LOG")" "Guest" client_ssid
```

- [ ] **Step 2: Run to verify it fails** — Run: `bash test/run.sh` — Expected: alerts_test FAILs.

- [ ] **Step 3: Write the four payloads**

`deauth_flood_detected/squachwatch_deauth/payload.sh`:
```bash
#!/bin/bash
# Title: SquachWatch Deauth Alert
# Description: Full-screen alert on a deauth flood (SquachWatch attacker class).
LOG cyan "Deauth flood: src ${_ALERT_DENIAL_SOURCE_MAC_ADDRESS} -> ap ${_ALERT_DENIAL_AP_MAC_ADDRESS}" 2>/dev/null
ALERT "DEAUTH FLOOD
src ${_ALERT_DENIAL_SOURCE_MAC_ADDRESS}
ap  ${_ALERT_DENIAL_AP_MAC_ADDRESS}" 2>/dev/null
RINGTONE alert 2>/dev/null
exit 0
```

`handshake_captured/squachwatch_handshake/payload.sh`:
```bash
#!/bin/bash
# Title: SquachWatch Handshake Alert
LOG cyan "Handshake ${_ALERT_HANDSHAKE_TYPE} ap ${_ALERT_HANDSHAKE_AP_MAC_ADDRESS}" 2>/dev/null
ALERT "HANDSHAKE ${_ALERT_HANDSHAKE_TYPE}
ap ${_ALERT_HANDSHAKE_AP_MAC_ADDRESS}" 2>/dev/null
exit 0
```

`pineapple_client_connected/squachwatch_client/payload.sh`:
```bash
#!/bin/bash
# Title: SquachWatch Client Alert
# Description: Alert + vendor lookup when a client associates.
OUI_FILE=/lib/hak5/oui.txt; [ -f "$OUI_FILE" ] || OUI_FILE=/rom/lib/hak5/oui.txt
mac="${_ALERT_CLIENT_CONNECTED_CLIENT_MAC_ADDRESS}"
vendor="Unknown"
if [ -f "$OUI_FILE" ]; then
  key="$(printf '%s' "$mac" | tr -d ':' | cut -c1-6 | tr '[:lower:]' '[:upper:]')"
  v="$(grep -i "$key" "$OUI_FILE" 2>/dev/null | cut -f3 | head -1)"
  [ -n "$v" ] && vendor="$v"
fi
LOG yellow "Client ${mac} (${vendor}) -> ${_ALERT_CLIENT_CONNECTED_SSID}" 2>/dev/null
ALERT "CLIENT CONNECTED
${mac}
${vendor}
SSID: ${_ALERT_CLIENT_CONNECTED_SSID}" 2>/dev/null
exit 0
```

`pineapple_auth_captured/squachwatch_auth/payload.sh`:
```bash
#!/bin/bash
# Title: SquachWatch Auth Alert
LOG cyan "Auth captured: ${_ALERT_AUTH_SUMMARY:-${_ALERT_AUTH_TYPE:-credential}}${_ALERT_AUTH_USERNAME:+ user=${_ALERT_AUTH_USERNAME}}" 2>/dev/null
ALERT "AUTH CAPTURED
${_ALERT_AUTH_SUMMARY:-${_ALERT_AUTH_TYPE:-credential}}${_ALERT_AUTH_USERNAME:+
user: ${_ALERT_AUTH_USERNAME}}" 2>/dev/null
RINGTONE alert 2>/dev/null
exit 0
```

- [ ] **Step 4: Run to verify it passes** — Run: `bash test/run.sh` — Expected: alerts_test PASS.

- [ ] **Step 5: Commit**

```bash
git add payloads/alerts test/alerts_test.sh
git commit -m "feat(alerts): native deauth/handshake/client/auth alert payloads"
```

---

### Task 14: README + install notes

**Files:**
- Create: `README.md`

- [ ] **Step 1: Write README** covering: what it is (homage to SquachWatch-CYD), the two payload types, install via `scp -r payloads/user/reconnaissance/squachwatch root@172.16.42.1:/root/payloads/user/reconnaissance/` and the alert dirs, the `sqlite3-cli` dependency check (`which sqlite3 || opkg update && opkg install sqlite3-cli`), how signatures work (the 6-field format + how to add a line), running the tests (`bash test/run.sh`), the P0 findings reference, and the deferred phases (Tier-3 raw-adv, drone Remote-ID, framebuffer skin). Credit the community payloads (Attribution section of the spec).

- [ ] **Step 2: Verify tests still green + commit**

```bash
bash test/run.sh && git add README.md && git commit -m "docs: README with install, signatures, testing, and roadmap"
```

---

### Task 15: On-device smoke test (real Pager)

Not TDD — real-hardware validation of the whole v1, using a temporary self-signature as the on-device positive control (a real Flock camera isn't available).

- [ ] **Step 1: Deploy**

Run:
```bash
ssh root@172.16.42.1 'which sqlite3 || (opkg update && opkg install sqlite3-cli)'
scp -r payloads/user/reconnaissance/squachwatch root@172.16.42.1:/root/payloads/user/reconnaissance/
scp -r payloads/alerts/* root@172.16.42.1:/root/payloads/alerts/ 2>/dev/null || true
```

- [ ] **Step 2: Positive control — add a signature matching a device you own**

Get your phone's WiFi MAC OUI (or a Bluetooth name), then on the Pager:
```bash
ssh root@172.16.42.1 'echo "wifi_oui|AA:BB:CC|selftest_device|SELFTEST hit|high|attacker" >> /root/payloads/user/reconnaissance/squachwatch/signatures.db'
```
(Replace `AA:BB:CC` with your device's real OUI.)

- [ ] **Step 3: Run from the Pager UI** — Payloads → reconnaissance → SquachWatch. Expected: within one BLE cycle, a full-screen `SELFTEST hit` ALERT + buzz + LED, and a row in `/root/loot/squachwatch/detections.csv`.

- [ ] **Step 4: Negative confirmation** — remove the selftest line; relaunch; confirm no `SELFTEST` alert fires (proves the earlier hit was real, not a UI artifact). Confirm real nearby devices (or a Flipper/known SSID) behave as expected.

- [ ] **Step 5: Record results + commit any syntax fixes**

Append an "On-device smoke — v1" section to `docs/superpowers/P0-findings.md` (LED/RINGTONE syntax as it actually behaved, any adjustments made to `sw_hw_notify`). Commit:
```bash
git add -A && git commit -m "test(device): v1 on-device smoke results + syntax fixes"
```

---

## Deferred to their own plans (out of scope for this plan)
- **Tier-3 raw-BLE-adv detections** (AirTag/Find My, SmartTag, Google FMN, iBeacon, gunshot UUID) — gated on Task-1 `btmon`/raw-adv finding. Adds a `ble_company`/`ble_uuid` matcher branch + a raw-adv record field.
- **Phase 5:** drone Remote-ID over WiFi (monitor-mode `wlan1mon` capture + IE/NAN parsing).
- **Phase 6:** framebuffer "vaporwave" skin + mascot via `/dev/fb0` + RGB565 renderer.

## Self-Review notes
- Spec coverage: signature model (T3,T11), WiFi enum + lock workaround (T5), BLE name (T6), alerting/dedupe/throttle (T8,T9), logging+GPS (T7), 4 native alerts (T13), P0 spike incl. Tier-3 gate (T1), local harness + positive controls (T2,T3,T6,T8,T10), on-device smoke w/ positive control (T15). Tier-3/4/framebuffer explicitly deferred. Full parity's Tier-2 growth continues via signature additions (format frozen in T3/T11).
- Type consistency: record `radio|mac|ident|rssi`, detection `category|label|confidence|threat_class|radio|mac|ident|rssi`, and function names (`sw_match_record`, `sw_wifi_records`, `sw_ble_parse`, `sw_emit`, `sw_should_alert`, `sw_scan_once`) are used identically across tasks.
- No placeholders: every code/test step carries real content; P0-dependent hardware syntax is isolated to `sw_hw_notify` with an explicit gate note, not a TODO.
