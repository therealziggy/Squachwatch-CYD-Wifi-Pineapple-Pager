# SquachWatch-Pager Evil-Twin Detector Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Warn when a network name near the Pager is offered both open and password-protected at the same time: each open copy is reported as an evil twin (full alert, CSV row), and the check warns if it ever goes blind.

**Architecture:** A new `lib/eviltwin.sh` runs one read-only SQLite query per lap on the lap's copy of the Pager's recon database and prints finished detections in the matcher's 8-field format. The lap (`payload.sh`, `sw_scan_once`) makes ONE database copy, runs the twin check first, then the existing WiFi signature sweep on the same copy, and feeds everything through the existing emit loop (ignore list, screen cap, cooldowns, CSV, alert). The health check gains a "blind" warning for a database that stops recording network security.

**Tech Stack:** bash 5 (the Pager runs bash on a BusyBox userland), the `sqlite3` CLI (3.46.1 on the Pager; a python3-backed stand-in in `test/stubs/sqlite3` on the dev box), the repo's own bash test harness (`bash test/run.sh`).

**Spec:** `docs/superpowers/specs/2026-09-29-squachwatch-evil-twin-design.md` (approved 2026-09-29).

## Global Constraints

- **Public repository.** Made-up MACs and network names only (tests, fixtures, docs, commit messages). Never a real address, network name, date or time from the Pager's history, and never a local path (`/home/...`).
- **Commits:** `TZ=UTC git -c user.name=Ziggy -c user.email=79704039+therealziggy@users.noreply.github.com commit ...`. Every message ends with exactly ONE line `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Copy it verbatim; never put another model's name in it. Subject style: `area: what changed` (e.g. `wifi: ...`, `eviltwin: ...`, `payload: ...`, `docs: ...`).
- **Do not push, and do not touch the Pager.** The controller does both, with the user's OK.
- **The Pager runs bash on BusyBox:** no `[:class:]` in `tr`; a `mktemp` template ends in `XXXXXX` with nothing after it; no `od`, `hexdump`, `diff`, `paste` on the device.
- **Per-row code is fork-free:** inside loops that run per record or per result row, use builtins only (no `$( )`, backticks, `tr`/`sed`/`cut`/`awk`/`grep`). Helpers answer in `REPLY`. `test/perf_test.sh` enforces this.
- **No `:=` defaults in `lib/*.sh`.** `payload.sh` sources its libs BEFORE its config block, so a lib default would win. Read variables as `${VAR:-x}` at the point of use.
- **sqlite3 output:** build ONE column per row, joined with `char(9)` in SQL, with the free-text field (the network name) LAST. The Pager's CLI separates columns with `|`, the test stand-in with TAB. The CLI prints a line break inside a value as it is, so names get `replace(replace(CAST(... AS TEXT), char(10), ''), char(13), '')` in SQL.
- **Reads of a recon DB copy use `sqlite3 -readonly`.** On a missing file it fails and creates nothing, while a plain `sqlite3` leaves an empty 0-byte file. Both behaviours were checked on the Pager on 2026-09-29.
- **Tests:** every "stays silent" assertion has a positive control (a sibling case that fires on the same data). Test files are `source`d into one shell by `test/run.sh`, so clean up your variables and functions at the end of each block. `bash test/run.sh` must end with `FAIL=0`. The baseline before this plan is `PASS=690 FAIL=0` (about 80 s).
- **Functions the payload's main shell runs** (`sw_main`, `sw_prune_ledger`, `sw_seen_prune`, `sw_clear_tmp`, `sw_log_init`, `sw_cleanup`) never use `continue` or `break`. There is a static test for this. Code in the lap and in the new lib may use them.

## Plan additions beyond the spec (the spec is amended in Task 5)

1. **The WiFi signature reader had a real forgery bug** (reproduced 2026-09-29 on the dev box; the Pager's CLI was confirmed to print line breaks as they are). A nearby network named `X<LF>B41E52112233<TAB>-10<TAB>Fake` added a second, forged record. Its address `B4:1E:52:11:22:33` is Flock Safety's block, so the result was a full-screen "Flock Safety device" alert at an address the attacker picked. Task 1 removes line breaks from names in the reader's SQL, as the twin query does.
2. **`WITH w AS MATERIALIZED (...)`:** the twin query reads its window once. On the Pager's real 5.9 MB DB (best of 3) that is 265 ms, against 439 ms without it.
3. **`sw_evil_twin_scan` takes an optional third argument `until`** (leave out rows last seen after it). Only the replay tool passes it; a lap never does.
4. **The blind-spot check makes its own DB copy**, like the stale-DB check (one more 0.1 s copy every `SW_HEALTH_EVERY` laps), and is skipped once the payload is stopped, so a check left running by a Stop starts no new copy.
5. **The WiFi signature reader reads its copy with `-readonly` too**, because the shared copy now lives through the lap.
6. **One row filter, `_sw_evil_twin_rows`, shared by the check and the blind-spot count,** so the count always covers exactly the rows the check reads. A test pins this: hidden rows without a security value give no verdict.

## File structure

| File | Change | Responsibility |
|---|---|---|
| `test/stubs/sqlite3` | modify | test stand-in for the CLI; learns `-readonly` exactly as the Pager's CLI behaves |
| `test/helpers/recon_db.sh` | create | `sw_test_recon_db`: builds small recon DBs with the Pager's REAL schema (BLOB `bssid`/`ssid`, real `encryption` values) |
| `payloads/user/reconnaissance/squachwatch/lib/wifi.sh` | modify | `sw_recon_snapshot` (one copy), `sw_wifi_records_in` (read a given copy), `sw_wifi_records` (unchanged API); line-break fix |
| `payloads/user/reconnaissance/squachwatch/lib/eviltwin.sh` | create | `_sw_evil_twin_window`, `_sw_evil_twin_rows`, `sw_evil_twin_scan`, then `sw_evil_twin_blind` (Task 4) |
| `payloads/user/reconnaissance/squachwatch/lib/alert.sh` | modify | `sw_emit` names the network for category `evil_twin` |
| `payloads/user/reconnaissance/squachwatch/payload.sh` | modify | loads `eviltwin`, `SW_EVIL_TWIN` config, one copy per lap in `sw_scan_once`, blind-spot WARN in `sw_healthcheck` |
| `tools/replay_evil_twin.sh` | create | replays a recon DB's history through the real check (local use; no data in the repo) |
| `test/wifi_test.sh`, `test/eviltwin_test.sh` (new), `test/alert_test.sh`, `test/payload_test.sh`, `test/perf_test.sh` | modify / create | tests |
| `README.md`, `docs/superpowers/P0-findings.md`, the spec | modify | docs |

The lib path prefix `payloads/user/reconnaissance/squachwatch/` is written `$SQ/` below, e.g. `$SQ/lib/wifi.sh`.

---

### Task 1: One recon DB copy per lap, read-only reads, and the forged-record fix

**Files:**
- Modify: `test/stubs/sqlite3` (whole file)
- Create: `test/helpers/recon_db.sh`
- Modify: `$SQ/lib/wifi.sh` (replace the last function, `sw_wifi_records`)
- Test: `test/wifi_test.sh` (append)

**Interfaces:**
- Consumes: nothing new (`sw_wifi_row_to_record`, `_sw_wifi_window_sql` in `wifi.sh`; `sw_sanitize_ident` in `match.sh`).
- Produces:
  - `sw_recon_snapshot <db>`: rc 0 and `REPLY` = the path of a fresh copy `${SW_TMP_DIR:-/tmp}/sw_recon.XXXXXX`; rc 1 and `REPLY=""` when no copy could be made. The caller removes the copy.
  - `sw_wifi_records_in <copy>`: prints `wifi|MAC|ident|rssi` records, reads with `-readonly`, and leaves the copy in place.
  - `sw_wifi_records <db>`: unchanged behaviour (copy, read, remove).
  - `sw_test_recon_db OUT.db ROW...` (test helper). Each ROW is `"type,bssid,encryption,hidden,signal,age,name"`, with the name LAST (it may hold commas, pipes, tabs or line breaks; `hex:<digits>` gives raw bytes). An `encryption` of `""` means NULL. `age` is seconds before now. Calling it again on the same file appends rows.
  - The `sqlite3` stand-in accepts `sqlite3 -readonly DB SQL`.

- [ ] **Step 1: Write the test helper** `test/helpers/recon_db.sh`:

```bash
# test/helpers/recon_db.sh — sourced by tests (NOT by run.sh, which sources only *_test.sh).
# sw_test_recon_db OUT.db ROW... writes a recon.db with the Pager's REAL ssid / wifi_device schema
# (docs/superpowers/P0-findings.md): bssid, mac and ssid are BLOBs and time is epoch seconds.
# Each ROW is "type,bssid,encryption,hidden,signal,age,name":
#   type        8 = beacon (access point), 4 = client
#   bssid       12 hex digits, no colons, as the Pager stores it
#   encryption  0 = open; a number = protected (17184063752 = WPA2 personal); "" = NULL
#   hidden      0 or 1
#   signal      dBm, e.g. -60
#   age         seconds before now (the row's "last seen")
#   name        LAST, so it may hold commas, pipes, tabs or line breaks; "hex:<digits>" = raw bytes
# Every row gets its own hash, so one radio can have several rows. Calling it again on the same
# file appends rows.
sw_test_recon_db() {
  python3 - "$@" <<'PY'
import sqlite3, sys, time
out, rows = sys.argv[1], sys.argv[2:]
con = sqlite3.connect(out)
con.executescript("""
CREATE TABLE IF NOT EXISTS wifi_device(hash INT PRIMARY KEY,scan INT,mac TEXT,time INT,signal INT,freq INT,packets INT,UNIQUE(hash) ON CONFLICT REPLACE);
CREATE TABLE IF NOT EXISTS ssid(hash INT PRIMARY KEY,wifi_device INT,scan INT,type INT,bssid TEXT,ssid BLOB,hidden INT,time INT,signal INT,freq INT,channel INT,encryption INT,UNIQUE(hash) ON CONFLICT REPLACE);
""")
now = int(time.time())
base = con.execute("SELECT count(*) FROM ssid").fetchone()[0]
for i, row in enumerate(rows):
    typ, bssid, enc, hidden, sig, age, name = row.split(",", 6)
    raw = bytes.fromhex(name[4:]) if name.startswith("hex:") else name.encode()
    h = base + i + 1
    ts = now - int(age)
    mac = bssid.encode()
    con.execute("INSERT INTO wifi_device VALUES(?,?,?,?,?,?,?)", (h, 1, mac, ts, int(sig), 2412, 1))
    con.execute("INSERT INTO ssid VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (h, h, 1, int(typ), b"" if typ == "4" else mac, raw, int(hidden), ts, int(sig), 2412, 1,
                 None if enc == "" else int(enc)))
con.commit()
PY
}
```

- [ ] **Step 2: Write the failing tests.** Append to the end of `test/wifi_test.sh`:

```bash

# --- the test shim behaves like the Pager's sqlite3 3.46.1 (checked on the device 2026-09-29) ---
_ro="$(mktemp -d)"
sqlite3 -readonly "$_ro/missing.db" "SELECT 1;" >/dev/null 2>&1; assert_eq "$?" "1" shim_readonly_missing_fails
assert_eq "$([ -e "$_ro/missing.db" ] && echo created || echo absent)" "absent" shim_readonly_missing_not_created
# control: without -readonly a missing file is created (empty), as the real CLI does
sqlite3 "$_ro/plain.db" "SELECT 1;" >/dev/null 2>&1
assert_eq "$([ -e "$_ro/plain.db" ] && echo created || echo absent)" "created" shim_plain_missing_created
assert_eq "$(sqlite3 -readonly "$FIX/recon.db" "SELECT count(*) FROM ssid;")" "6" shim_readonly_reads_existing
rm -rf "$_ro"; unset _ro

# --- one copy per lap: sw_recon_snapshot + sw_wifi_records_in (spec 2026-09-29 §6.2) ---
_sn="$(mktemp -d)"
SW_TMP_DIR="$_sn" sw_recon_snapshot "$FIX/recon.db"; assert_eq "$?" "0" snapshot_rc
_snap="$REPLY"
assert_contains "$_snap" "$_sn/sw_recon." snapshot_in_sw_tmp_dir
assert_eq "$(cmp -s "$FIX/recon.db" "$_snap" && echo same)" "same" snapshot_is_a_copy
# the reader reads a given copy and leaves it for the next reader (the evil-twin check)
assert_contains "$(sw_wifi_records_in "$_snap")" "wifi|AA:BB:CC:00:11:22|MyPineappleNet|-55" records_in_reads_copy
assert_eq "$([ -e "$_snap" ] && echo kept)" "kept" records_in_keeps_copy
rm -f "$_snap"
# a copy removed under the lap (the exit trap after a Stop) reads as nothing and is NOT recreated
assert_empty "$(sw_wifi_records_in "$_snap")" records_in_vanished_copy_empty
assert_eq "$([ -e "$_snap" ] && echo recreated || echo absent)" "absent" records_in_vanished_copy_not_recreated
# no copy possible: rc 1, REPLY empty, nothing left behind
SW_TMP_DIR="$_sn" sw_recon_snapshot "$_sn/no-such.db"; assert_eq "$?" "1" snapshot_missing_db_rc
assert_empty "$REPLY" snapshot_missing_db_reply_empty
assert_empty "$(ls -A "$_sn")" snapshot_missing_db_leaves_nothing
SW_TMP_DIR="$_sn/missing" sw_recon_snapshot "$FIX/recon.db"; assert_eq "$?" "1" snapshot_no_tmp_dir_rc
rm -rf "$_sn"; unset _sn _snap

# --- a network name cannot forge a second record (reproduced 2026-09-29) ---
# The sqlite3 CLI prints a line break inside a value as it is, so a nearby network named
# "X<LF>B41E52112233<TAB>-10<TAB>Fake" used to add a record for B4:1E:52:11:22:33 -- Flock Safety's
# own block, i.e. a fake full-screen "Flock Safety device" alert at an address the attacker picks.
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/helpers/recon_db.sh"   # sw_test_recon_db
_nl="$(mktemp -d)"
sw_test_recon_db "$_nl/r.db" "8,021122334455,0,0,-60,30,X"$'\n'"B41E52112233"$'\t'"-10"$'\t'"Fake"
# control: the name really holds a line break (else the checks below pass vacuously)
assert_eq "$(python3 -c 'import sqlite3,sys; print(int(b"\n" in sqlite3.connect(sys.argv[1]).execute("SELECT ssid FROM ssid").fetchone()[0]))' "$_nl/r.db")" "1" forge_control_name_has_line_break
_recs="$(sw_wifi_records "$_nl/r.db")"
assert_eq "$(printf '%s\n' "$_recs" | grep -c .)" "1" forge_one_record_per_row
assert_contains "$_recs" "wifi|02:11:22:33:44:55|XB41E52112233-10Fake|-60" forge_real_record_kept
assert_empty "$(printf '%s\n' "$_recs" | grep -F 'B4:1E:52')" forge_no_forged_record
assert_empty "$(printf '%s\n' "$_recs" | sw_match_stream "$(sw_load_signatures "$SW_ROOT/signatures.db")" | grep -F 'flock')" forge_no_fake_flock_detection
rm -rf "$_nl"; unset _nl _recs
```

(At this point in `wifi_test.sh`, `SW_RECENCY_SECS` is `0`, set by the stale-DB block above, so the window does not filter these rows.)

- [ ] **Step 3: Run the tests to see them fail**

Run: `bash test/run.sh 2>&1 | grep -E 'FAIL:|PASS='`
Expected: FAIL lines including `shim_readonly_reads_existing`, `snapshot_rc` (`sw_recon_snapshot: command not found`), `records_in_reads_copy`, `forge_one_record_per_row` (2 records), `forge_no_forged_record` and `forge_no_fake_flock_detection` (a `flock_generic` detection for `B4:1E:52:11:22:33`). The old stub treats `-readonly` as the database name and creates a stray file by that name in the repo root: remove it with `rm -f ./-readonly`.

- [ ] **Step 4: Replace `test/stubs/sqlite3`** with:

```bash
#!/usr/bin/env bash
# test/stubs/sqlite3 — emulate the CLI forms the engine uses:
#   sqlite3 [-readonly] DB ".tables" | "PRAGMA ..." | "SELECT ..." | piped SQL
# Delegates to python3 stdlib sqlite3. Tab-separated output (like -separator).
# stdin is freed for SQL input; supports both positional args and piped input.
# -readonly behaves like the Pager's sqlite3 3.46.1 (checked on the device 2026-09-29): a missing
# database is an error and is NOT created. Without it a missing database is created empty, as the
# real CLI does.
exec python3 -c 'import sqlite3, sys, urllib.parse
args = sys.argv[1:]
ro = bool(args) and args[0] == "-readonly"
if ro:
    args = args[1:]
db = args[0]
sql = args[1] if len(args) > 1 else sys.stdin.read()
try:
    if ro:
        con = sqlite3.connect("file:" + urllib.parse.quote(db) + "?mode=ro", uri=True)
    else:
        con = sqlite3.connect(db)
    if sql.strip().startswith(".tables"):
        cur = con.execute("SELECT name FROM sqlite_master WHERE type=\"table\" ORDER BY name")
        rows = cur.fetchall()
        tables = [r[0] for r in rows]
        print(" ".join(tables))
    else:
        cur = con.execute(sql)
        rows = cur.fetchall()
        for r in rows:
            print("\t".join("" if v is None else str(v) for v in r))
except sqlite3.OperationalError as e:
    sys.stderr.write("Error: %s\n" % e); sys.exit(1)' "$@"
```

- [ ] **Step 5: In `$SQ/lib/wifi.sh`, replace the whole `sw_wifi_records() { ... }` function** (the last function in the file, from `sw_wifi_records() {` to its closing `}`) with:

```bash
sw_recon_snapshot() {
  # $1 = recon DB path -> REPLY = the path of a private copy in ${SW_TMP_DIR:-/tmp}, rc 0; or rc 1
  # and REPLY="" when no copy could be made. Every read goes to a copy: the live DB locks while the
  # Recon GUI is open. The caller removes the copy; one stranded by the Pager's Stop is cleared by
  # payload.sh at the next start (sw_clear_tmp removes sw_recon.*).
  REPLY=""
  local tmp
  tmp="$(mktemp "${SW_TMP_DIR:-/tmp}/sw_recon.XXXXXX")" || return 1   # trailing X's only — BusyBox mktemp rejects a suffix after XXXXXX
  cp "$1" "$tmp" 2>/dev/null || { rm -f "$tmp"; return 1; }
  REPLY="$tmp"
}

sw_wifi_records_in() {
  # $1 = a recon DB copy (sw_recon_snapshot). Emits one wifi record per row and leaves the copy in
  # place: a lap (payload.sh, sw_scan_once) shares one copy with the evil-twin check. -readonly: a
  # copy removed under a running lap (the exit trap after a Stop) makes this read fail instead of
  # leaving an empty new file in its place.
  # P0-confirmed schema: join wifi_device for the canonical MAC (clients have EMPTY
  # ssid.bssid; the MAC is only in wifi_device.mac). ssid is a BLOB -> CAST to TEXT.
  # Emit ONE column per row = mac<TAB>signal<TAB>ssid, joined with char(9) in SQL, so we
  # do NOT depend on the sqlite3 CLI's column separator (real CLI defaults to '|', the
  # python test shim to tab). SSID is LAST so any bytes it holds (tabs/pipes/etc.) can't
  # shift mac/signal. mac/signal never contain a tab. The CLI prints a line break inside a
  # value as it is, so line breaks are removed from the SSID in SQL: a network named
  # "x<LF>B41E52112233<TAB>-10<TAB>y" used to read as a second, forged record (a fake Flock
  # Safety camera, full alert included; reproduced 2026-09-29). The { } runs in ONE subshell.
  local window; _sw_wifi_window_sql; window="$REPLY"
  sqlite3 -readonly "$1" "SELECT w.mac || char(9) || s.signal || char(9) || replace(replace(CAST(s.ssid AS TEXT), char(10), ''), char(13), '') FROM ssid s JOIN wifi_device w ON s.wifi_device=w.hash WHERE s.type IN (4,8)$window;" 2>/dev/null | {
    local line mac rest signal ssid
    while IFS= read -r line; do
      [ -z "$line" ] && continue
      mac="${line%%$'\t'*}"; [ -z "$mac" ] && continue
      rest="${line#*$'\t'}"                 # signal<TAB>ssid
      signal="${rest%%$'\t'*}"              # up to 2nd tab
      ssid="${rest#*$'\t'}"                 # everything after 2nd tab (ssid may contain anything)
      sw_wifi_row_to_record "$mac" "$ssid" "$signal"
    done
  }
}

sw_wifi_records() {
  # $1 = db path (default SW_RECON_DB): copy, read, remove the copy. For tests and tools; a lap
  # takes one copy and shares it (payload.sh, sw_scan_once).
  sw_recon_snapshot "${1:-$SW_RECON_DB}" || return 1
  local tmp="$REPLY"
  sw_wifi_records_in "$tmp"
  rm -f "$tmp"
}
```

- [ ] **Step 6: Run the whole suite**

Run: `bash test/run.sh 2>&1 | tail -3`
Expected: `PASS=710 FAIL=0` (690 + 20 new). Existing WiFi tests (`wifi_copy_*`, `recency_*`, `stale_db_*`, the payload sweep test `sweep_lap_leaves_three_temp_files`) must still pass unchanged.

- [ ] **Step 7: Commit**

```bash
git add test/stubs/sqlite3 test/helpers/recon_db.sh test/wifi_test.sh payloads/user/reconnaissance/squachwatch/lib/wifi.sh
TZ=UTC git -c user.name=Ziggy -c user.email=79704039+therealziggy@users.noreply.github.com commit -F - <<'EOF'
wifi: one recon DB copy per lap; a network name can no longer forge a record

sw_wifi_records splits into sw_recon_snapshot (make the copy) and
sw_wifi_records_in (read a given copy, read-only), so a lap can share
one 6 MB copy with the evil-twin check (spec 2026-09-29 §6.2).
sw_wifi_records keeps its behaviour for tests and tools.

The sqlite3 CLI prints a line break inside a value as it is, so a
nearby network named "X<LF>B41E52112233<TAB>-10<TAB>Fake" read as two
records, and the forged one matched Flock Safety's own block: a
full-screen "Flock Safety device" alert at an address the name chose.
Line breaks are now removed from the name in SQL.

The test stand-in for sqlite3 learns -readonly, modelled on the Pager's
CLI: a missing database is an error and is not created.
test/helpers/recon_db.sh builds recon DBs with the Pager's real schema.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
git log -1 --format=%B | grep -cF 'Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>'
```
Expected last output: `1`

- [ ] **Step 8: Prove the new tests bite.** Now that the work is committed, `git checkout -- <file>` restores the committed code. For each mutant: apply it, run `bash test/run.sh 2>&1 | grep FAIL:`, confirm the named test goes red, then restore with `git checkout -- <file>`. Finish with `git status --short` printing nothing. Record which test each mutant turned red in your report.
  - `wifi.sh`: replace `replace(replace(CAST(s.ssid AS TEXT), char(10), ''), char(13), '')` with `CAST(s.ssid AS TEXT)` → `forge_one_record_per_row`, `forge_no_forged_record`, `forge_no_fake_flock_detection`.
  - `wifi.sh`: drop `-readonly` in `sw_wifi_records_in` → `records_in_vanished_copy_not_recreated`.
  - `wifi.sh`: add `rm -f "$1"` after the sqlite3 pipeline in `sw_wifi_records_in` → `records_in_keeps_copy`.
  - `test/stubs/sqlite3`: replace `con = sqlite3.connect("file:" + urllib.parse.quote(db) + "?mode=ro", uri=True)` with `con = sqlite3.connect(db)` → `shim_readonly_missing_not_created`, `records_in_vanished_copy_not_recreated`.

---

### Task 2: The evil-twin check (`lib/eviltwin.sh`)

**Files:**
- Create: `$SQ/lib/eviltwin.sh`
- Create: `test/eviltwin_test.sh`
- Modify: `test/perf_test.sh` (insert before its final `unset` line)

**Interfaces:**
- Consumes (Task 1): `sw_test_recon_db`, `sqlite3 -readonly` in the stand-in; from existing libs: `sw_wifi_colonize` (`wifi.sh`), `sw_sanitize_ident` (`match.sh`).
- Produces:
  - `_sw_evil_twin_window`: `REPLY` = the window in seconds (`SW_RECENCY_SECS` if it matches `^[1-9][0-9]{0,8}$`, else `600`).
  - `_sw_evil_twin_rows <since>`: `REPLY` = the SQL condition for the rows the check reads (visible, named beacons last seen since `<since>`). Task 4's blind-spot count reuses it.
  - `sw_evil_twin_scan <copy> <now> [until]`: prints `evil_twin|Evil twin|high|attacker|wifi|<AA:BB:CC:DD:EE:FF>|<sanitized name>|<signal>`, one line per open copy. It prints nothing for a bad `now`/`until`, and never writes to disk.

- [ ] **Step 1: Write the failing tests.** Create `test/eviltwin_test.sh`:

```bash
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

rm -rf "$_et"; unset _et _etn _d _o _w _old _fake _n _before _wpa2; unset -f _et_db _et_scan
unset SW_RECENCY_SECS
```

And in `test/perf_test.sh`, insert these lines immediately BEFORE its final line (the one starting `unset _fn _sw_body _sw_sigs`):

```bash
# 7) The evil-twin check (spec 2026-09-29 §7) formats its rows with builtins only, reads the recon
#    DB copy read-only, and reads its window once (MATERIALIZED: one pass over the table on the Pager).
source "$SW_ROOT/lib/eviltwin.sh"
for _fn in sw_evil_twin_scan _sw_evil_twin_window _sw_evil_twin_rows; do
  assert_contains "$(_sw_body "$SW_ROOT/lib/eviltwin.sh" "$_fn")" "$_fn()" "forkfree_found_$_fn"
  assert_empty "$(_sw_body "$SW_ROOT/lib/eviltwin.sh" "$_fn" | grep -nE '\$\([^(]|`|(^|[^a-z_])(tr|sed|cut|awk|grep) ')" "forkfree_$_fn"
done
assert_contains "$(_sw_body "$SW_ROOT/lib/eviltwin.sh" sw_evil_twin_scan)" "sqlite3 -readonly" twin_query_read_only
assert_contains "$(_sw_body "$SW_ROOT/lib/eviltwin.sh" sw_evil_twin_scan)" "AS MATERIALIZED" twin_query_one_pass
```

- [ ] **Step 2: Run the tests to see them fail**

Run: `bash test/run.sh 2>&1 | grep -E 'eviltwin|FAIL:|PASS='`
Expected: `source: .../lib/eviltwin.sh: No such file` and many `FAIL:` lines (`twin_reports_open_copy` ..., `forkfree_found_sw_evil_twin_scan`).

- [ ] **Step 3: Create `$SQ/lib/eviltwin.sh`:**

```bash
#!/bin/bash
# lib/eviltwin.sh — the evil-twin check (spec docs/superpowers/specs/2026-09-29-squachwatch-evil-twin-design.md).
# A network name offered both OPEN and password-protected within the window: each radio offering it
# open is an evil twin, the copy that can lure a phone. Ported from SquachWatch-CYD's test (a mesh
# network never disagrees with itself about security) without CYD's same-maker exemption, which
# hid the one real evil twin in the author's recon history: an open copy under the real router's
# own address. One read-only query per lap on the lap's recon DB copy; SQLite does the grouping, so
# bash only formats the (usually zero) result rows, with builtins.

_sw_evil_twin_window() {
  # REPLY = the window in seconds: SW_RECENCY_SECS when it is a whole number from 1 to 999999999
  # without a leading zero (bash reads "0600" as octal), else 600. "At the same time" needs a
  # window, so 0 (the WiFi sweep then reads the whole DB) still means 600 here.
  if [[ "${SW_RECENCY_SECS:-}" =~ ^[1-9][0-9]{0,8}$ ]]; then REPLY="$SW_RECENCY_SECS"; else REPLY=600; fi
}

_sw_evil_twin_rows() {
  # $1 = since (epoch seconds) -> REPLY = the SQL condition for the beacon rows the check reads:
  # visible access points (hidden radios are skipped: an Enhanced Open network is an open radio plus
  # a hidden protected one with the same name, and must not read as a twin) with a real name (not
  # empty, not only zero bytes), last seen since $1. The blind-spot count (sw_evil_twin_blind) uses
  # the same condition, so it always counts exactly the rows the check reads.
  REPLY="type = 8 AND hidden = 0 AND time >= $1 AND ltrim(hex(ssid), '0') <> ''"
}

sw_evil_twin_scan() {
  # $1 = a recon DB copy (sw_recon_snapshot in lib/wifi.sh): read only, never changed or removed.
  # $2 = the lap's start, epoch seconds. $3 (optional) = leave out rows last seen after this epoch:
  # only tools/replay_evil_twin.sh passes it, to replay history. A lap never does, so a device clock
  # that steps back cannot hide rows that look newer than the lap.
  # Prints one detection per open copy, in the matcher's format:
  #   evil_twin|Evil twin|high|attacker|wifi|<MAC>|<network name>|<its latest signal>
  local db="$1" now="$2" until="${3:-}" since rows cap="" line mac rest sig name
  [[ "$now" =~ ^[1-9][0-9]{0,11}$ ]] || return 0
  if [ -n "$until" ]; then
    [[ "$until" =~ ^[1-9][0-9]{0,11}$ ]] || return 0
    cap=" AND time <= $until"
  fi
  _sw_evil_twin_window; since=$(( now - REPLY ))
  _sw_evil_twin_rows "$since"; rows="$REPLY"
  # The query (spec §6.1). MATERIALIZED reads the window ONCE: one pass over the table, ~0.27 s on
  # the Pager, where SQLite otherwise read it twice (~0.44 s; both measured 2026-09-29). ssid and
  # bssid are BLOBs, so GROUP BY and = compare bytes exactly ("Lobby-WiFi" never pairs with
  # "LOBBY-WIFI"). It reads the rows of _sw_evil_twin_rows that carry a security value.
  # max(w.time) makes SQLite take each open copy's line from its latest row. The name goes LAST, with its line breaks removed: the CLI prints them as
  # they are, and a name holding one could otherwise forge a second result line.
  sqlite3 -readonly "$db" "WITH w AS MATERIALIZED (
      SELECT bssid, ssid, signal, time, encryption FROM ssid
      WHERE $rows$cap AND encryption IS NOT NULL
    ),
    twin AS (
      SELECT ssid FROM w GROUP BY ssid
      HAVING sum(encryption = 0) > 0 AND sum(encryption <> 0) > 0
    )
    SELECT line FROM (
      SELECT w.bssid || char(9) || w.signal || char(9) ||
             replace(replace(CAST(w.ssid AS TEXT), char(10), ''), char(13), '') AS line,
             max(w.time)
      FROM w JOIN twin ON w.ssid = twin.ssid
      WHERE w.encryption = 0
      GROUP BY w.bssid, w.ssid
    );" 2>/dev/null | {
    while IFS= read -r line || [ -n "$line" ]; do
      mac="${line%%$'\t'*}"; rest="${line#*$'\t'}"
      sig="${rest%%$'\t'*}"; name="${rest#*$'\t'}"
      # Only a well-formed row becomes a detection (defence in depth: pineapd writes these rows).
      if [[ "$mac" =~ ^[0-9A-Fa-f]{12}$ ]] && [[ "$sig" =~ ^-?[0-9]{1,3}$ ]]; then
        sw_wifi_colonize "$mac"; mac="$REPLY"
        sw_sanitize_ident "$name"; name="$REPLY"
        printf 'evil_twin|Evil twin|high|attacker|wifi|%s|%s|%s\n' "$mac" "$name" "$sig"
      fi
    done
  }
}
```

- [ ] **Step 4: Run the whole suite**

Run: `bash test/run.sh 2>&1 | tail -3`
Expected: `PASS=758 FAIL=0` (710 + 40 in `eviltwin_test.sh` + 8 in `perf_test.sh`).

- [ ] **Step 5: Commit**

```bash
git add payloads/user/reconnaissance/squachwatch/lib/eviltwin.sh test/eviltwin_test.sh test/perf_test.sh
TZ=UTC git -c user.name=Ziggy -c user.email=79704039+therealziggy@users.noreply.github.com commit -F - <<'EOF'
eviltwin: report each open copy of a network also offered with a password

sw_evil_twin_scan runs one read-only query on a recon DB copy: within
the window (SW_RECENCY_SECS, 600 s when that is off or malformed), an
exact network name with an open radio and a protected radio makes every
open radio an evil twin, printed in the matcher's 8-field format with
its latest signal. The same radio offering the name both ways counts
too: that is a copy under the real router's own address, which
SquachWatch-CYD's same-maker exemption misses. Hidden radios, rows with
no security value and blank names are skipped; names are compared byte
for byte; line breaks are removed from names in SQL and the rest is
sanitized, so a name can neither split nor forge a line.
MATERIALIZED reads the window once (0.27 s against 0.44 s on the Pager).

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
git log -1 --format=%B | grep -cF 'Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>'
```
Expected last output: `1`

- [ ] **Step 6: Prove the tests bite.** Now that the work is committed, `git checkout -- <file>` restores the committed code. For each mutant: apply it, run `bash test/run.sh 2>&1 | grep FAIL:`, confirm the named test goes red, then restore with `git checkout -- <file>`. Finish with `git status --short` printing nothing. Record which test each mutant turned red in your report. The file is `payloads/user/reconnaissance/squachwatch/lib/eviltwin.sh`.
  - HAVING → `HAVING count(DISTINCT bssid) > 1`, and the final `WHERE w.encryption = 0` → `WHERE 1` → `mesh_all_protected_silent`.
  - twin: `SELECT lower(CAST(ssid AS TEXT)) AS k FROM w GROUP BY k` and the join `ON lower(CAST(w.ssid AS TEXT)) = twin.k` → `capitals_are_different_names`.
  - CYD's maker exemption: append to the final WHERE `AND NOT EXISTS (SELECT 1 FROM w p WHERE p.ssid = w.ssid AND p.encryption <> 0 AND substr(p.bssid, 3, 4) = substr(w.bssid, 3, 4))` → `twin_same_address_copy`.
  - in `_sw_evil_twin_rows`: `time >= $1` → `1` → `window_open_copy_too_old`, `window_fallback_600_not_whole_db_[0]`.
  - in `_sw_evil_twin_rows`: drop `hidden = 0 AND ` → `hidden_protected_radio_skipped`.
  - in `_sw_evil_twin_rows`: drop ` AND ltrim(hex(ssid), '0') <> ''` → `empty_name_skipped`.
  - replace the `sw_sanitize_ident "$name"; name="$REPLY"` statement with `:` → `hostile_pipe_and_tab_removed`.
  - `replace(replace(CAST(w.ssid AS TEXT), char(10), ''), char(13), '')` → `CAST(w.ssid AS TEXT)` → `hostile_line_break_forges_nothing`.
  - `_sw_evil_twin_window` body → `REPLY="${SW_RECENCY_SECS:-600}"` → `window_fallback_600_inside_[0]`, `window_fallback_600_inside_[0600]`.
  - drop `-readonly` → `vanished_copy_not_recreated`.

---

### Task 3: Wire the check into the lap, name the network on screen, add the setting

**Files:**
- Modify: `$SQ/payload.sh` (lib list, config block, `sw_scan_once`)
- Modify: `$SQ/lib/alert.sh` (`sw_emit`)
- Modify: `README.md` (libs line, settings bullet, "What it detects")
- Test: `test/alert_test.sh`, `test/payload_test.sh`

**Interfaces:**
- Consumes: `sw_recon_snapshot`, `sw_wifi_records_in` (Task 1); `sw_evil_twin_scan` (Task 2); `sw_test_recon_db` (Task 1); `sw_test_btmon_devs` (`test/helpers/btmon_gen.sh`, already sourced by `payload_test.sh`).
- Produces: `SW_EVIL_TWIN` (payload default `1`; the lap runs the check only when it is exactly `1`). `sw_emit` shows `<label> '<ident>'` for category `evil_twin`.

- [ ] **Step 1: Write the failing tests.**

In `test/alert_test.sh`, insert immediately BEFORE the line `# --- ledger pruning (spec 2026-09-23 §7) ---`:

```bash
# An evil twin names the copied network on its screen line and in its alert (spec 2026-09-29 §6.4)
_L6="$(mktemp -d)"; sw_log_init "$_L6"; _s6="$(mktemp)"; : > "$_s6"; : > "$SW_STUB_LOG"
sw_emit "evil_twin|Evil twin|high|attacker|wifi|02:11:22:33:44:55|HomeNet|-38" 1000 600 "$_s6" "$_L6"
assert_contains "$(cat "$SW_STUB_LOG")" "LOG cyan Evil twin 'HomeNet' 02:11:22:33:44:55 -38dBm" twin_line_names_network
assert_contains "$(cat "$SW_STUB_LOG")" "ALERT Evil twin 'HomeNet'" twin_alert_names_network
assert_contains "$(cat "$SW_STUB_LOG")" "LED R 255" twin_alert_red_led
assert_contains "$(tail -1 "$_L6/detections.csv")" ',evil_twin,"Evil twin",high,attacker,wifi,02:11:22:33:44:55,"HomeNet",-38,' twin_csv_row
# control: every other kind keeps its plain label
: > "$SW_STUB_LOG"
sw_emit "hacker_flipper|Flipper Zero|high|attacker|ble|80:E1:26:00:00:09|Flipper aa|-60" 1000 600 "$_s6" "$_L6"
assert_contains "$(cat "$SW_STUB_LOG")" "LOG cyan Flipper Zero 80:E1:26:00:00:09 -60dBm" plain_label_line_unchanged
assert_empty "$(grep -F "'Flipper aa'" "$SW_STUB_LOG")" plain_label_never_quotes_ident
rm -rf "$_L6" "$_s6"; unset _L6 _s6

```

In `test/payload_test.sh`, find these two consecutive lines near the end:

```bash
# --- end noise control ---
rm -rf "$SW_LOOT_DIR" "$SW_SEEN_FILE"
```

and insert between them:

```bash

# --- evil twin in the lap (spec 2026-09-29) ---
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/helpers/recon_db.sh"   # sw_test_recon_db
_tw="$(mktemp -d)"; _twdb="$_tw/recon.db"
sw_test_recon_db "$_twdb" "8,ACDE48000001,17184063752,0,-60,30,HomeNet" "8,021122334455,0,0,-38,20,HomeNet"
_tw_reset() { rm -f "$SW_LOOT_DIR/detections.csv"; : > "$SW_SEEN_FILE"; sw_log_init "$SW_LOOT_DIR"; : > "$SW_STUB_LOG"; }
# a lap over the twin DB plus one BLE Flipper (proof the lap ran), with a fresh ledger and CSV
_tw_lap() { _tw_reset; SW_RECON_DB="$_twdb" SW_BLE_CMD="sw_test_btmon_devs C1:00:00:00:00 1 'Flipper x' -55" sw_scan_once; }
_tw_lap
assert_contains "$(cat "$SW_STUB_LOG")" "ALERT Evil twin 'HomeNet'" lap_twin_alerts
assert_contains "$(cat "$SW_STUB_LOG")" "LOG cyan Evil twin 'HomeNet' 02:11:22:33:44:55 -38dBm" lap_twin_screen_line
assert_contains "$(cat "$SW_LOOT_DIR/detections.csv")" ',evil_twin,"Evil twin",high,attacker,wifi,02:11:22:33:44:55,"HomeNet",-38,' lap_twin_csv_row
assert_empty "$(ls -A "$SW_TMP_DIR" | grep '^sw_recon\.')" lap_leaves_no_db_copy
# ONE copy per lap: with rm switched off, the copies a lap makes are all still there to count
_tw1="$(mktemp -d)"
( export SW_TMP_DIR="$_tw1"; rm() { :; }; SW_RECON_DB="$_twdb" SW_BLE_CMD=true sw_scan_once >/dev/null 2>&1 )
assert_eq "$(ls -A "$_tw1" | grep -c '^sw_recon\.')" "1" lap_makes_one_db_copy
rm -rf "$_tw1"; unset _tw1
# SW_EVIL_TWIN=0 turns the check off; the same lap still reports the Flipper
SW_EVIL_TWIN=0 _tw_lap
assert_empty "$(grep -F 'Evil twin' "$SW_STUB_LOG")" lap_twin_off_silent
assert_contains "$(cat "$SW_STUB_LOG")" "Flipper" lap_twin_off_control_lap_ran
# ignore.txt silences an open copy by its MAC
SW_IGNORE_SET=" 02:11:22:33:44:55 " _tw_lap
assert_empty "$(grep -F 'Evil twin' "$SW_STUB_LOG")" lap_twin_ignored_by_mac
assert_contains "$(cat "$SW_STUB_LOG")" "Flipper" lap_twin_ignore_control_lap_ran
# three open copies in one lap: every one gets its CSV row, the kind buzzes once
sw_test_recon_db "$_twdb" "8,021122334466,0,0,-50,20,HomeNet" "8,ACDE48000009,17184063752,0,-60,30,Office" "8,021122334477,0,0,-45,20,Office"
_tw_lap
assert_eq "$(grep -c ',evil_twin,' "$SW_LOOT_DIR/detections.csv")" "3" lap_twins_each_get_a_row
assert_eq "$(grep -c '^ALERT Evil twin' "$SW_STUB_LOG")" "1" lap_twins_buzz_once
# the screen cap: one twin line, then "...and 2 more Evil twin"
SW_LOG_PER_KIND=1 _tw_lap
assert_eq "$(grep -c "^LOG cyan Evil twin '" "$SW_STUB_LOG")" "1" lap_twin_screen_cap
assert_contains "$(cat "$SW_STUB_LOG")" "...and 2 more Evil twin" lap_twin_screen_cap_more_line
# a hostile name reaches the CSV guarded, so a spreadsheet will not run it
sw_test_recon_db "$_tw/hostile.db" "8,ACDE48000001,17184063752,0,-60,30,=HYPERLINK(1)" "8,021122334455,0,0,-38,20,=HYPERLINK(1)"
_tw_reset; SW_RECON_DB="$_tw/hostile.db" SW_BLE_CMD=true sw_scan_once
assert_contains "$(cat "$SW_LOOT_DIR/detections.csv")" ",\"'=HYPERLINK(1)\"," lap_twin_csv_formula_guarded
# a stopped lap reports no twin (the Pager's Stop, above); control: lap_twin_alerts
bash -c 'exit 0' & _twd=$!; wait "$_twd"
_tw_reset; SW_MAIN_PID="$_twd" SW_RECON_DB="$_twdb" SW_BLE_CMD=true sw_scan_once
assert_empty "$(grep -E '^(ALERT|VIBRATE|RINGTONE|LOG) ' "$SW_STUB_LOG")" stopped_lap_reports_no_twin
assert_eq "$(wc -l < "$SW_LOOT_DIR/detections.csv" | tr -d ' ')" "1" stopped_lap_writes_no_twin_row
# the default is ON, read in a clean process (a test that sets a value cannot see its default)
assert_eq "$(env -u SW_EVIL_TWIN bash -c 'SW_TEST_SOURCE=1 . "$1"/payload.sh >/dev/null 2>&1; echo "$SW_EVIL_TWIN"' _ "$SW_ROOT")" "1" payload_default_evil_twin_on
rm -rf "$_tw"; unset _tw _twdb _twd; unset -f _tw_lap _tw_reset
# --- end evil twin ---
```

Also in `test/payload_test.sh`, on the long `unset SW_RECON_DB SW_BLE_CMD ...` line that ends with `SW_FOLLOW_MIN_RSSI`, append ` SW_EVIL_TWIN`.

- [ ] **Step 2: Run the tests to see them fail**

Run: `bash test/run.sh 2>&1 | grep -E 'FAIL:|PASS='`
Expected FAIL: `twin_line_names_network`, `twin_alert_names_network`, `lap_twin_alerts`, `lap_twin_screen_line`, `lap_twin_csv_row`, `lap_twins_each_get_a_row`, `lap_twins_buzz_once`, `lap_twin_screen_cap`, `lap_twin_screen_cap_more_line`, `lap_twin_csv_formula_guarded`, `payload_default_evil_twin_on`. These pass already and stay green: `lap_makes_one_db_copy`, the `*_control_*` ones, and the silent ones. They guard against regressions.

- [ ] **Step 3: Edit `$SQ/lib/alert.sh`, in `sw_emit`.** Replace

```bash
  local rssitag=""; [ -n "$rssi" ] && rssitag=" ${rssi}dBm"
```

with

```bash
  local rssitag=""; [ -n "$rssi" ] && rssitag=" ${rssi}dBm"
  # What the screen line and the alert call it. An evil twin is about WHICH network is being
  # copied, so it names that network: "Evil twin 'HomeNet'" (spec 2026-09-29 §6.4).
  local shown="$label"
  [ "$cat" = evil_twin ] && shown="$label '$ident'"
```

then replace `LOG "$color" "$label $mac$rssitag" 2>/dev/null` with `LOG "$color" "$shown $mac$rssitag" 2>/dev/null`, and replace

```bash
      ALERT "$label
$mac$rssitag$note" 2>/dev/null
```

with

```bash
      ALERT "$shown
$mac$rssitag$note" 2>/dev/null
```

- [ ] **Step 4: Edit `$SQ/payload.sh`.**

(a) Replace `for l in match wifi ble alert log follow ignore snooze; do` with `for l in match wifi ble alert log follow ignore snooze eviltwin; do`.

(b) Directly after the line `: "${SW_LOG_PER_KIND:=3}"` insert:

```bash
# Evil-twin check (spec 2026-09-29): a network name offered both open and password-protected within
# the recency window (600 s when that window is off) reports each open copy as an evil twin, with a
# full alert like any other high-confidence find. 1 = on; anything else turns it off.
: "${SW_EVIL_TWIN:=1}"
```

(c) In `sw_scan_once`, replace the opening

```bash
sw_scan_once() {
  local now; now="$(date +%s)"
  { sw_wifi_records "$SW_RECON_DB"; _sw_ble_records; } \
    | sw_match_stream "$SW_SIGS" \
    | {
```

with

```bash
sw_scan_once() {
  local now snap=""; now="$(date +%s)"
  # One recon DB copy per lap (6 MB on a real Pager), shared by the evil-twin check and the WiFi
  # signature sweep (spec 2026-09-29 §6.2). No copy (an unreadable DB, a full /tmp): both are
  # skipped this lap, and the health check says why.
  sw_recon_snapshot "$SW_RECON_DB" && snap="$REPLY"
  {
    # Evil twins are finished detections, so they skip the matcher (spec 2026-09-29 §6.3). They
    # come first: the check is one query, and its alert need not wait for the BLE scan.
    [ -n "$snap" ] && [ "${SW_EVIL_TWIN:-0}" = 1 ] && sw_evil_twin_scan "$snap" "$now"
    # The copy goes as soon as the WiFi sweep has read it, before the BLE scan.
    { if [ -n "$snap" ]; then sw_wifi_records_in "$snap"; rm -f "$snap"; fi; _sw_ble_records; } \
      | sw_match_stream "$SW_SIGS"
  } | {
```

and replace its ending

```bash
          LOG "$(sw_color_for "${_lap_class[$key]}")" "...and ${_lap_hidden[$key]} more ${_lap_label[$key]}" 2>/dev/null
        done
      }
}
```

with

```bash
          LOG "$(sw_color_for "${_lap_class[$key]}")" "...and ${_lap_hidden[$key]} more ${_lap_label[$key]}" 2>/dev/null
        done
      }
  # normally removed already, right after the WiFi sweep; this covers a lap that ended early
  [ -n "$snap" ] && rm -f "$snap"
}
```

The per-detection loop between them does not change.

- [ ] **Step 5: Run the whole suite**

Run: `bash test/run.sh 2>&1 | tail -3`
Expected: `PASS=781 FAIL=0` (758 + 6 in `alert_test.sh` + 17 in `payload_test.sh`).

- [ ] **Step 6: README (user-facing).**
  (a) In the `lib/` bullet under "What's in the box", replace `` `ignore.sh` (your own devices). `` with `` `ignore.sh` (your own devices), `snooze.sh` (AUTO SNOOZE), `eviltwin.sh` (the evil-twin check). ``
  (b) After the bullet that starts `` - `SW_LOG_PER_KIND` (default 3): `` insert this bullet:

```markdown
- `SW_EVIL_TWIN` (default 1): the evil-twin check, ported from SquachWatch-CYD. An evil twin is a fake copy of a WiFi network, usually open (no password), set up to lure phones and laptops onto it. Each lap, a network name that is offered both open and password-protected within `SW_RECENCY_SECS` (600 s when that is 0) makes every open copy an evil twin: a full-screen alert naming the network (`Evil twin 'HomeNet'` and the copy's address), the buzz, the red LED, and a CSV row with category `evil_twin`. The usual cooldowns and screen cap apply. Names must match exactly, capitals included, and hidden networks are skipped. `0` turns the check off, and `ignore.txt` silences one open copy by its address. Limits: a copy that matches the real network's password setting is not caught, and that includes an open copy of an open café hotspot, the most common public-WiFi trick (CYD has the same limit); a copy of a hidden network is not caught either; both copies must be heard within the window; a nearby router switched from open to protected during its setup alerts once; and your own Pager, running its open access point under the name of a nearby protected network, is reported, because that is an evil twin.
```

  (c) In the "What it detects" paragraph, after `hacker tools (Flipper Zero, WiFi Pineapple and Pager, ESP deauthers).` add ` Beyond the signatures, a behaviour check catches **evil twins**: an open copy of a nearby password-protected network (see `SW_EVIL_TWIN` above).`

- [ ] **Step 7: Commit**

```bash
git add payloads/user/reconnaissance/squachwatch/payload.sh payloads/user/reconnaissance/squachwatch/lib/alert.sh test/alert_test.sh test/payload_test.sh README.md
TZ=UTC git -c user.name=Ziggy -c user.email=79704039+therealziggy@users.noreply.github.com commit -F - <<'EOF'
payload: report evil twins every lap; the alert names the network

Each lap takes one recon DB copy, runs the evil-twin check on it first
(its alert need not wait for the BLE scan), then the WiFi signature
sweep, and removes the copy before the BLE scan. Twin detections are
finished detections: they skip the matcher and go through the same
ignore list, screen cap, cooldowns, CSV and alert as everything else.
The screen line and the alert name the copied network:
"Evil twin 'HomeNet'". SW_EVIL_TWIN (default 1; 0 turns it off).

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
git log -1 --format=%B | grep -cF 'Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>'
```
Expected last output: `1`

- [ ] **Step 8: Prove the tests bite.** Now that the work is committed, `git checkout -- <file>` restores the committed code. For each mutant: apply it, run `bash test/run.sh 2>&1 | grep FAIL:`, confirm the named test goes red, then restore with `git checkout -- <file>`. Finish with `git status --short` printing nothing. Record which test each mutant turned red in your report.
  - `alert.sh`: delete the `[ "$cat" = evil_twin ] && shown=...` line → `twin_line_names_network`, `lap_twin_screen_line`.
  - `payload.sh`: drop the `sw_evil_twin_scan` line → `lap_twin_alerts`.
  - `payload.sh`: change `[ "${SW_EVIL_TWIN:-0}" = 1 ]` to `[ "${SW_EVIL_TWIN:-0}" != x ]` → `lap_twin_off_silent`.
  - `payload.sh`: make `sw_evil_twin_scan` take its own copy (`sw_recon_snapshot "$SW_RECON_DB" && sw_evil_twin_scan "$REPLY" "$now"`) → `lap_makes_one_db_copy`.

---

### Task 4: Warn when the evil-twin check goes blind

**Files:**
- Modify: `$SQ/lib/eviltwin.sh` (append `sw_evil_twin_blind`)
- Modify: `$SQ/payload.sh` (`sw_healthcheck`)
- Modify: `README.md` (health paragraph)
- Test: `test/eviltwin_test.sh` (append), `test/payload_test.sh`

**Interfaces:**
- Consumes: `_sw_evil_twin_window` and `_sw_evil_twin_rows` (Task 2), `sw_recon_snapshot` (Task 1), `sw_stopped` (`lib/ble.sh`), `_sw_health_warn` (`payload.sh`).
- Produces: `sw_evil_twin_blind [db]`: rc 0 = blind, rc 1 = fine or no verdict. It makes and removes its own copy.

- [ ] **Step 1: Write the failing tests.** Append to `test/eviltwin_test.sh`:

```bash

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
# rows the check skips (hidden radios) are not counted either: the count reads what the check reads
sw_test_recon_db "$_eb/hid.db" "8,ACDE48000001,,1,-60,30,HomeNet"
SW_TMP_DIR="$_eb" sw_evil_twin_blind "$_eb/hid.db"; assert_eq "$?" "1" blind_no_verdict_on_rows_the_check_skips
# no DB: no verdict (the health check's unreadable-DB WARN covers it)
SW_TMP_DIR="$_eb" sw_evil_twin_blind "$_eb/missing.db"; assert_eq "$?" "1" blind_no_verdict_without_db
# A copy that vanishes during the check (the exit trap after a Stop) is "unknown", never "blind":
# this sqlite3 removes the copy just before the count opens it. The DB would read as blind otherwise.
( sqlite3() { case "$*" in *"count(encryption)"*) rm -f "$2"; : > "$_eb/vanished" ;; esac; command sqlite3 "$@"; }
  SW_TMP_DIR="$_eb" sw_evil_twin_blind "$_eb/null.db" ); assert_eq "$?" "1" blind_vanished_copy_is_unknown
assert_eq "$([ -e "$_eb/vanished" ] && echo yes)" "yes" blind_vanished_control_removed
assert_empty "$(ls "$_eb" | grep '^sw_recon\.')" blind_leaves_no_copy
rm -rf "$_eb"; unset _eb SW_RECENCY_SECS
```

In `test/payload_test.sh`, directly after the line `rm -rf "$SW_STALED"; unset SW_STALED`, insert:

```bash

# health signal: a recon DB that stops recording network security leaves the evil-twin check blind
# (spec 2026-09-29 §7): it would find nothing, forever, and read as "all clear"
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/helpers/recon_db.sh"   # sw_test_recon_db
_hb2="$(mktemp -d)"
sw_test_recon_db "$_hb2/null.db" "8,ACDE48000001,,0,-60,30,HomeNet"
: > "$SW_STUB_LOG"
SW_RECON_DB="$_hb2/null.db" SW_RECENCY_SECS=600 sw_healthcheck; assert_eq "$?" "1" health_twin_blind_rc
assert_contains "$(cat "$SW_STUB_LOG")" "evil-twin check is blind" health_twin_blind_warns
# control: the same DB with the check switched off says nothing about it
: > "$SW_STUB_LOG"
SW_EVIL_TWIN=0 SW_RECON_DB="$_hb2/null.db" SW_RECENCY_SECS=600 sw_healthcheck
assert_empty "$(grep -F 'evil-twin' "$SW_STUB_LOG")" health_twin_blind_quiet_when_off
# control: a DB that records security is healthy and silent
sw_test_recon_db "$_hb2/ok.db" "8,ACDE48000001,17184063752,0,-60,30,HomeNet"
: > "$SW_STUB_LOG"
SW_RECON_DB="$_hb2/ok.db" SW_RECENCY_SECS=600 sw_healthcheck; assert_eq "$?" "0" health_twin_ok_rc
assert_empty "$(grep WARN "$SW_STUB_LOG")" health_twin_ok_silent
# an unreadable DB gets its own WARN only, not a second, evil-twin one
: > "$SW_STUB_LOG"
SW_RECON_DB=/nonexistent/recon.db sw_healthcheck
assert_contains "$(cat "$SW_STUB_LOG")" "WiFi detection OFF" health_unreadable_control_warns
assert_empty "$(grep -F 'evil-twin' "$SW_STUB_LOG")" health_unreadable_no_twin_warn
# a check left running by a Stop starts no new DB copy for the blind-spot count
bash -c 'exit 0' & _hbd=$!; wait "$_hbd"
( sw_recon_snapshot() { echo called >> "$_hb2/calls"; return 1; }
  SW_MAIN_PID="$_hbd" SW_RECON_DB="$_hb2/null.db" SW_RECENCY_SECS=600 sw_healthcheck >/dev/null 2>&1 )
assert_eq "$( { cat "$_hb2/calls" 2>/dev/null; } | grep -c called)" "0" health_stopped_check_makes_no_twin_copy
# control: the same check while the payload runs does ask for one
( sw_recon_snapshot() { echo called >> "$_hb2/calls"; return 1; }
  SW_RECON_DB="$_hb2/null.db" SW_RECENCY_SECS=600 sw_healthcheck >/dev/null 2>&1 )
assert_eq "$( { cat "$_hb2/calls" 2>/dev/null; } | grep -c called)" "1" health_running_check_asks_for_a_copy
rm -rf "$_hb2"; unset _hb2 _hbd
```

- [ ] **Step 2: Run the tests to see them fail**

Run: `bash test/run.sh 2>&1 | grep -E 'FAIL:|PASS='`
Expected FAIL: every `blind_*` test except `blind_leaves_no_copy` (`sw_evil_twin_blind: command not found`, rc 127), plus `health_twin_blind_rc`, `health_twin_blind_warns` and `health_running_check_asks_for_a_copy`.

- [ ] **Step 3: Append to `$SQ/lib/eviltwin.sh`:**

```bash

sw_evil_twin_blind() {
  # $1 = recon DB (default SW_RECON_DB). True (0) when the evil-twin check cannot work: the window
  # holds named, visible beacon rows but none carries a security value, or the count fails on a
  # readable copy (a firmware update renamed the column, say). The check would then find nothing,
  # forever, and read as "all clear". False (1) = fine, or no verdict: no copy, no rows in the
  # window (the stale-DB check reports that one), or the copy vanished during the check (the exit
  # trap after a Stop), which is "unknown", never "blind".
  local win now rows tmp out rc named secured
  _sw_evil_twin_window; win="$REPLY"
  now="$(date +%s)"; _sw_evil_twin_rows "$(( now - win ))"; rows="$REPLY"
  sw_recon_snapshot "${1:-$SW_RECON_DB}" || return 1
  tmp="$REPLY"
  out="$(sqlite3 -readonly "$tmp" "SELECT count(*) || char(9) || count(encryption) FROM ssid WHERE $rows;" 2>/dev/null)"; rc=$?
  [ -s "$tmp" ] || { rm -f "$tmp"; return 1; }
  rm -f "$tmp"
  [ "$rc" -eq 0 ] || return 0
  named="${out%%$'\t'*}"; secured="${out#*$'\t'}"
  [[ "$named" =~ ^[0-9]+$ ]] && [[ "$secured" =~ ^[0-9]+$ ]] || return 0
  [ "$named" -gt 0 ] && [ "$secured" -eq 0 ]
}
```

- [ ] **Step 4: Edit `sw_healthcheck` in `$SQ/payload.sh`.** Replace

```bash
  if ! command -v btmon >/dev/null 2>&1; then
    _sw_health_warn "WARN: btmon missing — BLE detection OFF"; degraded=1
  fi
  return $degraded
```

with

```bash
  if ! command -v btmon >/dev/null 2>&1; then
    _sw_health_warn "WARN: btmon missing — BLE detection OFF"; degraded=1
  fi
  # The evil-twin check needs each network's security from the recon DB. A DB that stops recording
  # it (a firmware update, say) would leave that check finding nothing, forever, and reading as "all
  # clear" (spec 2026-09-29 §7). Asked only when the DB itself is usable (the WARNs above cover the
  # rest), and never once stopped: a check left running by a Stop starts no new DB copy.
  if [ "${SW_EVIL_TWIN:-0}" = 1 ] && command -v sqlite3 >/dev/null 2>&1 && [ -r "$SW_RECON_DB" ] \
     && ! sw_stopped && sw_evil_twin_blind "$SW_RECON_DB"; then
    _sw_health_warn "WARN: evil-twin check is blind (the recon DB no longer records network security)"; degraded=1
  fi
  return $degraded
```

- [ ] **Step 5: Run the whole suite**

Run: `bash test/run.sh 2>&1 | tail -3`
Expected: `PASS=799 FAIL=0` (781 + 9 in `eviltwin_test.sh` + 9 in `payload_test.sh`). The Stop tests that stall the health check (`stop_during_periodic_health_check_*`, `stop_during_startup_health_check_*`) and `health_warns_only_through_the_stop_guard` must stay green.

- [ ] **Step 6: README.** In the paragraph that starts `If the recon DB stops updating, every sweep would return zero rows`, append this sentence at its end: ` The same goes for the evil-twin check: if the recon DB stops recording each network's security (after a firmware change, say), it warns "evil-twin check is blind" instead of quietly finding nothing.`

- [ ] **Step 7: Commit**

```bash
git add payloads/user/reconnaissance/squachwatch/lib/eviltwin.sh payloads/user/reconnaissance/squachwatch/payload.sh test/eviltwin_test.sh test/payload_test.sh README.md
TZ=UTC git -c user.name=Ziggy -c user.email=79704039+therealziggy@users.noreply.github.com commit -F - <<'EOF'
health: warn when the evil-twin check goes blind

The check needs each network's security from the recon DB. If a
firmware change stops recording it, or renames the column, the check
would find nothing forever and read as "all clear". The health check
(startup and every SW_HEALTH_EVERY laps) now counts the named, visible
beacon rows in the window and how many carry a security value: rows
but no values, or a failing count on a readable copy, is
"WARN: evil-twin check is blind" and DEGRADED. A copy that vanished
(a Stop) is "unknown"; an unreadable DB keeps its own WARN only; a
stopped check starts no new copy.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
git log -1 --format=%B | grep -cF 'Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>'
```
Expected last output: `1`

- [ ] **Step 8: Prove the tests bite.** Now that the work is committed, `git checkout -- <file>` restores the committed code. For each mutant: apply it, run `bash test/run.sh 2>&1 | grep FAIL:`, confirm the named test goes red, then restore with `git checkout -- <file>`. Finish with `git status --short` printing nothing. Record which test each mutant turned red in your report.
  - move `[ -s "$tmp" ] || { rm -f "$tmp"; return 1; }` below `[ "$rc" -eq 0 ] || return 0` → `blind_vanished_copy_is_unknown`.
  - delete the `[ "$rc" -eq 0 ] || return 0` line → `blind_yes_when_column_gone`.
  - in `sw_evil_twin_blind`, replace `WHERE $rows;` with `WHERE type = 8 AND time >= $(( now - win ));` (a filter of its own) → `blind_no_verdict_on_rows_the_check_skips`.
  - in `sw_healthcheck`, drop `&& ! sw_stopped` → `health_stopped_check_makes_no_twin_copy`.
  - in `sw_healthcheck`, delete the whole new `if` block → `health_twin_blind_rc`, `health_twin_blind_warns`.

---

### Task 5: Replay tool, device findings, docs

**Files:**
- Create: `tools/replay_evil_twin.sh`
- Test: `test/eviltwin_test.sh` (append)
- Modify: `docs/superpowers/P0-findings.md` (append a section), `README.md` (status paragraph, test count), `docs/superpowers/specs/2026-09-29-squachwatch-evil-twin-design.md` (amendments)

**Interfaces:**
- Consumes: `sw_evil_twin_scan <db> <now> <until>` and `_sw_evil_twin_window` (Task 2).
- Produces: `bash tools/replay_evil_twin.sh <recon.db> [window]`. It prints `window <N>s; minutes with beacon data: <M>; open copies found: <K>`, then one line per copy: `<MAC>  '<name>'  minutes it fired: <n>  first: <UTC time>`.

- [ ] **Step 1: Write the failing test.** Append to `test/eviltwin_test.sh`:

```bash

# --- tools/replay_evil_twin.sh (spec 2026-09-29 §8) replays history through the real check ---
_rp="$(mktemp -d)"; _rpt="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/tools/replay_evil_twin.sh"
sw_test_recon_db "$_rp/twin.db" "8,ACDE48000001,17184063752,0,-60,30,HomeNet" "8,021122334455,0,0,-38,20,HomeNet"
_out="$(bash "$_rpt" "$_rp/twin.db")"
assert_contains "$_out" "open copies found: 1" replay_finds_the_twin
assert_contains "$_out" "02:11:22:33:44:55  'HomeNet'" replay_names_the_copy
# control: a history where every radio is protected finds nothing
sw_test_recon_db "$_rp/mesh.db" "8,ACDE48000001,17184063752,0,-60,30,MeshNet" "8,ACDE48000002,17184063752,0,-60,30,MeshNet"
assert_contains "$(bash "$_rpt" "$_rp/mesh.db")" "open copies found: 0" replay_control_mesh_finds_nothing
rm -rf "$_rp"; unset _rp _rpt _out
```

Run: `bash test/run.sh 2>&1 | grep -E 'replay|PASS='` → FAIL `replay_finds_the_twin` etc. (the tool does not exist yet).

- [ ] **Step 2: Create `tools/replay_evil_twin.sh`:**

```bash
#!/bin/bash
# tools/replay_evil_twin.sh — replay the evil-twin check over a recon DB's whole history
# (spec 2026-09-29 §8). Usage: bash tools/replay_evil_twin.sh <recon.db> [window seconds]
# Runs the real sw_evil_twin_scan once for every minute that holds beacon data, as a lap at the end
# of that minute would have: only rows last seen by then, inside the window. Read-only. It prints
# real network names and addresses, so keep its output out of the repository.
set -u
db="${1:?usage: replay_evil_twin.sh <recon.db> [window seconds]}"
[ -r "$db" ] || { echo "can't read $db" >&2; exit 1; }
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIB="$ROOT/payloads/user/reconnaissance/squachwatch/lib"
source "$LIB/match.sh"; source "$LIB/wifi.sh"; source "$LIB/eviltwin.sh"
# no sqlite3 CLI on this machine (a dev PC): use the test suite's python3-backed stand-in
command -v sqlite3 >/dev/null 2>&1 || PATH="$ROOT/test/stubs:$PATH"
SW_RECENCY_SECS="${2:-600}"
declare -A hits=() first=()
minutes=0
while IFS= read -r m; do
  [ -n "$m" ] || continue
  minutes=$((minutes + 1))
  end=$(( m * 60 + 59 ))
  while IFS= read -r det; do
    [ -n "$det" ] || continue
    key="${det#*|*|*|*|*|}"; key="${key%|*}"          # "<MAC>|<name>"
    hits[$key]=$(( ${hits[$key]:-0} + 1 ))
    [ -n "${first[$key]:-}" ] || first[$key]="$end"
  done < <(sw_evil_twin_scan "$db" "$end" "$end")
done < <(sqlite3 -readonly "$db" "SELECT DISTINCT time / 60 FROM ssid WHERE type = 8 ORDER BY 1;")
_sw_evil_twin_window
echo "window ${REPLY}s; minutes with beacon data: $minutes; open copies found: ${#hits[@]}"
for key in "${!hits[@]}"; do
  echo "  ${key%%|*}  '${key#*|}'  minutes it fired: ${hits[$key]}  first: $(date -u -d "@${first[$key]}" '+%Y-%m-%d %H:%M UTC')"
done
```

Run: `bash test/run.sh 2>&1 | tail -3` → Expected: `PASS=802 FAIL=0`.

- [ ] **Step 3: Append to `docs/superpowers/P0-findings.md`:**

```markdown

## Evil-twin check (2026-09-29)

Checked on the Pager for the evil-twin design (`specs/2026-09-29-squachwatch-evil-twin-design.md`):

- `ssid.encryption` is a 64-bit bit field written by `pineapd`: 0 = open, any other value = protected
  (the low bits carry WEP / WPA / WPA2 / WPA3, the higher ones the ciphers and key-management
  suites; `17184063752`, the most common value, is a WPA2 personal network). It is NULL only on client
  rows (type 4) and on type-5 rows, which are names that clients probed for and have no BSSID.
- There is one `ssid` row per radio, name and recon session, and its `time` is when it was last seen in
  that session. A `hidden = 1` row can carry a name the Pager learned from a probe response.
- The Pager's `sqlite3` (3.46.1): with `-readonly`, a missing file fails (rc 1) and nothing is created.
  Without it, the same call leaves a 0-byte file. A missing column fails with rc 1.
- It prints a line break inside a value as it is. A network named `X<LF>B41E52112233<TAB>-10<TAB>Fake`
  therefore read as two WiFi records, and the second became a full-screen "Flock Safety device" alert
  at an address the name chose (reproduced on the dev box; the CLI behaviour was confirmed on the Pager).
  Both WiFi queries now remove line breaks from names in SQL.
- Timing on the real 5.9 MB DB, best of 3: the twin query 265 ms with `MATERIALIZED` and 439 ms without
  (SQLite then reads the window twice); one full pass over `ssid` 250 ms; the health check's blind-spot
  count 248 ms; copying the DB 112 ms; starting sqlite3 37 ms.
- Replaying the author's whole recon history (`tools/replay_evil_twin.sh`: 1,286 minutes that hold
  beacon data, 600 s window) finds exactly one open copy, which fired in 7 minutes. It is the Pager's own
  open access point, run on its first day under the name and address of the owner's router. CYD's rule
  finds nothing in the same history, because its same-maker exemption covers that copy. Ignoring
  capitals would add 22 false finds: a venue's open guest network on 23 radios next to a protected
  network with the same name in other capitals.
```

- [ ] **Step 4: README.**
  (a) In "Status & roadmap", after the paragraph that starts `**Signature port** (2026-09-26):`, add:

```markdown
**Evil twin** (2026-09-29): each lap, a network name that is offered both open and password-protected reports every open copy as an evil twin (see `SW_EVIL_TWIN` above). This is SquachWatch-CYD's test without CYD's same-maker exemption. Replayed over months of a real Pager's recon history (about 4,600 access points), the check reports exactly one event, the one real evil twin in it; CYD's rule reports nothing there, because that copy used the real router's own address. On the Pager the check adds about a quarter of a second to a lap. The same work closed a hole in the WiFi reader: a network name holding a line break could forge a second, fake device (a fake Flock camera with a full alert, say). Line breaks are now removed from names before they are read.
```

  (b) In "Tests", replace `**638 assertions, all passing**` with `**N assertions, all passing**`. Take N from the `PASS=` line of your last full run.

- [ ] **Step 5: Amend the spec** (`docs/superpowers/specs/2026-09-29-squachwatch-evil-twin-design.md`), so it matches what was built:
  (a) In §6.1, replace the whole ```` ```sql ```` block with the query as built (the first condition line is `_sw_evil_twin_rows`, which the blind-spot count shares):

```sql
WITH w AS MATERIALIZED (
  SELECT bssid, ssid, signal, time, encryption FROM ssid
  WHERE type = 8 AND hidden = 0 AND time >= <since> AND ltrim(hex(ssid), '0') <> ''<cap>
    AND encryption IS NOT NULL
),
twin AS (
  SELECT ssid FROM w GROUP BY ssid
  HAVING sum(encryption = 0) > 0 AND sum(encryption <> 0) > 0
)
SELECT line FROM (
  SELECT w.bssid || char(9) || w.signal || char(9) ||
         replace(replace(CAST(w.ssid AS TEXT), char(10), ''), char(13), '') AS line,
         max(w.time)
  FROM w JOIN twin ON w.ssid = twin.ssid
  WHERE w.encryption = 0
  GROUP BY w.bssid, w.ssid
);
```

     Below it, add: `` `<cap>` is empty on a lap; `tools/replay_evil_twin.sh` passes a third argument `until`, which adds `AND time <= <until>`, to replay history. MATERIALIZED makes SQLite read the window once (265 ms on the Pager, against 439 ms). ``
  (b) In §7, at the end of the **Hostile names** bullet, add: `` Line breaks are removed from the name in SQL (the CLI prints them as they are, so a name holding one could forge a second result line). The WiFi signature reader had exactly that bug and gets the same fix (a network name could forge a fake Flock Safety camera, full alert included; reproduced 2026-09-29). ``
  (c) In §7, in the **Blind-spot health check** bullet, replace `runs one more count on its database copy:` with `runs one more count, on its own copy of the database (as the stale-DB check does), and never once the payload is stopped:`.
  (d) In §8, after the **Real-history replay** paragraph, add: `` A suite test runs the tool on a synthetic history (one twin found, and none in an all-protected control). ``

- [ ] **Step 6: Privacy check, then commit.** The check below lists every added line holding a local path or a MAC address other than the made-up ones (`AC:DE:48...`, `02:11:22...`, and Flock Safety's public `B4:1E:52` block); it must print only `privacy-grep exit=1`:

```bash
git add tools/replay_evil_twin.sh test/eviltwin_test.sh docs/superpowers/P0-findings.md README.md docs/superpowers/specs/2026-09-29-squachwatch-evil-twin-design.md
git diff --cached | grep -n -E '/home/|([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}' | grep -v -E 'AC:DE:48|02:11:22|B4:1E:52'; echo "privacy-grep exit=$? (1 = clean)"
TZ=UTC git -c user.name=Ziggy -c user.email=79704039+therealziggy@users.noreply.github.com commit -F - <<'EOF'
tools/docs: evil-twin history replay and what the Pager showed

tools/replay_evil_twin.sh runs the real check once per minute of a
recon DB's history (read-only; its output holds real names, so it
stays out of the repo). On the author's DB it finds exactly the one
real evil twin; a suite test runs it on a synthetic history.
P0-findings records the device facts (the encryption bit field, the
CLI's -readonly and line-break behaviour, timings); the README gains
the status paragraph and the test count; the spec now matches what
was built (MATERIALIZED, the replay argument, the reader's line-break
fix, the health check's own copy).

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
git log -1 --format=%B | grep -cF 'Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>'
```
Expected last output: `1`

---

## After the tasks (the controller)

1. **Whole-branch review** (two independent reviewers): one general, one adversarial. The adversarial one attacks the hostile-name path end to end (SQL → bash → LOG/ALERT/CSV), the per-lap copy and the Stop (a Stop at every step of `sw_scan_once` and `sw_healthcheck`), and the window arithmetic. Fold in what survives and re-run.
2. **Root run:** `unshare -r bash test/run.sh` must end `FAIL=0` too.
3. **Real-history replay:** run `bash tools/replay_evil_twin.sh <copy of the Pager's recon.db>` with the copy kept outside the repo. Expected: `open copies found: 1`, 7 minutes. Delete the copy afterwards.
4. **On the Pager, only with the user's OK:** time a lap of the installed code (launcher-faithful, verbs stubbed); install (`payload.sh`, `lib/wifi.sh`, `lib/alert.sh`, `lib/eviltwin.sh`); check 11/11 md5 against HEAD. Then the user runs a menu launch at home (no twin alerts), followed by the live test: an open network under the name of a protected network the user owns (for example, the Pager's own open access point given the phone hotspot's name). Expected: `Evil twin '<name>'` within a lap or two; then the user turns it off.
5. **Push, only with the user's OK:** first search `git log -p origin/main..main` for local paths and for the real network names and addresses seen in the local replay (the search patterns are kept outside the repo, since they are the private data); it must find nothing.
