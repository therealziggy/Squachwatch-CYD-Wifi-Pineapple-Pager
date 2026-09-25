# SquachWatch-Pager Tier-3 (raw BLE advertisements) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Detect name-less personal trackers (Apple Find My, Samsung SmartTag, Tile, Google Find My) and Raven gunshot sensors from raw BLE advertisements, logging trackers on presence and alerting only when one stays with you.

**Architecture:** `btmon` becomes the single BLE data source. `hcitool lescan` only switches scanning on and its output is discarded. One capture per lap is parsed by one awk pass into one record per MAC, carrying a token field (`mfr:` / `uuid:` / `sd:`). Two new fork-free match types (`ble_mfr`, `ble_uuid`) read those tokens. A new `lib/follow.sh` escalates a tracker seen continuously for `SW_FOLLOW_SECS` into a high-confidence `<category>_follow` detection. `lib/ignore.sh` drops the owner's own devices.

**Tech Stack:** bash 5.2 payloads on the Hak5 WiFi Pineapple Pager (MIPS, BusyBox userland but GNU `timeout`), BusyBox awk 1.36.1, btmon 5.72, hcitool; offline test harness `bash test/run.sh` (sourced `*_test.sh` files + stubs in `test/stubs/`).

**Spec:** `docs/superpowers/specs/2026-09-22-squachwatch-tier3-ble-adv-design.md` (read it first).

## Global Constraints

- **Repo:** `<repo>`, branch `master`, no remote. Every commit message ends with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- **Run tests with** `bash test/run.sh`. It prints `PASS=N FAIL=M` and exits non-zero on any failure. Test files are *sourced* into one shell running `set -u`: prefix helper variables with `_` and `unset` them at the end of the file, and `unset` any variable you `export`.
- **Assertions available:** `assert_eq ACTUAL EXPECTED NAME`, `assert_contains HAYSTACK NEEDLE NAME`, `assert_empty VALUE NAME`, `pass`, `fail "msg"`.
- **TDD is mandatory:** write the test, run it, and see it FAIL for the expected reason (quote the failing assertion names) before writing code.
- **Positive controls are mandatory:** every assertion that something is absent/empty/zero is paired with one that proves the same code path produced something.
- **awk must run on BOTH mawk (dev box) and BusyBox awk 1.36.1 (Pager):** no gawk extensions (`strtonum`, `gensub`, `\s`, `{n}` intervals, `--` options).
- **Hot-path contract** (header of `lib/match.sh`): functions that run once per record (`sw_match_record`, `sw_sanitize_ident`, `sw_oui`, `_sw_lower`, `sw_wifi_colonize`, `sw_wifi_row_to_record`, and the new `_sw_uuid_hit`) use bash builtins only: no pipes, no `$( )`, no backticks. Arithmetic `$(( ))` is fine. `test/perf_test.sh` enforces this.
- **Config defaults live ONLY in `payload.sh`'s config block.** Libraries never assign a default with `:=` (that silently pinned `SW_RECENCY_SECS` to 0 once); they read `${VAR:-fallback}` at the point of use, or take values as arguments. Each new payload default gets a clean-process test.
- **BusyBox gotchas** (guarded by `test/portability_test.sh`): `tr` has no `[:class:]` (bash glob classes are fine); `mktemp` templates end in `XXXXXX` with no suffix.
- **Record formats:** WiFi records `wifi|MAC|ssid|rssi` (unchanged). BLE records become `ble|MAC|name|rssi|tokens`. Detections stay `category|label|confidence|threat_class|radio|mac|ident|rssi` (8 fields), so the loot CSV stays 10 columns.
- **Device:** `root@172.16.52.1`, passwordless ssh. The ssh login shell is BusyBox `ash`, so run payload code with `bash` explicitly. Deploy with `scp -r`.

## File Structure

| File | Responsibility |
|---|---|
| `payloads/user/reconnaissance/squachwatch/lib/ble.sh` | **rewritten**: btmon capture per lap (`sw_ble_scan`), parser (`_sw_btmon_awk`, `sw_btmon_parse`), BLE health (`sw_btmon_health`, `sw_ble_health_note`). The lescan parser (`sw_ble_line_to_record`, `sw_ble_parse`) is removed. |
| `payloads/user/reconnaissance/squachwatch/lib/match.sh` | modify: 5th record field; `ble_mfr` / `ble_uuid` matchers; `_sw_uuid_hit` |
| `payloads/user/reconnaissance/squachwatch/lib/follow.sh` | **new**: `sw_follow_update`, continuous-presence escalation + `track.db` state |
| `payloads/user/reconnaissance/squachwatch/lib/ignore.sh` | **new**: `sw_load_ignore`, `sw_ignored` |
| `payloads/user/reconnaissance/squachwatch/signatures.db` | modify: Tier-3 signature lines |
| `payloads/user/reconnaissance/squachwatch/payload.sh` | modify: source new libs, config defaults, ignore/follow wiring, btmon health, cleanup |
| `test/fixtures/btmon_synthetic.txt`, `btmon_scan_failed.txt`, `btmon_quiet.txt`, `btmon_unknown_format.txt` | **new** fixtures (the live capture `btmon_live_2026-09-22.txt` already exists) |
| `test/fixtures/lescan.txt` | **deleted** (Task 5) |
| `test/stubs/btmon`, `test/stubs/killall` | **new** stubs |
| `test/stubs/hcitool` | simplified (Task 5): its output is no longer read |
| `test/btmon_test.sh`, `test/follow_test.sh`, `test/ignore_test.sh` | **new** tests |
| `test/ble_test.sh` | rewritten (Task 5): `sw_ble_scan` end-to-end through stubs |
| `test/match_test.sh`, `test/perf_test.sh`, `test/signatures_test.sh`, `test/e2e_test.sh`, `test/payload_test.sh` | modify |
| `README.md`, `docs/superpowers/P0-findings.md` | docs |

---

### Task 1: btmon parser + fixtures

**Files:**
- Create: `test/fixtures/btmon_synthetic.txt`, `test/fixtures/btmon_scan_failed.txt`, `test/fixtures/btmon_quiet.txt`, `test/fixtures/btmon_unknown_format.txt`, `test/btmon_test.sh`
- Modify: `payloads/user/reconnaissance/squachwatch/lib/ble.sh` (append two functions; do not touch the existing ones yet)

**Interfaces:**
- Consumes: `sw_sanitize_ident STR` → sets `REPLY` (lib/match.sh).
- Produces: `sw_btmon_parse` reads btmon text on stdin and writes `ble|MAC|name|rssi|tokens` lines, one per MAC (order unspecified). Tokens are space-separated from: `mfr:<4 hex>:<2 hex>:<decimal len>`, `uuid:<4 hex>`, `sd:<4 hex>:<2 hex>`, all lowercase. The four fixtures are used by Tasks 2–5 and 8.

- [ ] **Step 1: Create the fixtures**

`test/fixtures/btmon_synthetic.txt` (exact content; its layout is copied from the real capture, but its device values are invented):

```
# SYNTHETIC btmon 5.72 capture for the SquachWatch tests. The LAYOUT is copied from the real
# capture test/fixtures/btmon_live_2026-09-22.txt (incl. real "Service Data:" rendering); the
# device VALUES (SmartTag, Tile, Google Find My, Eddystone, Raven, ...) are NOT from real devices.
> HCI Event: Command Complete (0x0e) plen 4                  #1 [hci0] 1.000000
      LE Set Scan Enable (0x08|0x000c) ncmd 1
        Status: Success (0x00)
> HCI Event: LE Meta Event (0x3e) plen 30                    #2 [hci0] 1.100000
      LE Advertising Report (0x02)
        Num reports: 1
        Event type: Connectable undirected - ADV_IND (0x00)
        Address type: Public (0x00)
        Address: 80:E1:26:00:00:01 (OUI 80-E1-26)
        Data length: 17
        Flags: 0x06
          LE General Discoverable Mode
          BR/EDR Not Supported
        Name (complete): Flipper aa
        16-bit Service UUIDs (partial): 1 entry
          Unknown (0x3082)
        RSSI: -60 dBm (0xc4)
> HCI Event: LE Meta Event (0x3e) plen 30                    #3 [hci0] 1.200000
      LE Advertising Report (0x02)
        Num reports: 1
        Event type: Connectable undirected - ADV_IND (0x00)
        Address type: Public (0x00)
        Address: 80:E1:26:00:00:01 (OUI 80-E1-26)
        Data length: 17
        Flags: 0x06
          LE General Discoverable Mode
          BR/EDR Not Supported
        16-bit Service UUIDs (partial): 1 entry
          Unknown (0x3082)
        RSSI: -55 dBm (0xc9)
> HCI Event: LE Meta Event (0x3e) plen 25                    #4 [hci0] 1.300000
      LE Advertising Report (0x02)
        Num reports: 1
        Event type: Connectable undirected - ADV_IND (0x00)
        Address type: Public (0x00)
        Address: 58:8E:81:12:34:56 (OUI 58-8E-81)
        Data length: 15
        Name (complete): Penguin-1234
        RSSI: -70 dBm (0xba)
> HCI Event: LE Meta Event (0x3e) plen 30                    #5 [hci0] 1.400000
      LE Advertising Report (0x02)
        Num reports: 1
        Event type: Non connectable undirected - ADV_NONCONN_IND (0x03)
        Address type: Random (0x01)
        Address: AA:00:00:00:00:01 (Resolvable)
        Data length: 22
        Service Data: Samsung Electronics Co., Ltd. (0xfd5a)
          Data: 02a1b2c3d4e5f60718293a4b5c6d7e8f
        RSSI: -80 dBm (0xb0)
> HCI Event: LE Meta Event (0x3e) plen 20                    #6 [hci0] 1.500000
      LE Advertising Report (0x02)
        Num reports: 1
        Event type: Connectable undirected - ADV_IND (0x00)
        Address type: Random (0x01)
        Address: AA:00:00:00:00:02 (Static)
        Data length: 7
        16-bit Service UUIDs (complete): 1 entry
          Tile, Inc. (0xfeed)
        RSSI: -81 dBm (0xaf)
> HCI Event: LE Meta Event (0x3e) plen 36                    #7 [hci0] 1.600000
      LE Advertising Report (0x02)
        Num reports: 1
        Event type: Non connectable undirected - ADV_NONCONN_IND (0x03)
        Address type: Random (0x01)
        Address: AA:00:00:00:00:03 (Non-Resolvable)
        Data length: 25
        Service Data: Google LLC (0xfeaa)
          Data: 41a1b2c3d4e5f60718293a4b5c6d7e8f9a0b1c2d
        RSSI: -82 dBm (0xae)
> HCI Event: LE Meta Event (0x3e) plen 30                    #8 [hci0] 1.700000
      LE Advertising Report (0x02)
        Num reports: 1
        Event type: Non connectable undirected - ADV_NONCONN_IND (0x03)
        Address type: Random (0x01)
        Address: AA:00:00:00:00:04 (Non-Resolvable)
        Data length: 19
        Service Data: Google LLC (0xfeaa)
          Data: 10eb03676f6f676c6507
        RSSI: -83 dBm (0xad)
> HCI Event: LE Meta Event (0x3e) plen 20                    #9 [hci0] 1.800000
      LE Advertising Report (0x02)
        Num reports: 1
        Event type: Connectable undirected - ADV_IND (0x00)
        Address type: Random (0x01)
        Address: AA:00:00:00:00:05 (Static)
        Data length: 7
        16-bit Service UUIDs (complete): 1 entry
          Unknown (0x3100)
        RSSI: -84 dBm (0xac)
> HCI Event: LE Meta Event (0x3e) plen 20                    #10 [hci0] 1.900000
      LE Advertising Report (0x02)
        Num reports: 1
        Event type: Connectable undirected - ADV_IND (0x00)
        Address type: Random (0x01)
        Address: AA:00:00:00:00:06 (Static)
        Data length: 7
        16-bit Service UUIDs (complete): 1 entry
          Unknown (0x3500)
        RSSI: -85 dBm (0xab)
> HCI Event: LE Meta Event (0x3e) plen 20                    #11 [hci0] 2.000000
      LE Advertising Report (0x02)
        Num reports: 1
        Event type: Connectable undirected - ADV_IND (0x00)
        Address type: Random (0x01)
        Address: AA:00:00:00:00:07 (Static)
        Data length: 7
        16-bit Service UUIDs (complete): 1 entry
          Unknown (0x3501)
        RSSI: -86 dBm (0xaa)
> HCI Event: LE Meta Event (0x3e) plen 40                    #12 [hci0] 2.100000
      LE Advertising Report (0x02)
        Num reports: 2
        Event type: Connectable undirected - ADV_IND (0x00)
        Address type: Random (0x01)
        Address: AA:00:00:00:00:08 (Static)
        Data length: 8
        Name (complete): MultiA
        RSSI: -87 dBm (0xa9)
        Event type: Connectable undirected - ADV_IND (0x00)
        Address type: Random (0x01)
        Address: AA:00:00:00:00:09 (Static)
        Data length: 8
        Name (complete): MultiB
        RSSI: -88 dBm (0xa8)
> HCI Event: LE Meta Event (0x3e) plen 50                    #13 [hci0] 2.200000
      LE Extended Advertising Report (0x0d)
        Num reports: 1
        Entry 0
          Event type: 0x0010
            Props: 0x0010
              Use legacy advertising PDUs
            Data status: Complete
          Address type: Random (0x01)
          Address: AA:00:00:00:00:0A (Static)
          Primary PHY: LE 1M
          Secondary PHY: No packets
          SID: no ADI field (0xff)
          TX power: 127 dBm
          RSSI: -71 dBm (0xb9)
          Periodic advertising interval: 0.00 msec (0x0000)
          Direct address type: Public (0x00)
          Direct address: 00:00:00:00:00:00 (OUI 00-00-00)
          Data length: 0x16
          Service Data: Samsung Electronics Co., Ltd. (0xfd5a)
            Data: 02ffeeddccbbaa99887766554433221100
> HCI Event: LE Meta Event (0x3e) plen 20                    #14 [hci0] 2.300000
      LE Advertising Report (0x02)
        Num reports: 1
        Event type: Connectable undirected - ADV_IND (0x00)
        Address type: Public (0x00)
        Address: AA:BB:CC:00:11:22 (OUI AA-BB-CC)
        Data length: 3
        Flags: 0x06
          LE General Discoverable Mode
          BR/EDR Not Supported
        RSSI: -72 dBm (0xb8)
> HCI Event: LE Meta Event (0x3e) plen 20                    #15 [hci0] 2.400000
      LE Advertising Report (0x02)
        Num reports: 1
        Event type: Scan response - SCAN_RSP (0x04)
        Address type: Public (0x00)
        Address: AA:BB:CC:00:11:22 (OUI AA-BB-CC)
        Data length: 11
        Name (complete): Tracker-9
        RSSI: -73 dBm (0xb7)
> HCI Event: LE Meta Event (0x3e) plen 20                    #16 [hci0] 2.500000
      LE Advertising Report (0x02)
        Num reports: 1
        Event type: Connectable undirected - ADV_IND (0x00)
        Address type: Random (0x01)
        Address: AA:00:00:00:00:0B (Static)
        Data length: 7
        Name (complete): Ev|il
        RSSI: -74 dBm (0xb6)
> HCI Event: LE Meta Event (0x3e) plen 30                    #17 [hci0] 2.600000
      LE Advertising Report (0x02)
        Num reports: 1
        Event type: Non connectable undirected - ADV_NONCONN_IND (0x03)
        Address type: Random (0x01)
        Address: AA:00:00:00:00:0C (Non-Resolvable)
        Data length: 30
        Company: Microsoft (6)
          Data: 0109202200aabbccdd
        RSSI: -75 dBm (0xb5)
```

`test/fixtures/btmon_scan_failed.txt`: a real capture from 2026-09-22, where the controller refused the scan with `Command Disallowed` (exact content):

```
Bluetooth monitor ver 5.72
btmon[1144]: = Note: Linux version 6.6.86 (mips)                       0.164431
btmon[1144]: = Note: Bluetooth subsystem version 2.22                  0.164454
= New Index: 00:13:37:BC:8F:94 (Primary,USB,hci0)               [hci0] 0.164460
= Open Index: 00:13:37:BC:8F:94                                 [hci0] 0.164464
= Index Info: 00:13:37:BC:8F:94 (MediaTek, Inc.)                [hci0] 0.164468
bluetoothd[2941]: @ MGMT Open: b.. (privileged) version 1.22  {0x0001} 0.164475
[1148]: @ RAW Open: hcitool (privileged) version 2.22         {0x0002} 0.931746
[1148]: @ RAW Close: hcitool                                  {0x0002} 0.931827
[1148]: @ RAW Open: hcitool (privileged) version 2.22         {0x0002} 0.931910
[1148]: @ RAW Close: hcitool                                  {0x0002} 0.931927
[1148]: @ RAW Open: hcitool (privileged) version 2.22  {0x0002} [hci0] 0.932051
[1148]: < HCI Command: LE Set Scan P.. (0x08|0x000b) plen 7  #1 [hci0] 0.932221
        Type: Active (0x01)
        Interval: 10.000 msec (0x0010)
        Window: 10.000 msec (0x0010)
        Own address type: Public (0x00)
        Filter policy: Accept all advertisement (0x00)
> HCI Event: Command Complete (0x0e) plen 4                  #2 [hci0] 0.932721
      LE Set Scan Parameters (0x08|0x000b) ncmd 1
        Status: Command Disallowed (0x0c)
[1148]: @ RAW Close: hcitool                                  {0x0002} [hci0] 0.933580
```

`btmon_quiet.txt` (real header plus scan enable/disable, no reports) and `btmon_unknown_format.txt` (the same, plus one real report whose `Address:` label is renamed, to simulate a btmon format change) are cut from the live capture:

```bash
cd <repo>
{ sed -n '1,27p' test/fixtures/btmon_live_2026-09-22.txt; sed -n '680,686p' test/fixtures/btmon_live_2026-09-22.txt; } > test/fixtures/btmon_quiet.txt
{ cat test/fixtures/btmon_quiet.txt; sed -n '28,39p' test/fixtures/btmon_live_2026-09-22.txt | sed 's/ Address: / BD_ADDR: /'; } > test/fixtures/btmon_unknown_format.txt
grep -c 'Set Scan Enable' test/fixtures/btmon_quiet.txt          # expect 2
grep -c 'BD_ADDR' test/fixtures/btmon_unknown_format.txt          # expect 1
```

- [ ] **Step 2: Write the failing test** `test/btmon_test.sh`

```bash
# test/btmon_test.sh  (sourced by run.sh) — the btmon parser (Tier-3 spec §3).
SW_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../payloads/user/reconnaissance/squachwatch" && pwd)"
_FIX="$(cd "$(dirname "${BASH_SOURCE[0]}")/fixtures" && pwd)"
source "$SW_ROOT/lib/match.sh"; source "$SW_ROOT/lib/ble.sh"

# REAL capture, 2026-09-22: 7 distinct devices -> exactly one record each.
_live="$(sw_btmon_parse < "$_FIX/btmon_live_2026-09-22.txt")"
assert_eq "$(printf '%s\n' "$_live" | grep -c '^ble|')" "7" btmon_live_one_record_per_mac
assert_contains "$_live" "ble|F9:C1:A3:83:F0:48||-96|mfr:004c:12:25" btmon_live_findmy_separated
assert_contains "$_live" "ble|FB:E5:3D:E8:87:19||-99|mfr:004c:12:2" btmon_live_findmy_nearowner
assert_contains "$_live" "ble|6C:E3:68:45:20:97||-99|mfr:004c:10:5" btmon_live_apple_nearby_info
assert_contains "$_live" "ble|80:E1:26:FA:D6:22|MyFlipper|-74|uuid:3082" btmon_live_flipper
assert_contains "$_live" "ble|06:92:D4:30:B1:09||-99|sd:fcf1:04" btmon_live_service_data
assert_contains "$_live" "ble|D4:06:74:62:37:27|InfiniTime|-92|" btmon_live_128bit_only_no_tokens

_syn="$(sw_btmon_parse < "$_FIX/btmon_synthetic.txt")"
# two sightings of one MAC merge: strongest RSSI (-55 beats -60), name kept, token once
assert_contains "$_syn" "ble|80:E1:26:00:00:01|Flipper aa|-55|uuid:3082" btmon_merge_strongest_rssi
assert_eq "$(printf '%s\n' "$_syn" | grep -c '80:E1:26:00:00:01')" "1" btmon_merge_one_record
assert_contains "$_syn" "ble|58:8E:81:12:34:56|Penguin-1234|-70|" btmon_name_only
assert_contains "$_syn" "ble|AA:00:00:00:00:01||-80|sd:fd5a:02" btmon_smarttag_service_data
assert_contains "$_syn" "ble|AA:00:00:00:00:02||-81|uuid:feed" btmon_tile_uuid16
assert_contains "$_syn" "ble|AA:00:00:00:00:03||-82|sd:feaa:41" btmon_gfmd_service_data
assert_contains "$_syn" "ble|AA:00:00:00:00:04||-83|sd:feaa:10" btmon_eddystone_service_data
assert_contains "$_syn" "ble|AA:00:00:00:00:07||-86|uuid:3501" btmon_uuid16_outside_range
# multi-report event -> two devices
assert_contains "$_syn" "ble|AA:00:00:00:00:08|MultiA|-87|" btmon_multi_report_a
assert_contains "$_syn" "ble|AA:00:00:00:00:09|MultiB|-88|" btmon_multi_report_b
# extended report: RSSI comes BEFORE the data, and "Direct address:" is not a device
assert_contains "$_syn" "ble|AA:00:00:00:00:0A||-71|sd:fd5a:02" btmon_extended_report
assert_empty "$(printf '%s\n' "$_syn" | grep '00:00:00:00:00:00')" btmon_direct_address_not_a_device
# name only in the SCAN_RSP still lands on the record (v1 parity: unknown-first keeps the name)
assert_contains "$_syn" "ble|AA:BB:CC:00:11:22|Tracker-9|-72|" btmon_name_from_scan_response
# Finding-1: '|' in an advertised name is stripped (single sanitizer: sw_sanitize_ident)
assert_contains "$_syn" "ble|AA:00:00:00:00:0B|Evil|-74|" btmon_name_sanitized
# manufacturer data WITHOUT a btmon "Type:" line: type = first byte, len = the rest
assert_contains "$_syn" "ble|AA:00:00:00:00:0C||-75|mfr:0006:01:8" btmon_mfr_without_type_line

# no advertising reports -> no records, and command-parameter lines ("Type: Active" under
# LE Set Scan Parameters) are never read as devices. Positive control: _live above has 7.
assert_empty "$(sw_btmon_parse < "$_FIX/btmon_scan_failed.txt")" btmon_no_reports_no_records

# BUDGET: a crowded room. ~31k lines must parse in well under a lap (one awk pass).
_big="$(mktemp)"; for _i in $(seq 45); do cat "$_FIX/btmon_live_2026-09-22.txt"; done > "$_big"
SECONDS=0; _n="$(sw_btmon_parse < "$_big" | grep -c '^ble|')"; _el=$SECONDS
assert_eq "$_n" "7" btmon_big_capture_positive_control
if [ "$_el" -lt 5 ]; then pass; else fail "btmon_parse_budget: $(wc -l < "$_big") lines took ${_el}s (budget 5s)"; fi
rm -f "$_big"
unset _FIX _live _syn _big _i _n _el
```

- [ ] **Step 3: Run it and verify it fails**

Run: `bash test/run.sh 2>&1 | grep -E 'FAIL|PASS='`
Expected: the `btmon_*` assertions FAIL (`sw_btmon_parse: command not found`, e.g. `FAIL: btmon_live_one_record_per_mac: expected [7] got [0]`). All other files still pass.

- [ ] **Step 4: Implement** by appending to `payloads/user/reconnaissance/squachwatch/lib/ble.sh`:

```bash
# --- btmon parser (Tier-3 spec §3) ---------------------------------------------------
# One awk pass over a lap's btmon capture -> one line per MAC:
#   MAC<TAB>strongest rssi<TAB>tokens<TAB>name
# The name goes LAST because it is the only free text, so any byte inside it cannot shift
# the other fields. Runs unchanged on mawk (dev box) and BusyBox awk 1.36.1 (Pager).
_sw_btmon_awk() {
  awk '
# One record per MAC: MAC<TAB>rssi<TAB>tokens<TAB>name (name LAST: it is the only free text)
function flush(   n, i, t) {
  if (mac == "") return
  seen[mac] = 1
  if (name != "" && nm[mac] == "") nm[mac] = name
  if (rssi != "" && rssi != "127" && (!(mac in rs) || rssi + 0 > rs[mac] + 0)) rs[mac] = rssi
  n = split(toks, t, " ")
  for (i = 1; i <= n; i++)
    if (index(" " tk[mac] " ", " " t[i] " ") == 0) tk[mac] = (tk[mac] == "" ? t[i] : tk[mac] " " t[i])
  mac = ""; name = ""; rssi = ""; toks = ""; ctx = ""
}
function lastparen(s,   p) {           # "... (76)" -> "76" ; "... (0x3081)" -> "0x3081"
  p = match(s, /\([^()]*\)$/); if (!p) return ""
  return substr(s, RSTART + 1, RLENGTH - 2)
}
/^[^ ]/                  { flush(); inrep = 0; next }          # any new HCI packet / note
/Advertising Report/     { flush(); inrep = 1; next }
!inrep                   { next }
/^ +Address: /           { flush(); mac = toupper($2); next }
mac == ""                { next }
/^ +RSSI: /              { rssi = $2; ctx = ""; next }
/^ +Name \([a-z]+\): /   { name = $0; sub(/^ +Name \([a-z]+\): /, "", name); ctx = ""; next }
/^ +Company: /           { comp = sprintf("%04x", lastparen($0) + 0); ctx = "mfr"; mtype = ""; next }
ctx == "mfr" && /^ +Type: / { mtype = sprintf("%02x", lastparen($0) + 0); next }
/^ +Service Data: /      { u = lastparen($0); sduuid = tolower(substr(u, 3)); ctx = "sd"; next }
/^ +Data(\[[0-9]+\])?: / {
  hex = tolower($NF)
  if (ctx == "mfr") {
    if (mtype != "") { toks = toks " mfr:" comp ":" mtype ":" (length(hex) / 2); mtype = "" }
    else { toks = toks " mfr:" comp ":" substr(hex, 1, 2) ":" (length(hex) / 2 - 1); ctx = "" }
  } else if (ctx == "sd") { toks = toks " sd:" sduuid ":" substr(hex, 1, 2); ctx = "" }
  next
}
/^ +16-bit Service UUIDs/ { ctx = "u16"; next }
ctx == "u16" && /\(0x[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]\)$/ {
  u = lastparen($0); toks = toks " uuid:" tolower(substr(u, 3)); next
}
{ ctx = "" }
END {
  flush()
  for (m in seen) printf "%s\t%s\t%s\t%s\n", m, rs[m], tk[m], nm[m]
}
'
}

sw_btmon_parse() {
  # stdin = btmon text -> stdout "ble|MAC|name|rssi|tokens", one per MAC. The name is
  # cleaned by sw_sanitize_ident (lib/match.sh), the ONE implementation of the Finding-1
  # boundary: never re-implement it in awk.
  local line mac rssi toks r
  _sw_btmon_awk | while IFS= read -r line; do
    mac="${line%%$'\t'*}"; r="${line#*$'\t'}"
    rssi="${r%%$'\t'*}";   r="${r#*$'\t'}"
    toks="${r%%$'\t'*}"
    sw_sanitize_ident "${r#*$'\t'}"
    printf 'ble|%s|%s|%s|%s\n' "$mac" "$REPLY" "$rssi" "$toks"
  done
}
```

- [ ] **Step 5: Run the tests and verify they pass**

Run: `bash test/run.sh 2>&1 | grep -E 'FAIL|PASS='`
Expected: `PASS=147 FAIL=0` (122 before this task + the 25 new assertions).

- [ ] **Step 6: Verify the awk on the real BusyBox awk** (it must give identical output)

```bash
cd <repo>
bash -c '. payloads/user/reconnaissance/squachwatch/lib/match.sh; . payloads/user/reconnaissance/squachwatch/lib/ble.sh; sw_btmon_parse < test/fixtures/btmon_synthetic.txt' | sort > /tmp/sw_local_parse.txt
scp -q -r payloads/user/reconnaissance/squachwatch/lib test/fixtures/btmon_synthetic.txt root@172.16.52.1:/tmp/
ssh root@172.16.52.1 'cd /tmp && bash -c ". lib/match.sh; . lib/ble.sh; sw_btmon_parse < btmon_synthetic.txt" | sort; rm -rf /tmp/lib /tmp/btmon_synthetic.txt' > /tmp/sw_pager_parse.txt
diff /tmp/sw_local_parse.txt /tmp/sw_pager_parse.txt && echo IDENTICAL; wc -l < /tmp/sw_pager_parse.txt; rm -f /tmp/sw_local_parse.txt /tmp/sw_pager_parse.txt
```
Expected: `IDENTICAL` and `15`. If the Pager is unreachable, record that in the task report. Do not skip it silently.

- [ ] **Step 7: Commit**

```bash
git add test/fixtures/btmon_synthetic.txt test/fixtures/btmon_scan_failed.txt test/fixtures/btmon_quiet.txt test/fixtures/btmon_unknown_format.txt test/btmon_test.sh payloads/user/reconnaissance/squachwatch/lib/ble.sh
git commit -m "feat(ble): btmon capture parser -> one record per MAC with adv tokens

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 2: `ble_mfr` / `ble_uuid` matchers

**Files:**
- Modify: `payloads/user/reconnaissance/squachwatch/lib/match.sh` (`sw_match_record` field split + two case arms; new `_sw_uuid_hit`)
- Modify: `test/match_test.sh`, `test/perf_test.sh`

**Interfaces:**
- Consumes: BLE records `ble|MAC|name|rssi|tokens` (Task 1). 4-field records must still work.
- Produces: signature match types `ble_mfr|<company>[:<type>[:<len>]]` (whole-segment prefix) and `ble_uuid|<xxxx>` / `ble_uuid|<xxxx>:<bb>` / `ble_uuid|<lo>-<hi>`; `_sw_uuid_hit PATTERN TOKENS` → rc 0 on hit.

- [ ] **Step 1: Write the failing tests.** Append to `test/match_test.sh`:

```bash
# --- Tier-3: ble_mfr / ble_uuid over btmon token records (spec §4) ---
_T3='ble_mfr|004c:12:25|tracker_findmy|Apple Find My (separated)|med|tracker
ble_uuid|fd5a|tracker_smarttag|Samsung SmartTag|med|tracker
ble_uuid|feed|tracker_tile|Tile|med|tracker
ble_uuid|feaa:41|tracker_gfmd|Google Find My (separated)|med|tracker
ble_uuid|3100-3500|surveillance_raven|Raven gunshot sensor (possible)|low|surveillance'
# positives (the detection keeps 8 fields: the token field is NOT copied into it)
assert_eq "$(sw_match_record 'ble|F9:C1:A3:83:F0:48||-96|mfr:004c:12:25' "$_T3")" "tracker_findmy|Apple Find My (separated)|med|tracker|ble|F9:C1:A3:83:F0:48||-96" t3_findmy_separated
assert_contains "$(sw_match_record 'ble|AA:00:00:00:00:01||-80|sd:fd5a:02' "$_T3")" "tracker_smarttag|" t3_smarttag_by_service_data
assert_contains "$(sw_match_record 'ble|AA:00:00:00:00:02||-81|uuid:feed' "$_T3")" "tracker_tile|" t3_tile_by_uuid16
assert_contains "$(sw_match_record 'ble|AA:00:00:00:00:03||-82|sd:feaa:41' "$_T3")" "tracker_gfmd|" t3_gfmd_separated
assert_contains "$(sw_match_record 'ble|AA:00:00:00:00:05||-84|uuid:3100' "$_T3")" "surveillance_raven|" t3_raven_low_boundary
assert_contains "$(sw_match_record 'ble|AA:00:00:00:00:06||-85|uuid:3500' "$_T3")" "surveillance_raven|" t3_raven_high_boundary
# negatives, where the false positives live
assert_empty "$(sw_match_record 'ble|FB:E5:3D:E8:87:19||-99|mfr:004c:12:2' "$_T3")" t3_findmy_nearowner_silent
assert_empty "$(sw_match_record 'ble|6C:E3:68:45:20:97||-99|mfr:004c:10:5' "$_T3")" t3_apple_nearby_info_silent
assert_empty "$(sw_match_record 'ble|AA:00:00:00:00:04||-83|sd:feaa:10' "$_T3")" t3_eddystone_not_gfmd
assert_empty "$(sw_match_record 'ble|80:E1:26:FA:D6:22|MyFlipper|-74|uuid:3082' "$_T3")" t3_flipper_uuid_below_raven
assert_empty "$(sw_match_record 'ble|AA:00:00:00:00:07||-86|uuid:3501' "$_T3")" t3_uuid_above_raven
# whole-segment prefix: a near-owner rule must NOT match the separated token...
assert_empty "$(sw_match_record 'ble|F9:C1:A3:83:F0:48||-96|mfr:004c:12:25' 'ble_mfr|004c:12:2|near|Near owner|low|tracker')" t3_mfr_whole_segment
# ...while shorter prefixes DO match on segment boundaries (positive controls)
assert_contains "$(sw_match_record 'ble|F9:C1:A3:83:F0:48||-96|mfr:004c:12:25' 'ble_mfr|004c:12|anyfm|Any Find My|low|tracker')" "anyfm|" t3_mfr_prefix_type
assert_contains "$(sw_match_record 'ble|6C:E3:68:45:20:97||-99|mfr:004c:10:5' 'ble_mfr|004C|apple|Any Apple|low|tracker')" "apple|" t3_mfr_prefix_company_case_insensitive
# the tokens only count on BLE: a wifi record can't match a BLE rule
assert_empty "$(sw_match_record 'wifi|AA:00:00:00:00:02|uuid:feed|-81' "$_T3")" t3_wifi_ignored
# non-vacuity: drop the Find My signature and the separated record matches nothing
assert_empty "$(sw_match_record 'ble|F9:C1:A3:83:F0:48||-96|mfr:004c:12:25' "$(printf '%s\n' "$_T3" | grep -v tracker_findmy)")" t3_nonvacuous
# a 4-field v1-shape record still splits correctly (rssi is not swallowed by an empty 5th field)
assert_contains "$(sw_match_record 'ble|80:E1:26:00:00:01|Flipper aa|-60' 'ble_name_sub|flipper|hacker_flipper|Flipper|high|attacker')" "hacker_flipper|Flipper|high|attacker|ble|80:E1:26:00:00:01|Flipper aa|-60" t3_four_field_record
unset _T3
```

In the same file, change the comment above the existing `SIG_CO=` test from `# ble_company is Tier-3: must be ignored by v1 matcher` to `# an unknown match_type (here the old draft name ble_company) is ignored, never an error`.

In `test/perf_test.sh`:

1. Arithmetic `$((…))` is legal in the hot path, and `_sw_uuid_hit` uses it. The fork guards must still catch `$(` but not `$((`. Rewrite all **four** regexes (helper loop, `forkfree_sw_wifi_colonize`, `forkfree_row_to_record`, `forkfree_match_record`) with:

   ```bash
   python3 - <<'PY'
   p = 'test/perf_test.sh'; s = open(p).read()
   old = "'\\$\\(|"; new = "'\\$\\([^(]|"
   assert s.count(old) == 4, s.count(old)
   open(p, 'w').write(s.replace(old, new))
   PY
   grep -cF '[^(]' test/perf_test.sh     # expect 4 (fixed-string: bracket escapes in a regex here are a trap)
   ```
2. Add `_sw_uuid_hit` to the helper loop: `for _fn in sw_sanitize_ident sw_oui _sw_lower _sw_uuid_hit; do`.
3. Right after that loop, add a self-check that the new regex still catches a real subshell and doesn't flag arithmetic:

```bash
# regex self-check: still catches a command substitution, does not flag arithmetic
assert_contains "$(printf 'x="$(date)"\n' | grep -E '\$\([^(]')" 'x=' perf_regex_catches_subshell
assert_empty "$(printf 'x=$((16#ff))\n' | grep -E '\$\([^(]')" perf_regex_allows_arithmetic
```

4. Before the final `unset` line, add a BLE-token latency budget:

```bash
# LATENCY BUDGET for token records: 500 BLE records carrying tokens x a rule set that
# includes a RANGE (the most expensive matcher: loops tokens with arithmetic).
_sw_t3sigs='ble_mfr|004c:12:25|tracker_findmy|Apple Find My (separated)|med|tracker
ble_uuid|fd5a|tracker_smarttag|Samsung SmartTag|med|tracker
ble_uuid|feaa:41|tracker_gfmd|Google Find My (separated)|med|tracker
ble_uuid|3100-3500|surveillance_raven|Raven gunshot sensor (possible)|low|surveillance'
_sw_bulk_ble="$(i=0; while [ $i -lt 499 ]; do printf 'ble|AA:BB:CC:00:11:%02X||-60|mfr:004c:10:5 uuid:%04x sd:fcf1:04\n' $((i%256)) $((i+4096)); i=$((i+1)); done
                printf 'ble|F9:C1:A3:83:F0:48||-96|mfr:004c:12:25\n')"   # POSITIVE CONTROL row
SECONDS=0
_sw_out_ble="$(printf '%s\n' "$_sw_bulk_ble" | sw_match_stream "$_sw_t3sigs")"
_sw_el_ble=$SECONDS
assert_eq "$(printf '%s\n' "$_sw_out_ble" | grep -c 'tracker_findmy')" "1" perf_ble_positive_control
if [ "$_sw_el_ble" -lt 5 ]; then pass; else fail "perf_ble_budget: 500 token records took ${_sw_el_ble}s (budget 5s)"; fi
```

and extend the final `unset` with `_sw_t3sigs _sw_bulk_ble _sw_out_ble _sw_el_ble`.

- [ ] **Step 2: Run and verify failures**

Run: `bash test/run.sh 2>&1 | grep -E 'FAIL|PASS='`
Expected FAILs: the `t3_*` positives (e.g. `t3_findmy_separated: expected [...] got []`), `t3_four_field_record` should still PASS (proving the old path), `forkfree__sw_uuid_hit` (empty body is empty, so it may PASS: that's fine), and `perf_ble_positive_control` (expected 1, got 0). The regex self-checks PASS.

- [ ] **Step 3: Implement in `lib/match.sh`.**

Replace the field-split block in `sw_match_record`:

```bash
  # Split the 4 fields with parameter expansion (ident is sanitized, so it holds no '|').
  local radio="${rec%%|*}" _r="${rec#*|}"
  local mac="${_r%%|*}" _r2="${_r#*|}"
  local ident="${_r2%%|*}" rssi="${_r2#*|}"
```

with:

```bash
  # Split the fields with parameter expansion (ident is sanitized, so it holds no '|').
  # BLE records carry an optional 5th field of advertisement tokens (lib/ble.sh).
  local radio="${rec%%|*}" _r="${rec#*|}"
  local mac="${_r%%|*}" _r2="${_r#*|}"
  local ident="${_r2%%|*}" _r3="${_r2#*|}"
  local rssi="${_r3%%|*}" adv=""
  [ "$_r3" = "$rssi" ] || adv="${_r3#*|}"
```

Replace the case arm `*) : ;;   # ble_company / ble_uuid / unknown: Tier-3, ignored in v1` with:

```bash
      # Tier-3 (spec §4). ble_mfr is a WHOLE-SEGMENT prefix: equal, or followed by ':'.
      # A plain string prefix would let 004c:12:2 (near owner) match 004c:12:25 (separated).
      ble_mfr)       if [ "$radio" = ble ] && [ -n "$adv" ]; then case " $adv " in *" mfr:$norm "*|*" mfr:$norm:"*) hit=0;; esac; fi ;;
      ble_uuid)      [ "$radio" = ble ] && [ -n "$adv" ] && _sw_uuid_hit "$norm" "$adv" && hit=0 ;;
      *) : ;;   # unknown match_type: ignored (test/signatures_test.sh rejects unknown types)
```

Add this function between `_sw_lower` and `sw_prepare_sigs`:

```bash
_sw_uuid_hit() {
  # $1 = normalized ble_uuid pattern, $2 = the record's token list. rc 0 = hit.
  #   xxxx     a 16-bit service UUID (uuid:xxxx) OR service data under it (sd:xxxx:*)
  #   xxxx:bb  service data whose FIRST byte is bb only. This is what keeps Eddystone
  #            beacons (feaa:10) from reading as Google Find My (feaa:41).
  #   lo-hi    inclusive numeric range over uuid: and sd: UUIDs
  local p="$1" t u lo hi
  case "$p" in
    *-*)
      lo=$((16#${p%-*})); hi=$((16#${p#*-}))
      for t in $2; do
        case "$t" in
          uuid:*) u="${t#uuid:}" ;;
          sd:*)   u="${t#sd:}"; u="${u%%:*}" ;;
          *)      continue ;;
        esac
        u=$((16#$u))
        [ "$u" -ge "$lo" ] && [ "$u" -le "$hi" ] && return 0
      done
      return 1 ;;
    *:*) case " $2 " in *" sd:$p "*) return 0 ;; esac; return 1 ;;
    *)   case " $2 " in *" uuid:$p "*|*" sd:$p:"*) return 0 ;; esac; return 1 ;;
  esac
}
```

(`sw_prepare_sigs` already lowercases every pattern except `wifi_oui` / `ble_oui`, and the tokens are lowercase, so `004C` in a signature works.)

- [ ] **Step 4: Run and verify all pass**

Run: `bash test/run.sh 2>&1 | grep -E 'FAIL|PASS='`
Expected: `FAIL=0`.

- [ ] **Step 5: Prove the whole-segment test is not vacuous.** Temporarily change the `ble_mfr` arm's pattern to a plain prefix, `*" mfr:$norm"*`, run the suite, and confirm `t3_mfr_whole_segment` FAILS. Restore the arm and confirm `FAIL=0` again. Note both results in the task report.

- [ ] **Step 6: Commit**

```bash
git add payloads/user/reconnaissance/squachwatch/lib/match.sh test/match_test.sh test/perf_test.sh
git commit -m "feat(match): ble_mfr + ble_uuid matchers over btmon adv tokens

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 3: Tier-3 signatures + README signature docs

**Files:**
- Modify: `payloads/user/reconnaissance/squachwatch/signatures.db`, `test/signatures_test.sh`, `README.md` (Signatures section)

**Interfaces:**
- Consumes: `sw_btmon_parse` (Task 1), `ble_mfr`/`ble_uuid` (Task 2).
- Produces: categories `tracker_findmy`, `tracker_smarttag`, `tracker_tile`, `tracker_gfmd` (class `tracker`, `med`) and `surveillance_raven` (class `surveillance`, `low`). Task 6 derives `<category>_follow` from the tracker ones.

- [ ] **Step 1: Write the failing tests.** In `test/signatures_test.sh`, change the source line to `source "$SW_ROOT/lib/match.sh"; source "$SW_ROOT/lib/ble.sh"`, add `_FIX="$(cd "$(dirname "${BASH_SOURCE[0]}")/fixtures" && pwd)"` below `SW_ROOT=`, and append:

```bash
# every match_type is one the matcher implements: a typo (ble_mrf) would otherwise be
# silently ignored by sw_match_record's catch-all arm
_types_awk='$1!="wifi_oui" && $1!="wifi_ssid_sub" && $1!="ble_name_sub" && $1!="ble_oui" && $1!="ble_mfr" && $1!="ble_uuid" {print}'
assert_empty "$(printf '%s\n' "$SIGS" | awk -F'|' "$_types_awk")" sig_match_types_known
assert_contains "$(printf 'ble_mrf|004c|x|x|med|tracker\n' | awk -F'|' "$_types_awk")" "ble_mrf" sig_match_type_check_catches_typo

# Tier-3 seeds against the REAL 2026-09-22 capture, through the real parser
_live="$(sw_btmon_parse < "$_FIX/btmon_live_2026-09-22.txt" | sw_match_stream "$SIGS")"
assert_contains "$_live" "tracker_findmy|Apple Find My (separated)|med|tracker|ble|F9:C1:A3:83:F0:48||-96" seed_live_findmy_separated
assert_empty "$(printf '%s\n' "$_live" | grep -E 'FB:E5:3D:E8:87:19|D3:FC:B3:1C:81:E4|6C:E3:68:45:20:97')" seed_live_nearowner_and_nearby_silent
# the Flipper is still caught via the btmon path (OUI rule: its name is "MyFlipper")
assert_contains "$_live" "hacker_flipper|Flipper Zero|high|attacker|ble|80:E1:26:FA:D6:22" seed_live_flipper_via_btmon

# Tier-3 seeds against the synthetic capture
_syn="$(sw_btmon_parse < "$_FIX/btmon_synthetic.txt" | sw_match_stream "$SIGS")"
assert_contains "$_syn" "tracker_smarttag|Samsung SmartTag|med|tracker|ble|AA:00:00:00:00:01" seed_smarttag
assert_contains "$_syn" "tracker_tile|Tile|med|tracker|ble|AA:00:00:00:00:02" seed_tile_uuid
assert_contains "$_syn" "tracker_gfmd|Google Find My (separated)|med|tracker|ble|AA:00:00:00:00:03" seed_gfmd
assert_contains "$_syn" "surveillance_raven|Raven gunshot sensor (possible)|low|surveillance|ble|AA:00:00:00:00:05" seed_raven
assert_empty "$(printf '%s\n' "$_syn" | grep -E 'AA:00:00:00:00:04|AA:00:00:00:00:07')" seed_eddystone_and_out_of_range_silent
unset _types_awk _live _syn _FIX
```

- [ ] **Step 2: Run and verify failures**

Run: `bash test/run.sh 2>&1 | grep -E 'FAIL|PASS='`
Expected FAILs: `seed_live_findmy_separated`, `seed_smarttag`, `seed_tile_uuid`, `seed_gfmd`, `seed_raven`. `seed_live_flipper_via_btmon` already PASSES (the `ble_oui|80:E1:26` seed exists), which proves the parser-to-matcher chain works before any Tier-3 line is added. The two silent checks PASS.

- [ ] **Step 3: Add the signatures.** In `signatures.db`, replace the block that starts `# ---- Tier 2 starters (expand in a later task) ----` with:

```
# ---- Tier 2 starters ----
ble_name_sub|tile|tracker_tile|Tile tracker|med|tracker
wifi_ssid_sub|ring-|surveillance_ring|Ring doorbell|med|surveillance
# ---- Tier 3: raw BLE advertisements via btmon (spec 2026-09-22) ----
# Trackers log at med (colored line + CSV row). lib/follow.sh escalates one that STAYS
# with you to a high "<category>_follow" alert. Your own devices: loot dir ignore.txt.
# Apple Find My, separated from its owner: type 0x12, 25-byte payload (seen live
# 2026-09-22). The near-owner form (2-byte payload) deliberately does NOT match.
ble_mfr|004c:12:25|tracker_findmy|Apple Find My (separated)|med|tracker
ble_uuid|fd5a|tracker_smarttag|Samsung SmartTag|med|tracker
ble_uuid|feed|tracker_tile|Tile|med|tracker
ble_uuid|feec|tracker_tile|Tile|med|tracker
# Google Find My: service data 0xFEAA with frame 0x41 = separated (inferred from Google's
# spec). The first-byte check keeps Eddystone beacons (also 0xFEAA) out.
ble_uuid|feaa:41|tracker_gfmd|Google Find My (separated)|med|tracker
# Raven gunshot sensors: UUID range from SquachWatch-CYD, not device-verified, hence low
# (log only). Hobby devices live nearby: a Flipper advertises 0x3081.
ble_uuid|3100-3500|surveillance_raven|Raven gunshot sensor (possible)|low|surveillance
```

Note that the Tile *name* rule keeps its old category, `tracker_tile`, so a Tile that both names itself and advertises `0xFEED` gets one cooldown key and one CSV row.

- [ ] **Step 4: Run and verify all pass**

Run: `bash test/run.sh 2>&1 | grep -E 'FAIL|PASS='`
Expected: `FAIL=0`.

- [ ] **Step 5: Update the README Signatures section.** Replace the `match_type` bullet:

```
- `match_type`: `wifi_oui` · `wifi_ssid_sub` · `ble_name_sub` · `ble_oui`
```

with:

```
- `match_type`: `wifi_oui` · `wifi_ssid_sub` · `ble_name_sub` · `ble_oui` · `ble_mfr` · `ble_uuid`
```

and after the paragraph that ends `…so a device can't split a token to evade a signature.`, add:

```
**Raw-advertisement matchers (Tier 3).** Every BLE device seen in a lap gets a list of tokens decoded from its advertisement by `btmon`: `mfr:<company>:<type>:<length>` for manufacturer data (Apple Find My separated from its owner = `mfr:004c:12:25`), `uuid:<16-bit>` for service UUIDs, and `sd:<16-bit>:<first byte>` for service data. Match them with:

- `ble_mfr|004c:12:25`: a whole-segment prefix, so `004c` = any Apple, `004c:12` = any Find My, and `004c:12:25` = separated Find My only.
- `ble_uuid|fd5a` (the UUID as a service UUID or under service data), `ble_uuid|feaa:41` (service data whose first byte is `41`), and `ble_uuid|3100-3500` (a range).
```

- [ ] **Step 6: Commit**

```bash
git add payloads/user/reconnaissance/squachwatch/signatures.db test/signatures_test.sh README.md
git commit -m "feat(signatures): Tier-3 tracker + Raven seeds, match_type validity guard

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 4: BLE health: scan-start and format signals

**Files:**
- Modify: `payloads/user/reconnaissance/squachwatch/lib/ble.sh` (append two functions)
- Modify: `test/btmon_test.sh` (append)

**Interfaces:**
- Consumes: the Task 1 fixtures; `LOG` (DuckyScript verb, a stub in tests).
- Produces: `sw_btmon_health CAPTURE_FILE PARSED_COUNT` → sets `REPLY` to `ok` | `scan_failed` | `not_understood`. `sw_ble_health_note STATUS` → LOGs only when the status changes; state lives in `${SW_BLE_STATE_FILE:-${SW_TMP_DIR:-/tmp}/sw_ble.state}`.

- [ ] **Step 1: Write the failing tests.** Append to `test/btmon_test.sh`:

```bash
# --- BLE health (spec §7): a blind BLE path must never read as "all clear" ---
_FIX="$(cd "$(dirname "${BASH_SOURCE[0]}")/fixtures" && pwd)"
_n_of() { sw_btmon_parse < "$1" | grep -c '^ble|'; }
# REPLY may be unset here (earlier callers set it only inside subshells). Under run.sh's
# `set -u` a missing function would then ABORT the whole runner instead of failing asserts.
REPLY=""
sw_btmon_health "$_FIX/btmon_live_2026-09-22.txt" "$(_n_of "$_FIX/btmon_live_2026-09-22.txt")"
assert_eq "$REPLY" "ok" health_live_ok
sw_btmon_health "$_FIX/btmon_quiet.txt" 0
assert_eq "$REPLY" "ok" health_quiet_room_is_not_a_fault
sw_btmon_health "$_FIX/btmon_scan_failed.txt" 0
assert_eq "$REPLY" "scan_failed" health_command_disallowed
sw_btmon_health "$_FIX/btmon_unknown_format.txt" "$(_n_of "$_FIX/btmon_unknown_format.txt")"
assert_eq "$REPLY" "not_understood" health_format_changed

# state-change logging: loud once, never every ~20 s lap; a first-lap "ok" is silent
_st="$(mktemp -d)"; : > "$SW_STUB_LOG"
SW_BLE_STATE_FILE="$_st/ble.state" sw_ble_health_note ok
SW_BLE_STATE_FILE="$_st/ble.state" sw_ble_health_note scan_failed
SW_BLE_STATE_FILE="$_st/ble.state" sw_ble_health_note scan_failed
SW_BLE_STATE_FILE="$_st/ble.state" sw_ble_health_note ok
SW_BLE_STATE_FILE="$_st/ble.state" sw_ble_health_note not_understood
_log="$(cat "$SW_STUB_LOG")"
assert_eq "$(printf '%s\n' "$_log" | grep -c 'BLE scan failed to start')" "1" health_note_warns_once
assert_eq "$(printf '%s\n' "$_log" | grep -c 'BLE scan recovered')" "1" health_note_recovers_once
assert_eq "$(printf '%s\n' "$_log" | grep -c 'BLE capture not understood')" "1" health_note_format_warn
assert_eq "$(printf '%s\n' "$_log" | grep -c .)" "3" health_note_first_ok_silent
assert_eq "$(cat "$_st/ble.state")" "not_understood" health_note_state_persisted
rm -rf "$_st"; unset -f _n_of; unset _FIX _st _log
```

- [ ] **Step 2: Run and verify failures**

Run: `bash test/run.sh 2>&1 | grep -E 'FAIL|PASS='`
Expected: all `health_*` assertions FAIL (`sw_btmon_health: command not found`, e.g. `FAIL: health_live_ok: expected [ok] got []`), and the runner still prints its `PASS=… FAIL=…` summary. If it doesn't, something aborted it under `set -u`: fix that first.

- [ ] **Step 3: Implement** by appending to `lib/ble.sh`:

```bash
# --- BLE health (spec §7) --------------------------------------------------------------
sw_btmon_health() {
  # $1 = btmon capture file, $2 = records parsed from it -> REPLY:
  #   scan_failed     no "LE Set Scan Enable" completion with Status: Success, e.g. the
  #                   controller answered "Command Disallowed" and scanning never started.
  #                   Keyed on the opcode (0x08|0x000c) with "ncmd": btmon TRUNCATES
  #                   command names ("LE Set.. (0x08|0x000c)") when it prefixes a process.
  #   not_understood  advertising reports are present but zero records parsed: btmon's
  #                   text format changed under the parser.
  #   ok              otherwise, INCLUDING a quiet room (scan ran, nobody advertising).
  local cap="$1" n="$2"
  if ! awk 'p ~ /\(0x08\|0x000c\) ncmd/ && /Status: Success/ {ok = 1} {p = $0} END {exit !ok}' "$cap" 2>/dev/null; then
    REPLY=scan_failed
  elif [ "$n" -eq 0 ] && grep -q 'Advertising Report' "$cap" 2>/dev/null; then
    REPLY=not_understood
  else
    REPLY=ok
  fi
}

sw_ble_health_note() {
  # $1 = status from sw_btmon_health. LOGs only when the status CHANGES, so a dead scan is
  # loud once instead of every lap; a first-lap "ok" is silent.
  local st="$1" sf="${SW_BLE_STATE_FILE:-${SW_TMP_DIR:-/tmp}/sw_ble.state}" prev=""
  [ -f "$sf" ] && read -r prev < "$sf"
  [ "$st" = "$prev" ] && return 0
  printf '%s\n' "$st" > "$sf"
  case "$st" in
    ok)             [ -n "$prev" ] && LOG green "BLE scan recovered" 2>/dev/null ;;
    scan_failed)    LOG yellow "WARN: BLE scan failed to start — BLE detection OFF" 2>/dev/null ;;
    not_understood) LOG yellow "WARN: BLE capture not understood — BLE detection OFF" 2>/dev/null ;;
  esac
  return 0
}
```

- [ ] **Step 4: Run and verify all pass**

Run: `bash test/run.sh 2>&1 | grep -E 'FAIL|PASS='`
Expected: `FAIL=0`.

- [ ] **Step 5: Commit**

```bash
git add payloads/user/reconnaissance/squachwatch/lib/ble.sh test/btmon_test.sh
git commit -m "feat(ble): scan-start + capture-format health signals, logged on change

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 5: Switch `sw_ble_scan` to btmon; retire the lescan parser

**Files:**
- Rewrite: `payloads/user/reconnaissance/squachwatch/lib/ble.sh` (final content below)
- Rewrite: `test/ble_test.sh`, `test/stubs/hcitool`
- Create: `test/stubs/btmon`, `test/stubs/killall`
- Modify: `payloads/user/reconnaissance/squachwatch/payload.sh` (`_sw_ble_records`, `sw_cleanup`), `test/e2e_test.sh`, `test/payload_test.sh`
- Delete: `test/fixtures/lescan.txt`

**Interfaces:**
- Consumes: `sw_btmon_parse`, `sw_btmon_health`, `sw_ble_health_note` (Tasks 1, 4).
- Produces: `sw_ble_scan SECS IFACE` writes BLE records on stdout (always rc 0; a failed scan shows up as a health WARN and no records). Temp files go in `${SW_TMP_DIR:-/tmp}`. `sw_cleanup` (payload.sh) runs `killall hcitool btmon` and removes `${SW_TMP_DIR:-/tmp}/sw_ble.*`. The test seam is `SW_BLE_CMD` (its output is now btmon text).

- [ ] **Step 1: Stubs.** `test/stubs/btmon` (then `chmod +x`):

```bash
#!/usr/bin/env bash
# test/stubs/btmon — models the real monitor: prints a capture ($SW_FAKE_BTMON), then idles
# until TERM/INT and exits cleanly (btmon flushes on TERM). Self-limiting (30s) if orphaned.
fix="${SW_FAKE_BTMON:?test must set SW_FAKE_BTMON to a btmon capture}"
trap 'exit 0' TERM INT
cat "$fix"
end=$((SECONDS + 30)); while [ "$SECONDS" -lt "$end" ]; do sleep 0.05; done
```

`test/stubs/killall` (then `chmod +x`). The suite must never kill real processes on the dev box:

```bash
#!/usr/bin/env bash
# test/stubs/killall — records the call instead of killing anything on the dev box.
echo "${0##*/} $*" >> "${SW_STUB_LOG:-/dev/null}"
```

Replace `test/stubs/hcitool` (its output is no longer read, but its SIGINT behaviour still matters):

```bash
#!/usr/bin/env bash
# test/stubs/hcitool — models `hcitool lescan` as far as the scanner still depends on it:
# it runs until SIGINT (clean exit) or TERM. Its stdout is discarded by sw_ble_scan since
# Tier-3 (btmon is the data source). SW_FAKE_LESCAN_IGNORE_INT=1 models an hcitool that
# never honours SIGINT, the hang risk that `timeout -k` backstops.
case " $* " in *" lescan "*) : ;; *) exit 0 ;; esac
echo "LE Scan ..."
if [ -n "${SW_FAKE_LESCAN_IGNORE_INT:-}" ]; then trap '' INT; else trap 'exit 0' INT; fi
trap 'exit 143' TERM
# Self-limiting: even if orphaned by a failing test, this stub is gone within 30s.
end=$((SECONDS + 30)); while [ "$SECONDS" -lt "$end" ]; do sleep 0.05; done
```

- [ ] **Step 2: Write the failing test.** Replace `test/ble_test.sh` entirely:

```bash
#!/bin/bash
# test/ble_test.sh — sw_ble_scan end-to-end through test/stubs/{btmon,hcitool,hciconfig}.
SW_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../payloads/user/reconnaissance/squachwatch" && pwd)"
_FIX="$(cd "$(dirname "${BASH_SOURCE[0]}")/fixtures" && pwd)"
source "$SW_ROOT/lib/match.sh"; source "$SW_ROOT/lib/ble.sh"
export SW_TMP_DIR="$(mktemp -d)"            # keep captures out of the dev box's /tmp
export SW_FAKE_BTMON="$_FIX/btmon_synthetic.txt"

_recs="$(sw_ble_scan 1 hci0)"
assert_contains "$_recs" "ble|80:E1:26:00:00:01|Flipper aa|-55|uuid:3082" ble_scan_via_btmon
assert_contains "$_recs" "ble|AA:00:00:00:00:01||-80|sd:fd5a:02" ble_scan_carries_tokens
assert_eq "$(cat "$SW_TMP_DIR/sw_ble.state")" "ok" ble_scan_records_health
# the capture file is removed (positive control: the state file proves this dir was used)
assert_empty "$(ls "$SW_TMP_DIR" | grep -v '^sw_ble.state$')" ble_scan_removes_capture

# a scan that never started: no records, and a WARN (not a silent empty lap)
: > "$SW_STUB_LOG"
_recs="$(SW_FAKE_BTMON="$_FIX/btmon_scan_failed.txt" sw_ble_scan 1 hci0)"
assert_empty "$_recs" ble_scan_failed_no_records
assert_contains "$(cat "$SW_STUB_LOG")" "BLE scan failed to start" ble_scan_failed_warns

# an hcitool that ignores SIGINT must not hang the lap (-k backstop). Outer 12 s guard so
# a regression FAILS instead of hanging the suite; stderr hides bash's "Killed" notice.
SECONDS=0
SW_FAKE_LESCAN_IGNORE_INT=1 timeout 12 bash -c 'source "$1/lib/match.sh"; source "$1/lib/ble.sh"; sw_ble_scan 1 hci0 >/dev/null' _ "$SW_ROOT" 2>/dev/null
_rc=$?; _el=$SECONDS
assert_eq "$([ "$_rc" -ne 124 ] && [ "$_el" -lt 8 ] && echo bounded || echo "hung rc=$_rc ${_el}s")" "bounded" ble_scan_bounded_if_int_ignored

rm -rf "$SW_TMP_DIR"
unset SW_TMP_DIR SW_FAKE_BTMON _FIX _recs _rc _el
```

- [ ] **Step 3: Run and verify failures**

Run: `bash test/run.sh 2>&1 | grep -E 'FAIL|PASS='`
Expected FAILs: `ble_scan_via_btmon`, `ble_scan_carries_tokens` and `ble_scan_records_health` (the old `sw_ble_scan` still reads lescan output), plus `ble_scan_failed_warns`.

- [ ] **Step 4: Rewrite `lib/ble.sh`** with exactly this content (the Task 1 and Task 4 functions are carried over unchanged; the lescan parser and the `: "${SW_BLE_IFACE:=hci0}"` library default are gone):

```bash
#!/bin/bash
# lib/ble.sh — BLE capture via btmon, parsed into ble records (Tier-3 spec §3).
#
# btmon is the single BLE data source for every BLE matcher. `hcitool lescan` only switches
# scanning on; its output is discarded (it buffers its device lines and loses all of them
# unless it exits on SIGINT). One capture per lap is parsed ONCE into one record per MAC:
#   ble|<MAC>|<name>|<rssi>|<tokens>
#   tokens: mfr:<company>:<type>:<len>   uuid:<16-bit>   sd:<16-bit>:<first byte>
# Temp files live in ${SW_TMP_DIR:-/tmp} (a test seam; on the Pager /tmp is RAM).

# One awk pass over a lap's btmon capture -> one line per MAC:
#   MAC<TAB>strongest rssi<TAB>tokens<TAB>name
# The name goes LAST because it is the only free text, so any byte inside it cannot shift
# the other fields. Runs unchanged on mawk (dev box) and BusyBox awk 1.36.1 (Pager).
_sw_btmon_awk() {
  awk '
# One record per MAC: MAC<TAB>rssi<TAB>tokens<TAB>name (name LAST: it is the only free text)
function flush(   n, i, t) {
  if (mac == "") return
  seen[mac] = 1
  if (name != "" && nm[mac] == "") nm[mac] = name
  if (rssi != "" && rssi != "127" && (!(mac in rs) || rssi + 0 > rs[mac] + 0)) rs[mac] = rssi
  n = split(toks, t, " ")
  for (i = 1; i <= n; i++)
    if (index(" " tk[mac] " ", " " t[i] " ") == 0) tk[mac] = (tk[mac] == "" ? t[i] : tk[mac] " " t[i])
  mac = ""; name = ""; rssi = ""; toks = ""; ctx = ""
}
function lastparen(s,   p) {           # "... (76)" -> "76" ; "... (0x3081)" -> "0x3081"
  p = match(s, /\([^()]*\)$/); if (!p) return ""
  return substr(s, RSTART + 1, RLENGTH - 2)
}
/^[^ ]/                  { flush(); inrep = 0; next }          # any new HCI packet / note
/Advertising Report/     { flush(); inrep = 1; next }
!inrep                   { next }
/^ +Address: /           { flush(); mac = toupper($2); next }
mac == ""                { next }
/^ +RSSI: /              { rssi = $2; ctx = ""; next }
/^ +Name \([a-z]+\): /   { name = $0; sub(/^ +Name \([a-z]+\): /, "", name); ctx = ""; next }
/^ +Company: /           { comp = sprintf("%04x", lastparen($0) + 0); ctx = "mfr"; mtype = ""; next }
ctx == "mfr" && /^ +Type: / { mtype = sprintf("%02x", lastparen($0) + 0); next }
/^ +Service Data: /      { u = lastparen($0); sduuid = tolower(substr(u, 3)); ctx = "sd"; next }
/^ +Data(\[[0-9]+\])?: / {
  hex = tolower($NF)
  if (ctx == "mfr") {
    if (mtype != "") { toks = toks " mfr:" comp ":" mtype ":" (length(hex) / 2); mtype = "" }
    else { toks = toks " mfr:" comp ":" substr(hex, 1, 2) ":" (length(hex) / 2 - 1); ctx = "" }
  } else if (ctx == "sd") { toks = toks " sd:" sduuid ":" substr(hex, 1, 2); ctx = "" }
  next
}
/^ +16-bit Service UUIDs/ { ctx = "u16"; next }
ctx == "u16" && /\(0x[0-9a-fA-F][0-9a-fA-F][0-9a-fA-F][0-9a-fA-F]\)$/ {
  u = lastparen($0); toks = toks " uuid:" tolower(substr(u, 3)); next
}
{ ctx = "" }
END {
  flush()
  for (m in seen) printf "%s\t%s\t%s\t%s\n", m, rs[m], tk[m], nm[m]
}
'
}

sw_btmon_parse() {
  # stdin = btmon text -> stdout "ble|MAC|name|rssi|tokens", one per MAC. The name is
  # cleaned by sw_sanitize_ident (lib/match.sh), the ONE implementation of the Finding-1
  # boundary: never re-implement it in awk.
  local line mac rssi toks r
  _sw_btmon_awk | while IFS= read -r line; do
    mac="${line%%$'\t'*}"; r="${line#*$'\t'}"
    rssi="${r%%$'\t'*}";   r="${r#*$'\t'}"
    toks="${r%%$'\t'*}"
    sw_sanitize_ident "${r#*$'\t'}"
    printf 'ble|%s|%s|%s|%s\n' "$mac" "$REPLY" "$rssi" "$toks"
  done
}

sw_btmon_health() {
  # $1 = btmon capture file, $2 = records parsed from it -> REPLY:
  #   scan_failed     no "LE Set Scan Enable" completion with Status: Success, e.g. the
  #                   controller answered "Command Disallowed" and scanning never started.
  #                   Keyed on the opcode (0x08|0x000c) with "ncmd": btmon TRUNCATES
  #                   command names ("LE Set.. (0x08|0x000c)") when it prefixes a process.
  #   not_understood  advertising reports are present but zero records parsed: btmon's
  #                   text format changed under the parser.
  #   ok              otherwise, INCLUDING a quiet room (scan ran, nobody advertising).
  local cap="$1" n="$2"
  if ! awk 'p ~ /\(0x08\|0x000c\) ncmd/ && /Status: Success/ {ok = 1} {p = $0} END {exit !ok}' "$cap" 2>/dev/null; then
    REPLY=scan_failed
  elif [ "$n" -eq 0 ] && grep -q 'Advertising Report' "$cap" 2>/dev/null; then
    REPLY=not_understood
  else
    REPLY=ok
  fi
}

sw_ble_health_note() {
  # $1 = status from sw_btmon_health. LOGs only when the status CHANGES, so a dead scan is
  # loud once instead of every lap; a first-lap "ok" is silent.
  local st="$1" sf="${SW_BLE_STATE_FILE:-${SW_TMP_DIR:-/tmp}/sw_ble.state}" prev=""
  [ -f "$sf" ] && read -r prev < "$sf"
  [ "$st" = "$prev" ] && return 0
  printf '%s\n' "$st" > "$sf"
  case "$st" in
    ok)             [ -n "$prev" ] && LOG green "BLE scan recovered" 2>/dev/null ;;
    scan_failed)    LOG yellow "WARN: BLE scan failed to start — BLE detection OFF" 2>/dev/null ;;
    not_understood) LOG yellow "WARN: BLE capture not understood — BLE detection OFF" 2>/dev/null ;;
  esac
  return 0
}

sw_ble_scan() {
  # $1 = seconds (default 12), $2 = iface (default hci0). Writes ble records to stdout.
  local secs="${1:-12}" iface="${2:-hci0}" cap bpid recs n=0
  hciconfig "$iface" down 2>/dev/null; hciconfig "$iface" reset 2>/dev/null; hciconfig "$iface" up 2>/dev/null
  cap="$(mktemp "${SW_TMP_DIR:-/tmp}/sw_ble.XXXXXX")" || return 1
  # btmon has its OWN timeout: if this payload is SIGKILLed mid-lap, an orphaned btmon
  # still dies within secs+5 s instead of logging into RAM-backed /tmp forever. It is
  # stopped with TERM (timeout's default), not INT: a background job in a non-interactive
  # shell starts with SIGINT ignored, and btmon exits cleanly on TERM.
  timeout -k 2 $((secs + 3)) btmon > "$cap" 2>&1 &
  bpid=$!
  sleep 1                      # let btmon attach, or the first reports are missed
  # lescan only switches scanning ON; its output is discarded. SIGINT so it disables the
  # scan cleanly; -k 2 so an hcitool that ignored SIGINT can't hang the lap.
  timeout -s INT -k 2 "$secs" hcitool -i "$iface" lescan --duplicates > /dev/null 2>&1
  kill "$bpid" 2>/dev/null; wait "$bpid" 2>/dev/null
  recs="$(sw_btmon_parse < "$cap")"
  [ -n "$recs" ] && n="$(printf '%s\n' "$recs" | grep -c .)"
  sw_btmon_health "$cap" "$n"; sw_ble_health_note "$REPLY"
  rm -f "$cap"
  [ -n "$recs" ] && printf '%s\n' "$recs"
  return 0
}
```

- [ ] **Step 5: Retire lescan everywhere else.**
  - `payload.sh`, in `_sw_ble_records`: change `eval "$SW_BLE_CMD" | sw_ble_parse` to `eval "$SW_BLE_CMD" | sw_btmon_parse`.
  - `payload.sh`: replace `sw_cleanup() { killall hcitool 2>/dev/null; exit 0; }` with:

    ```bash
    # Kill the scanner's children AND remove their temp files: an orphaned btmon would keep
    # logging into RAM-backed /tmp, and a kill mid-scan used to leave /tmp/sw_ble.* behind.
    sw_cleanup() {
      killall hcitool btmon 2>/dev/null
      rm -f "${SW_TMP_DIR:-/tmp}"/sw_ble.* 2>/dev/null
      exit 0
    }
    ```
  - `test/payload_test.sh`: change `export SW_BLE_CMD="cat $FIX/lescan.txt"` to `export SW_BLE_CMD="cat $FIX/btmon_synthetic.txt"`.
  - `test/e2e_test.sh`: change `dets_b="$(sw_ble_parse < "$FIX/lescan.txt" | sw_match_stream "$SIGS")"` to `dets_b="$(sw_btmon_parse < "$FIX/btmon_synthetic.txt" | sw_match_stream "$SIGS")"`. The expected row count stays 5: the synthetic capture's "Flipper aa" and "Penguin-1234" are the only BLE hits for this file's 4 signatures.
  - `git rm test/fixtures/lescan.txt`
  - Confirm nothing references the old parser: `grep -rn 'lescan.txt\|sw_ble_parse\|sw_ble_line_to_record\|SW_FAKE_LESCAN[^_]' payloads test` → expect no output.

- [ ] **Step 6: Add the cleanup test.** Append to `test/payload_test.sh`, before the `rm -rf "$SW_LOOT_DIR" "$SW_SEEN_FILE"` line:

```bash
# sw_cleanup kills BOTH scanner children and removes their temp files (killall is a stub:
# the suite never kills real processes on the dev box)
_ct="$(mktemp -d)"; : > "$_ct/sw_ble.AbC123"; : > "$_ct/sw_ble.state"; : > "$_ct/keep.me"; : > "$SW_STUB_LOG"
( SW_TMP_DIR="$_ct" sw_cleanup )
assert_contains "$(cat "$SW_STUB_LOG")" "killall hcitool btmon" cleanup_kills_hcitool_and_btmon
assert_empty "$(ls "$_ct" | grep '^sw_ble\.')" cleanup_removes_ble_temp
assert_eq "$(ls "$_ct")" "keep.me" cleanup_leaves_other_files   # control: it is not rm -rf
rm -rf "$_ct"; unset _ct
```

- [ ] **Step 7: Run and verify all pass**

Run: `bash test/run.sh 2>&1 | grep -E 'FAIL|PASS='`
Expected: `FAIL=0`. Also run `pgrep -fa 'stubs/(btmon|hcitool) '`; anything it finds must be gone within 30s. A match on the `pgrep` command line itself doesn't count.

- [ ] **Step 8: Commit**

```bash
git add -A payloads test
git commit -m "feat(ble): btmon is the single BLE source; retire the lescan parser

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 6: Follow detection (`lib/follow.sh`)

**Files:**
- Create: `payloads/user/reconnaissance/squachwatch/lib/follow.sh`, `test/follow_test.sh`

**Interfaces:**
- Consumes: detections `category|label|confidence|threat_class|radio|mac|ident|rssi`; `LOG`.
- Produces: `sw_follow_update DETECTION NOW TRACKFILE FOLLOW_SECS GAP_SECS`. It prints the escalated detection `<category>_follow|<label> — following you <N>+ min|high|tracker|radio|mac|ident|rssi` or nothing. It returns 1 (with a WARN) if the state can't be written, and 0 otherwise. State lines are `mac|category|first_seen|last_seen`.

- [ ] **Step 1: Write the failing test** `test/follow_test.sh`:

```bash
# test/follow_test.sh  (sourced by run.sh) — continuous-presence escalation (spec §5).
SW_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../payloads/user/reconnaissance/squachwatch" && pwd)"
source "$SW_ROOT/lib/follow.sh"
_T="$(mktemp -d)"; _tf="$_T/track.db"
_D='tracker_findmy|Apple Find My (separated)|med|tracker|ble|F9:C1:A3:83:F0:48||-96'
_E='tracker_tile|Tile|med|tracker|ble|AA:00:00:00:00:02||-81'
_W='flock_alpr|Flock Falcon camera|high|surveillance|wifi|70:C9:4E:11:22:33||-40'

assert_empty "$(sw_follow_update "$_D" 1000 "$_tf" 900 300)" follow_first_sighting_silent
sw_follow_update "$_D" 1299 "$_tf" 900 300 >/dev/null
sw_follow_update "$_D" 1599 "$_tf" 900 300 >/dev/null
assert_empty "$(sw_follow_update "$_D" 1899 "$_tf" 900 300)" follow_silent_at_899s
assert_eq "$(sw_follow_update "$_D" 1900 "$_tf" 900 300)" "tracker_findmy_follow|Apple Find My (separated) — following you 15+ min|high|tracker|ble|F9:C1:A3:83:F0:48||-96" follow_escalates_at_900s
assert_eq "$(cat "$_tf")" "F9:C1:A3:83:F0:48|tracker_findmy|1000|1900" follow_state_line

# a gap longer than GAP breaks continuity: the clock restarts
assert_empty "$(sw_follow_update "$_D" 2201 "$_tf" 900 300)" follow_gap_resets
assert_eq "$(cat "$_tf")" "F9:C1:A3:83:F0:48|tracker_findmy|2201|2201" follow_gap_reset_state

# stale entries are pruned on rewrite, so the file stays bounded
: > "$_tf"
sw_follow_update "$_D" 5000 "$_tf" 900 300 >/dev/null
sw_follow_update "$_E" 5000 "$_tf" 900 300 >/dev/null
sw_follow_update "$_D" 5400 "$_tf" 900 300 >/dev/null
assert_empty "$(grep 'AA:00:00:00:00:02' "$_tf")" follow_prunes_stale
assert_eq "$(cat "$_tf")" "F9:C1:A3:83:F0:48|tracker_findmy|5400|5400" follow_keeps_current

# non-trackers never enter follow: with follow_secs=0 a tracker WOULD escalate at once
_before="$(cat "$_tf")"
assert_empty "$(sw_follow_update "$_W" 6000 "$_tf" 0 300)" follow_ignores_non_tracker
assert_eq "$(cat "$_tf")" "$_before" follow_non_tracker_leaves_state
assert_contains "$(sw_follow_update "$_E" 6000 "$_tf" 0 300)" "tracker_tile_follow|Tile — following you 0+ min|high|" follow_zero_secs_escalates_tracker

# unwritable state: loud (rc 1 + WARN), never a false escalation. A missing parent dir
# makes mktemp fail even for root, unlike chmod.
: > "$SW_STUB_LOG"
_out="$(sw_follow_update "$_D" 7000 "$_T/no/such/dir/track.db" 0 300)"; _rc=$?
assert_eq "$_rc" "1" follow_unwritable_rc
assert_empty "$_out" follow_unwritable_no_escalation
assert_contains "$(cat "$SW_STUB_LOG")" "follow state unwritable" follow_unwritable_warns

# atomic rewrite: the live file is only ever replaced by mv, never written in place
_body="$(sed -n '/^sw_follow_update()/,/^}/p' "$SW_ROOT/lib/follow.sh" | grep -v '^[[:space:]]*#')"
assert_empty "$(printf '%s\n' "$_body" | grep -E '>>? *"\$tf"')" follow_never_writes_live_file
assert_contains "$_body" 'mv -f "$tmp" "$tf"' follow_replaces_via_mv   # control: right body
rm -rf "$_T"; unset _T _tf _D _E _W _before _out _rc _body
```

- [ ] **Step 2: Run and verify failures**

Run: `bash test/run.sh 2>&1 | grep -E 'FAIL|PASS='`
Expected: a `source: ... follow.sh: No such file` error, then FAILs for `follow_escalates_at_900s`, `follow_state_line`, `follow_zero_secs_escalates_tracker`, `follow_unwritable_rc`, `follow_replaces_via_mv`, and others.

- [ ] **Step 3: Implement** `payloads/user/reconnaissance/squachwatch/lib/follow.sh`:

```bash
#!/bin/bash
# lib/follow.sh — escalate a tracker that STAYS with you (Tier-3 spec §5).
#
# A tracker that is merely nearby is logged at med by sw_emit. One seen continuously for
# FOLLOW_SECS becomes a second, HIGH-confidence detection "<category>_follow", which sw_emit
# turns into a full ALERT with its own mac+category cooldown.
# State: one line per tracker, "mac|category|first_seen|last_seen".
# Runs per tracker DETECTION (a handful per lap), not per record, so it may fork.

sw_follow_update() {
  # $1=detection $2=now $3=trackfile $4=follow_secs $5=gap_secs
  # Prints the escalated detection, or nothing. rc 1 if the state could not be written.
  local det="$1" now="$2" tf="$3" follow="$4" gap="$5"
  local cat label conf tclass radio mac ident rssi r
  cat="${det%%|*}";  r="${det#*|}"
  label="${r%%|*}";  r="${r#*|}"
  conf="${r%%|*}";   r="${r#*|}"
  tclass="${r%%|*}"; r="${r#*|}"
  radio="${r%%|*}";  r="${r#*|}"
  mac="${r%%|*}";    r="${r#*|}"
  ident="${r%%|*}";  rssi="${r#*|}"
  [ "$tclass" = tracker ] || return 0
  local key="$mac|$cat" first="$now" tmp line k f l
  # Rewrite via a temp file + mv, so a kill mid-write can't truncate the state.
  if ! tmp="$(mktemp "$tf.XXXXXX" 2>/dev/null)"; then
    LOG yellow "WARN: follow state unwritable ($tf) — follow alerts OFF" 2>/dev/null
    return 1
  fi
  if [ -f "$tf" ]; then
    while IFS= read -r line; do
      [ -n "$line" ] || continue
      l="${line##*|}"; f="${line%|*}"; f="${f##*|}"; k="${line%|*|*}"
      [ $((now - l)) -le "$gap" ] || continue            # prune: gone longer than the gap
      if [ "$k" = "$key" ]; then first="$f"; continue; fi   # continuous: keep its clock
      printf '%s\n' "$line" >> "$tmp"
    done < "$tf"
  fi
  printf '%s|%s|%s\n' "$key" "$first" "$now" >> "$tmp"
  mv -f "$tmp" "$tf" || { rm -f "$tmp"; return 1; }
  if [ $((now - first)) -ge "$follow" ]; then
    printf '%s_follow|%s — following you %d+ min|high|%s|%s|%s|%s|%s\n' \
      "$cat" "$label" $(( (now - first) / 60 )) "$tclass" "$radio" "$mac" "$ident" "$rssi"
  fi
}
```

- [ ] **Step 4: Run and verify all pass**

Run: `bash test/run.sh 2>&1 | grep -E 'FAIL|PASS='`
Expected: `FAIL=0`.

- [ ] **Step 5: Commit**

```bash
git add payloads/user/reconnaissance/squachwatch/lib/follow.sh test/follow_test.sh
git commit -m "feat(follow): escalate a tracker seen continuously for SW_FOLLOW_SECS

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 7: Ignore list (`lib/ignore.sh`)

**Files:**
- Create: `payloads/user/reconnaissance/squachwatch/lib/ignore.sh`, `test/ignore_test.sh`

**Interfaces:**
- Produces: `sw_load_ignore FILE` prints a space-padded, uppercased set `" MAC1 MAC2 "` (`" "` when the file is missing or empty). `sw_ignored DETECTION SET` → rc 0 when the detection's MAC column (field 6) is in the set. It's fork-free.

- [ ] **Step 1: Write the failing test** `test/ignore_test.sh`:

```bash
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
sw_ignored "$_D" " "; assert_eq "$?" "1" ignore_empty_set_keeps_all
# only the MAC column counts: a listed MAC appearing as an advertised NAME is not a match
_X='hacker_flipper|Flipper Zero|high|attacker|ble|80:E1:26:00:00:01|F9:C1:A3:83:F0:48|-60'
sw_ignored "$_X" "$_set"; assert_eq "$?" "1" ignore_matches_mac_column_only
rm -rf "$_T"; unset _T _set _D _X
```

- [ ] **Step 2: Run and verify failures**

Run: `bash test/run.sh 2>&1 | grep -E 'FAIL|PASS='`
Expected: `ignore_load_normalises` and `ignore_listed_mac_dropped` FAIL (command not found gives rc 127, not 0).

- [ ] **Step 3: Implement** `payloads/user/reconnaissance/squachwatch/lib/ignore.sh`:

```bash
#!/bin/bash
# lib/ignore.sh — the owner's own devices (Tier-3 spec §6). Without this, your own Tile or
# SmartTag in your bag would raise a follow alert every cooldown forever. The file lives in
# the loot dir so a payload redeploy never overwrites it; it is read once at startup.

sw_load_ignore() {
  # $1 = ignore file: one MAC per line, '#' comments, any case, CRLF tolerated.
  # Prints " MAC1 MAC2 " (upper-case, space-padded) for a fork-free membership test.
  local line set=" "
  if [ -f "$1" ]; then
    while IFS= read -r line; do
      line="${line%%#*}"; line="${line//[[:space:]]/}"
      [ -n "$line" ] && set="$set${line^^} "
    done < "$1"
  fi
  printf '%s' "$set"
}

sw_ignored() {
  # $1 = detection (cat|label|conf|tclass|radio|mac|ident|rssi), $2 = sw_load_ignore set.
  # rc 0 = drop it. Only the MAC column is compared.
  local r="${1#*|*|*|*|*|}"
  case "$2" in *" ${r%%|*} "*) return 0 ;; esac
  return 1
}
```

- [ ] **Step 4: Run and verify all pass**

Run: `bash test/run.sh 2>&1 | grep -E 'FAIL|PASS='`
Expected: `FAIL=0`.

- [ ] **Step 5: Commit**

```bash
git add payloads/user/reconnaissance/squachwatch/lib/ignore.sh test/ignore_test.sh
git commit -m "feat(ignore): drop the owner's own devices before follow/emit

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 8: Wire it into `payload.sh` (+ README)

**Files:**
- Modify: `payloads/user/reconnaissance/squachwatch/payload.sh`, `test/payload_test.sh`, `README.md`

**Interfaces:**
- Consumes: `sw_follow_update` (Task 6), `sw_load_ignore` / `sw_ignored` (Task 7), `sw_ble_scan` (Task 5).
- Produces: payload defaults `SW_FOLLOW_SECS=900`, `SW_FOLLOW_GAP=300`, `SW_TRACK_FILE=$SW_LOOT_DIR/track.db`, `SW_IGNORE_FILE=$SW_LOOT_DIR/ignore.txt`; `SW_IGNORE_SET` loaded at startup; and a `btmon missing` health warning.

- [ ] **Step 1: Write the failing tests.** Append to `test/payload_test.sh`, before the final `rm -rf "$SW_LOOT_DIR" "$SW_SEEN_FILE"` line:

```bash
# --- Tier-3 wiring ---
# follow is wired into the lap: with SW_FOLLOW_SECS=0 a tracker escalates on first sight
: > "$SW_STUB_LOG"; : > "$SW_SEEN_FILE"
SW_FOLLOW_SECS=0 sw_scan_once
assert_contains "$(cat "$SW_STUB_LOG")" "following you" payload_follow_alerts
assert_contains "$(cat "$SW_LOOT_DIR/detections.csv")" "tracker_smarttag_follow" payload_follow_logged
# control: with the real default nothing escalates on a first sighting, but presence is logged.
# Fresh CSV: rows left by the scan above would otherwise satisfy this vacuously.
# "${SW_TRACK_FILE:-}" because the variable only exists once Step 3 lands (set -u in RED).
: > "$SW_STUB_LOG"; : > "$SW_SEEN_FILE"; rm -f "${SW_TRACK_FILE:-}"
rm -f "$SW_LOOT_DIR/detections.csv"; sw_log_init "$SW_LOOT_DIR"
sw_scan_once
assert_empty "$(grep 'following you' "$SW_STUB_LOG")" payload_no_follow_on_first_sight
assert_contains "$(cat "$SW_LOOT_DIR/detections.csv")" 'tracker_smarttag,"Samsung SmartTag",med,tracker' payload_presence_logged   # the CSV is comma-delimited with a quoted label

# ignore is wired in before emit AND follow
rm -f "$SW_LOOT_DIR/detections.csv" "${SW_TRACK_FILE:-}"; : > "$SW_SEEN_FILE"; sw_log_init "$SW_LOOT_DIR"
SW_IGNORE_SET=" AA:00:00:00:00:02 " sw_scan_once
assert_empty "$(grep 'AA:00:00:00:00:02' "$SW_LOOT_DIR/detections.csv")" payload_ignore_drops_row
assert_empty "$(grep 'AA:00:00:00:00:02' "${SW_TRACK_FILE:-/dev/null}" 2>/dev/null)" payload_ignore_skips_follow
assert_contains "$(cat "$SW_LOOT_DIR/detections.csv")" "AA:00:00:00:00:01" payload_ignore_control_other_tracker_kept

# btmon missing must be LOUD. The dev box has a real /usr/bin/btmon, so build a PATH with
# only what sw_healthcheck needs and no btmon at all.
_bin="$(mktemp -d)"; _stubs="$(cd "$(dirname "${BASH_SOURCE[0]}")/stubs" && pwd)"
ln -s "$_stubs/LOG" "$_bin/LOG"; ln -s "$_stubs/sqlite3" "$_bin/sqlite3"; ln -s "$(command -v bash)" "$_bin/bash"
: > "$SW_STUB_LOG"
PATH="$_bin" sw_healthcheck; _hc=$?
assert_eq "$_hc" "1" health_btmon_missing_rc
assert_contains "$(cat "$SW_STUB_LOG")" "btmon missing" health_btmon_missing_warns
rm -rf "$_bin"; unset _bin _stubs _hc

# defaults, asserted in a CLEAN process (a lib-level := would otherwise shadow them)
_defs="$(env -u SW_FOLLOW_SECS -u SW_FOLLOW_GAP -u SW_TRACK_FILE -u SW_IGNORE_FILE -u SW_LOOT_DIR \
  bash -c 'SW_TEST_SOURCE=1 . "$1"/payload.sh >/dev/null 2>&1; echo "$SW_FOLLOW_SECS|$SW_FOLLOW_GAP|$SW_TRACK_FILE|$SW_IGNORE_FILE"' _ "$SW_ROOT")"
assert_eq "$_defs" "900|300|/root/loot/squachwatch/track.db|/root/loot/squachwatch/ignore.txt" payload_default_follow_and_ignore
unset _defs
```

- [ ] **Step 2: Run and verify failures**

Run: `bash test/run.sh 2>&1 | grep -E 'FAIL|PASS='`
Expected FAILs: `payload_follow_alerts`, `payload_follow_logged`, `payload_ignore_drops_row`, `health_btmon_missing_rc`, `health_btmon_missing_warns`, `payload_default_follow_and_ignore`. `payload_presence_logged` already PASSES (Tasks 3 and 5 put tracker presence through `sw_emit`), which is its job as a control.

- [ ] **Step 3: Implement in `payload.sh`.**

Source the new libs: `for l in match wifi ble alert log follow ignore; do . "$SW_HOME/lib/$l.sh"; done`.

After `: "${SW_HEALTH_EVERY:=20}"`, add:

```bash
# Tier-3 follow detection: a tracker seen continuously for SW_FOLLOW_SECS escalates from a
# logged presence to a full alert; a gap longer than SW_FOLLOW_GAP restarts its clock.
: "${SW_FOLLOW_SECS:=900}"
: "${SW_FOLLOW_GAP:=300}"
: "${SW_TRACK_FILE:=$SW_LOOT_DIR/track.db}"
# The owner's own devices, one MAC per line. Lives in the loot dir so redeploys keep it.
: "${SW_IGNORE_FILE:=$SW_LOOT_DIR/ignore.txt}"
```

After `SW_SIGS="$(sw_load_signatures "$SW_HOME/signatures.db")"`, add:

```bash
SW_IGNORE_SET="$(sw_load_ignore "$SW_IGNORE_FILE")"
```

In `sw_healthcheck`, before `return $degraded`, add:

```bash
  # btmon is the only BLE data source (Tier-3): without it every BLE lap is empty.
  if ! command -v btmon >/dev/null 2>&1; then
    LOG yellow "WARN: btmon missing — BLE detection OFF" 2>/dev/null; degraded=1
  fi
```

Replace `sw_scan_once` with:

```bash
sw_scan_once() {
  local now fdet; now="$(date +%s)"
  { sw_wifi_records "$SW_RECON_DB"; _sw_ble_records; } \
    | sw_match_stream "$SW_SIGS" \
    | while IFS= read -r det; do
        [ -n "$det" ] || continue
        sw_ignored "$det" "$SW_IGNORE_SET" && continue
        sw_emit "$det" "$now" "$SW_COOLDOWN" "$SW_SEEN_FILE" "$SW_LOOT_DIR"
        # A tracker that has stayed with us escalates to its own high-confidence detection.
        fdet="$(sw_follow_update "$det" "$now" "$SW_TRACK_FILE" "$SW_FOLLOW_SECS" "$SW_FOLLOW_GAP")"
        [ -n "$fdet" ] && sw_emit "$fdet" "$now" "$SW_COOLDOWN" "$SW_SEEN_FILE" "$SW_LOOT_DIR"
      done
}
```

In `test/payload_test.sh`, extend the final `unset` line with `SW_FOLLOW_SECS SW_FOLLOW_GAP SW_TRACK_FILE SW_IGNORE_FILE SW_IGNORE_SET` (the payload sets them when sourced).

- [ ] **Step 4: Run and verify all pass**

Run: `bash test/run.sh 2>&1 | grep -E 'FAIL|PASS='`
Expected: `FAIL=0`.

- [ ] **Step 5: README.**
  - Intro sentence: replace `` and `hcitool` for Bluetooth `` with `` and `btmon` for Bluetooth (decoding each advertisement, so it can spot trackers that broadcast no name) ``.
  - "What's in the box": replace `` `ble.sh` (hcitool parse) `` with `` `ble.sh` (btmon capture + parse) ``, and after `` `log.sh` (CSV loot log) `` add `` , `follow.sh` (tracker-following escalation), `ignore.sh` (your own devices) ``.
  - After the settings bullets (`SW_RECENCY_SECS`, `SW_COOLDOWN`), add:

    ```
    - `SW_FOLLOW_SECS` (default 900) / `SW_FOLLOW_GAP` (default 300): a tracker separated from its owner (AirTag / Find My, SmartTag, Tile, Google Find My) is only *logged* when seen. If the same one keeps showing up for `SW_FOLLOW_SECS` with no gap longer than `SW_FOLLOW_GAP`, it escalates to a full "following you" alert.
    - `/root/loot/squachwatch/ignore.txt`: your own devices, one MAC per line (`#` comments allowed). They're skipped entirely, so your own Tile never alerts. It's read at launch.
    ```
  - Status & roadmap: delete the "Tier-3 raw-BLE-advertisement detection" bullet under "Deferred to their own phases", and add to the status paragraph: `**Tier 3 (raw BLE advertisements)** is built: name-less trackers are logged on sight and alert only when one stays with you; Raven gunshot sensors are logged at low confidence. Known limits: follow detection needs the tracker to keep its address (true for separated AirTags and Tiles; Google Find My rotates about every 17 min) and is time-only, since GPS rarely has a fix.`
  - Tests: update the assertion count in `**N assertions, all passing**` to the new `PASS=` total.

- [ ] **Step 6: Commit**

```bash
git add payloads/user/reconnaissance/squachwatch/payload.sh test/payload_test.sh README.md
git commit -m "feat(payload): wire Tier-3 follow + ignore into the lap; btmon health check

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```

---

### Task 9: Deploy + on-device verification (spec §9)

**Files:**
- Modify: `docs/superpowers/P0-findings.md` (results section)

This task is verification on real hardware. Every step records its actual output in P0-findings, including failures. A step that can't run (Pager unreachable, no tracker in range) is reported as NOT RUN, never as passed.

- [ ] **Step 1: Full suite green, then deploy**

```bash
cd <repo>
bash test/run.sh 2>&1 | tail -1                                   # expect FAIL=0
scp -q -r payloads/user/reconnaissance/squachwatch root@172.16.52.1:/root/payloads/user/reconnaissance/
ssh root@172.16.52.1 'cd /root/payloads/user/reconnaissance/squachwatch && chmod +x payload.sh && for f in payload.sh lib/*.sh; do bash -n "$f" || echo "SYNTAX FAIL $f"; done; ls lib/'
```
Expected: no `SYNTAX FAIL`, and `lib/` lists `alert.sh ble.sh follow.sh ignore.sh log.sh match.sh wifi.sh`.

- [ ] **Step 2: A real lap's BLE records carry tokens** (spec §9.3, plus a parse-time check on the real CPU)

```bash
ssh root@172.16.52.1 'cd /root/payloads/user/reconnaissance/squachwatch && bash -c ". lib/match.sh; . lib/ble.sh; s=\$(date +%s); r=\$(sw_ble_scan 12 hci0); e=\$(date +%s); printf \"%s\n\" \"\$r\"; echo \"records=\$(printf \"%s\n\" \"\$r\" | grep -c ^ble) seconds=\$((e-s)) state=\$(cat /tmp/sw_ble.state)\""'
```
Expected: records with `mfr:` / `uuid:` / `sd:` tokens; the Flipper `80:E1:26:FA:D6:22|MyFlipper|…|uuid:3082`; `state=ok`; `seconds` ≈ 13–15 (12 s scan + 1 s attach + parse).

- [ ] **Step 3: Matches against the real signatures** (spec §9.1, §9.2)

```bash
ssh root@172.16.52.1 'cd /root/payloads/user/reconnaissance/squachwatch && bash -c ". lib/match.sh; . lib/ble.sh; S=\$(sw_load_signatures signatures.db); r=\$(sw_ble_scan 12 hci0); printf \"%s\n\" \"\$r\" | grep -E \"mfr:004c:12:\"; echo ---; printf \"%s\n\" \"\$r\" | sw_match_stream \"\$S\""'
```
Expected: every record carrying `mfr:004c:12:25` produces a `tracker_findmy|…|med|tracker` detection; records carrying only `mfr:004c:12:2` or `mfr:004c:10:*` produce none; the Flipper produces `hacker_flipper`. If no separated Find My device is in range, record "§9.1 NOT RUN: no 004c:12:25 in range" and rely on the fixture tests.

- [ ] **Step 4: Follow fires for real** (spec §9.4). **This buzzes the Pager.** Use a throwaway loot dir and a short follow window:

```bash
ssh root@172.16.52.1 'rm -rf /tmp/sw_verify_loot; cd /root/payloads/user/reconnaissance/squachwatch && SW_LOOT_DIR=/tmp/sw_verify_loot SW_FOLLOW_SECS=60 SW_FOLLOW_GAP=300 timeout 150 bash ./payload.sh >/dev/null 2>&1; echo "--- csv"; cat /tmp/sw_verify_loot/detections.csv; echo "--- track"; cat /tmp/sw_verify_loot/track.db'
```
Expected: presence rows (`tracker_*|…|med`) and, for any tracker present for at least 60 s, a `*_follow|… — following you 1+ min|high` row. If no tracker was in range, record NOT RUN. Leave `/tmp/sw_verify_loot` for the user to inspect, and say so in the report.

- [ ] **Step 5: The scan-failure warning fires on the device** (spec §9.5). A nonexistent interface makes the real `hcitool` fail, so the real capture has no successful scan-enable:

```bash
ssh root@172.16.52.1 'cd /root/payloads/user/reconnaissance/squachwatch && rm -f /tmp/sw_ble.state && bash -c ". lib/match.sh; . lib/ble.sh; r=\$(sw_ble_scan 3 hci9); echo \"records=[\$r] state=\$(cat /tmp/sw_ble.state)\""; rm -f /tmp/sw_ble.state'
```
Expected: `records=[] state=scan_failed`, and a yellow `WARN: BLE scan failed to start` on the Pager's log screen (ask the user to confirm they saw it, or note it as unconfirmed). This deviates from the spec's "skip the hci0 reset" wording: `sw_ble_scan` always resets, and a bogus interface drives the same `scan_failed` path through the real tools.

- [ ] **Step 6: No leftovers**

```bash
ssh root@172.16.52.1 'ls /tmp/sw_ble.* 2>/dev/null; ps w | grep -E "[b]tmon|[h]citool" || echo "no stray btmon/hcitool"'
```
Expected: no capture files (a `/tmp/sw_ble.state` may remain, which is fine) and `no stray btmon/hcitool`.

- [ ] **Step 7 (GATED: ask the user first; do NOT run without an explicit yes):** replace the synthetic SmartTag / Tile / Google Find My fixtures' *values* with real captures by having the user's desktop Bluetooth adapter, or a phone running nRF Connect, advertise those packets while the Pager captures. The service-data *format* is already device-verified (the live capture's `sd:fcf1:04`), so this step only confirms the specific UUID and frame values. If the user declines, record "§9.6 declined; values remain spec-inferred".

- [ ] **Step 8: Record results and commit.** Append a "Tier-3 on-device verification (YYYY-MM-DD, the day you run it)" section to `docs/superpowers/P0-findings.md` with the actual output of Steps 2–6 (trimmed), each marked PASS / FAIL / NOT RUN, then:

```bash
git add docs/superpowers/P0-findings.md
git commit -m "docs: Tier-3 on-device verification results

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"
```
