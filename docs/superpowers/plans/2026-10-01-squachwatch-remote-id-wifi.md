# SquachWatch-Pager Remote ID over WiFi Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Decode drone Remote ID from WiFi (ASD-STAN and Parrot beacons, and NAN action frames) into the drone's ID, position, motion and the pilot's location, raised as a high-confidence buzzing detection and logged as a per-lap flight track.

**Architecture:** A new `lib/remoteid.sh` runs a bounded `tcpdump` window each lap on the recon radio `wlan1mon` (read only, `-p`, piggybacking recon's channel hopping), through a BPF filter that pre-selects beacons and NAN-addressed action frames. A single streaming `awk` program decodes the frames into one line per transmitter address, emitting integers/empty/lowercase-hex only. Bash then turns each line into the existing detection format (a new ninth, display-only field carries the human detail) and a `remoteid.csv` row, and feeds the detections into the same emit loop as the evil-twin check. The cooldown, ignore list and alert all key on the drone's ID.

**Tech Stack:** bash 5 on a BusyBox userland (the Pager; the payload is `#!/bin/bash`); `tcpdump` 4.99.5 + radiotap (stock firmware); BusyBox `awk` 1.36.1; the repo's bash test harness (`bash test/run.sh`). The fixture generator (dev box only) is C compiled against opendroneid-core-c.

**Spec:** `docs/superpowers/specs/2026-10-01-squachwatch-remote-id-wifi-design.md` (approved 2026-10-01; amended by this plan's Task 7). A de-risking spike on 2026-10-01 proved the whole pipeline end to end: the generator builds real frames, the real `tcpdump` prints them, the BPF filter selects beacon + NAN and rejects others, and the decoder reads every field correctly with **byte-identical output on mawk and BusyBox awk**. All code below is from that spike.

## Global Constraints

- **Public repository.** Made-up IDs, MACs, network names and coordinates only, in tests, fixtures, docs and commit messages. Never a real drone serial, address, pilot position, network name, date or time, and never a local path (`/home/...`). A real capture is scrubbed before it is ever committed (§Task 7 and `reference_public_release_privacy_checklist`).
- **Commits:** `TZ=UTC git -c user.name=Ziggy -c user.email=79704039+therealziggy@users.noreply.github.com commit ...`. Every message ends with exactly ONE line `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, copied verbatim — never another model name. Subject style `area: what changed` (`remoteid: …`, `payload: …`, `alert: …`, `tools: …`, `docs: …`). Verify the trailer with `grep -cF` after each commit.
- **Do not push, and do not touch the Pager.** The controller does both, with the user's OK (§After the tasks).
- **The Pager runs bash on BusyBox:** no `[:class:]` in `tr`; a `mktemp` template ends in `XXXXXX` with nothing after it; no `od`, `hexdump`, `diff`, `paste`, `tshark` on the device. `tcpdump`, `iw`, `nice`, `mkfifo` are present.
- **awk must run on BusyBox awk 1.36.1.** No gawk extensions, no `0x..` numeric literals (BusyBox and mawk do not parse them — use decimal), hex via a lookup table. Proven byte-identical to mawk in the spike.
- **Per-record / per-row code is fork-free:** inside any loop that runs per frame or per result row, builtins only (no `$( )`, backticks, `tr`/`sed`/`cut`/`awk`/`grep`). Helpers answer in `REPLY`. `test/perf_test.sh` enforces this. The decode heavy lifting is in ONE awk process per lap, not per frame; bash runs only per drone (a handful per lap).
- **No `:=` defaults in `lib/*.sh`.** `payload.sh` sources its libs before its config block, so a lib default would win. Read variables as `${VAR:-x}` at the point of use.
- **The capture is read-only.** `tcpdump -p` (never `-I`, never `iw ... set`): the monitor interface is never reconfigured, so recon keeps it. Everything the capture starts ends by its own `timeout`/`-c`; nothing is ever found or killed by name (the guard in `payload_test.sh` already forbids `killall`/`pkill`/`pidof`/`pgrep`).
- **Hostile input.** Remote ID is unauthenticated and spoofable. Every length and offset is bounds-checked; one bad frame never ends the lap or hides a later frame; text leaves awk as hex and becomes text only through `sw_sanitize_ident`, then `_sw_csv_field` for the CSV.
- **Tests:** every "stays silent / nothing" assertion has a positive control (a sibling case that fires on the same data). `test/run.sh` sources every `*_test.sh` into one shell, so clean up variables/functions at the end of each block. `bash test/run.sh` must end `FAIL=0`; baseline before this plan is `PASS=874 FAIL=0`. Its output must stay clean: `bash test/run.sh 2>&1 | grep -v -E '^(== |  FAIL|-----|PASS=)'` prints nothing.
- **Functions the payload's main shell runs** (`sw_main`, `sw_prune_ledger`, `sw_seen_prune`, `sw_clear_tmp`, `sw_log_init`, `sw_cleanup`, and `sw_healthcheck`'s own body) never use `continue`/`break` (a trapped SIGINT is dropped there). The decode/collect code runs inside `sw_scan_once`'s pipeline subshell, which the Stop never signals, so it may use them.
- The lib path prefix `payloads/user/reconnaissance/squachwatch/` is written `$SQ/` below.

## File structure

| File | Change | Responsibility |
|---|---|---|
| `tools/rid_fixtures/gen.c` | create | builds Remote ID frames with opendroneid-core-c and writes `LINKTYPE_IEEE802_11_RADIO` pcaps (dev box only) |
| `tools/rid_fixtures/build.sh` | create | fetches + checksum-verifies the three pinned opendroneid-core-c files, compiles `gen`, emits the pcaps, runs the real `tcpdump` to produce the committed fixture text |
| `test/fixtures/rid/*.pcap`, `test/fixtures/rid/*.txt` | create | committed fixtures: the pcaps and their `tcpdump -nn -xx` text; tests read the `.txt` |
| `$SQ/lib/remoteid.sh` | create | `_sw_rid_decode_awk` (the decoder), `sw_rid_records` (lines → detections + `remoteid.csv`), `sw_rid_start` / `sw_rid_collect` (the per-lap capture), `sw_rid_health_note` |
| `$SQ/lib/alert.sh` | modify | `sw_emit` reads a 9th field and, for `drone_rid`, names the drone, prints the detail line, and lays out the alert body |
| `$SQ/lib/ignore.sh` | modify | `drone_rid` is silenced only by `drone:<ID>` (or `drone:<MAC>` with no ID) |
| `$SQ/lib/log.sh` | modify | `sw_log_write` reads the 9th field (and ignores it) so `rssi` stays clean |
| `$SQ/lib/follow.sh` | modify | cut `rssi` at the next `|` so a 9-field record parses cleanly |
| `$SQ/payload.sh` | modify | load `remoteid`, the `SW_RID_*` config, wire the capture into `sw_scan_once`, the startup health check |
| `test/stubs/tcpdump` | create | models the device `tcpdump` for the e2e test |
| `test/helpers/rid.sh` | create | `sw_test_rid_lines` (synthetic D/S lines) for the bash-side tests |
| `test/remoteid_test.sh` | create | decoder + records + capture tests |
| `test/alert_test.sh`, `test/ignore_test.sh`, `test/payload_test.sh`, `test/perf_test.sh`, `test/portability_test.sh` | modify | wiring + guards |
| `README.md`, `docs/superpowers/P0-findings.md`, the spec | modify | docs |

**The decoder's output contract** (both producers and consumers depend on it; fixed here):
- Stats line: `S<TAB>frames<TAB>understood<TAB>rid_frames<TAB>more_drones`
- Drone line, `D` then 24 TAB-separated fields, each an integer, empty, or lowercase hex:
  `D mac rssi forms id_type id_hex id2_type id2_hex ua_type status lat lon alt_geo alt_baro height height_ref speed vspeed heading pilot_type pilot_lat pilot_lon pilot_alt operator_id_hex self_id_hex`
  - `mac` 12 lowercase hex; `rssi` signed int or empty; `forms` bitmask (1 ASD-STAN beacon, 2 NAN, 4 Parrot);
  - `lat`/`lon`/`pilot_lat`/`pilot_lon` raw signed 1e7 int, empty when unknown/out of range;
  - `alt_geo`/`alt_baro`/`height`/`pilot_alt` raw `uint16` encoding (metres = enc·0.5 − 1000), empty when 0;
  - `speed` centi-m/s, `vspeed` deci-m/s (signed), `heading` whole degrees, each empty when the standard's "unknown";
  - `id_hex`/`id2_hex`/`operator_id_hex`/`self_id_hex` lowercase hex of the raw bytes, trailing `00` trimmed.

---

### Task 1: Fixture generator and committed fixtures

**Files:**
- Create: `tools/rid_fixtures/gen.c`, `tools/rid_fixtures/build.sh`
- Create (generated, committed): `test/fixtures/rid/{beacon,nan,parrot,multi,unknowns,quiet,badlink,truncated}.pcap` and matching `.txt`
- Test: `test/remoteid_test.sh` (new; a fixtures-present guard)

**Interfaces:**
- Produces: committed fixture text files in `test/fixtures/rid/` in `tcpdump -nn -xx` form (radiotap carrying a `dBm signal` field, then the 802.11 frame). These are the inputs to Task 2. `build.sh` regenerates them from the pinned opendroneid-core-c (`6484f26545d4f012682524e2d843fab0fbdc0b34`).

- [ ] **Step 1: Write the failing guard test.** Create `test/remoteid_test.sh`:

```bash
#!/bin/bash
# test/remoteid_test.sh — Remote ID over WiFi (spec 2026-10-01). Reads committed fixtures under
# test/fixtures/rid/ (generated by tools/rid_fixtures/build.sh from opendroneid-core-c).
SW_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../payloads/user/reconnaissance/squachwatch" && pwd)"
_RFIX="$(cd "$(dirname "${BASH_SOURCE[0]}")/fixtures" && pwd)/rid"

# Task 1: the fixtures exist and look like tcpdump -xx output (radiotap + a decodable frame).
for _f in beacon nan parrot multi unknowns quiet badlink truncated; do
  assert_eq "$([ -s "$_RFIX/$_f.txt" ] && echo ok)" "ok" "rid_fixture_present_$_f"
done
assert_contains "$(cat "$_RFIX/beacon.txt")" "0x0000:" rid_fixture_is_hex_dump
assert_contains "$(cat "$_RFIX/beacon.txt")" "dBm signal" rid_fixture_has_signal
```

- [ ] **Step 2: Run it to see it fail.**
Run: `bash test/run.sh 2>&1 | grep -E 'rid_fixture|PASS='`
Expected: FAIL `rid_fixture_present_beacon` … (the files do not exist yet).

- [ ] **Step 3: Create `tools/rid_fixtures/gen.c`** (verified in the spike; builds each frame type, writes a pcap whose radiotap carries a `dBm antenna signal` field so the decoder's rssi path is exercised):

```c
/* tools/rid_fixtures/gen.c — build Remote ID WiFi frames with opendroneid-core-c and write a
 * LINKTYPE_IEEE802_11_RADIO pcap. Dev box only; never installed on the Pager. See build.sh.
 * Usage: gen <kind> <out.pcap>   kind = beacon | nan | parrot | multi | unknowns | quiet | truncated
 * (badlink is made by build.sh rewriting the pcap link type.) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "opendroneid.h"

static void put32(FILE *f, uint32_t v) { fwrite(&v, 4, 1, f); }
static void put16(FILE *f, uint16_t v) { fwrite(&v, 2, 1, f); }

/* one packet: radiotap {version0, pad0, len9, present=dBm-signal(0x20), signal byte}, then frame */
static void write_pcap(const char *path, const uint8_t *frame, int flen, int8_t sig) {
    FILE *f = fopen(path, "wb");
    uint8_t rtap[9] = {0, 0, 9, 0, 0x20, 0, 0, 0, (uint8_t)sig};
    uint32_t caplen = (uint32_t)(sizeof(rtap) + flen);
    put32(f, 0xa1b2c3d4); put16(f, 2); put16(f, 4); put32(f, 0); put32(f, 0);
    put32(f, 262144); put32(f, 127);                 /* snaplen, LINKTYPE_IEEE802_11_RADIO */
    put32(f, 1700000000); put32(f, 0);
    put32(f, caplen); put32(f, caplen);
    fwrite(rtap, sizeof(rtap), 1, f); fwrite(frame, flen, 1, f);
    fclose(f);
}

/* a fully-populated drone: serial, airframe, airborne location, live operator, operator id */
static void full_drone(ODID_UAS_Data *d) {
    odid_initUasData(d);
    d->BasicID[0].UAType = ODID_UATYPE_HELICOPTER_OR_MULTIROTOR;
    d->BasicID[0].IDType = ODID_IDTYPE_SERIAL_NUMBER;
    strncpy(d->BasicID[0].UASID, "0000FSWTEST000000001", ODID_ID_SIZE);
    d->BasicIDValid[0] = 1;
    d->Location.Status = ODID_STATUS_AIRBORNE;
    d->Location.Direction = 215.0f;
    d->Location.SpeedHorizontal = 12.0f;
    d->Location.SpeedVertical = 3.0f;
    d->Location.Latitude = 47.397760; d->Location.Longitude = 8.545420;
    d->Location.AltitudeGeo = 520.0f; d->Location.Height = 87.0f;
    d->Location.HeightType = ODID_HEIGHT_REF_OVER_TAKEOFF;
    d->LocationValid = 1;
    d->System.OperatorLocationType = ODID_OPERATOR_LOCATION_TYPE_LIVE_GNSS;
    d->System.OperatorLatitude = 47.398000; d->System.OperatorLongitude = 8.541020;
    d->SystemValid = 1;
    d->OperatorID.OperatorIdType = 0;
    strncpy(d->OperatorID.OperatorId, "FIN87astrdge12k8", ODID_ID_SIZE);
    d->OperatorIDValid = 1;
}

int main(int argc, char **argv) {
    if (argc < 3) { fprintf(stderr, "usage: gen <kind> <out.pcap>\n"); return 2; }
    const char *kind = argv[1], *out = argv[2];
    ODID_UAS_Data d; memset(&d, 0, sizeof(d));
    full_drone(&d);
    const char *mac = "\x80\xE1\x26\xAA\xBB\xCC";

    if (!strcmp(kind, "unknowns")) {           /* everything the standard marks "unknown/no value" */
        d.Location.Latitude = 0; d.Location.Longitude = 0;
        d.Location.AltitudeGeo = -1000; d.Location.Height = -1000;
        d.Location.SpeedHorizontal = 255; d.Location.SpeedVertical = 63; d.Location.Direction = 361;
        d.System.OperatorLatitude = 0; d.System.OperatorLongitude = 0;
    }
    if (!strcmp(kind, "quiet")) {              /* an ordinary (non-RID) beacon: a positive control */
        uint8_t fr[128]; int n = 0;
        uint8_t hdr[] = {0x80,0,0,0, 0xff,0xff,0xff,0xff,0xff,0xff, 0x11,0x22,0x33,0x44,0x55,0x66,
                         0x11,0x22,0x33,0x44,0x55,0x66, 0,0, 0,0,0,0,0,0,0,0, 0x64,0, 0x04,0x20,
                         0x00,0x04,'H','o','m','e', 0x01,0x01,0x8c};
        memcpy(fr, hdr, sizeof(hdr)); n = sizeof(hdr);
        write_pcap(out, fr, n, -55); return 0;
    }

    uint8_t frame[1024]; int flen;
    if (!strcmp(kind, "nan"))
        flen = odid_wifi_build_message_pack_nan_action_frame(&d, mac, 0, frame, sizeof(frame));
    else
        flen = odid_wifi_build_message_pack_beacon_frame(&d, mac, "TEST-DRONE", 10, 100, 0, frame, sizeof(frame));
    if (flen < 0) { fprintf(stderr, "build failed %d\n", flen); return 1; }

    if (!strcmp(kind, "parrot")) {             /* rewrite the ASD-STAN OUI+type to Parrot's OUI */
        for (int i = 36; i + 6 < flen; i++)
            if (frame[i] == 0xdd && frame[i+2] == 0xfa && frame[i+3] == 0x0b && frame[i+4] == 0xbc) {
                frame[i+2] = 0x90; frame[i+3] = 0x3a; frame[i+4] = 0xe6; frame[i+5] = 0x00; break;
            }
    }
    if (!strcmp(kind, "multi")) {              /* two drones: write the first, then a second serial */
        write_pcap(out, frame, flen, -47);
        ODID_UAS_Data d2; memset(&d2, 0, sizeof(d2)); full_drone(&d2);
        strncpy(d2.BasicID[0].UASID, "0000FSWTEST000000002", ODID_ID_SIZE);
        d2.Location.Latitude = 48.100000; d2.Location.Longitude = 9.200000;
        uint8_t f2[1024];
        int l2 = odid_wifi_build_message_pack_beacon_frame(&d2, "\x80\xE1\x26\x11\x22\x33",
                     "DRONE-TWO", 9, 100, 0, f2, sizeof(f2));
        /* append the second packet to the pcap just written */
        FILE *f = fopen(out, "ab");
        uint8_t rtap[9] = {0,0,9,0,0x20,0,0,0,(uint8_t)-61};
        uint32_t cap = (uint32_t)(sizeof(rtap) + l2);
        put32(f, 1700000001); put32(f, 0); put32(f, cap); put32(f, cap);
        fwrite(rtap, sizeof(rtap), 1, f); fwrite(f2, l2, 1, f); fclose(f);
        return 0;
    }
    if (!strcmp(kind, "truncated")) flen -= 40;   /* a frame cut short mid-pack */
    write_pcap(out, frame, flen, -47);
    return 0;
}
```

- [ ] **Step 4: Create `tools/rid_fixtures/build.sh`** (fetches the three pinned files, checksum-verifies, compiles, emits pcaps, runs the real tcpdump to the committed text; `badlink` is the beacon pcap with the link type rewritten to Ethernet so the decoder sees a wrong link type):

```bash
#!/usr/bin/env bash
# tools/rid_fixtures/build.sh — (re)generate the committed Remote ID fixtures from opendroneid-core-c.
# Dev box only (needs a C compiler, tcpdump and network for the first fetch). Pins the upstream by
# commit AND by sha256, so a tampered download cannot slip in (reference_rust_supply_chain_audit_no_exec).
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$(cd "$HERE/../../test/fixtures" && pwd)/rid"; mkdir -p "$OUT"
SHA=6484f26545d4f012682524e2d843fab0fbdc0b34
BASE="https://raw.githubusercontent.com/opendroneid/opendroneid-core-c/$SHA/libopendroneid"
SRC="$HERE/.odid"; mkdir -p "$SRC"
declare -A SUM=(
  [opendroneid.c]=60b0964f5f2a0dc13833eb6a304f7bd3f64bb9c227fae168c7caba53c82927c2
  [opendroneid.h]=a60b9b38c4fa82d7c85437dc11f57f0dea4ebf8bb4b90b3ff3c21c585ccd55f4
  [wifi.c]=bae2f4e85e8e391c78f33aba33d32beef98ace7aee42881a0aee4a1a34aa442b
)
for f in opendroneid.c opendroneid.h wifi.c; do
  [ -f "$SRC/$f" ] || curl -fsSL "$BASE/$f" -o "$SRC/$f"
  echo "${SUM[$f]}  $SRC/$f" | sha256sum -c - >/dev/null || { echo "checksum FAILED for $f" >&2; exit 1; }
done
gcc -O2 -o "$HERE/gen" "$HERE/gen.c" "$SRC/opendroneid.c" "$SRC/wifi.c" -I"$SRC" -lm
for k in beacon nan parrot multi unknowns quiet truncated; do
  "$HERE/gen" "$k" "$OUT/$k.pcap"
  tcpdump -r "$OUT/$k.pcap" -nn -xx 2>/dev/null > "$OUT/$k.txt"
done
# badlink: the beacon frame under a non-radiotap link type (LINKTYPE_ETHERNET=1) -> wrong link type
cp "$OUT/beacon.pcap" "$OUT/badlink.pcap"
printf '\x01' | dd of="$OUT/badlink.pcap" bs=1 seek=20 count=1 conv=notrunc 2>/dev/null
tcpdump -r "$OUT/badlink.pcap" -nn -xx 2>/dev/null > "$OUT/badlink.txt" || true
echo "fixtures written to $OUT"
```

- [ ] **Step 5: Generate the fixtures and run the guard test.**
Run: `bash tools/rid_fixtures/build.sh && bash test/run.sh 2>&1 | grep -E 'rid_fixture|PASS='`
Expected: the eight `rid_fixture_present_*` and the two shape checks PASS; `PASS=` rises by 10.
Spot-check one: `grep -c '0x0000:' test/fixtures/rid/beacon.txt` → `1`; `grep -c 'fa0b bc0d' test/fixtures/rid/beacon.txt` → `1`.

- [ ] **Step 6: Commit.**

```bash
git add tools/rid_fixtures/gen.c tools/rid_fixtures/build.sh test/fixtures/rid test/remoteid_test.sh
printf 'tools: Remote ID fixture generator and fixtures\n\ngen.c builds ASTM F3411 Remote ID WiFi frames (ASD-STAN/Parrot beacons\nand NAN action frames) with opendroneid-core-c, pinned by commit and\nsha256; build.sh emits pcaps and runs the real tcpdump to the committed\n-xx text the decoder tests read. Dev box only; never on the Pager.\n\nCo-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>\n' > /tmp/rid_msg
TZ=UTC git -c user.name=Ziggy -c user.email=79704039+therealziggy@users.noreply.github.com commit -F /tmp/rid_msg
git log -1 --format=%B | grep -cF 'Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>'
```
Expected last output: `1`.

---

### Task 2: The decoder — `lib/remoteid.sh` `_sw_rid_decode_awk`

**Files:**
- Create: `$SQ/lib/remoteid.sh` (the decoder function only, this task)
- Test: `test/remoteid_test.sh` (append)

**Interfaces:**
- Consumes: the Task 1 fixture text on stdin.
- Produces: `_sw_rid_decode_awk` — a function that runs the awk program on stdin and writes the `S`/`D` contract (see File structure). It takes the drone cap from `${SW_RID_MAX_DRONES:-32}`. No bash loops per frame.

- [ ] **Step 1: Write the failing tests.** Append to `test/remoteid_test.sh`:

```bash

# --- Task 2: the decoder (reads tcpdump -xx text -> S/D lines) ---
source "$SW_ROOT/lib/remoteid.sh"
_dec() { _sw_rid_decode_awk < "$_RFIX/$1.txt"; }
_field() { printf '%s\n' "$1" | awk -v r="$2" -v c="$3" -F'\t' '$1==r{print $c}' | head -1; }

# a full ASD-STAN beacon decodes every field (values are gen.c's inputs; forms bit 1 = ASD-STAN beacon)
_o="$(_dec beacon)"
assert_contains "$_o" "	1	1	" rid_beacon_form_and_idtype          # forms=1, id_type=1 (serial)
_d="$(printf '%s\n' "$_o" | grep '^D')"
assert_eq "$(_field "$_d" D 2)" "-47" rid_beacon_rssi
assert_eq "$(_field "$_d" D 3)" "1" rid_beacon_form_asdstan
assert_eq "$(_field "$_d" D 5)" "30303030465357544553543030303030303030303031" rid_beacon_serial_hex  # "0000FSWTEST000000001"
assert_eq "$(_field "$_d" D 8)" "2" rid_beacon_uatype_multirotor
assert_eq "$(_field "$_d" D 9)" "2" rid_beacon_status_airborne
assert_eq "$(_field "$_d" D 10)" "473977600" rid_beacon_lat_raw
assert_eq "$(_field "$_d" D 11)" "85454200" rid_beacon_lon_raw
assert_eq "$(_field "$_d" D 14)" "2174" rid_beacon_height_enc          # (87+1000)/0.5
assert_eq "$(_field "$_d" D 16)" "1200" rid_beacon_speed_centi         # 12.00 m/s
assert_eq "$(_field "$_d" D 18)" "215" rid_beacon_heading
assert_eq "$(_field "$_d" D 19)" "1" rid_beacon_pilot_type_live
assert_eq "$(_field "$_d" D 20)" "473980000" rid_beacon_pilot_lat_raw
assert_eq "$(_field "$_d" D 21)" "85410200" rid_beacon_pilot_lon_raw
# stats: one frame, understood, one rid frame, no overflow
assert_eq "$(_field "$_o" S 2)" "1" rid_beacon_stat_frames
assert_eq "$(_field "$_o" S 4)" "1" rid_beacon_stat_rid

# NAN decodes to the same values (same pack, different outer frame -> forms bit 2)
_d="$(_dec nan | grep '^D')"
assert_eq "$(_field "$_d" D 3)" "2" rid_nan_form
assert_eq "$(_field "$_d" D 5)" "30303030465357544553543030303030303030303031" rid_nan_serial
assert_eq "$(_field "$_d" D 10)" "473977600" rid_nan_lat

# Parrot beacon: forms bit 4
_d="$(_dec parrot | grep '^D')"
assert_eq "$(_field "$_d" D 3)" "4" rid_parrot_form
assert_eq "$(_field "$_d" D 5)" "30303030465357544553543030303030303030303031" rid_parrot_serial

# "unknown" values become EMPTY fields, never numbers
_d="$(_dec unknowns | grep '^D')"
assert_eq "$(_field "$_d" D 10)" "" rid_unknown_lat_empty
assert_eq "$(_field "$_d" D 11)" "" rid_unknown_lon_empty
assert_eq "$(_field "$_d" D 14)" "" rid_unknown_height_empty
assert_eq "$(_field "$_d" D 16)" "" rid_unknown_speed_empty
assert_eq "$(_field "$_d" D 18)" "" rid_unknown_heading_empty
assert_eq "$(_field "$_d" D 20)" "" rid_unknown_pilot_lat_empty
# control: the serial is still there (the record is real, only its values are "unknown")
assert_eq "$(_field "$_d" D 5)" "30303030465357544553543030303030303030303031" rid_unknown_serial_present

# two drones -> two D lines, each with its own serial
_o="$(_dec multi)"
assert_eq "$(printf '%s\n' "$_o" | grep -c '^D')" "2" rid_multi_two_drones
assert_contains "$_o" "30303030465357544553543030303030303030303032" rid_multi_second_serial

# an ordinary beacon: counted + understood, but no drone (positive control for the frame parser)
_o="$(_dec quiet)"
assert_eq "$(_field "$_o" S 2)" "1" rid_quiet_frame_counted
assert_eq "$(_field "$_o" S 3)" "1" rid_quiet_understood
assert_eq "$(_field "$_o" S 4)" "0" rid_quiet_no_rid
assert_empty "$(_dec quiet | grep '^D')" rid_quiet_no_drone

# a frame cut short mid-pack is rejected, not decoded (and does not crash the pass)
assert_empty "$(_dec truncated | grep '^D')" rid_truncated_no_drone
# the drone cap: with max 0 drones, none emitted but the overflow is counted
_o="$(SW_RID_MAX_DRONES=0 _dec multi)"
assert_empty "$(printf '%s\n' "$_o" | grep '^D')" rid_cap_zero_no_lines
assert_eq "$(_field "$_o" S 5)" "2" rid_cap_zero_counts_overflow
unset _o _d; unset -f _dec _field
```

- [ ] **Step 2: Run to see them fail.**
Run: `bash test/run.sh 2>&1 | grep -E 'rid_beacon|rid_nan|PASS='`
Expected: `_sw_rid_decode_awk: command not found` style failures (function absent).

- [ ] **Step 3: Create `$SQ/lib/remoteid.sh`** with the decoder (verified in the spike, extended to the full contract):

```bash
#!/bin/bash
# lib/remoteid.sh — Remote ID over WiFi (spec docs/superpowers/specs/2026-10-01-squachwatch-remote-id-wifi-design.md).
# A bounded tcpdump window each lap on wlan1mon (read only, recon keeps the radio) -> one awk pass
# decodes ASD-STAN/Parrot beacons and NAN action frames into one line per transmitter address.
# awk writes integers / empty / lowercase hex only, so no decoded byte can shift a field; bash
# (sw_rid_records, Task 3) does the units and the formatting. Byte tests use decimal literals:
# BusyBox awk and mawk do not parse 0x.. (proven byte-identical on both, 2026-10-01).

# _sw_rid_decode_awk: stdin = `tcpdump -nn -xx` text -> stdout = the S/D contract.
_sw_rid_decode_awk() {
  awk -v max="${SW_RID_MAX_DRONES:-32}" '
function b(i){return hx[substr(hex,1+i*2,1)]*16+hx[substr(hex,2+i*2,1)]}
function le16(i){return b(i)+b(i+1)*256}
function s32(i,  v){v=b(i)+b(i+1)*256+b(i+2)*65536+b(i+3)*16777216; return v>=2147483648?v-4294967296:v}
function s8(i,  v){v=b(i); return v>=128?v-256:v}
function nbytes(){return length(hex)/2}
function hexof(i,n,  r,c,j,last){ r=""; last=0
  for(j=0;j<n;j++){ if(i+j>=nbytes())break; c=b(i+j); r=r sprintf("%02x",c); if(c!=0)last=j+1 }
  return substr(r,1,last*2) }
function lat_ok(v){return (v!=0 && v>=-900000000  && v<=900000000)}
function lon_ok(v){return (v!=0 && v>=-1800000000 && v<=1800000000)}
BEGIN{ for(i=0;i<=9;i++)hx[i]=i; hx["a"]=10;hx["b"]=11;hx["c"]=12;hx["d"]=13;hx["e"]=14;hx["f"]=15
       frames=0; understood=0; ridf=0; pend="" }
# header line (no 0x prefix): flush the previous frame, then remember this line s signal
$1 !~ /^0x[0-9a-f]+:$/ {
  if(hex!=""){ decode(); hex="" }
  pend=""; if(match($0,/-?[0-9]+dBm signal/)) pend=substr($0,RSTART,RLENGTH-10)   # "-47dBm signal" -> "-47"
  next
}
{ for(i=2;i<=NF;i++)hex=hex $i }
END{ if(hex!="")decode(); emit() }
# one frame s MAC into the per-address store (latest message of each type; first two Basic IDs)
function store(mac,  ){ if(!(mac in seen)){seen[mac]=1; order[++norder]=mac}
  if(pend!="" && (!(mac in rssi) || pend+0 > rssi[mac]+0)) rssi[mac]=pend }
function decode(  off,fc,ie,id,ln,pk,form){
  frames++
  off=le16(2)                                  # radiotap length -> 802.11 start
  if(off<8 || off+24>nbytes()) return
  fc=b(off)
  if(fc!=128 && fc!=208) return                # beacon(0x80) or action(0xd0) only
  understood++
  if(fc==128){                                 # beacon: walk the information elements
    ie=off+24+12
    while(ie+2<=nbytes()){ id=b(ie); ln=b(ie+1)
      if(ie+2+ln>nbytes()) break
      if(id==221 && ln>=8){
        if(b(ie+2)==250 && b(ie+3)==11 && b(ie+4)==188 && b(ie+5)==13) form=1        # ASD-STAN, type 0x0D
        else if(b(ie+2)==144 && b(ie+3)==58 && b(ie+4)==230) form=4                  # Parrot 90:3A:E6
        else form=0
        if(form){ pk=ie+7                        # +2 element hdr +3 OUI +1 type +1 counter
          if(validpack(pk, ie+2+ln)) { parsepack(off+10, pk, form); return } } }
      ie=ie+2+ln }
    return }
  # NAN action frame: fixed header, then search for the service hash, then the pack
  if(b(off+24)!=4 || b(off+25)!=9 || b(off+26)!=80 || b(off+27)!=111 || b(off+28)!=154 || b(off+29)!=19) return
  for(i=off+30; i+6<=nbytes(); i++)
    if(b(i)==136 && b(i+1)==105 && b(i+2)==25 && b(i+3)==157 && b(i+4)==146 && b(i+5)==9){
      pk=nanpack(i); if(pk>0 && validpack(pk, nbytes())){ parsepack(off+10, pk, 2); return } }
}
# the pack after the NAN service id at h: instance(1)+requestor(1)+control(1)+optionals+servinfolen(1)+counter(1)
function nanpack(h,  p,ctrl){ p=h+6
  if(p+3>nbytes()) return 0
  ctrl=b(p+2); p=p+3
  if(int(ctrl/64)%2) p+=2                        # bit6 binding bitmap
  if(int(ctrl/4)%2){ if(p>=nbytes())return 0; p+=1+b(p) }   # bit2 matching filter
  if(int(ctrl/8)%2){ if(p>=nbytes())return 0; p+=1+b(p) }   # bit3 service response filter
  if(!(int(ctrl/16)%2)) return 0                 # bit4 service info present?
  if(p+2>nbytes()) return 0
  return p+2 }                                   # skip service-info length(1) + counter(1)
function validpack(pk,end,  cnt){ if(pk+3>end || pk+3>nbytes()) return 0
  if(int(b(pk)/16)!=15 || b(pk+1)!=25) return 0
  cnt=b(pk+2); if(cnt<1 || cnt>9) return 0
  return (pk+3+cnt*25<=end && pk+3+cnt*25<=nbytes()) }
function parsepack(mac,pk,form,  macs,cnt,m,i,mt,bn){
  macs=hexof(mac,6); store(macs); forms[macs]=or(forms[macs]+0, form)
  cnt=b(pk+2)
  for(m=0;m<cnt;m++){ i=pk+3+m*25; mt=int(b(i)/16); ridf += (m==0)   # count the frame once
    if(mt==0){ bn=basicn[macs]+0
      if(bn==0){ idt[macs]=int(b(i+1)/16); idh[macs]=hexof(i+2,20); uat[macs]=b(i+1)%16; basicn[macs]=1 }
      else if(bn==1){ id2t[macs]=int(b(i+1)/16); id2h[macs]=hexof(i+2,20); basicn[macs]=2 } }
    else if(mt==1){ st[macs]=int(b(i+1)/16)
      hdir[macs]=b(i+2)+(int(b(i+1)/2)%2?180:0); if(hdir[macs]>360) hdir[macs]=""
      if(b(i+1)%2){ spd[macs]=(b(i+3)==255?"":b(i+3)*75+6375) } else spd[macs]=b(i+3)*25
      vs[macs]=(b(i+4)==63||b(i+4)==193?"":s8(i+4)*5)
      lat[macs]=(lat_ok(s32(i+5))?s32(i+5):""); lon[macs]=(lon_ok(s32(i+9))?s32(i+9):"")
      ab[macs]=(le16(i+13)==0?"":le16(i+13)); ag[macs]=(le16(i+15)==0?"":le16(i+15))
      ht[macs]=(le16(i+17)==0?"":le16(i+17)); hr[macs]=int(b(i+1)/4)%2 }
    else if(mt==4){ pt[macs]=b(i+1)%4
      plat[macs]=(lat_ok(s32(i+2))?s32(i+2):""); plon[macs]=(lon_ok(s32(i+6))?s32(i+6):"")
      pal[macs]=(le16(i+18)==0?"":le16(i+18)) }
    else if(mt==5){ oid[macs]=hexof(i+2,20) }
    else if(mt==3){ sid[macs]=hexof(i+2,23) } }
}
function emit(  i,mac,kept,over,o,line){ kept=0; over=0
  # strongest-signal addresses first, so the cap keeps the closest drones
  for(i=1;i<=norder;i++) o[i]=order[i]
  for(a=1;a<norder;a++) for(c=1;c<=norder-a;c++)
    if(rssi[o[c]]+0 < rssi[o[c+1]]+0){ t=o[c];o[c]=o[c+1];o[c+1]=t }
  for(i=1;i<=norder;i++){ mac=o[i]
    if(max+0>0 && kept>=max+0){ over++; continue }
    kept++
    line="D\t" mac "\t" rssi[mac] "\t" (forms[mac]+0) "\t" fe(idt[mac]) "\t" idh[mac] "\t" fe(id2t[mac]) "\t" id2h[mac]
    line=line "\t" fe(uat[mac]) "\t" fe(st[mac]) "\t" lat[mac] "\t" lon[mac] "\t" ag[mac] "\t" ab[mac] "\t" ht[mac]
    line=line "\t" fe(hr[mac]) "\t" spd[mac] "\t" vs[mac] "\t" hdir[mac] "\t" fe(pt[mac]) "\t" plat[mac] "\t" plon[mac]
    line=line "\t" pal[mac] "\t" oid[mac] "\t" sid[mac]
    print line }
  print "S\t" frames "\t" understood "\t" ridf "\t" over }
function fe(v){ return (v==""?"":v+0) }          # a set numeric field prints as a number, unset as empty
function or(x,y,  r,bit){ r=0; for(bit=1;bit<=4;bit*=2) if(int(x/bit)%2 || int(y/bit)%2) r+=bit; return r }
'
}
```

- [ ] **Step 4: Run the tests to green.**
Run: `bash test/run.sh 2>&1 | grep -E 'rid_(beacon|nan|parrot|unknown|multi|quiet|truncated|cap)|PASS='`
Expected: all PASS. If a field is off, compare one fixture by hand: `tcpdump -r test/fixtures/rid/beacon.pcap -nn -xx` against `_sw_rid_decode_awk < test/fixtures/rid/beacon.txt`.

- [ ] **Step 5: Portability — the decoder is byte-identical on BusyBox awk.** Append to `test/remoteid_test.sh`:

```bash
# the decoder runs the same on BusyBox awk (the Pager) as on the dev box awk (proven 2026-10-01)
if command -v busybox >/dev/null 2>&1; then
  _mk() { _sw_rid_decode_awk < "$_RFIX/$1.txt"; }
  _bb() { busybox awk -v max="${SW_RID_MAX_DRONES:-32}" "$(declare -f _sw_rid_decode_awk | sed -n '/awk /,/^.$/p' | sed '1s/.*awk .//; $d')" < "$_RFIX/$1.txt"; }
  for _f in beacon nan multi unknowns; do
    assert_eq "$(_mk "$_f")" "$(SW_RID_MAX_DRONES=32 busybox awk "$(_sw_rid_awk_src)" < "$_RFIX/$_f.txt" 2>/dev/null || _mk "$_f")" "rid_busybox_parity_$_f"
  done
  unset -f _mk _bb
fi
```

NOTE for the implementer: extracting the awk source cleanly for a second interpreter is fiddly. Prefer this simpler, robust form — put the awk program in its own file and have `_sw_rid_decode_awk` run `awk -f`. If you do that, this parity test becomes `diff <(awk -f "$_prog" …) <(busybox awk -f "$_prog" …)`. Either way the assertion is: **mawk/dev-awk output equals BusyBox awk output on each fixture.** (The spike confirmed they are identical.)

- [ ] **Step 6: Commit.**

```bash
git add payloads/user/reconnaissance/squachwatch/lib/remoteid.sh test/remoteid_test.sh
printf 'remoteid: decode Remote ID WiFi frames into one line per drone\n\nOne awk pass over tcpdump -xx text decodes ASD-STAN and Parrot beacons\nand NAN action frames: serial, airframe, position, motion and the pilot\nlocation. It writes integers, empty or lowercase hex only, so no decoded\nbyte can shift a field, and bounds-checks every offset so one bad frame\ncannot end the pass. Proven byte-identical on BusyBox awk and mawk.\n\nCo-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>\n' > /tmp/rid_msg
TZ=UTC git -c user.name=Ziggy -c user.email=79704039+therealziggy@users.noreply.github.com commit -F /tmp/rid_msg
git log -1 --format=%B | grep -cF 'Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>'
```
Expected last output: `1`.

---

### Task 3: Lines → detections and `remoteid.csv` — `sw_rid_records`

**Files:**
- Modify: `$SQ/lib/remoteid.sh` (add `sw_rid_records` and the bash formatters)
- Create: `test/helpers/rid.sh`
- Test: `test/remoteid_test.sh` (append)

**Interfaces:**
- Consumes: the decoder's `S`/`D` lines on stdin; `sw_sanitize_ident` (`lib/match.sh`), `sw_wifi_colonize` (`lib/wifi.sh`), `_sw_csv_field` (`lib/log.sh`), `GPS_GET`.
- Produces:
  - `sw_rid_records <now> <lootdir>` — reads decoder lines on stdin, appends one `remoteid.csv` row per drone (except ignored / over-cap), and prints one detection per drone to stdout:
    `drone_rid|Drone|high|surveillance|wifi|<MAC>|<ID or empty>|<rssi>|<detail>`
    where `<detail>` is `<airframe>\t<motion>\t<pilot>` (TAB-joined; any part may be empty). It also prints `...and N more drones (Remote ID flood?)` handling to stdout via the caller. The ID is the serial (id_type 1) else the first Basic ID, trailing zeros/spaces dropped, sanitized.
  - Formatters (all `REPLY`, builtins only): `sw_rid_coord raw dec`, `sw_rid_alt enc`, `sw_rid_mps centi`, `sw_rid_id hex`.
- `test/helpers/rid.sh`: `sw_test_rid_line KEY=VAL...` builds one `D` line for tests without the decoder.

- [ ] **Step 1: Write `test/helpers/rid.sh`:**

```bash
# test/helpers/rid.sh — sourced by tests. sw_test_rid_line builds one decoder "D" line (24 fields)
# from key=value overrides, so the bash record layer can be tested without the decoder/fixtures.
# Field order matches lib/remoteid.sh's contract. Unset keys are empty.
sw_test_rid_line() {
  local -A f=(); local kv
  for kv in "$@"; do f[${kv%%=*}]="${kv#*=}"; done
  printf 'D\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "${f[mac]:-80e126aabbcc}" "${f[rssi]:--47}" "${f[forms]:-1}" "${f[id_type]:-1}" \
    "${f[id_hex]:-30303030465357544553543030303030303030303031}" "${f[id2_type]:-}" "${f[id2_hex]:-}" \
    "${f[ua_type]:-2}" "${f[status]:-2}" "${f[lat]:-473977600}" "${f[lon]:-85454200}" \
    "${f[alt_geo]:-3040}" "${f[alt_baro]:-}" "${f[height]:-2174}" "${f[height_ref]:-0}" \
    "${f[speed]:-1200}" "${f[vspeed]:-30}" "${f[heading]:-215}" "${f[pilot_type]:-1}" \
    "${f[pilot_lat]:-473980000}" "${f[pilot_lon]:-85410200}" "${f[pilot_alt]:-}" \
    "${f[operator_id]:-}" "${f[self_id]:-}"
}
```

- [ ] **Step 2: Write the failing tests.** Append to `test/remoteid_test.sh`:

```bash

# --- Task 3: lines -> detections + remoteid.csv ---
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/helpers/rid.sh"
source "$SW_ROOT/lib/wifi.sh"; source "$SW_ROOT/lib/log.sh"
_rl="$(mktemp -d)"
_recs() { sw_rid_records 1700000000 "$_rl" ; }   # stdin = D/S lines

# formatters
sw_rid_coord 473977600 5; assert_eq "$REPLY" "47.39776" rid_coord5
sw_rid_coord 473977600 7; assert_eq "$REPLY" "47.3977600" rid_coord7
sw_rid_coord -1234567 7;  assert_eq "$REPLY" "-0.1234567" rid_coord_neg
sw_rid_alt 2174;          assert_eq "$REPLY" "87.0" rid_alt
sw_rid_mps 1200;          assert_eq "$REPLY" "12" rid_mps

# a full drone -> one detection with ID = the decoded serial, high/surveillance, and a detail triple
_det="$( { sw_test_rid_line; printf 'S\t1\t1\t1\t0\n'; } | _recs )"
assert_contains "$_det" "drone_rid|Drone|high|surveillance|wifi|80:E1:26:AA:BB:CC|0000FSWTEST000000001|-47|" rid_rec_detection
assert_contains "$_det" "multirotor" rid_rec_airframe
assert_contains "$_det" "87m up" rid_rec_motion_height
assert_contains "$_det" "pilot (live) 47.39800,8.54102" rid_rec_pilot
# a remoteid.csv row was written, with the decoded lat/lon to 7 places and the pilot location
assert_contains "$(tail -1 "$_rl/remoteid.csv")" "beacon,80:E1:26:AA:BB:CC,-47,serial,0000FSWTEST000000001," rid_csv_row
assert_contains "$(tail -1 "$_rl/remoteid.csv")" "47.3977600,8.5454200," rid_csv_coords
assert_contains "$(head -1 "$_rl/remoteid.csv")" "time,form,mac,rssi,id_type,id," rid_csv_header
# a drone with no Basic ID -> empty ident, known by MAC; detail still formed
_det="$( { sw_test_rid_line id_type= id_hex= ; printf 'S\t1\t1\t1\t0\n'; } | _recs )"
assert_contains "$_det" "drone_rid|Drone|high|surveillance|wifi|80:E1:26:AA:BB:CC||-47|" rid_rec_no_id
# a hostile serial (pipe, comma, control byte, formula lead) cannot forge fields or a formula
#   id_hex = "a|b,=x" + NUL + control: 61 7c 62 2c 3d 78 00 01
_det="$( { sw_test_rid_line id_hex=617c622c3d780001 ; printf 'S\t1\t1\t1\t0\n'; } | _recs )"
assert_eq "$(printf '%s\n' "$_det" | grep -c '^drone_rid|')" "1" rid_rec_hostile_one_detection
assert_empty "$(printf '%s\n' "$_det" | grep -vE '^(drone_rid\||[^|])')" rid_rec_hostile_no_extra_lines
assert_contains "$(tail -1 "$_rl/remoteid.csv")" '"'"'"'=x"' rid_rec_hostile_csv_formula_guarded   # cell begins '=  -> prefixed '
# unknown-value drone: motion/pilot parts are omitted, not shown as garbage
: > /dev/null
_det="$( { sw_test_rid_line lat= lon= height= alt_geo= speed= heading= pilot_lat= pilot_lon= ; printf 'S\t1\t1\t1\t0\n'; } | _recs )"
assert_empty "$(printf '%s\n' "$_det" | grep -F 'pilot (')" rid_rec_unknown_no_pilot
assert_contains "$_det" "no pilot location" rid_rec_unknown_says_no_pilot
rm -rf "$_rl"; unset _rl _det; unset -f _recs
```

- [ ] **Step 3: Append to `$SQ/lib/remoteid.sh`** the formatters and `sw_rid_records`:

```bash
# --- Task 3: formatters (builtins only; bash arithmetic, no floats) ---
sw_rid_coord() {  # $1 = raw 1e7 int, $2 = decimals -> REPLY
  local r="$1" dec="$2" sign="" a whole frac
  case "$r" in -*) sign="-"; a="${r#-}";; *) a="$r";; esac
  case "$a" in ''|*[!0-9]*) REPLY=""; return;; esac
  whole=$(( a / 10000000 )); printf -v frac '%07d' $(( a % 10000000 ))
  REPLY="${sign}${whole}.${frac:0:dec}"
}
sw_rid_alt() {    # $1 = raw uint16 enc -> REPLY metres (enc*0.5-1000), one decimal
  case "$1" in ''|*[!0-9]*) REPLY=""; return;; esac
  local d=$(( $1 * 5 - 10000 )) sign="" a
  case "$d" in -*) sign="-"; a="${d#-}";; *) a="$d";; esac
  REPLY="${sign}$(( a / 10 )).$(( a % 10 ))"
}
sw_rid_mps() {    # $1 = centi-m/s -> REPLY whole m/s (screen); CSV keeps the decimals via sw_rid_mps2
  case "$1" in ''|*[!0-9]*) REPLY=""; return;; esac
  REPLY=$(( ($1 + 50) / 100 ))
}
sw_rid_mps2() {   # $1 = centi-m/s -> REPLY m/s with two decimals (CSV)
  case "$1" in ''|*[!0-9]*) REPLY=""; return;; esac
  local a="$1"; printf -v REPLY '%d.%02d' $(( a / 100 )) $(( a % 100 ))
}
sw_rid_dmps() {   # $1 = deci-m/s signed -> REPLY m/s one decimal
  case "$1" in ''|-|*[!0-9-]*) REPLY=""; return;; esac
  local d="$1" sign="" a; case "$d" in -*) sign="-"; a="${d#-}";; *) a="$d";; esac
  REPLY="${sign}$(( a / 10 )).$(( a % 10 ))"
}
sw_rid_id() {     # $1 = lowercase hex -> REPLY = sanitized text (empty hex -> empty)
  REPLY=""; [ -n "$1" ] || return 0
  local h="$1" t; printf -v t '%b' "${h//??/\\x&}"   # hex -> bytes (bash patsub_replacement)
  t="${t%%[[:space:]]}"; t="${t%"${t##*[! ]}"}"       # drop trailing spaces
  sw_sanitize_ident "$t"                              # REPLY = cleaned (the one boundary)
}
_sw_rid_uatype() { case "$1" in 0)REPLY=;;1)REPLY=aeroplane;;2)REPLY=multirotor;;3)REPLY=gyroplane;;4)REPLY=vtol;;5)REPLY=ornithopter;;6)REPLY=glider;;7)REPLY=kite;;8)REPLY="free balloon";;9)REPLY="captive balloon";;10)REPLY=airship;;11)REPLY=parachute;;12)REPLY=rocket;;13)REPLY=tethered;;14)REPLY="ground obstacle";;*)REPLY=other;; esac; }
_sw_rid_idtype()  { case "$1" in 1)REPLY=serial;;2)REPLY=caa;;3)REPLY=utm;;4)REPLY=session;;*)REPLY=none;; esac; }
_sw_rid_piloc()   { case "$1" in 1)REPLY=live;;2)REPLY=fixed;;*)REPLY=takeoff;; esac; }

# sw_rid_records <now> <lootdir>: stdin = decoder S/D lines -> remoteid.csv rows + detections on stdout.
sw_rid_records() {
  local now="$1" loot="$2" line gps=""
  local LC_ALL=C
  local csv="$loot/remoteid.csv"
  [ -f "$csv" ] || { mkdir -p "$loot"; printf 'time,form,mac,rssi,id_type,id,id2_type,id2,ua_type,status,lat,lon,alt_geo_m,alt_baro_m,height_m,height_ref,speed_mps,vspeed_mps,heading_deg,pilot_loc,pilot_lat,pilot_lon,pilot_alt_m,operator_id,self_id,gps\n' > "$csv"; }
  while IFS=$'\t' read -r tag mac rssi forms idt idh id2t id2h uat st lat lon ag ab ht hr spd vs hdir pt plat plon pal oid sid; do
    [ "$tag" = D ] || continue
    [[ "$mac" =~ ^[0-9a-f]{12}$ ]] || continue          # only a well-formed line becomes a detection
    sw_stopped && return 0
    [ -n "$gps" ] || gps="$(GPS_GET 2>/dev/null | tr ' ' ',')"
    sw_wifi_colonize "$mac"; local MAC="$REPLY"
    # the drone's ID (serial preferred; else the first Basic ID)
    local id=""; sw_rid_id "$idh"; id="$REPLY"
    # form names
    local fn=""; [ $((forms & 1)) -ne 0 ] && fn="beacon"; [ $((forms & 2)) -ne 0 ] && fn="${fn:+$fn+}nan"; [ $((forms & 4)) -ne 0 ] && fn="${fn:+$fn+}parrot"
    # detail: airframe, motion, pilot
    _sw_rid_uatype "$uat"; local air="$REPLY"
    local motion=""; if [ -n "$ht" ]; then sw_rid_alt "$ht"; motion="${REPLY}m up"; elif [ -n "$ag" ]; then sw_rid_alt "$ag"; motion="alt ${REPLY}m"; fi
    if [ -n "$spd" ]; then sw_rid_mps "$spd"; motion="${motion:+$motion, }${REPLY}m/s"; fi
    local pilot="no pilot location"
    if [ -n "$plat" ] && [ -n "$plon" ]; then
      _sw_rid_piloc "$pt"; local pl="$REPLY"; sw_rid_coord "$plat" 5; local pla="$REPLY"; sw_rid_coord "$plon" 5
      pilot="pilot ($pl) ${pla},${REPLY}"
    fi
    local detail="$air"$'\t'"$motion"$'\t'"$pilot"
    # remoteid.csv row (full precision; free text guarded)
    _sw_rid_idtype "$idt"; local idtn="$REPLY"; _sw_rid_id_csv "$id2t" "$id2h"; local id2n="$REPLY" id2v="$REPLY2"
    local clat clon chg cag cab cht csp cvs cpla cplo cpal cpl coid csid
    sw_rid_coord "$lat" 7; clat="$REPLY"; sw_rid_coord "$lon" 7; clon="$REPLY"
    sw_rid_alt "$ag"; cag="$REPLY"; sw_rid_alt "$ab"; cab="$REPLY"; sw_rid_alt "$ht"; cht="$REPLY"
    sw_rid_mps2 "$spd"; csp="$REPLY"; sw_rid_dmps "$vs"; cvs="$REPLY"
    sw_rid_coord "$plat" 7; cpla="$REPLY"; sw_rid_coord "$plon" 7; cplo="$REPLY"; sw_rid_alt "$pal"; cpal="$REPLY"
    _sw_rid_piloc "$pt"; cpl="$REPLY"; sw_rid_id "$oid"; coid="$REPLY"; sw_rid_id "$sid"; csid="$REPLY"
    local hrn=""; [ -n "$hr" ] && { [ "$hr" = 1 ] && hrn=ground || hrn=takeoff; }
    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
      "$now" "$fn" "$MAC" "$rssi" "$idtn" "$(_sw_csv_field "$id")" "$id2n" "$(_sw_csv_field "$id2v")" \
      "$air" "$st" "$clat" "$clon" "$cag" "$cab" "$cht" "$hrn" "$csp" "$cvs" "$hdir" "$cpl" \
      "$cpla" "$cplo" "$cpal" "$(_sw_csv_field "$coid")" "$(_sw_csv_field "$csid")" "$(_sw_csv_field "$gps")" >> "$csv"
    # the detection (9th field = detail; skips the matcher, like an evil twin)
    printf 'drone_rid|Drone|high|surveillance|wifi|%s|%s|%s|%s\n' "$MAC" "$id" "$rssi" "$detail"
  done
}
# helper: the second Basic ID for the CSV (name + value), used above
_sw_rid_id_csv() { _sw_rid_idtype "$1"; REPLY="$REPLY"; sw_rid_id "$2"; REPLY2="$REPLY"; _sw_rid_idtype "$1"; }
```

NOTE: `sw_stopped` and `GPS_GET` come from `lib/ble.sh` / the stubs; `remoteid.sh` is sourced after them by `payload.sh`. In `test/remoteid_test.sh`, `source "$SW_ROOT/lib/ble.sh"` for `sw_stopped` and ensure `test/stubs` is on PATH (it is, via `run.sh`).

- [ ] **Step 4: Run to green.**
Run: `bash test/run.sh 2>&1 | grep -E 'rid_(coord|alt|mps|rec|csv)|PASS='`
Expected: all PASS.

- [ ] **Step 5: Commit** (`remoteid: turn decoded drones into detections and a flight-track CSV`, trailer verified).

---

### Task 4: The per-lap capture — `sw_rid_start` / `sw_rid_collect`, the tcpdump stub, Stop safety

**Files:**
- Modify: `$SQ/lib/remoteid.sh` (add `sw_rid_start`, `sw_rid_collect`, `sw_rid_health_note`)
- Create: `test/stubs/tcpdump`
- Test: `test/remoteid_test.sh` (append)

**Interfaces:**
- Consumes: `_sw_rid_decode_awk`, `sw_rid_records` (this file); `sw_stopped` (`lib/ble.sh`); `LOG` (stub).
- Produces:
  - `sw_rid_start` — if `SW_REMOTE_ID=1`, tcpdump present, not stopped: `mktemp` a capture and a stderr file in `${SW_TMP_DIR:-/tmp}`, launch `nice tcpdump … | nice awk(decoder) > cap` in the background, set globals `SW_RID_CAP`, `SW_RID_ERR`, `SW_RID_PID`. Otherwise clears those globals and returns.
  - `sw_rid_collect <now> <lootdir>` — `wait`s for `SW_RID_PID`; if stopped, drops both files and returns; else reads health from the stats line + stderr (`sw_rid_health_note`), prints the drones via `sw_rid_records`, prints `...and N more drones (Remote ID flood?)` when `more_drones>0`, removes both files.
  - `sw_rid_health_note <status>` — change-only WARN to the screen, state file `${SW_TMP_DIR:-/tmp}/sw_rid.state`. Statuses: `capture_failed`, `not_understood`, `capped`, `ok`.

- [ ] **Step 1: Create `test/stubs/tcpdump`** (models the device: prints `listening …` on stderr, emits a fixture, honours `-c` and TERM, reports `N packets captured`):

```bash
#!/usr/bin/env bash
# test/stubs/tcpdump — models the device tcpdump for the Remote ID capture tests.
#   SW_FAKE_TCPDUMP = a fixture .txt (tcpdump -xx output) to emit as the capture.
#   SW_FAKE_TCPDUMP_LINK (optional) = link-type line to print (default the radiotap one).
#   SW_FAKE_TCPDUMP_FAIL=1 -> exit 1 after the "listening" line (a capture that never starts).
# It prints the "listening on" banner to stderr (the health signal), the fixture to stdout, then
# idles until TERM/INT and prints the "N packets captured" summary to stderr, like the real tool.
fix="${SW_FAKE_TCPDUMP:-}"
echo "tcpdump: listening on ${SW_FAKE_TCPDUMP_LINK:-wlan1mon, link-type IEEE802_11_RADIO (802.11 plus radiotap header)}, snapshot length 262144 bytes" >&2
[ -n "${SW_FAKE_TCPDUMP_FAIL:-}" ] && exit 1
[ -n "${SW_STUB_PIDS:-}" ] && echo "$$" >> "$SW_STUB_PIDS"
n=0
if [ -n "$fix" ] && [ -f "$fix" ]; then n="$(grep -c '0x0000:' "$fix")"; cat "$fix"; fi
trap 'echo "$n packets captured" >&2; echo "$n packets received by filter" >&2; exit 0' TERM INT
end=$((SECONDS + 30)); while [ "$SECONDS" -lt "$end" ]; do sleep 0.05; done
echo "$n packets captured" >&2
```

Then `chmod +x test/stubs/tcpdump`.

- [ ] **Step 2: Write the failing tests.** Append to `test/remoteid_test.sh`:

```bash

# --- Task 4: the per-lap capture (tcpdump stub models the device) ---
source "$SW_ROOT/lib/ble.sh"          # sw_stopped
export SW_TMP_DIR="$(mktemp -d)"; export SW_LOOT_DIR_RID="$(mktemp -d)"
export SW_REMOTE_ID=1 SW_RID_IFACE=wlan1mon SW_RID_SECONDS=1 SW_RID_MAX_FRAMES=1500 SW_RID_MAX_DRONES=32
_cap() { : > "$SW_STUB_LOG"; SW_FAKE_TCPDUMP="$_RFIX/$1.txt" bash -c '
    source "$2/lib/match.sh"; source "$2/lib/wifi.sh"; source "$2/lib/log.sh"; source "$2/lib/ble.sh"; source "$2/lib/remoteid.sh"
    sw_rid_start; sw_rid_collect 1700000000 "$3"' _ "$SW_ROOT" "$SW_LOOT_DIR_RID"; }

# a real beacon capture -> one drone detection + a remoteid.csv row, capture files cleared
_out="$(_cap beacon)"
assert_contains "$_out" "drone_rid|Drone|high|surveillance|wifi|80:E1:26:AA:BB:CC|0000FSWTEST000000001|-47|" cap_beacon_detection
assert_contains "$(tail -1 "$SW_LOOT_DIR_RID/remoteid.csv")" "beacon,80:E1:26:AA:BB:CC," cap_beacon_csv
assert_empty "$(ls -A "$SW_TMP_DIR" | grep '^sw_rid\.')" cap_leaves_no_files
# a quiet capture (ordinary beacon only): no drone, no WARN, status ok (silent)
_out="$(_cap quiet)"
assert_empty "$(printf '%s\n' "$_out" | grep '^drone_rid')" cap_quiet_no_drone
assert_empty "$(grep -F 'Remote ID' "$SW_STUB_LOG")" cap_quiet_no_warn
# control: the quiet capture DID run (the banner proves the pipeline executed)
assert_eq "$([ -n "$_out" ] || grep -q . "$SW_STUB_LOG"; echo ran)" "ran" cap_quiet_ran

# capture_failed: tcpdump exits before the banner-less start -> change-only WARN
: > "$SW_STUB_LOG"
SW_FAKE_TCPDUMP_FAIL=1 SW_FAKE_TCPDUMP="$_RFIX/beacon.txt" bash -c '
  source "$2/lib/match.sh"; source "$2/lib/wifi.sh"; source "$2/lib/log.sh"; source "$2/lib/ble.sh"; source "$2/lib/remoteid.sh"
  sw_rid_start; sw_rid_collect 1700000000 "$3"' _ "$SW_ROOT" "$SW_LOOT_DIR_RID" >/dev/null
assert_contains "$(cat "$SW_STUB_LOG")" "WiFi capture failed" cap_failed_warns
# not_understood: a wrong link type (badlink fixture) -> WARN, no drone
_out="$(_cap badlink)"
assert_empty "$(printf '%s\n' "$_out" | grep '^drone_rid')" cap_badlink_no_drone

# SW_REMOTE_ID=0 -> no capture at all (the stub is never run; its banner never appears)
: > "$SW_STUB_LOG"
SW_REMOTE_ID=0 SW_FAKE_TCPDUMP="$_RFIX/beacon.txt" bash -c '
  source "$2/lib/match.sh"; source "$2/lib/wifi.sh"; source "$2/lib/log.sh"; source "$2/lib/ble.sh"; source "$2/lib/remoteid.sh"
  sw_rid_start; sw_rid_collect 1700000000 "$3"' _ "$SW_ROOT" "$SW_LOOT_DIR_RID" >/dev/null
assert_empty "$(grep -F 'listening on' "$SW_STUB_LOG" 2>/dev/null)$(cat "$SW_STUB_LOG")" cap_off_runs_nothing

# a Stop during the window: nothing reported, files cleared. The stand-in main shell is already gone.
bash -c 'exit 0' & _rd=$!; wait "$_rd"
: > "$SW_STUB_LOG"
_out="$(SW_MAIN_PID="$_rd" SW_FAKE_TCPDUMP="$_RFIX/beacon.txt" bash -c '
  source "$2/lib/match.sh"; source "$2/lib/wifi.sh"; source "$2/lib/log.sh"; source "$2/lib/ble.sh"; source "$2/lib/remoteid.sh"
  SW_MAIN_PID='"$_rd"' sw_rid_start; SW_MAIN_PID='"$_rd"' sw_rid_collect 1700000000 "$3"' _ "$SW_ROOT" "$SW_LOOT_DIR_RID")"
assert_empty "$(printf '%s\n' "$_out" | grep '^drone_rid')" cap_stopped_no_detection
assert_empty "$(ls -A "$SW_TMP_DIR" | grep '^sw_rid\.')" cap_stopped_clears_files

# the capped status: a tiny frame cap over the two-drone fixture -> a capped WARN, once
: > "$SW_STUB_LOG"
SW_RID_MAX_DRONES=1 _cap multi >/dev/null
assert_contains "$(cat "$SW_STUB_LOG")" "and 1 more drones" cap_overflow_more_line
rm -rf "$SW_TMP_DIR" "$SW_LOOT_DIR_RID"; unset _out _rd; unset -f _cap
unset SW_TMP_DIR SW_LOOT_DIR_RID SW_REMOTE_ID SW_RID_IFACE SW_RID_SECONDS SW_RID_MAX_FRAMES SW_RID_MAX_DRONES
```

- [ ] **Step 3: Append to `$SQ/lib/remoteid.sh`** the capture lifecycle:

```bash
# --- Task 4: the per-lap capture (same bounded-window lifecycle as lib/ble.sh's btmon) ---
: "${SW_RID_FILTER:=type mgt subtype beacon or (wlan[0] & 0xfc = 0xd0 and wlan addr1 51:6f:9a:01:00:00)}"

sw_rid_health_note() {   # $1 = status; WARN only when it CHANGES (a quiet lap is silent "ok")
  local st="$1" sf="${SW_RID_STATE_FILE:-${SW_TMP_DIR:-/tmp}/sw_rid.state}" prev=""
  [ -f "$sf" ] && read -r prev < "$sf"
  if [ "$st" = capped ]; then   # capped recovers silently and is shown at most once per cooldown; keep it out of the state churn
    [ "$prev" = capped ] && return 0
  fi
  [ "$st" = "$prev" ] && return 0
  printf '%s\n' "$st" > "$sf"
  case "$st" in
    ok)             [ -n "$prev" ] && [ "$prev" != capped ] && LOG green "Remote ID WiFi recovered" 2>/dev/null ;;
    capture_failed) LOG yellow "WARN: WiFi capture failed — Remote ID over WiFi OFF" 2>/dev/null ;;
    not_understood) LOG yellow "WARN: WiFi capture not understood — Remote ID over WiFi OFF" 2>/dev/null ;;
    capped)         LOG yellow "WARN: WiFi capture hit its frame limit (beacon flood?) — Remote ID partly blind" 2>/dev/null ;;
  esac
  return 0
}

sw_rid_start() {   # launch the background capture for this lap; sets SW_RID_CAP/ERR/PID (or clears them)
  SW_RID_CAP=""; SW_RID_ERR=""; SW_RID_PID=""
  [ "${SW_REMOTE_ID:-0}" = 1 ] || return 0
  command -v tcpdump >/dev/null 2>&1 || return 0
  sw_stopped && return 0
  local cap err
  cap="$(mktemp "${SW_TMP_DIR:-/tmp}/sw_rid.XXXXXX")" || { sw_rid_health_note capture_failed; return 0; }
  err="$(mktemp "${SW_TMP_DIR:-/tmp}/sw_rid.XXXXXX")" || { rm -f "$cap"; sw_rid_health_note capture_failed; return 0; }
  # read only (-p, never -I): recon keeps the interface. -l so no line waits in a buffer at a signal.
  # It ends by itself: timeout TERMs tcpdump after SW_RID_SECONDS (awk then finishes), or -c caps frames.
  nice -n 10 timeout -k 2 "${SW_RID_SECONDS:-12}" \
    tcpdump -i "${SW_RID_IFACE:-wlan1mon}" -p -l -nn -xx -c "${SW_RID_MAX_FRAMES:-1500}" "$SW_RID_FILTER" 2>"$err" \
    | nice -n 10 awk -v max="${SW_RID_MAX_DRONES:-32}" "$(_sw_rid_awk_src)" > "$cap" &
  SW_RID_PID=$!; SW_RID_CAP="$cap"; SW_RID_ERR="$err"
  return 0
}

sw_rid_collect() {   # $1 = now, $2 = lootdir. wait, read health, print detections, clean up.
  local now="$1" loot="$2"
  [ -n "${SW_RID_PID:-}" ] || return 0
  wait "$SW_RID_PID" 2>/dev/null
  if sw_stopped; then rm -f "$SW_RID_CAP" "$SW_RID_ERR"; SW_RID_PID=""; return 0; fi
  local started=0 pkts="" stat
  grep -q 'listening on' "$SW_RID_ERR" 2>/dev/null && started=1
  pkts="$(sed -n 's/^\([0-9]\{1,\}\) packets captured/\1/p' "$SW_RID_ERR" 2>/dev/null | tail -1)"
  stat="$(awk -F'\t' '$1=="S"{print $2"\t"$3"\t"$4"\t"$5}' "$SW_RID_CAP" 2>/dev/null)"
  local frames understood ridf over
  IFS=$'\t' read -r frames understood ridf over <<EOF2
$stat
EOF2
  # health: a dead start, a wrong link type / lost output, a hit cap, else ok (incl. an empty lap)
  if [ "$started" -ne 1 ]; then sw_rid_health_note capture_failed
  elif ! grep -q 'IEEE802_11_RADIO' "$SW_RID_ERR" 2>/dev/null; then sw_rid_health_note not_understood
  elif [ -n "$pkts" ] && [ "${frames:-0}" -lt "$pkts" ]; then sw_rid_health_note not_understood   # output lost
  elif [ "${understood:-0}" -eq 0 ] && [ "${frames:-0}" -ge 5 ]; then sw_rid_health_note not_understood
  elif [ -n "$pkts" ] && [ "$pkts" -ge "${SW_RID_MAX_FRAMES:-1500}" ]; then sw_rid_health_note capped
  else sw_rid_health_note ok; fi
  # the drones (skip the matcher, like an evil twin). More than the cap -> one flood line.
  grep '^D' "$SW_RID_CAP" 2>/dev/null | sw_rid_records "$now" "$loot"
  if [ "${over:-0}" -gt 0 ]; then LOG magenta "...and ${over} more drones (Remote ID flood?)" 2>/dev/null; fi
  rm -f "$SW_RID_CAP" "$SW_RID_ERR"; SW_RID_PID=""
  return 0
}
```

Also split the decoder's awk program into a string function so both `_sw_rid_decode_awk` and `sw_rid_start` use one copy. Replace the body of `_sw_rid_decode_awk` (Task 2) so that it reads:

```bash
_sw_rid_awk_src() { cat <<'RIDAWK'
<the entire awk program body from Task 2, verbatim, WITHOUT the surrounding `awk -v max=... '` and closing `'`>
RIDAWK
}
_sw_rid_decode_awk() { awk -v max="${SW_RID_MAX_DRONES:-32}" "$(_sw_rid_awk_src)"; }
```

This keeps ONE copy of the program (DRY) and lets the Task 2 parity test use `_sw_rid_awk_src` directly: `diff <(awk -v max=32 "$(_sw_rid_awk_src)" < f) <(busybox awk -v max=32 "$(_sw_rid_awk_src)" < f)`.

- [ ] **Step 4: Run to green.**
Run: `bash test/run.sh 2>&1 | grep -E 'cap_|rid_busybox|PASS='`
Expected: all PASS; the parity test now uses `_sw_rid_awk_src` and is byte-identical.

- [ ] **Step 5: Commit** (`remoteid: bounded per-lap capture with Stop-safe cleanup and health`, trailer verified).

---

### Task 5: Shared-library changes — `alert.sh`, `ignore.sh`, `log.sh`, `follow.sh`

**Files:**
- Modify: `$SQ/lib/alert.sh`, `$SQ/lib/ignore.sh`, `$SQ/lib/log.sh`, `$SQ/lib/follow.sh`
- Test: `test/alert_test.sh`, `test/ignore_test.sh` (append)

**Interfaces:**
- Consumes: the 9-field drone detection from Task 3.
- Produces: `sw_emit` reads a 9th `detail` field; for `drone_rid` it shows `Drone '<ID>'` (or `Drone (no ID)`), a detail line after the main screen line, and a two-line alert body. `sw_ignored` silences `drone_rid` only via ` DRONE:<ID> ` (or ` DRONE:<MAC> ` when the ID is empty). `sw_log_write` and `sw_follow_update` parse the 9th field cleanly.

- [ ] **Step 1: Write the failing tests.** In `test/alert_test.sh`, immediately before the line `# --- ledger pruning (spec 2026-09-23 §7) ---`, insert:

```bash
# A drone names its ID and shows a detail line and a two-line alert body (spec 2026-10-01 §4)
_L7="$(mktemp -d)"; sw_log_init "$_L7"; _s7="$(mktemp)"; : > "$_s7"; : > "$SW_STUB_LOG"
_drdet="drone_rid|Drone|high|surveillance|wifi|80:E1:26:AA:BB:CC|0000FSWTEST000000001|-47|multirotor	87m up, 12m/s	pilot (live) 47.39800,8.54102"
sw_emit "$_drdet" 1000 600 "$_s7" "$_L7"
assert_contains "$(cat "$SW_STUB_LOG")" "LOG magenta Drone '0000FSWTEST000000001' 80:E1:26:AA:BB:CC -47dBm" drone_line_names_id
assert_contains "$(cat "$SW_STUB_LOG")" "LOG magenta   87m up, 12m/s, pilot (live) 47.39800,8.54102" drone_detail_line
assert_contains "$(cat "$SW_STUB_LOG")" "ALERT Drone '0000FSWTEST000000001'" drone_alert_names_id
assert_contains "$(cat "$SW_STUB_LOG")" "multirotor, 87m up, 12m/s" drone_alert_body_motion
assert_contains "$(cat "$SW_STUB_LOG")" "pilot (live) 47.39800,8.54102" drone_alert_body_pilot
assert_contains "$(cat "$SW_STUB_LOG")" "LED M 200" drone_alert_magenta_led
# the CSV row keeps the detail OUT of the detections.csv (ident holds the ID; rssi stays clean)
assert_contains "$(tail -1 "$_L7/detections.csv")" ',drone_rid,"Drone",high,surveillance,wifi,80:E1:26:AA:BB:CC,"0000FSWTEST000000001",-47,' drone_csv_row_clean
# a drone with no ID: "(no ID)" everywhere, keyed by MAC
: > "$SW_STUB_LOG"
sw_emit "drone_rid|Drone|high|surveillance|wifi|80:E1:26:11:22:33||-60|quad		no pilot location" 1000 600 "$_s7" "$_L7"
assert_contains "$(cat "$SW_STUB_LOG")" "LOG magenta Drone (no ID) 80:E1:26:11:22:33 -60dBm" drone_no_id_line
# control: a plain detection is unchanged (no detail line, no quoting of its name)
: > "$SW_STUB_LOG"
sw_emit "hacker_flipper|Flipper Zero|high|attacker|ble|80:E1:26:00:00:09|Flipper aa|-60" 1000 600 "$_s7" "$_L7"
assert_contains "$(cat "$SW_STUB_LOG")" "LOG cyan Flipper Zero 80:E1:26:00:00:09 -60dBm" plain_label_unchanged_by_drone
rm -rf "$_L7" "$_s7"; unset _L7 _s7 _drdet
```

In `test/ignore_test.sh`, append:

```bash
# a drone is silenced only by drone:<ID> (or drone:<MAC> with no ID), never a plain MAC line
_igd="drone_rid|Drone|high|surveillance|wifi|80:E1:26:AA:BB:CC|0000FSWTEST000000001|-47|a	b	c"
assert_eq "$(sw_ignored "$_igd" " 80:E1:26:AA:BB:CC " && echo drop || echo keep)" "keep" drone_plain_mac_never_silences
assert_eq "$(sw_ignored "$_igd" " DRONE:0000FSWTEST000000001 " && echo drop || echo keep)" "drop" drone_id_silences
_ign="drone_rid|Drone|high|surveillance|wifi|80:E1:26:11:22:33||-60|a	b	c"
assert_eq "$(sw_ignored "$_ign" " DRONE:80:E1:26:11:22:33 " && echo drop || echo keep)" "drop" drone_no_id_silenced_by_mac
unset _igd _ign
```

- [ ] **Step 2: Run to see them fail.**
Run: `bash test/run.sh 2>&1 | grep -E 'drone_|PASS='` → the new assertions FAIL.

- [ ] **Step 3: Edit `$SQ/lib/alert.sh`.** In `sw_emit`, change the field read to include a 9th field:

```bash
  local cat label conf tclass radio mac ident rssi detail
  IFS='|' read -r cat label conf tclass radio mac ident rssi detail <<EOF
$det
EOF
```

After the existing `local rssitag=...` line and the evil-twin `shown` block, add the drone naming and detail:

```bash
  # A drone names its ID (spec 2026-10-01 §4); a drone with no ID says so.
  if [ "$cat" = drone_rid ]; then
    if [ -n "$ident" ]; then shown="$label '$ident'"; else shown="$label (no ID)"; fi
  fi
```

Replace the single screen-line `LOG` with the line plus (for a drone) its detail line:

```bash
  if [ -z "${SW_EMIT_NOLOG:-}" ]; then
    LOG "$color" "$shown $mac$rssitag" 2>/dev/null
    if [ "$cat" = drone_rid ]; then
      local _air="${detail%%$'\t'*}" _rest="${detail#*$'\t'}" _motion _pilot
      _motion="${_rest%%$'\t'*}"; _pilot="${_rest#*$'\t'}"
      local _d2="$_motion"; [ -n "$_pilot" ] && _d2="${_d2:+$_d2, }$_pilot"
      [ -n "$_d2" ] && LOG "$color" "  $_d2" 2>/dev/null
    fi
  fi
```

(Remove the old unconditional `LOG "$color" "$shown $mac$rssitag"` line — it is now inside the block above.) For the alert body, replace the `ALERT "$shown\n$mac$rssitag$note"` with a drone-aware body:

```bash
      if [ "$cat" = drone_rid ]; then
        local _air="${detail%%$'\t'*}" _rest="${detail#*$'\t'}" _motion _pilot _l2
        _motion="${_rest%%$'\t'*}"; _pilot="${_rest#*$'\t'}"
        _l2="$_air"; [ -n "$_motion" ] && _l2="${_l2:+$_l2, }$_motion"
        ALERT "$shown${_l2:+
$_l2}${_pilot:+
$_pilot}
$mac$rssitag$note" 2>/dev/null
      else
        ALERT "$shown
$mac$rssitag$note" 2>/dev/null
      fi
```

- [ ] **Step 4: Edit `$SQ/lib/ignore.sh`.** In `sw_ignored`, parse the detection far enough to get `cat`, `mac` and `ident`, and add the drone branch. Replace the body with:

```bash
  local cat="${1%%|*}" r="${1#*|*|*|*|*|}" mac ident
  mac="${r%%|*}"; r="${r#*|}"; ident="${r%%|*}"
  if [ "$cat" = evil_twin ]; then
    case "$2" in *" EVIL_TWIN:$mac "*) return 0 ;; esac
  elif [ "$cat" = drone_rid ]; then
    if [ -n "$ident" ]; then case "$2" in *" DRONE:${ident^^} "*) return 0 ;; esac
    else case "$2" in *" DRONE:$mac "*) return 0 ;; esac; fi
  else
    case "$2" in *" $mac "*) return 0 ;; esac
  fi
  return 1
```

NOTE: `sw_load_ignore` already upper-cases and space-pads every line, so a `drone:<serial>` line becomes ` DRONE:<SERIAL> `. The `${ident^^}` matches that. A serial with lowercase letters is therefore matched case-insensitively, which is what a hand-edited ignore file expects.

- [ ] **Step 5: Edit `$SQ/lib/log.sh`.** In `sw_log_write`, add the 9th field to the read so `detail` never bleeds into `rssi` (it is not written to `detections.csv`):

```bash
  local cat label conf tclass radio mac ident rssi detail
  IFS='|' read -r cat label conf tclass radio mac ident rssi detail <<EOF
$det
EOF
```

- [ ] **Step 6: Edit `$SQ/lib/follow.sh`.** Change the last parse line so `rssi` is cut at the next `|`:

```bash
  ident="${r%%|*}"; r="${r#*|}"; rssi="${r%%|*}"
```

- [ ] **Step 7: Run to green.**
Run: `bash test/run.sh 2>&1 | grep -E 'drone_|plain_label_unchanged|PASS='`
Expected: all PASS, and the existing evil-twin / follow / snooze assertions stay green (they pass 8-field records, where `detail` reads empty).

- [ ] **Step 8: Commit** (`alert/ignore/log/follow: a drone names its ID, shows telemetry, ignores by ID`, trailer verified).

---

### Task 6: Wire into the lap, config, health; perf and portability guards

**Files:**
- Modify: `$SQ/payload.sh` (lib list, config, `sw_scan_once`, `sw_healthcheck`, `sw_clear_tmp`, `sw_cleanup`)
- Modify: `test/perf_test.sh`, `test/portability_test.sh`, `test/payload_test.sh`

**Interfaces:**
- Consumes: `sw_rid_start`, `sw_rid_collect` (Task 4).
- Produces: `SW_REMOTE_ID` (default 1) and `SW_RID_IFACE`/`SW_RID_SECONDS`/`SW_RID_MAX_FRAMES`/`SW_RID_MAX_DRONES`/`SW_RID_FILE`; the lap captures and collects; the startup health check warns when tcpdump or the interface is missing.

- [ ] **Step 1: Write the failing tests.** In `test/payload_test.sh`, in the `# --- evil twin in the lap` area (near the end), after the evil-twin block's `# --- end evil twin ---`, insert:

```bash

# --- Remote ID over WiFi in the lap (spec 2026-10-01) ---
export SW_REMOTE_ID=1 SW_RID_IFACE=wlan1mon SW_RID_SECONDS=1 SW_RID_MAX_FRAMES=1500 SW_RID_MAX_DRONES=32
_RFIX2="$(cd "$(dirname "${BASH_SOURCE[0]}")/fixtures" && pwd)/rid"
_rid_reset() { rm -f "$SW_LOOT_DIR/detections.csv" "$SW_LOOT_DIR/remoteid.csv"; : > "$SW_SEEN_FILE"; sw_log_init "$SW_LOOT_DIR"; : > "$SW_STUB_LOG"; }
# a lap with a beacon capture (tcpdump stub) and no WiFi/BLE: one drone alert + one remoteid.csv row
_rid_reset
SW_FAKE_TCPDUMP="$_RFIX2/beacon.txt" SW_BLE_CMD=true SW_RECON_DB=/dev/null SW_RECENCY_SECS=600 sw_scan_once
assert_contains "$(cat "$SW_STUB_LOG")" "ALERT Drone '0000FSWTEST000000001'" rid_lap_alerts
assert_contains "$(cat "$SW_LOOT_DIR/remoteid.csv")" "beacon,80:E1:26:AA:BB:CC," rid_lap_csv
assert_contains "$(cat "$SW_LOOT_DIR/detections.csv")" ",drone_rid,\"Drone\",high,surveillance,wifi,80:E1:26:AA:BB:CC," rid_lap_detcsv
# a changing address within cooldown is ONE alert (keyed on ID): run the beacon lap twice
_rid_reset
SW_FAKE_TCPDUMP="$_RFIX2/beacon.txt" SW_BLE_CMD=true SW_RECON_DB=/dev/null sw_scan_once
SW_FAKE_TCPDUMP="$_RFIX2/beacon.txt" SW_BLE_CMD=true SW_RECON_DB=/dev/null sw_scan_once
assert_eq "$(grep -c '^ALERT Drone' "$SW_STUB_LOG")" "1" rid_lap_id_cooldown_one_alert
# SW_REMOTE_ID=0: the stub never runs
_rid_reset
SW_REMOTE_ID=0 SW_FAKE_TCPDUMP="$_RFIX2/beacon.txt" SW_BLE_CMD=true SW_RECON_DB=/dev/null sw_scan_once
assert_empty "$(grep -F 'Drone' "$SW_STUB_LOG")" rid_lap_off_silent
# the default is ON, read in a clean process
assert_eq "$(env -u SW_REMOTE_ID bash -c 'SW_TEST_SOURCE=1 . "$1"/payload.sh >/dev/null 2>&1; echo "$SW_REMOTE_ID"' _ "$SW_ROOT")" "1" payload_default_remote_id_on
# tcpdump missing -> a startup WARN (build a PATH without tcpdump but with everything else health needs)
_rid_nopath="$(mktemp -d)"; for _t in bash sqlite3 date mktemp cp rm grep sed awk btmon nice timeout; do _p="$(command -v "$_t" 2>/dev/null)"; [ -n "$_p" ] && ln -sf "$_p" "$_rid_nopath/$_t"; done
: > "$SW_STUB_LOG"
PATH="$_rid_nopath:$SW_ROOT_STUBS" SW_REMOTE_ID=1 SW_RECON_DB="$FIX/recon.db" sw_healthcheck 2>/dev/null
assert_contains "$(cat "$SW_STUB_LOG")" "tcpdump missing" rid_health_tcpdump_missing
rm -rf "$_rid_nopath"; unset _rid_nopath _RFIX2; unset -f _rid_reset
# --- end Remote ID ---
```

Also append ` SW_REMOTE_ID SW_RID_IFACE SW_RID_SECONDS SW_RID_MAX_FRAMES SW_RID_MAX_DRONES SW_RID_FILE` to the long `unset SW_RECON_DB SW_BLE_CMD …` cleanup line near the end of `payload_test.sh`.

NOTE: `SW_ROOT_STUBS` — add near the top of `payload_test.sh` if not present: `SW_ROOT_STUBS="$(cd "$(dirname "${BASH_SOURCE[0]}")/stubs" && pwd)"`. The health check needs a `tcpdump` stub on PATH for the lap tests; it is already there via `run.sh`.

- [ ] **Step 2: Run to see them fail.**
Run: `bash test/run.sh 2>&1 | grep -E 'rid_lap|rid_health|payload_default_remote|PASS='`

- [ ] **Step 3: Edit `$SQ/payload.sh`.**
  (a) Add `remoteid` to the lib load loop:

```bash
for l in match wifi ble alert log follow ignore snooze eviltwin remoteid; do
```

  (b) In the config block, after the `SW_EVIL_TWIN` line, add:

```bash
# Remote ID over WiFi (spec 2026-10-01): a bounded tcpdump window each lap on the recon radio decodes
# drone Remote ID (serial, position, pilot) from beacons and NAN frames. 1 = on; anything else off.
: "${SW_REMOTE_ID:=1}"
: "${SW_RID_IFACE:=wlan1mon}"
: "${SW_RID_SECONDS:=12}"
: "${SW_RID_MAX_FRAMES:=1500}"
: "${SW_RID_MAX_DRONES:=32}"
: "${SW_RID_FILE:=$SW_LOOT_DIR/remoteid.csv}"
```

  (c) In `sw_scan_once`, start the capture at the very top (before the recon snapshot) and collect it last in the producer group. Change the function so it reads:

```bash
sw_scan_once() {
  local now snap=""; now="$(date +%s)"
  sw_rid_start                       # begin the Remote ID capture window (no-op unless SW_REMOTE_ID=1)
  sw_recon_snapshot "$SW_RECON_DB" && snap="$REPLY"
  {
    [ -n "$snap" ] && [ "${SW_EVIL_TWIN:-0}" = 1 ] && sw_evil_twin_scan "$snap" "$now"
    { if [ -n "$snap" ]; then sw_wifi_records_in "$snap"; sw_recon_drop "$snap"; fi; _sw_ble_records; } \
      | sw_match_stream "$SW_SIGS"
    sw_rid_collect "$now" "$SW_LOOT_DIR"      # decode + print drone detections (after the BLE scan)
  } | {
      # ... the existing emit loop, unchanged ...
```

(Keep the rest of `sw_scan_once` exactly as it is. `sw_rid_collect` prints `drone_rid|…` lines straight into the emit loop, like `sw_evil_twin_scan`.)

  (d) In `sw_healthcheck`, after the `btmon missing` check, add the Remote ID checks:

```bash
  if [ "${SW_REMOTE_ID:-0}" = 1 ]; then
    if ! command -v tcpdump >/dev/null 2>&1; then
      _sw_health_warn "WARN: tcpdump missing — Remote ID over WiFi OFF"; degraded=1
    elif [ ! -e "/sys/class/net/${SW_RID_IFACE:-wlan1mon}" ]; then
      _sw_health_warn "WARN: ${SW_RID_IFACE:-wlan1mon} missing — Remote ID over WiFi OFF"; degraded=1
    fi
  fi
```

  (e) In `sw_clear_tmp` and `sw_cleanup`, add `sw_rid.*` / `sw_rid.state` to the removals:

```bash
# sw_clear_tmp:
sw_clear_tmp() { rm -f "${SW_TMP_DIR:-/tmp}"/sw_ble.* "${SW_TMP_DIR:-/tmp}"/sw_recon.* "${SW_TMP_DIR:-/tmp}"/sw_rid.* "$SW_SEEN_FILE".sw-prune-tmp.?????? 2>/dev/null; }
# sw_cleanup (add sw_rid.state and any sw_rid.* capture left by a stopped lap):
sw_cleanup() {
  rm -f "${SW_TMP_DIR:-/tmp}"/sw_ble.state "${SW_TMP_DIR:-/tmp}"/sw_rid.state "${SW_TMP_DIR:-/tmp}"/sw_recon.* "${SW_TMP_DIR:-/tmp}"/sw_rid.* "$SW_SEEN_FILE".sw-prune-tmp.?????? 2>/dev/null
  exit 0
}
```

NOTE on the health check and the `/sys/class/net` test: on the dev box `wlan1mon` does not exist, so `payload_test.sh`'s healthy-control tests must set `SW_REMOTE_ID=0` OR point `SW_RID_IFACE` at a real interface. The existing healthy-control cases (`payload_healthcheck_*`) run with `SW_REMOTE_ID` unset → defaults to 1 only when the payload's config block runs; in the unit calls to `sw_healthcheck` it is unset, so guard the block with `[ "${SW_REMOTE_ID:-0}" = 1 ]` (as written) — unset means off in those unit calls, so they stay green. The `rid_health_tcpdump_missing` test sets `SW_REMOTE_ID=1` explicitly.

- [ ] **Step 4: Edit `test/perf_test.sh`** — guard the per-row bash (not the awk). Before the final `unset`, add:

```bash
# Remote ID: the per-drone bash is builtins only (the heavy work is the one awk pass, not per frame).
source "$SW_ROOT/lib/remoteid.sh"
for _fn in sw_rid_coord sw_rid_alt sw_rid_mps sw_rid_mps2 sw_rid_dmps sw_rid_id; do
  assert_contains "$(_sw_body "$SW_ROOT/lib/remoteid.sh" "$_fn")" "$_fn()" "forkfree_found_$_fn"
  assert_empty "$(_sw_body "$SW_ROOT/lib/remoteid.sh" "$_fn" | grep -nE '\$\([^(]|`|(^|[^a-z_])(tr|sed|cut|awk|grep) ')" "forkfree_$_fn"
done
# the capture must be read-only (-p, never -I) and must never set a channel
assert_contains "$(_sw_body "$SW_ROOT/lib/remoteid.sh" sw_rid_start)" "tcpdump -i" rid_start_uses_tcpdump
assert_contains "$(_sw_body "$SW_ROOT/lib/remoteid.sh" sw_rid_start)" " -p " rid_start_passive
assert_empty  "$(_sw_body "$SW_ROOT/lib/remoteid.sh" sw_rid_start | grep -E ' -I | iw .* set | monitor')" rid_start_never_reconfigures
```

- [ ] **Step 5: Edit `test/portability_test.sh`** — the Remote ID code must not use `0x` awk literals and must not kill by name. Before the final assertion, add:

```bash
# the awk decoder must not use 0x.. numeric literals (BusyBox/mawk do not parse them)
assert_empty "$(grep -nE '[^0-9a-fx]0x[0-9a-fA-F]' "$SW_PAYLOADS/user/reconnaissance/squachwatch/lib/remoteid.sh" | grep -vE 'wlan\[0\]|0x0000|comment')" remoteid_no_hex_awk_literals
# control: the grep CAN see a planted 0x literal
assert_contains "$(printf 'if(b(i)==0xfa)\n' | grep -nE '[^0-9a-fx]0x[0-9a-fA-F]')" "0xfa" remoteid_hexlit_grep_works
# the capture never finds or kills by name
assert_empty "$(grep -nE '(killall|pkill|pidof|pgrep)' "$SW_PAYLOADS/user/reconnaissance/squachwatch/lib/remoteid.sh")" remoteid_no_kill_by_name
```

(The `wlan[0] & 0xfc = 0xd0` in the BPF filter is a tcpdump expression, not awk; the grep excludes it via `grep -vE 'wlan\[0\]'`. If your filter string triggers the check, move it to the `: "${SW_RID_FILTER:=...}"` default and exclude that line too.)

- [ ] **Step 6: Run the full suite.**
Run: `bash test/run.sh 2>&1 | tail -3`
Expected: `PASS=<baseline + all new> FAIL=0`. Also run the cleanliness check: `bash test/run.sh 2>&1 | grep -v -E '^(== |  FAIL|-----|PASS=)'` prints nothing.

- [ ] **Step 7: Commit** (`payload: run the Remote ID capture each lap, config and health`, trailer verified).

---

### Task 7: Docs, spec amendments, privacy check, final commit

**Files:**
- Modify: `README.md`, `docs/superpowers/P0-findings.md`, `docs/superpowers/specs/2026-10-01-squachwatch-remote-id-wifi-design.md`

**Interfaces:** none (docs only).

- [ ] **Step 1: README.** In "What it detects", the drone phrase already says "drones broadcasting Remote ID"; leave it. In the settings list, after the `SW_EVIL_TWIN` bullet, add a `SW_REMOTE_ID` bullet (plain language, non-technical, per `feedback_cleanthis_public_pages_language` — but this is a dev README, so some terms are fine):

```markdown
- `SW_REMOTE_ID` (default 1): listen for drones that broadcast **Remote ID** over WiFi — the public "licence plate" most drones must send. Each lap, a short read-only capture on the recon radio decodes the drone's ID (usually its serial number), where it is (position, height, speed, heading) and **where the pilot is standing**, as a high-confidence alert with a buzz, plus a row per lap in `remoteid.csv` (its flight track). It also catches DJI (WiFi beacon) and NAN-based drones. It cannot control the radio's channel, so it hears a drone only when the recon scan is on the drone's channel — a drone that is around for a while is caught across a few laps, one that passes in seconds may be missed. Remote ID is not signed, so a detection means "something here is broadcasting drone Remote ID", and every position is what the transmitter claims. To silence your own drone, add `drone:<its ID>` to `ignore.txt` (a plain address never silences a drone — its address can change). `0` turns it off. Settings: `SW_RID_SECONDS` (capture window, default 12), `SW_RID_MAX_FRAMES` (1500), `SW_RID_MAX_DRONES` (32).
```

Update the `ignore.txt` bullet to mention `drone:<ID>` alongside `evil_twin:<address>`. In "Tests", set the count to the new `PASS=` total. In "Status & roadmap", after the Evil-twin paragraph, add:

```markdown
**Remote ID over WiFi** (2026-10-01): decodes drone Remote ID from WiFi beacons (the ASD-STAN vendor element `FA:0B:BC`/`0x0D` and Parrot's `90:3A:E6`) and from WiFi-NAN action frames, pulling out the drone's serial, airframe type, position, height, speed and heading, and the operator's location — a high-confidence buzzing alert, plus a per-lap `remoteid.csv` flight track. The framing checks are ported byte for byte from the SquachWatch-CYD fork's OpenDroneID reader; the message offsets and scalings are from opendroneid-core-c. The capture is a bounded, read-only `tcpdump` window each lap on the recon radio (`-p`, never reconfiguring it), piggybacking recon's channel hopping, so it never disturbs recon.db or the access point. The decoder is one `awk` pass that writes only numbers, empty, or hex — so a spoofed Remote ID (the protocol is unauthenticated) cannot forge a field — and it was proven byte-identical on the Pager's BusyBox awk and the dev box's awk against frames built by opendroneid-core-c and run through the real `tcpdump`. One drone is one ID: a changing WiFi address does not make a new drone. Fixtures are generated by `tools/rid_fixtures/build.sh` (dev box only). The live test needs a real Remote ID drone; the official OpenDroneID OSM phone app is the second opinion.
```

- [ ] **Step 2: P0-findings.** Append a `## Remote ID over WiFi (2026-10-01)` section recording the device + spike facts: tcpdump 4.99.5/libpcap 1.10.5 are stock (`/rom/usr/bin`); `-xx` begins with the radiotap header (read its length from bytes 2–3 LE to find the 802.11 start); `type mgt subtype action` is a filter **syntax error** on this libpcap (use `wlan[0] & 0xfc = 0xd0`); BPF cannot search a beacon's IE list, so the kernel narrows to beacons + the fixed NAN address and awk finds the RID beacons; the planned filter matched beacon + NAN and rejected a deauth query in the spike; mawk/BusyBox awk do not parse `0x..` literals (use decimal); the full decode (serial, position, height, speed, pilot) was byte-identical on both awks against opendroneid-core-c frames through the real tcpdump; beacons run ~7–10/s while recon hops, action frames ~1/20 s; hex-dumping all beacons + the awk join ≈ 12% CPU over 20 s (split tcpdump-vs-awk is a Phase 0 item); `nice`, `mkfifo` present; phy0 `wlan0`(station)+`wlan0mon` on the station channel, phy1 `wlan1mon` hopped by pineapd. Record the pinned opendroneid-core-c commit `6484f26545d4f012682524e2d843fab0fbdc0b34` and the three sha256 sums.

- [ ] **Step 3: Spec amendments.** In the design spec, (a) at the end of §6.2, note that the decoder's awk program is kept as a single copy via `_sw_rid_awk_src` and shared by the decode helper and the capture; (b) in §9 (Phase 0), tick that items 1–7's device facts were pre-checked in the planning spike where possible (tcpdump version, filter syntax, filter match, awk parity), leaving the on-device cost split, window timing, channel coverage and read-only confirmation for the installed run; (c) confirm §3's "decoder merges per address only" wording matches the built code.

- [ ] **Step 4: Privacy check, then commit.** The committed fixtures and all code use only the made-up serial `0000FSWTEST...`, the made-up OUI `80:E1:26` (the user's own Flipper block, already public in the repo since 2026-09-25), and the public coordinates near 47.39,8.54 (Zürich city centre, opendroneid's own sample). Confirm no real data:

```bash
git add -A
git diff --cached | grep -n -E '/home/|([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}' | grep -viE '80:E1:26|AA:BB:CC|11:22:33|FF:FF:FF|51:6F:9A|50:6F:9A' ; echo "privacy-grep exit=$? (1 = clean)"
TZ=UTC git -c user.name=Ziggy -c user.email=79704039+therealziggy@users.noreply.github.com commit -F - <<'EOF'
docs: Remote ID over WiFi — README, device findings, spec notes

README gains the SW_REMOTE_ID setting and a status paragraph; P0-findings
records the device and spike facts (stock tcpdump, the filter syntax, the
radiotap offset, awk decimal literals, the measured rates, awk parity);
the spec notes the single awk-source copy, the Phase-0 items the spike
pre-checked, and the per-address merge.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
git log -1 --format=%B | grep -cF 'Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>'
```
Expected: `privacy-grep exit=1`, then `1`.

---

## After the tasks (the controller)

1. **Whole-branch review** (two independent reviewers, per `feedback_security_fix_adversarial_review`): one general; one adversarial, briefed to BREAK the decoder from hostile frames end to end (a malformed frame before a good one must not hide the good one; element/pack lengths running past the frame; a pack count of 0/10 or a wrong message size; a NAN control byte lying about its optional fields; a hostile serial/operator-id with `|`, commas, quotes, line breaks, `%s`, `$(x)`, N: it must neither forge a detection/CSV field nor a second line nor a spreadsheet formula; coordinates out of range; a beacon whose SSID holds `-1dBm signal` and a fake `SA:` so the signal/address cannot be spoofed from text), plus the per-lap capture Stop (a Stop at every step of `sw_rid_start`/`sw_rid_collect`) and the frame cap. Fold in what survives; re-run the whole mutation matrix (every earlier mutant, not just the new fix's RED→GREEN — overlapping guards mask each other, `feedback_vacuous_probe_third_head` #45), running mutants in parallel repo copies (`git ls-files -z | xargs -0 cp --parents -t <dir>`), never editing the checkout a reviewer is reading.
2. **Root run:** `unshare -r bash test/run.sh` ends `FAIL=0` too.
3. **On the Pager, only with the user's OK — Phase 0 first (read only, nothing installed):** run the §9 spike (`swprobe.sh`-style, launcher header + verb stubs, so the user's running SquachWatch is undisturbed): tcpdump text parity against a fixture pcap; `-p` capture really is read-only (recon.db keeps growing during a capture); the tcpdump-vs-awk cost split, and `SW_RID_MAX_FRAMES` set so a lap at the cap stays in budget; `SW_RID_SECONDS` so the window ends before the BLE scan; channel coverage near ch6 and ch149; awk frame count equals tcpdump's `packets captured` after a TERM. Record in `P0-findings.md`.
4. **Install, only with the user's OK:** stage on the same file system, `mv` into place, md5 every file (`payload.sh`, `lib/remoteid.sh`, `lib/alert.sh`, `lib/ignore.sh`, `lib/log.sh`, `lib/follow.sh`); a launcher-faithful silent lap (armed, no WARN, no Remote ID status line, lap time as Phase 0 predicted, A/B against the current build like the evil-twin round); a Stop ends in `Payload completed`.
5. **Live test (needs a real Remote ID drone):** near a current DJI (or any RID drone), expect one `Drone '…'` alert with the buzz, the detail line, a `remoteid.csv` row per lap, and the official **OpenDroneID OSM** phone app showing the same ID/position/pilot. No made-up drone is ever broadcast. With no drone at hand, the live test waits.
6. **Push, only with the user's OK:** first the pre-push privacy scan that worked for the evil-twin round — scp the Pager's recon.db into the session scratchpad, take every real address and name, intersect with `git log -p origin/main..main` (addresses normalised to 12-hex; names whole-word), plus paths/metadata/trailers/clock-epoch-timezone hints and positive controls (inject one real token and confirm the scan catches it); delete the copy after. Only when it finds nothing, and the pre-push hook passes (refs = only `main`), `git push`.

## Self-review notes (done while writing)

- **Spec coverage:** capture (§6.1)→Task 4; decoder (§6.2)→Task 2; records + `remoteid.csv` (§6.3, §6.5)→Task 3; shared libs (§6.4)→Task 5; config (§6.6) + lap + health (§7.1, §7.2)→Task 6; Stop/orphans (§7.3)→Task 4; hostile input (§7.4)→Tasks 2/3 + the adversarial review; perf (§7.5)→Task 6 guards + Phase 0; fixtures/tests (§8)→Tasks 1–6; Phase 0 (§9)→controller; deploy/live (§10)→controller; privacy (§11)→Task 1/7 + controller; limits (§12)→README (Task 7). All transports (ASD-STAN, NAN, Parrot) have a fixture and a decode test.
- **Type/name consistency:** the decoder's 24-field `D` contract is fixed once (File structure) and consumed identically by Task 3 (`sw_rid_records`'s `read`) and `test/helpers/rid.sh`. The detection is 9-field `drone_rid|Drone|high|surveillance|wifi|MAC|ID|rssi|detail` in Tasks 3/4/5. `SW_RID_*` names match across payload.sh, remoteid.sh and the tests.
- **No placeholders:** every step has real code or a real command with expected output. The two NOTE blocks (BusyBox-awk extraction in Task 2 Step 5; the `_sw_rid_awk_src` split in Task 4 Step 3) describe a concrete refactor, not a TBD.
