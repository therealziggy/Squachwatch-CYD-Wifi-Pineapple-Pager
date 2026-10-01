# SquachWatch-Pager Remote ID over WiFi Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Decode drone Remote ID from WiFi (ASD-STAN and Parrot beacons, and NAN action frames) into the drone's ID, position, motion and the pilot's location, raised as a high-confidence buzzing detection and logged as a per-lap flight track.

**Architecture:** A new `lib/remoteid.sh` runs a bounded, read-only `tcpdump` window each lap on the recon radio `wlan1mon` (`-p`, riding recon's channel hopping), through a BPF filter that keeps beacons and NAN-addressed action frames. ONE streaming `awk` pass decodes them into one line per transmitter address, written as integers, empty fields or lowercase hex only. Bash turns each line into units, cleaned text, a `remoteid.csv` row and a detection in the existing format plus a ninth, display-only field; the detections enter the same emit loop as the evil-twin check, where the cooldown, ignore list and alert key on the drone's ID.

**Tech Stack:** bash 5 on a BusyBox userland (the Pager; the payload is `#!/bin/bash`); `tcpdump` 4.99.5 + radiotap (stock firmware); BusyBox `awk` 1.36.1; the repo's bash test harness (`bash test/run.sh`). The fixture generator (dev box only) is C compiled against opendroneid-core-c.

**Spec:** `docs/superpowers/specs/2026-10-01-squachwatch-remote-id-wifi-design.md` (approved 2026-10-01; its §14 records what the verified dry run settled).

**How this plan was verified (2026-10-01).** Before any task was dispatched, every patch below was applied, in order, to a copy of the repository at the commit this plan starts from, and the full suite was run after each task: Task 1 → 887, Task 2 → 948, Task 3 → 1006, Task 4 → 1037, Task 5 → 1056, Task 6 → 1105, Task 7 → 1105 assertions, all with `FAIL=0` and no stray output, and the final tree also passes as root. The "RED" results in each task's Step 2 come from applying that task's test patch alone. About thirty deliberately broken variants of the guards (a bounds check removed, the ledger keyed by address, the capture started outside the producer shell, ...) were each caught by a named test. The fixtures regenerate byte-identically.

## Global Constraints

- **Public repository.** Made-up IDs, MACs, network names and coordinates only, in tests, fixtures, docs and commit messages. Never a real drone serial, address, pilot position, network name, date or time, and never a local path (`/home/...`). The fixtures carry no clock times (`tcpdump -t`) and no machine uptime (the generator zeroes the beacon timestamp).
- **Commits:** `TZ=UTC git -c user.name=Ziggy -c user.email=79704039+therealziggy@users.noreply.github.com commit ...`. Every message ends with exactly ONE line `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`, copied verbatim, never another model name. Verify it with `grep -cF` after each commit (each task's Step 5 does).
- **Do not push, and do not touch the Pager.** The controller does both, with the user's OK.
- **Apply the patches exactly.** They were produced with `git diff` from the verified dry run. Never retype one, and never edit around a patch that does not apply: report BLOCKED with the error instead.
- **The Pager runs bash on BusyBox:** no `[:class:]` in `tr`; a `mktemp` template ends in `XXXXXX` with nothing after it; no `od`, `hexdump`, `diff`, `paste`, `tshark` on the device. `tcpdump`, `iw`, `nice` and `mkfifo` are there.
- **awk runs on BusyBox awk 1.36.1:** no gawk extensions, and no `0x..` numeric literals (BusyBox awk and mawk do not parse them; use decimal). `test/portability_test.sh` checks the second rule.
- **Per-frame and per-record work is fork-free.** The frames are read by one awk process per lap; bash runs per drone (a handful per lap), and its formatters are builtins only. `test/perf_test.sh` enforces both.
- **No `:=` defaults in `lib/*.sh`:** `payload.sh` loads its libs before its config block.
- **The capture is read-only and ends by itself:** `tcpdump -p`, never `-I`, `iw … set` or `ifconfig`; it runs under its own `timeout` and `-c`; nothing is ever found or killed by name.
- **Hostile input:** Remote ID is not authenticated. Every length and offset is bounds-checked, one bad frame never hides a later one, text leaves awk as hex and becomes text only through `sw_sanitize_ident`, and CSV cells go through `_sw_csv_cell` (the formula guard).
- **Tests:** every "nothing happened" assertion has a positive control. `test/run.sh` sources every `*_test.sh` into one shell, so a test file loads the libraries it uses itself and unsets what it sets. `bash test/run.sh` ends with the `PASS=` count each task gives and `FAIL=0`, and `bash test/run.sh 2>&1 | grep -v -E '^(== |  FAIL|-----|PASS=)'` prints nothing. The baseline before this plan is `PASS=874 FAIL=0` (about 90 s); the end is `PASS=1105 FAIL=0` (about 110 s).
- **Functions the payload's main shell runs** (`sw_main`, `sw_prune_ledger`, `sw_seen_prune`, `sw_clear_tmp`, `sw_log_init`, `sw_cleanup`) never use `continue` or `break`. The capture code runs in a lap's subshell and may.
- The lib path prefix `payloads/user/reconnaissance/squachwatch/` is written `$SQ/` below.

## Applying the patches

Each task has a test patch (Step 1) and an implementation patch (Step 3). Task 7 has one docs patch. All of them are fenced as `diff` blocks in this plan, so in the task's brief file too. Extract one with this helper and apply it from the repository root. Do not copy a patch by hand: patches hold TAB characters inside test strings, and Read-tool line numbers would corrupt them.

```bash
# rid_patch BRIEF K: the K-th ```diff block of the brief -> /tmp/rid-patch-K.patch, applied to the repo
rid_patch() {
  awk -v k="$2" '/^```diff$/ { n++; on = (n == k); next } /^```/ { on = 0 } on' "$1" > "/tmp/rid-patch-$2.patch" &&
    git apply --whitespace=nowarn "/tmp/rid-patch-$2.patch" && git apply --stat "/tmp/rid-patch-$2.patch"
}
rid_patch <your brief file> 1     # Step 1: the tests
rid_patch <your brief file> 2     # Step 3: the implementation
```

If `git apply` refuses (an earlier review fix changed a line it expects), retry once with `git apply --3way --whitespace=nowarn /tmp/rid-patch-K.patch`. If that fails too, stop and report BLOCKED with its output.

## File structure

| File | Task | Responsibility |
|---|---|---|
| `tools/rid_fixtures/gen.c`, `tools/rid_fixtures/build.sh` | 1 | build Remote ID frames with opendroneid-core-c (pinned) and turn them into the fixtures; dev box only |
| `test/fixtures/rid/*.pcap`, `*.txt` | 1 | ten fixtures: beacon, nan, parrot, multi, unknowns, equator, order, quiet, truncated, badlink |
| `$SQ/lib/remoteid.sh` | 2, 3, 4 | the decoder; the lines → detections + `remoteid.csv`; the per-lap capture and its health note |
| `$SQ/lib/log.sh` | 3, 5 | `_sw_csv_cell` (REPLY, no fork); `sw_log_write` reads the ninth field |
| `$SQ/lib/ignore.sh` | 3 | `drone_rid` is dropped only for `drone:<ID>` (or `drone:<MAC>` when it has no ID) |
| `$SQ/lib/alert.sh`, `$SQ/lib/follow.sh` | 5 | a drone's name, detail line, alert body and ID-only ledger key; the ninth field parses cleanly |
| `$SQ/payload.sh` | 6 | load `remoteid`, the `SW_RID_*` settings, the lap wiring, the health check, the temp-file sweep |
| `test/remoteid_test.sh`, `test/helpers/rid.sh`, `test/stubs/tcpdump` | 1–4 | the decoder, record and capture tests; a D-line builder; the device-faithful tcpdump |
| `test/ignore_test.sh`, `test/alert_test.sh`, `test/follow_test.sh`, `test/payload_test.sh`, `test/perf_test.sh`, `test/portability_test.sh` | 3, 5, 6 | wiring, guards and budgets |
| `README.md`, `docs/superpowers/P0-findings.md` | 7 | docs |

**The decoder's output contract** (Tasks 2–4 depend on it):
- Stats line: `S<TAB>frames<TAB>understood<TAB>rid_frames<TAB>more_drones`
- Drone line, `D` then 24 TAB-separated fields, each an integer, empty, or lowercase hex:
  `D mac rssi forms id_type id_hex id2_type id2_hex ua_type status lat lon alt_geo alt_baro height height_ref speed vspeed heading pilot_type pilot_lat pilot_lon pilot_alt operator_id_hex self_id_hex`
  - `mac` 12 lowercase hex; `rssi` a signed integer or empty; `forms` a bit mask (1 ASD-STAN beacon, 2 NAN, 4 Parrot beacon);
  - `lat`/`lon`/`pilot_lat`/`pilot_lon` the raw signed 1e7 integer, empty when unknown (both 0) or out of range;
  - `alt_geo`/`alt_baro`/`height`/`pilot_alt` the raw `uint16` encoding (metres = enc × 0.5 − 1000), empty when 0;
  - `speed` centi-m/s, `vspeed` deci-m/s (signed), `heading` whole degrees, each empty when the standard says "unknown";
  - `id_hex`/`id2_hex`/`operator_id_hex`/`self_id_hex` lowercase hex of the text, cut at the first zero byte, trailing spaces dropped.

## What changed from the first version of this plan

A pre-flight review found defects in the first version; this version was rebuilt from a dry run that fixed and proved each one. Those that would have reached the device: the capture was started outside the shell that collects it (its `wait` would return at once and read the capture early); `read` with `IFS=TAB` merged runs of empty fields and shifted every later field; the "one drone = one ID" ledger key was missing; the fixtures carried local clock times and the generating machine's uptime into a public repository; `build.sh` fetched three of the four files the library needs. The rest were in the tests: off-by-one field numbers and a wrong serial literal, several assertions that could not fail, a test file that passed only thanks to another file's state, and a gawk-builtin name in the awk.

---

### Task 1: Fixtures from the reference library

**Files:**
- `test/remoteid_test.sh`
- `tools/rid_fixtures/build.sh`
- `tools/rid_fixtures/gen.c`
- `test/fixtures/rid/*` (20 files, generated by `build.sh` in Step 3; not in the patch)

**Interfaces:**
- Consumes: nothing from this plan.
- Produces: `test/fixtures/rid/{beacon,nan,parrot,multi,unknowns,equator,order,quiet,truncated,badlink}.{pcap,txt}`
  (the `.txt` files are `tcpdump -t -nn -xx` text; the tests read those); `tools/rid_fixtures/build.sh`, which
  regenerates them byte-identically; `test/remoteid_test.sh` with its header (`SW_ROOT`, `_RFIX`), which later
  tasks extend.

- [ ] **Step 1: Write the failing tests.** Apply this task's FIRST patch (see "Applying the patches"):

```diff
diff --git a/test/remoteid_test.sh b/test/remoteid_test.sh
new file mode 100644
index 0000000..9c2dc5b
--- /dev/null
+++ b/test/remoteid_test.sh
@@ -0,0 +1,16 @@
+#!/bin/bash
+# test/remoteid_test.sh — Remote ID over WiFi (spec 2026-10-01). Reads the committed fixtures in
+# test/fixtures/rid/ (made by tools/rid_fixtures/build.sh from opendroneid-core-c).
+SW_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../payloads/user/reconnaissance/squachwatch" && pwd)"
+_RFIX="$(cd "$(dirname "${BASH_SOURCE[0]}")/fixtures" && pwd)/rid"
+
+# --- the fixtures: tcpdump -t -nn -xx text, radiotap with a signal, no clock times ---
+for _f in beacon nan parrot multi unknowns equator order quiet truncated badlink; do
+  assert_eq "$([ -s "$_RFIX/$_f.txt" ] && echo ok)" "ok" "rid_fixture_present_$_f"
+done
+assert_contains "$(cat "$_RFIX/beacon.txt")" "-47dBm signal Beacon (TEST-DRONE)" rid_fixture_signal_header
+assert_empty "$(grep -lE '^[0-9]{2}:[0-9]{2}:[0-9]{2}\.' "$_RFIX"/*.txt)" rid_fixtures_no_clock_times
+# control: the same check does see a clock time at the start of a line
+assert_contains "$(printf '22:13:20.000000 Beacon\n' | grep -E '^[0-9]{2}:[0-9]{2}:[0-9]{2}\.')" "22:13:20" rid_fixture_clock_check_works
+unset _f
+
```

- [ ] **Step 2: Run the suite and see the new tests fail.**

Run: `bash test/run.sh 2>&1 | tail -1`
Expected: `PASS=876 FAIL=11`. The failures are exactly these new tests: `rid_fixture_present_beacon`, `rid_fixture_present_nan`, `rid_fixture_present_parrot`, `rid_fixture_present_multi`, `rid_fixture_present_unknowns`, `rid_fixture_present_equator`, `rid_fixture_present_order`, `rid_fixture_present_quiet`, `rid_fixture_present_truncated`, `rid_fixture_present_badlink`, `rid_fixture_signal_header`. Other output is expected at this step too: the rest of multi-line failure messages, and errors such as `command not found` or `No such file or directory` for what this task has not added yet.

- [ ] **Step 3: Implement.** Apply this task's SECOND patch:

```diff
diff --git a/tools/rid_fixtures/build.sh b/tools/rid_fixtures/build.sh
new file mode 100755
index 0000000..8e7d007
--- /dev/null
+++ b/tools/rid_fixtures/build.sh
@@ -0,0 +1,34 @@
+#!/usr/bin/env bash
+# tools/rid_fixtures/build.sh — regenerate the committed Remote ID test fixtures (test/fixtures/rid/).
+# Dev box only: it needs curl, a C compiler and tcpdump. It downloads four files of opendroneid-core-c,
+# the reference Remote ID library (Apache-2.0), pinned by commit AND by sha256, so a changed download
+# stops it; builds gen.c against them in a temporary folder; writes one pcap per fixture; and runs the
+# real tcpdump over each to make the text the tests read. The frames only ever go to files.
+# -t: no clock times in that text (they would show this box's time zone in a public repository).
+set -eu
+HERE="$(cd "$(dirname "$0")" && pwd)"
+OUT="$(cd "$HERE/../../test/fixtures" && pwd)/rid"
+SHA=6484f26545d4f012682524e2d843fab0fbdc0b34
+BASE="https://raw.githubusercontent.com/opendroneid/opendroneid-core-c/$SHA/libopendroneid"
+WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
+mkdir -p "$OUT"
+while read -r sum f; do
+  curl -fsSL "$BASE/$f" -o "$WORK/$f"
+  echo "$sum  $WORK/$f" | sha256sum -c --quiet - || { echo "checksum mismatch: $f" >&2; exit 1; }
+done <<'SUMS'
+60b0964f5f2a0dc13833eb6a304f7bd3f64bb9c227fae168c7caba53c82927c2 opendroneid.c
+a60b9b38c4fa82d7c85437dc11f57f0dea4ebf8bb4b90b3ff3c21c585ccd55f4 opendroneid.h
+bae2f4e85e8e391c78f33aba33d32beef98ace7aee42881a0aee4a1a34aa442b wifi.c
+44e39ca04eb004233db78e8e91f44a732203e0bf57aabbb721632040aa82ffd8 odid_wifi.h
+SUMS
+gcc -O2 -w -o "$WORK/gen" "$HERE/gen.c" "$WORK/opendroneid.c" "$WORK/wifi.c" -I"$WORK" -lm
+for k in beacon nan parrot multi unknowns equator order quiet truncated; do
+  "$WORK/gen" "$k" "$OUT/$k.pcap"
+done
+# badlink: the beacon under another link type (LINKTYPE_ETHERNET = 1, at byte 20 of the pcap header)
+cp "$OUT/beacon.pcap" "$OUT/badlink.pcap"
+printf '\001' | dd of="$OUT/badlink.pcap" bs=1 seek=20 count=1 conv=notrunc 2>/dev/null
+for k in beacon nan parrot multi unknowns equator order quiet truncated badlink; do
+  TZ=UTC tcpdump -r "$OUT/$k.pcap" -t -nn -xx 2>/dev/null > "$OUT/$k.txt"
+done
+echo "fixtures written to $OUT"
diff --git a/tools/rid_fixtures/gen.c b/tools/rid_fixtures/gen.c
new file mode 100644
index 0000000..140f027
--- /dev/null
+++ b/tools/rid_fixtures/gen.c
@@ -0,0 +1,114 @@
+/* tools/rid_fixtures/gen.c — build Remote ID WiFi frames with opendroneid-core-c and write a
+ * LINKTYPE_IEEE802_11_RADIO pcap. Dev box only; never installed on the Pager. Frames go to a FILE
+ * only: nothing here touches a radio. See build.sh.
+ * Usage: gen <kind> <out.pcap>
+ *   kind = beacon | nan | parrot | multi | unknowns | equator | order | quiet | truncated */
+#include <stdio.h>
+#include <stdlib.h>
+#include <string.h>
+#include <stdint.h>
+#include "opendroneid.h"
+
+static void put32(FILE *f, uint32_t v) { fwrite(&v, 4, 1, f); }
+static void put16(FILE *f, uint16_t v) { fwrite(&v, 2, 1, f); }
+
+/* one packet record: radiotap {version 0, pad 0, length 9, present = dBm antenna signal, signal}, then the frame */
+static void put_packet(FILE *f, uint32_t ts, const uint8_t *frame, int flen, int8_t sig) {
+    uint8_t rtap[9] = {0, 0, 9, 0, 0x20, 0, 0, 0, (uint8_t)sig};
+    uint32_t caplen = (uint32_t)(sizeof(rtap) + flen);
+    put32(f, ts); put32(f, 0); put32(f, caplen); put32(f, caplen);
+    fwrite(rtap, sizeof(rtap), 1, f); fwrite(frame, flen, 1, f);
+}
+static FILE *open_pcap(const char *path) {
+    FILE *f = fopen(path, "wb");
+    if (!f) { perror(path); exit(1); }
+    put32(f, 0xa1b2c3d4); put16(f, 2); put16(f, 4); put32(f, 0); put32(f, 0);
+    put32(f, 262144); put32(f, 127);                 /* snaplen, LINKTYPE_IEEE802_11_RADIO */
+    return f;
+}
+
+/* a made-up drone: serial, airframe, airborne location, live pilot location, operator id */
+static void drone(ODID_UAS_Data *d, const char *serial, double lat, double lon) {
+    memset(d, 0, sizeof(*d));
+    odid_initUasData(d);
+    d->BasicID[0].UAType = ODID_UATYPE_HELICOPTER_OR_MULTIROTOR;
+    d->BasicID[0].IDType = ODID_IDTYPE_SERIAL_NUMBER;
+    strncpy(d->BasicID[0].UASID, serial, ODID_ID_SIZE);
+    d->BasicIDValid[0] = 1;
+    d->Location.Status = ODID_STATUS_AIRBORNE;
+    d->Location.Direction = 215.0f;
+    d->Location.SpeedHorizontal = 12.0f;
+    d->Location.SpeedVertical = 3.0f;
+    d->Location.Latitude = lat; d->Location.Longitude = lon;
+    d->Location.AltitudeGeo = 520.0f; d->Location.Height = 87.0f;
+    d->Location.HeightType = ODID_HEIGHT_REF_OVER_TAKEOFF;
+    d->LocationValid = 1;
+    d->System.OperatorLocationType = ODID_OPERATOR_LOCATION_TYPE_LIVE_GNSS;
+    d->System.OperatorLatitude = 47.398000; d->System.OperatorLongitude = 8.541020;
+    d->SystemValid = 1;
+    d->OperatorID.OperatorIdType = 0;
+    strncpy(d->OperatorID.OperatorId, "SWTESTOPERATOR01", ODID_ID_SIZE);
+    d->OperatorIDValid = 1;
+}
+
+static int beacon(const ODID_UAS_Data *d, const char *mac, const char *ssid, uint8_t *buf, size_t n) {
+    int l = odid_wifi_build_message_pack_beacon_frame(d, mac, ssid, strlen(ssid), 100, 0, buf, n);
+    if (l < 0) { fprintf(stderr, "beacon build failed %d\n", l); exit(1); }
+    /* The library stamps this machine's uptime into the beacon's timestamp (the 8 bytes after the
+     * 24-byte header). Zero it: the fixtures then come out the same on every run and say nothing
+     * about the machine that made them. Nothing reads this field. */
+    memset(buf + 24, 0, 8);
+    return l;
+}
+
+int main(int argc, char **argv) {
+    if (argc < 3) { fprintf(stderr, "usage: gen <kind> <out.pcap>\n"); return 2; }
+    const char *kind = argv[1];
+    const char *mac1 = "\x80\xE1\x26\xAA\xBB\xCC", *mac2 = "\x80\xE1\x26\x11\x22\x33";
+    ODID_UAS_Data d;
+    uint8_t fr[1024]; int n;
+    FILE *f = open_pcap(argv[2]);
+
+    if (!strcmp(kind, "quiet")) {              /* an ordinary beacon, no Remote ID: the frame-parser control */
+        static const uint8_t q[] = {0x80,0,0,0, 0xff,0xff,0xff,0xff,0xff,0xff, 0x02,0x00,0x00,0x00,0x00,0x01,
+            0x02,0x00,0x00,0x00,0x00,0x01, 0,0, 0,0,0,0,0,0,0,0, 0x64,0, 0x01,0x04,
+            0x00,0x06,'S','W','T','E','S','T', 0x01,0x01,0x8c};
+        put_packet(f, 1700000000, q, sizeof(q), -55); fclose(f); return 0;
+    }
+    drone(&d, "0000FSWTEST000000001", 47.397760, 8.545420);
+    if (!strcmp(kind, "unknowns")) {           /* every value the standard marks "unknown / no value" */
+        d.Location.Latitude = 0; d.Location.Longitude = 0;
+        d.Location.AltitudeGeo = -1000; d.Location.Height = -1000;
+        d.Location.SpeedHorizontal = 255; d.Location.SpeedVertical = 63; d.Location.Direction = 361;
+        d.System.OperatorLatitude = 0; d.System.OperatorLongitude = 0;
+    }
+    if (!strcmp(kind, "equator"))              /* latitude exactly 0 is a real place when longitude is not 0 */
+        d.Location.Latitude = 0;
+    if (!strcmp(kind, "nan")) {
+        n = odid_wifi_build_message_pack_nan_action_frame(&d, mac1, 0, fr, sizeof(fr));
+        if (n < 0) { fprintf(stderr, "nan build failed %d\n", n); return 1; }
+        put_packet(f, 1700000000, fr, n, -47); fclose(f); return 0;
+    }
+    n = beacon(&d, mac1, "TEST-DRONE", fr, sizeof(fr));
+    if (!strcmp(kind, "parrot")) {             /* the same element under Parrot's OUI (and a different type byte) */
+        for (int i = 36; i + 6 < n; i++)
+            if (fr[i] == 0xdd && fr[i+2] == 0xfa && fr[i+3] == 0x0b && fr[i+4] == 0xbc) {
+                fr[i+2] = 0x90; fr[i+3] = 0x3a; fr[i+4] = 0xe6; fr[i+5] = 0x00; break;
+            }
+    }
+    if (!strcmp(kind, "order")) {              /* Order bit set: 4 bytes of HT control after the 24-byte header */
+        uint8_t o[1024];
+        memcpy(o, fr, 24); o[1] |= 0x80; memset(o + 24, 0, 4); memcpy(o + 28, fr + 24, n - 24);
+        put_packet(f, 1700000000, o, n + 4, -47); fclose(f); return 0;
+    }
+    if (!strcmp(kind, "multi")) {              /* a WEAKER drone heard FIRST, so "strongest first" is not arrival order */
+        ODID_UAS_Data d2; uint8_t f2[1024];
+        drone(&d2, "0000FSWTEST000000002", 48.100000, 9.200000);
+        int l2 = beacon(&d2, mac2, "DRONE-TWO", f2, sizeof(f2));
+        put_packet(f, 1699999999, f2, l2, -61);
+    }
+    if (!strcmp(kind, "truncated")) n -= 40;   /* cut short inside the message pack */
+    put_packet(f, 1700000000, fr, n, -47);
+    fclose(f);
+    return 0;
+}
```

Then generate the fixtures (dev box: needs `curl`, `gcc` and `tcpdump`; it downloads four pinned files of
opendroneid-core-c into a temporary folder and checks each one's sha256) and check that they are exactly the
ones this plan was verified with:

```bash
bash tools/rid_fixtures/build.sh
(cd test/fixtures/rid && sha256sum -c --quiet <<'SUMS'
31b3b9197d71f3a56cebe6fe87713ca95d0da8f1ddeed40a70d7554c5b0088d6  badlink.txt
5c1e19deaae58fd6d0237642fe589a23cce045d55755573e46b1cabb8a2ceb30  beacon.txt
fc0a9bd6ee44db5fdff7393c2ab9e5454ff5312b8ca2ed4314ecc57dabc86c22  equator.txt
24dfe1d9c80da772242a6d49cbc88d9e02e3f5c8d91e93ac832688498508d033  multi.txt
38c3fdeff50fde38ad1bacee876c4b4b9c7300738da5080b17fe13d9a62b0d71  nan.txt
021feb5f6257e3934ea3bc50af15cc7680ea7bee94837ae2bf7efc6eaf007960  order.txt
70d5e948d898d032cb8d6f727bd33d99e3500af8369373bc78a89730b2cc9f31  parrot.txt
ce4efbf361abeb8416ff6c9aa0078e488b376fa1b58c83c7f601268d755266ff  quiet.txt
d27fae0ea7f6d3bdfb80c845c6def086eb0c6bb4dff43cdef3f935924ae9d003  truncated.txt
5d2dfcb479c483eaeb932278fe86a69962d74d388ef78cfeb8513484babd2f3f  unknowns.txt
b6942770bc75b7c24c4b8854b8e647ad40d59de1c1bcc23aa9126ec6d774a39a  badlink.pcap
e77fdc12e87ef1cbe3b30a47a01008ba8fbac3ad7c868d85776b12266c3734de  beacon.pcap
6c61c7ec36e384b3126b90ec7a8f6866b4fe7b4fdefc184a6cde54dceb6fbd1b  equator.pcap
ca9a8f54d5b2734492f5e50bcfad0c176d503f4afaf43c67cc42716368716b33  multi.pcap
52dcd1500348cca934953dfd983ccc40f3b13fb56282391313e2c0d53289dcd0  nan.pcap
1602382b3a6855de13ac8d218beb8069962390f55029e24c7252f737ca3c1fd4  order.pcap
ecd89ab055faa128131816f3768dcfdb9aa25684acdefe3d9da8eccde2854039  parrot.pcap
60b42eef3abee99d45198dbc6d90bf10e4741a004bb88094f1afe6ee67831d68  quiet.pcap
43a13cf0f9ce1037a363569a7806fcfec420cc4212ab9839ef498b5d3814ed12  truncated.pcap
e4a3593d7343ec5969a9ae072b07214ebfcddd2fd5797c6653a2150bf04291bc  unknowns.pcap
SUMS
) && echo "fixtures match the plan"
```
Expected: `fixtures written to …` and `fixtures match the plan`. If any checksum differs, stop and report BLOCKED
with the `sha256sum` output (a different tcpdump version prints different text; do not commit other fixtures).

- [ ] **Step 4: Run the suite: all green, nothing stray.**

Run: `bash test/run.sh 2>&1 | tail -1` → `PASS=887 FAIL=0`. Then `bash test/run.sh 2>&1 | grep -v -E '^(== |  FAIL|-----|PASS=)'` must print nothing (a stray line is a test that leaks output, or a missing function called somewhere).

- [ ] **Step 5: Commit.**

```bash
git add test/remoteid_test.sh tools/rid_fixtures/build.sh tools/rid_fixtures/gen.c test/fixtures/rid
TZ=UTC git -c user.name=Ziggy -c user.email=79704039+therealziggy@users.noreply.github.com commit -F - <<'EOF'
tools: Remote ID test fixtures from the reference library

gen.c builds Remote ID WiFi frames with opendroneid-core-c (pinned by
commit and sha256), and build.sh writes them to pcap files and runs the
real tcpdump over them, into the text the decoder tests read. Dev box
only; the frames only ever go to files. tcpdump -t and a zeroed beacon
timestamp keep every clock and this machine's uptime out of the public
fixtures, and make them byte-identical run to run.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
git log -1 --format=%B | grep -cF 'Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>'
```
Expected last output: `1`.

---

### Task 2: The decoder (`lib/remoteid.sh`: `_sw_rid_awk_src`, `_sw_rid_decode_awk`)

**Files:**
- `$SQ/lib/remoteid.sh`
- `test/remoteid_test.sh`

**Interfaces:**
- Consumes: the fixtures and `_RFIX` (Task 1).
- Produces: `$SQ/lib/remoteid.sh` with `_sw_rid_awk_src` (prints the awk program; the ONE copy, shared with
  Task 4's capture) and `_sw_rid_decode_awk` (stdin = `tcpdump -t -nn -xx` text → the S/D contract above;
  `SW_RID_MAX_DRONES`, default 32, `0` = no cap).

- [ ] **Step 1: Write the failing tests.** Apply this task's FIRST patch (see "Applying the patches"):

```diff
diff --git a/test/remoteid_test.sh b/test/remoteid_test.sh
index 9c2dc5b..48e2858 100644
--- a/test/remoteid_test.sh
+++ b/test/remoteid_test.sh
@@ -14,3 +14,102 @@ assert_empty "$(grep -lE '^[0-9]{2}:[0-9]{2}:[0-9]{2}\.' "$_RFIX"/*.txt)" rid_fi
 assert_contains "$(printf '22:13:20.000000 Beacon\n' | grep -E '^[0-9]{2}:[0-9]{2}:[0-9]{2}\.')" "22:13:20" rid_fixture_clock_check_works
 unset _f
 
+# --- the decoder: tcpdump -t -nn -xx text -> S/D lines ---
+# lib/remoteid.sh uses sw_sanitize_ident (match.sh), sw_wifi_colonize (wifi.sh), _sw_csv_cell (log.sh),
+# sw_stopped (ble.sh) and sw_ignored (ignore.sh): source them all here, so this file passes on its own too
+source "$SW_ROOT/lib/match.sh"; source "$SW_ROOT/lib/wifi.sh"; source "$SW_ROOT/lib/log.sh"
+source "$SW_ROOT/lib/ble.sh"; source "$SW_ROOT/lib/ignore.sh"; source "$SW_ROOT/lib/remoteid.sh"
+_dec() { _sw_rid_decode_awk < "$_RFIX/$1.txt"; }
+# _rf LINES FIELD: a field of the first D line, by name (the contract's order, after the "D" tag)
+_rf() { local c; case "$2" in mac) c=2;; rssi) c=3;; forms) c=4;; id_type) c=5;; id_hex) c=6;; id2_type) c=7;;
+  id2_hex) c=8;; ua_type) c=9;; status) c=10;; lat) c=11;; lon) c=12;; alt_geo) c=13;; alt_baro) c=14;; height) c=15;;
+  height_ref) c=16;; speed) c=17;; vspeed) c=18;; heading) c=19;; pilot_type) c=20;; pilot_lat) c=21;; pilot_lon) c=22;;
+  pilot_alt) c=23;; operator_id) c=24;; self_id) c=25;; esac
+  printf '%s\n' "$1" | awk -F'\t' -v c="$c" '$1 == "D" { print $c; exit }'; }
+# _rs LINES N: field N of the S line (2 frames, 3 understood, 4 rid_frames, 5 more_drones)
+_rs() { printf '%s\n' "$1" | awk -F'\t' -v c="$2" '$1 == "S" { print $c; exit }'; }
+_serial1=3030303046535754455354303030303030303031   # "0000FSWTEST000000001"
+_serial2=3030303046535754455354303030303030303032   # "0000FSWTEST000000002"
+
+# a full ASD-STAN beacon: every field decoded (values are gen.c's inputs)
+_o="$(_dec beacon)"
+assert_eq "$(_rf "$_o" mac)" "80e126aabbcc" rid_beacon_mac
+assert_eq "$(_rf "$_o" rssi)" "-47" rid_beacon_rssi
+assert_eq "$(_rf "$_o" forms)" "1" rid_beacon_form_asdstan
+assert_eq "$(_rf "$_o" id_type)" "1" rid_beacon_idtype_serial
+assert_eq "$(_rf "$_o" id_hex)" "$_serial1" rid_beacon_serial_hex
+assert_eq "$(_rf "$_o" ua_type)" "2" rid_beacon_uatype_multirotor
+assert_eq "$(_rf "$_o" status)" "2" rid_beacon_status_airborne
+assert_eq "$(_rf "$_o" lat)" "473977600" rid_beacon_lat_raw
+assert_eq "$(_rf "$_o" lon)" "85454200" rid_beacon_lon_raw
+assert_eq "$(_rf "$_o" alt_geo)" "3040" rid_beacon_altgeo_enc           # (520 + 1000) / 0.5
+assert_eq "$(_rf "$_o" height)" "2174" rid_beacon_height_enc            # (87 + 1000) / 0.5
+assert_eq "$(_rf "$_o" height_ref)" "0" rid_beacon_height_over_takeoff
+assert_eq "$(_rf "$_o" speed)" "1200" rid_beacon_speed_centi           # 12.00 m/s
+assert_eq "$(_rf "$_o" vspeed)" "30" rid_beacon_vspeed_deci            # 3.0 m/s
+assert_eq "$(_rf "$_o" heading)" "215" rid_beacon_heading
+assert_eq "$(_rf "$_o" pilot_type)" "1" rid_beacon_pilot_type_live
+assert_eq "$(_rf "$_o" pilot_lat)" "473980000" rid_beacon_pilot_lat_raw
+assert_eq "$(_rf "$_o" pilot_lon)" "85410200" rid_beacon_pilot_lon_raw
+assert_eq "$(_rf "$_o" operator_id)" "5357544553544f50455241544f523031" rid_beacon_operator_id   # "SWTESTOPERATOR01"
+assert_eq "$(_rf "$_o" alt_baro)" "" rid_beacon_altbaro_unknown_empty   # the encoder's default: unknown
+assert_eq "$(_rs "$_o" 2)/$(_rs "$_o" 3)/$(_rs "$_o" 4)/$(_rs "$_o" 5)" "1/1/1/0" rid_beacon_stats
+
+# NAN: the same pack in a different outer frame (form bit 2)
+_o="$(_dec nan)"
+assert_eq "$(_rf "$_o" forms)" "2" rid_nan_form
+assert_eq "$(_rf "$_o" id_hex)" "$_serial1" rid_nan_serial
+assert_eq "$(_rf "$_o" pilot_lat)" "473980000" rid_nan_pilot_lat
+# Parrot's OUI (form bit 4), any type byte
+_o="$(_dec parrot)"
+assert_eq "$(_rf "$_o" forms)" "4" rid_parrot_form
+assert_eq "$(_rf "$_o" id_hex)" "$_serial1" rid_parrot_serial
+# the Order bit: 4 more header bytes before the fixed fields
+assert_eq "$(_rf "$(_dec order)" id_hex)" "$_serial1" rid_order_bit_header
+
+# the standard's "unknown" values become EMPTY fields, never numbers
+_o="$(_dec unknowns)"
+for _k in lat lon height alt_geo speed vspeed heading pilot_lat pilot_lon; do
+  assert_eq "$(_rf "$_o" "$_k")" "" "rid_unknown_${_k}_empty"
+done
+# control: the record itself is real (its ID is there; only its values are unknown)
+assert_eq "$(_rf "$_o" id_hex)" "$_serial1" rid_unknown_control_serial
+# latitude 0 with a real longitude is a place on the equator, not "unknown"
+_o="$(_dec equator)"
+assert_eq "$(_rf "$_o" lat)/$(_rf "$_o" lon)" "0/85454200" rid_equator_lat_zero_kept
+
+# two drones, each its own line; the stronger signal first
+_o="$(_dec multi)"
+assert_eq "$(printf '%s\n' "$_o" | grep -c '^D')" "2" rid_multi_two_drones
+assert_eq "$(_rf "$_o" id_hex)" "$_serial1" rid_multi_strongest_first
+assert_contains "$_o" "$_serial2" rid_multi_second_serial
+# the cap keeps the strongest and counts the rest; 0 = no cap
+_o="$(SW_RID_MAX_DRONES=1 _dec multi)"
+assert_eq "$(printf '%s\n' "$_o" | grep -c '^D')" "1" rid_cap_one_line
+assert_eq "$(_rf "$_o" id_hex)" "$_serial1" rid_cap_keeps_strongest
+assert_eq "$(_rs "$_o" 5)" "1" rid_cap_counts_overflow
+assert_eq "$(SW_RID_MAX_DRONES=0 _dec multi | grep -c '^D')" "2" rid_cap_zero_means_no_cap
+
+# an ordinary beacon: counted and understood (the frame parser works), but no drone
+_o="$(_dec quiet)"
+assert_eq "$(_rs "$_o" 2)/$(_rs "$_o" 3)/$(_rs "$_o" 4)" "1/1/0" rid_quiet_stats
+assert_empty "$(printf '%s\n' "$_o" | grep '^D')" rid_quiet_no_drone
+# a frame cut short inside its pack: rejected, and the pass still ends with its stats line
+_o="$(_dec truncated)"
+assert_empty "$(printf '%s\n' "$_o" | grep '^D')" rid_truncated_no_drone
+assert_eq "$(_rs "$_o" 2)" "1" rid_truncated_stats_still_printed
+# a malformed frame BEFORE a good one cannot hide the good one (the Tier-3 lesson)
+_o="$( { cat "$_RFIX/truncated.txt"; cat "$_RFIX/beacon.txt"; } | _sw_rid_decode_awk )"
+assert_eq "$(_rf "$_o" id_hex)" "$_serial1" rid_bad_frame_does_not_hide_next
+assert_eq "$(_rs "$_o" 2)" "2" rid_bad_frame_both_counted
+
+# the decoder runs the same on BusyBox awk (the Pager) as on this box's awk
+if command -v busybox >/dev/null 2>&1; then
+  for _f in beacon nan parrot multi unknowns equator order quiet truncated badlink; do
+    assert_eq "$(busybox awk -v max=32 "$(_sw_rid_awk_src)" < "$_RFIX/$_f.txt")" "$(_dec "$_f")" "rid_busybox_parity_$_f"
+  done
+else
+  fail "rid_busybox_parity: busybox not installed (sudo apt install busybox)"
+fi
+unset _o _k _f _serial1 _serial2; unset -f _dec _rf _rs
+
```

- [ ] **Step 2: Run the suite and see the new tests fail.**

Run: `bash test/run.sh 2>&1 | tail -1`
Expected: `PASS=909 FAIL=39`. The failures are exactly these new tests: `rid_beacon_mac`, `rid_beacon_rssi`, `rid_beacon_form_asdstan`, `rid_beacon_idtype_serial`, `rid_beacon_serial_hex`, `rid_beacon_uatype_multirotor`, `rid_beacon_status_airborne`, `rid_beacon_lat_raw`, `rid_beacon_lon_raw`, `rid_beacon_altgeo_enc`, `rid_beacon_height_enc`, `rid_beacon_height_over_takeoff`, `rid_beacon_speed_centi`, `rid_beacon_vspeed_deci`, `rid_beacon_heading`, `rid_beacon_pilot_type_live`, `rid_beacon_pilot_lat_raw`, `rid_beacon_pilot_lon_raw`, `rid_beacon_operator_id`, `rid_beacon_stats`, `rid_nan_form`, `rid_nan_serial`, `rid_nan_pilot_lat`, `rid_parrot_form`, `rid_parrot_serial`, `rid_order_bit_header`, `rid_unknown_control_serial`, `rid_equator_lat_zero_kept`, `rid_multi_two_drones`, `rid_multi_strongest_first`, `rid_multi_second_serial`, `rid_cap_one_line`, `rid_cap_keeps_strongest`, `rid_cap_counts_overflow`, `rid_cap_zero_means_no_cap`, `rid_quiet_stats`, `rid_truncated_stats_still_printed`, `rid_bad_frame_does_not_hide_next`, `rid_bad_frame_both_counted`. Other output is expected at this step too: the rest of multi-line failure messages, and errors such as `command not found` or `No such file or directory` for what this task has not added yet.

- [ ] **Step 3: Implement.** Apply this task's SECOND patch:

```diff
diff --git a/payloads/user/reconnaissance/squachwatch/lib/remoteid.sh b/payloads/user/reconnaissance/squachwatch/lib/remoteid.sh
new file mode 100644
index 0000000..beaaec4
--- /dev/null
+++ b/payloads/user/reconnaissance/squachwatch/lib/remoteid.sh
@@ -0,0 +1,121 @@
+#!/bin/bash
+# lib/remoteid.sh — Remote ID over WiFi (spec docs/superpowers/specs/2026-10-01-squachwatch-remote-id-wifi-design.md).
+# Drones broadcast Remote ID (their ID, position and the pilot's location) in WiFi beacons and in NAN
+# action frames. Each lap a short, read-only tcpdump window on the recon radio feeds ONE awk pass, which
+# decodes those frames into one line per transmitter address, written as integers, empty fields or
+# lowercase hex only: Remote ID is not authenticated, so no broadcast byte may shift a field. Bash then
+# does the units, the cleaning (sw_sanitize_ident), the remoteid.csv rows and the detections.
+
+# --- The decoder: tcpdump -t -nn -xx text in; a stats line and one line per drone out (spec §6.2) ---
+#   S<TAB>frames<TAB>understood<TAB>rid_frames<TAB>more_drones
+#   D<TAB>mac rssi forms id_type id_hex id2_type id2_hex ua_type status lat lon alt_geo alt_baro height
+#        height_ref speed vspeed heading pilot_type pilot_lat pilot_lon pilot_alt operator_id_hex self_id_hex
+_sw_rid_awk_src() { cat <<'RIDAWK'
+# One frame per tcpdump header line; the hex lines that follow start with an offset like 0x0010:.
+# Every byte test uses a decimal literal: BusyBox awk and mawk do not parse 0x.. constants.
+function b(i) { return hx[substr(hex, 1 + i * 2, 1)] * 16 + hx[substr(hex, 2 + i * 2, 1)] }
+function le16(i) { return b(i) + b(i + 1) * 256 }
+function s32(i,  v) { v = b(i) + b(i + 1) * 256 + b(i + 2) * 65536 + b(i + 3) * 16777216; return v >= 2147483648 ? v - 4294967296 : v }
+function s8(i,  v) { v = b(i); return v >= 128 ? v - 256 : v }
+function nb() { return length(hex) / 2 }
+function bit(x, k) { return int(x / k) % 2 }                 # k = 1, 2, 4, 8, ...
+# hex of a text field: cut at the first zero byte (a C string), trailing spaces dropped
+function txt(i, n,  r, c, j) { r = ""
+  for (j = 0; j < n && i + j < nb(); j++) { c = b(i + j); if (c == 0) break; r = r sprintf("%02x", c) }
+  while (length(r) >= 2 && substr(r, length(r) - 1) == "20") r = substr(r, 1, length(r) - 2)
+  return r }
+function hexall(i, n,  r, j) { r = ""; for (j = 0; j < n; j++) r = r sprintf("%02x", b(i + j)); return r }
+# both 0 is the standard's "unknown"; out of range is garbage
+function okll(a, o) { return !(a == 0 && o == 0) && a >= -900000000 && a <= 900000000 && o >= -1800000000 && o <= 1800000000 }
+function okpack(pk, end,  c) { if (pk + 3 > end) return 0
+  if (int(b(pk) / 16) != 15 || b(pk + 1) != 25) return 0
+  c = b(pk + 2); if (c < 1 || c > 9) return 0
+  return pk + 3 + 25 * c <= end }
+BEGIN { for (k = 0; k <= 9; k++) hx[k] = k; hx["a"] = 10; hx["b"] = 11; hx["c"] = 12; hx["d"] = 13; hx["e"] = 14; hx["f"] = 15 }
+$1 !~ /^0x[0-9a-f]+:$/ { if (hex != "") decode(); hex = ""; sig = ""
+  # tcpdump prints the radiotap fields before any frame text, so a network name cannot supply this
+  if (match($0, /-?[0-9]+dBm signal/)) sig = substr($0, RSTART, RLENGTH - 10)
+  next }
+{ for (k = 2; k <= NF; k++) hex = hex $k }
+END { if (hex != "") decode(); emit() }
+function decode(  off, fc, hl, ie, id, ln, f, i, pk) {
+  frames++
+  if (length(hex) % 2) return
+  off = le16(2)                                              # the radiotap length = where 802.11 starts
+  if (b(0) != 0 || off < 8 || off + 24 > nb()) return
+  fc = b(off); fc = fc - fc % 4                              # frame control, version bits masked
+  if (fc != 128 && fc != 208) return                         # beacon or action frame only
+  hl = (b(off + 1) >= 128) ? 28 : 24                         # 4 more header bytes when the Order bit is set
+  if (off + hl > nb()) return
+  understood++
+  if (fc == 128) { ie = off + hl + 12                        # beacon: walk its elements
+    while (ie + 2 <= nb()) { id = b(ie); ln = b(ie + 1)
+      if (ie + 2 + ln > nb()) break                          # one running past the end ends the walk
+      if (id == 221 && ln >= 8) { f = 0
+        if (b(ie + 2) == 250 && b(ie + 3) == 11 && b(ie + 4) == 188 && b(ie + 5) == 13) f = 1   # ASD-STAN FA:0B:BC, 0x0D
+        else if (b(ie + 2) == 144 && b(ie + 3) == 58 && b(ie + 4) == 230) f = 4               # Parrot 90:3A:E6
+        if (f && okpack(ie + 7, ie + 2 + ln)) { take(off + 10, ie + 7, f); return } }       # OUI, type, counter
+      ie = ie + 2 + ln }
+    return }
+  # NAN: to 51:6F:9A:01:00:00, then public action / vendor specific / Wi-Fi Alliance / NAN
+  if (b(off + 4) != 81 || b(off + 5) != 111 || b(off + 6) != 154 || b(off + 7) != 1 || b(off + 8) != 0 || b(off + 9) != 0) return
+  i = off + hl
+  if (b(i) != 4 || b(i + 1) != 9 || b(i + 2) != 80 || b(i + 3) != 111 || b(i + 4) != 154 || b(i + 5) != 19) return
+  i = i + 6                                                  # the NAN attributes: id, 2-byte length, body
+  while (i + 3 <= nb()) { ln = le16(i + 1)
+    if (i + 3 + ln > nb()) break
+    if (b(i) == 3 && ln >= 9 && b(i + 3) == 136 && b(i + 4) == 105 && b(i + 5) == 25 && b(i + 6) == 157 && b(i + 7) == 146 && b(i + 8) == 9) {
+      pk = nanpack(i + 9, i + 3 + ln)                        # just after the service id hash
+      if (pk && okpack(pk, sie)) { take(off + 10, pk, 2); return } }
+    i = i + 3 + ln }
+}
+# after the service id: instance, requestor, control, the optional fields control announces, then
+# the service info (length, counter, pack). Returns the pack's offset (0 = none); sie = its end.
+function nanpack(p, end,  c) { if (p + 3 > end) return 0
+  c = b(p + 2); p = p + 3
+  if (bit(c, 64)) p = p + 2                                  # binding bitmap
+  if (bit(c, 4)) { if (p >= end) return 0; p = p + 1 + b(p) } # matching filter
+  if (bit(c, 8)) { if (p >= end) return 0; p = p + 1 + b(p) } # service response filter
+  if (!bit(c, 16) || p + 2 > end) return 0                   # service info present?
+  sie = p + 1 + b(p); if (sie > end) return 0
+  return p + 2 }
+function take(a, pk, f,  m, c, n, i, t, v, w) { m = hexall(a, 6)
+  if (!(m in seen)) { seen[m] = 1; ord[++no] = m }
+  if (sig != "" && (!(m in rs) || sig + 0 > rs[m] + 0)) rs[m] = sig
+  if (!bit(fm[m] + 0, f)) fm[m] = fm[m] + f
+  ridf++
+  c = b(pk + 2)
+  for (n = 0; n < c; n++) { i = pk + 3 + 25 * n; t = int(b(i) / 16)
+    if (t == 0) { v = txt(i + 2, 20)                         # Basic ID: the first two distinct ones
+      if (nbi[m] + 0 == 0) { it1[m] = int(b(i + 1) / 16); ih1[m] = v; ua[m] = b(i + 1) % 16; nbi[m] = 1 }
+      else if (nbi[m] == 1 && (v != ih1[m] || int(b(i + 1) / 16) != it1[m])) { it2[m] = int(b(i + 1) / 16); ih2[m] = v; nbi[m] = 2 } }
+    else if (t == 1) { st[m] = int(b(i + 1) / 16); hr[m] = bit(b(i + 1), 4)
+      v = b(i + 2) + (bit(b(i + 1), 2) ? 180 : 0); hd[m] = (v > 360) ? "" : v
+      v = b(i + 3); sp[m] = bit(b(i + 1), 1) ? ((v == 255) ? "" : v * 75 + 6375) : v * 25
+      v = s8(i + 4); vs[m] = (v >= 126 || v <= -126) ? "" : v * 5
+      v = s32(i + 5); w = s32(i + 9); if (okll(v, w)) { la[m] = v; lo[m] = w } else { la[m] = ""; lo[m] = "" }
+      v = le16(i + 13); ab[m] = v ? v : ""; v = le16(i + 15); ag[m] = v ? v : ""; v = le16(i + 17); ht[m] = v ? v : "" }
+    else if (t == 3) si[m] = txt(i + 2, 23)
+    else if (t == 4) { pt[m] = b(i + 1) % 4
+      v = s32(i + 2); w = s32(i + 6); if (okll(v, w)) { pa[m] = v; po[m] = w } else { pa[m] = ""; po[m] = "" }
+      v = le16(i + 18); pl[m] = v ? v : "" }
+    else if (t == 5) oi[m] = txt(i + 2, 20) }
+}
+function line(m) {
+  print "D\t" m "\t" rs[m] "\t" (fm[m] + 0) "\t" it1[m] "\t" ih1[m] "\t" it2[m] "\t" ih2[m] "\t" ua[m] "\t" st[m] \
+    "\t" la[m] "\t" lo[m] "\t" ag[m] "\t" ab[m] "\t" ht[m] "\t" hr[m] "\t" sp[m] "\t" vs[m] "\t" hd[m] \
+    "\t" pt[m] "\t" pa[m] "\t" po[m] "\t" pl[m] "\t" oi[m] "\t" si[m] }
+# the strongest signals first, at most max of them (0 = no cap); a missing signal counts as weakest
+function emit(  k, j, best, bv, v, kept) { kept = 0
+  if (max + 0 == 0) { for (k = 1; k <= no; k++) line(ord[k]); kept = no }
+  else for (k = 1; k <= no && kept < max + 0; k++) { best = 0
+    for (j = 1; j <= no; j++) { if (used[j]) continue
+      v = (ord[j] in rs) ? rs[ord[j]] + 0 : -999
+      if (!best || v > bv) { best = j; bv = v } }
+    used[best] = 1; kept++; line(ord[best]) }
+  print "S\t" frames + 0 "\t" understood + 0 "\t" ridf + 0 "\t" no - kept }
+RIDAWK
+}
+# stdin = tcpdump -t -nn -xx text -> the lines above; at most SW_RID_MAX_DRONES D lines (0 = no cap)
+_sw_rid_decode_awk() { awk -v max="${SW_RID_MAX_DRONES:-32}" "$(_sw_rid_awk_src)"; }
+
```

- [ ] **Step 4: Run the suite: all green, nothing stray.**

Run: `bash test/run.sh 2>&1 | tail -1` → `PASS=948 FAIL=0`. Then `bash test/run.sh 2>&1 | grep -v -E '^(== |  FAIL|-----|PASS=)'` must print nothing (a stray line is a test that leaks output, or a missing function called somewhere).

- [ ] **Step 5: Commit.**

```bash
git add payloads/user/reconnaissance/squachwatch/lib/remoteid.sh test/remoteid_test.sh
TZ=UTC git -c user.name=Ziggy -c user.email=79704039+therealziggy@users.noreply.github.com commit -F - <<'EOF'
remoteid: decode Remote ID WiFi frames into one line per drone

One awk pass reads tcpdump -t -nn -xx text and decodes ASD-STAN and
Parrot beacons and NAN action frames: ID, airframe, position, motion
and the pilot's location. It writes integers, empty fields or lowercase
hex only, so no broadcast byte can shift a field, and checks every
length, so a bad frame cannot hide the next. Byte-identical on BusyBox
awk and mawk.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
git log -1 --format=%B | grep -cF 'Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>'
```
Expected last output: `1`.

---

### Task 3: From the decoder's lines to detections and `remoteid.csv` (`sw_rid_records`)

**Files:**
- `$SQ/lib/ignore.sh`
- `$SQ/lib/log.sh`
- `$SQ/lib/remoteid.sh`
- `test/helpers/rid.sh`
- `test/ignore_test.sh`
- `test/remoteid_test.sh`

**Interfaces:**
- Consumes: the decoder's D lines (Task 2); `sw_sanitize_ident` (`lib/match.sh`), `sw_wifi_colonize`
  (`lib/wifi.sh`), `sw_stopped` (`lib/ble.sh`), `GPS_GET`.
- Produces: `sw_rid_records <now> <loot dir>`: stdin = decoder lines; one row per drone in
  `${SW_RID_FILE:-<loot dir>/remoteid.csv}` and one detection per drone on stdout,
  `drone_rid|Drone|high|surveillance|wifi|<MAC>|<ID or empty>|<rssi>|<airframe>TAB<motion>TAB<pilot>`;
  drones that `sw_ignored` drops leave nothing. Builtin formatters `sw_rid_coord`, `sw_rid_alt`, `sw_rid_m`,
  `sw_rid_mps`, `sw_rid_mps2`, `sw_rid_dmps`, `sw_rid_text`, `_sw_rid_name`, `_sw_rid_line_ok`,
  `_sw_rid_csv_row`. `_sw_csv_cell` in `lib/log.sh` (REPLY; `_sw_csv_field` now wraps it). `sw_ignored` drops a
  `drone_rid` only for `drone:<ID>` (or `drone:<MAC>` when it has no ID). `test/helpers/rid.sh`:
  `sw_test_rid_line KEY=VALUE...`.

- [ ] **Step 1: Write the failing tests.** Apply this task's FIRST patch (see "Applying the patches"):

```diff
diff --git a/test/helpers/rid.sh b/test/helpers/rid.sh
new file mode 100644
index 0000000..fd828f3
--- /dev/null
+++ b/test/helpers/rid.sh
@@ -0,0 +1,16 @@
+# test/helpers/rid.sh — sourced by tests (NOT by run.sh, which sources only *_test.sh).
+# sw_test_rid_line KEY=VALUE... prints one decoder "D" line (the 24 fields in lib/remoteid.sh's order),
+# so the bash layer can be tested without the decoder. A key not given takes the full test drone's value
+# (the same values as tools/rid_fixtures/gen.c's beacon); "key=" makes that field empty.
+sw_test_rid_line() {
+  local -A f=(); local kv
+  for kv in "$@"; do f[${kv%%=*}]="${kv#*=}"; done
+  printf 'D\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
+    "${f[mac]-80e126aabbcc}" "${f[rssi]--47}" "${f[forms]-1}" "${f[id_type]-1}" \
+    "${f[id_hex]-3030303046535754455354303030303030303031}" "${f[id2_type]-}" "${f[id2_hex]-}" \
+    "${f[ua_type]-2}" "${f[status]-2}" "${f[lat]-473977600}" "${f[lon]-85454200}" \
+    "${f[alt_geo]-3040}" "${f[alt_baro]-}" "${f[height]-2174}" "${f[height_ref]-0}" \
+    "${f[speed]-1200}" "${f[vspeed]-30}" "${f[heading]-215}" "${f[pilot_type]-1}" \
+    "${f[pilot_lat]-473980000}" "${f[pilot_lon]-85410200}" "${f[pilot_alt]-}" \
+    "${f[operator_id]-5357544553544f50455241544f523031}" "${f[self_id]-}"
+}
diff --git a/test/ignore_test.sh b/test/ignore_test.sh
index 1759aa0..59da15f 100644
--- a/test/ignore_test.sh
+++ b/test/ignore_test.sh
@@ -33,3 +33,15 @@ sw_ignored 'evil_twin|Evil twin|high|attacker|wifi|02:11:22:33:44:66|HomeNet|-38
 sw_ignored 'hacker_flipper|Flipper Zero|high|attacker|ble|02:11:22:33:44:66|Flipper|-60' "$_tset"; assert_eq "$?" "1" ignore_twin_entry_only_for_twins
 sw_ignored 'hacker_flipper|Flipper Zero|high|attacker|ble|02:11:22:33:44:55|Flipper|-60' "$_tset"; assert_eq "$?" "0" ignore_plain_entry_still_hides_other_kinds
 rm -rf "$_T"; unset _T _set _D _X _tset
+
+# A drone is silenced only by "drone:<its Remote ID>", or "drone:<MAC>" when it sends no ID (spec 2026-10-01
+# §4): any case, spaces ignored, as sw_load_ignore stores every line. A plain address never silences one.
+_igf="$(mktemp)"; printf '%s\n' '# my own drone' 'drone:0000fswtest000000001' 'drone:80:e1:26:44:55:66' '80:E1:26:AA:BB:CC' > "$_igf"
+_igs="$(sw_load_ignore "$_igf")"
+assert_eq "$(sw_ignored "drone_rid|Drone|high|surveillance|wifi|80:E1:26:99:99:99|0000FSWTEST000000001|-47|a	b	c" "$_igs" && echo drop || echo keep)" "drop" drone_ignored_by_id_at_any_address
+assert_eq "$(sw_ignored "drone_rid|Drone|high|surveillance|wifi|80:E1:26:AA:BB:CC|0000FSWTEST000000002|-47|a	b	c" "$_igs" && echo drop || echo keep)" "keep" drone_plain_mac_never_silences
+assert_eq "$(sw_ignored "drone_rid|Drone|high|surveillance|wifi|80:E1:26:44:55:66||-60|a	b	c" "$_igs" && echo drop || echo keep)" "drop" drone_no_id_ignored_by_address
+assert_eq "$(sw_ignored "drone_rid|Drone|high|surveillance|wifi|80:E1:26:99:99:99|0000 FSWTEST 000000001|-47|a	b	c" "$_igs" && echo drop || echo keep)" "drop" drone_id_spaces_ignored
+# control: the plain address line still silences an ordinary device at that address
+assert_eq "$(sw_ignored "hacker_flipper|Flipper Zero|high|attacker|ble|80:E1:26:AA:BB:CC|x|-60" "$_igs" && echo drop || echo keep)" "drop" drone_control_plain_mac_still_works
+rm -f "$_igf"; unset _igf _igs
diff --git a/test/remoteid_test.sh b/test/remoteid_test.sh
index 48e2858..673f449 100644
--- a/test/remoteid_test.sh
+++ b/test/remoteid_test.sh
@@ -113,3 +113,88 @@ else
 fi
 unset _o _k _f _serial1 _serial2; unset -f _dec _rf _rs
 
+# --- from the decoder's lines to detections and remoteid.csv rows ---
+source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/helpers/rid.sh"    # sw_test_rid_line
+_rl="$(mktemp -d)"
+_recs() { SW_FAKE_GPS= SW_RID_FILE= sw_rid_records 1700000000 "$_rl"; }   # stdin = decoder lines; no GPS fix; rows in $_rl
+_csv1() { tail -1 "$_rl/remoteid.csv"; }
+
+# formatters
+sw_rid_coord 473977600 5; assert_eq "$REPLY" "47.39776" rid_fmt_coord5
+sw_rid_coord 473977600 7; assert_eq "$REPLY" "47.3977600" rid_fmt_coord7
+sw_rid_coord -1234567 7;  assert_eq "$REPLY" "-0.1234567" rid_fmt_coord_negative
+sw_rid_coord 0 5;         assert_eq "$REPLY" "0.00000" rid_fmt_coord_zero
+sw_rid_alt 2174;          assert_eq "$REPLY" "87.0" rid_fmt_alt
+sw_rid_alt 1999;          assert_eq "$REPLY" "-0.5" rid_fmt_alt_below_zero
+sw_rid_m 2174;            assert_eq "$REPLY" "87" rid_fmt_metres
+sw_rid_mps 1200;          assert_eq "$REPLY" "12" rid_fmt_mps
+sw_rid_mps2 1225;         assert_eq "$REPLY" "12.25" rid_fmt_mps2
+sw_rid_dmps -25;          assert_eq "$REPLY" "-2.5" rid_fmt_dmps_negative
+sw_rid_text 3030303046535754455354303030303030303031; assert_eq "$REPLY" "0000FSWTEST000000001" rid_fmt_text
+
+# a full drone: one detection (ID = the serial) and a remoteid.csv row with the full precision
+_det="$(sw_test_rid_line | _recs)"
+assert_eq "$_det" "drone_rid|Drone|high|surveillance|wifi|80:E1:26:AA:BB:CC|0000FSWTEST000000001|-47|multirotor	87m up, 12m/s	pilot (live) 47.39800,8.54102" rid_rec_detection
+assert_eq "$(head -1 "$_rl/remoteid.csv")" "time,form,mac,rssi,id_type,id,id2_type,id2,ua_type,status,lat,lon,alt_geo_m,alt_baro_m,height_m,height_ref,speed_mps,vspeed_mps,heading_deg,pilot_loc,pilot_lat,pilot_lon,pilot_alt_m,operator_id,self_id,gps" rid_csv_header
+assert_eq "$(_csv1)" '1700000000,beacon,80:E1:26:AA:BB:CC,-47,serial,"0000FSWTEST000000001",,"",multirotor,airborne,47.3977600,8.5454200,520.0,,87.0,takeoff,12.00,3.0,215,live,47.3980000,8.5410200,,"SWTESTOPERATOR01","",""' rid_csv_row
+assert_eq "$(wc -l < "$_rl/remoteid.csv" | tr -d ' ')" "2" rid_csv_one_row_one_header
+# with a GPS attached, every row also records the Pager's own fix (GPS_GET), so distances can be worked out later
+sw_test_rid_line | SW_FAKE_GPS="1.5 2.5" SW_RID_FILE= sw_rid_records 1700000000 "$_rl" >/dev/null
+assert_eq "$(_csv1 | awk -F'"' '{print $(NF-1)}')" "1.5,2.5" rid_csv_records_own_gps_fix
+# the pilot's location kinds, as the alert words them
+assert_contains "$(sw_test_rid_line pilot_type=0 | _recs)" "takeoff point 47.39800,8.54102" rid_rec_takeoff_point
+assert_contains "$(sw_test_rid_line pilot_type=2 | _recs)" "pilot (fixed) 47.39800,8.54102" rid_rec_pilot_fixed
+# no height: the geodetic altitude instead; no System message: "no pilot location"
+assert_contains "$(sw_test_rid_line height= | _recs)" "	alt 520m, 12m/s	" rid_rec_altitude_fallback
+_det="$(sw_test_rid_line pilot_type= pilot_lat= pilot_lon= | _recs)"
+assert_contains "$_det" "	no pilot location" rid_rec_no_pilot_location
+assert_eq "$(_csv1 | cut -d, -f20-22)" ",," rid_csv_no_pilot_cells_empty
+# every motion value unknown: the motion piece is empty, never "m up" with no number
+_det="$(sw_test_rid_line height= alt_geo= speed= | _recs)"
+assert_contains "$_det" "|multirotor		pilot (live)" rid_rec_unknown_motion_empty
+# no Basic ID: an empty ID (the drone is then known by its address)
+assert_eq "$(sw_test_rid_line id_type= id_hex= | _recs | cut -d'|' -f6-8)" "80:E1:26:AA:BB:CC||-47" rid_rec_no_id
+# two Basic IDs, the serial second: the serial is the ID, the other one goes in id2
+_det="$(sw_test_rid_line id_type=2 id_hex=434141 id2_type=1 id2_hex=3030303046535754455354303030303030303031 | _recs)"
+assert_contains "$_det" "|0000FSWTEST000000001|" rid_rec_prefers_serial
+assert_contains "$(_csv1)" ',serial,"0000FSWTEST000000001",caa,"CAA",' rid_csv_second_id
+# forms: every form heard is named
+assert_contains "$(sw_test_rid_line forms=7 | _recs >/dev/null; _csv1)" ",beacon+nan+parrot," rid_csv_all_forms
+
+# hostile IDs: they cannot forge a field, a line or a spreadsheet formula
+#   "=HYPERLINK(1)" -> the CSV cell starts with a quote mark, so a spreadsheet keeps it as text
+_det="$(sw_test_rid_line id_hex=3d48595045524c494e4b283129 | _recs)"
+assert_contains "$_det" "|=HYPERLINK(1)|" rid_rec_formula_id_in_detection
+assert_contains "$(_csv1)" ",\"'=HYPERLINK(1)\"," rid_csv_formula_guarded
+#   "a|b,c<LF>d\"e" -> the pipe and the line break are removed, the comma and the quote stay inside one cell
+_det="$(sw_test_rid_line id_hex=617c622c630a642265 | _recs)"
+assert_eq "$(printf '%s\n' "$_det" | grep -c .)" "1" rid_rec_hostile_one_line
+assert_contains "$_det" "|ab,cd\"e|" rid_rec_hostile_cleaned
+assert_contains "$(_csv1)" ',"ab,cd""e",' rid_csv_hostile_one_cell
+#   a zero byte inside the hex: the text ends there (a C string)
+assert_contains "$(sw_test_rid_line id_hex=4142004344 | _recs)" "|AB|" rid_rec_text_stops_at_zero
+# malformed lines are dropped: a leading zero (bash would read it as octal), a bad address, a field missing
+assert_empty "$(sw_test_rid_line lat=0473977600 | _recs)" rid_rec_leading_zero_dropped
+assert_empty "$(sw_test_rid_line mac=80e126aabbcz | _recs)" rid_rec_bad_mac_dropped
+assert_empty "$(sw_test_rid_line | cut -f1-24 | _recs)" rid_rec_short_line_dropped
+# control: the same helper, unbroken, does produce a detection (the drops above are the checks, not the helper)
+assert_contains "$(sw_test_rid_line | _recs)" "drone_rid|" rid_rec_control_valid_line
+# S lines and anything else are ignored
+assert_empty "$(printf 'S\t1\t1\t1\t0\n' | _recs)" rid_rec_stats_line_ignored
+# the CSV cell helper gives exactly what _sw_csv_field gives
+for _v in "plain" "=SUM(1)" "+1" "-1" "@x" $'\tlead' $'\rlead' 'q"uote' $'trail\n\n' "" "a,b"; do
+  _sw_csv_cell "$_v"; assert_eq "$REPLY" "$(_sw_csv_field "$_v")" "csv_cell_matches_field_[$_v]"
+done
+# the owner's own drone (ignore.txt: drone:<its ID>) leaves no detection and no row
+rm -f "$_rl/remoteid.csv"
+assert_empty "$(sw_test_rid_line | SW_IGNORE_SET=" DRONE:0000FSWTEST000000001 " _recs)" rid_rec_ignored_no_detection
+assert_eq "$([ -e "$_rl/remoteid.csv" ] && echo written)" "" rid_rec_ignored_no_row
+# control: a plain address line never silences a drone (its address can change; anyone can send any)
+assert_contains "$(sw_test_rid_line | SW_IGNORE_SET=" 80:E1:26:AA:BB:CC " _recs)" "drone_rid|" rid_rec_plain_mac_not_ignored
+# a stopped payload writes and reports nothing
+bash -c 'exit 0' & _rd=$!; wait "$_rd"
+rm -f "$_rl/remoteid.csv"
+assert_empty "$(sw_test_rid_line | SW_MAIN_PID="$_rd" _recs)" rid_rec_stopped_no_detection
+assert_eq "$([ -e "$_rl/remoteid.csv" ] && echo written)" "" rid_rec_stopped_no_csv
+rm -rf "$_rl"; unset _rl _det _v _rd; unset -f _recs _csv1
+
```

- [ ] **Step 2: Run the suite and see the new tests fail.**

Run: `bash test/run.sh 2>&1 | tail -1`
Expected: `PASS=957 FAIL=49`. The failures are exactly these new tests: `drone_ignored_by_id_at_any_address`, `drone_plain_mac_never_silences`, `drone_no_id_ignored_by_address`, `drone_id_spaces_ignored`, `rid_fmt_coord5`, `rid_fmt_coord7`, `rid_fmt_coord_negative`, `rid_fmt_coord_zero`, `rid_fmt_alt`, `rid_fmt_alt_below_zero`, `rid_fmt_metres`, `rid_fmt_mps`, `rid_fmt_mps2`, `rid_fmt_dmps_negative`, `rid_fmt_text`, `rid_rec_detection`, `rid_csv_header`, `rid_csv_row`, `rid_csv_one_row_one_header`, `rid_csv_records_own_gps_fix`, `rid_rec_takeoff_point`, `rid_rec_pilot_fixed`, `rid_rec_altitude_fallback`, `rid_rec_no_pilot_location`, `rid_csv_no_pilot_cells_empty`, `rid_rec_unknown_motion_empty`, `rid_rec_no_id`, `rid_rec_prefers_serial`, `rid_csv_second_id`, `rid_csv_all_forms`, `rid_rec_formula_id_in_detection`, `rid_csv_formula_guarded`, `rid_rec_hostile_one_line`, `rid_rec_hostile_cleaned`, `rid_csv_hostile_one_cell`, `rid_rec_text_stops_at_zero`, `rid_rec_control_valid_line`, `csv_cell_matches_field_[plain]`, `csv_cell_matches_field_[=SUM(1)]`, `csv_cell_matches_field_[+1]`, `csv_cell_matches_field_[-1]`, `csv_cell_matches_field_[@x]`, `csv_cell_matches_field_[q"uote]`, `csv_cell_matches_field_[]`, `csv_cell_matches_field_[a,b]`, `rid_rec_plain_mac_not_ignored`. Other output is expected at this step too: the rest of multi-line failure messages, and errors such as `command not found` or `No such file or directory` for what this task has not added yet.

- [ ] **Step 3: Implement.** Apply this task's SECOND patch:

```diff
diff --git a/payloads/user/reconnaissance/squachwatch/lib/ignore.sh b/payloads/user/reconnaissance/squachwatch/lib/ignore.sh
index efabef0..2540965 100644
--- a/payloads/user/reconnaissance/squachwatch/lib/ignore.sh
+++ b/payloads/user/reconnaissance/squachwatch/lib/ignore.sh
@@ -5,7 +5,8 @@
 
 sw_load_ignore() {
   # $1 = ignore file: one MAC per line, '#' comments, any case, CRLF tolerated. A line
-  # "evil_twin:<MAC>" silences the evil twin with that address, and nothing else (sw_ignored).
+  # "evil_twin:<MAC>" silences the evil twin with that address, and nothing else (sw_ignored); a line
+  # "drone:<Remote ID>" silences that drone (or "drone:<MAC>" one that sends no ID).
   # Prints " MAC1 MAC2 " (upper-case, space-padded) for a fork-free membership test.
   local line out=" "
   if [ -f "$1" ]; then
@@ -23,10 +24,20 @@ sw_ignored() {
   # "evil_twin:<MAC>" line, never by a plain one: its address is whatever the attacker chose to
   # broadcast, and a copy made under one of your own addresses (your router's, your Flipper's)
   # must not be silenced by it (spec 2026-09-29, user decision).
-  local r="${1#*|*|*|*|*|}" mac
+  local r="${1#*|*|*|*|*|}" mac id
   mac="${r%%|*}"
   if [ "${1%%|*}" = evil_twin ]; then
     case "$2" in *" EVIL_TWIN:$mac "*) return 0 ;; esac
+  elif [ "${1%%|*}" = drone_rid ]; then
+    # A drone is dropped only by "drone:<its Remote ID>", or "drone:<MAC>" when it sends no ID: its
+    # address can change, and anyone can broadcast any address (spec 2026-10-01 §4). The ID is compared
+    # the way sw_load_ignore stores its lines: no spaces, upper case.
+    r="${r#*|}"; id="${r%%|*}"; id="${id//[[:space:]]/}"; id="${id^^}"
+    if [ -n "$id" ]; then
+      case "$2" in *" DRONE:$id "*) return 0 ;; esac
+    else
+      case "$2" in *" DRONE:$mac "*) return 0 ;; esac
+    fi
   else
     case "$2" in *" $mac "*) return 0 ;; esac
   fi
diff --git a/payloads/user/reconnaissance/squachwatch/lib/log.sh b/payloads/user/reconnaissance/squachwatch/lib/log.sh
index 928709c..be102ee 100644
--- a/payloads/user/reconnaissance/squachwatch/lib/log.sh
+++ b/payloads/user/reconnaissance/squachwatch/lib/log.sh
@@ -11,14 +11,19 @@ sw_log_init() {
 # (or a TAB/CR) is prefixed with a single quote so Excel/Sheets/LibreOffice treat it as
 # text, not a formula. The loot CSV is reviewed in spreadsheets and its ident field is an
 # attacker-chosen SSID/BLE name, so this closes an =HYPERLINK/DDE/WEBSERVICE vector.
-_sw_csv_field() {
+_sw_csv_field() { _sw_csv_cell "$1"; printf '%s' "$REPLY"; }
+
+# _sw_csv_cell: the same cell in REPLY, with builtins only, for callers that build many cells per row
+# (lib/remoteid.sh) and must not fork for each one.
+_sw_csv_cell() {
   local v="$1"
   case "$v" in
     [=+@-]*) v="'$v" ;;
     $'\t'*)  v="'$v" ;;
     $'\r'*)  v="'$v" ;;
   esac
-  printf '"%s"' "$(printf '%s' "$v" | sed 's/"/""/g')"
+  while [ "${v%$'\n'}" != "$v" ]; do v="${v%$'\n'}"; done   # as $( ) did: trailing line breaks dropped
+  REPLY="\"${v//\"/\"\"}\""
 }
 
 sw_log_write() {
diff --git a/payloads/user/reconnaissance/squachwatch/lib/remoteid.sh b/payloads/user/reconnaissance/squachwatch/lib/remoteid.sh
index beaaec4..26a5656 100644
--- a/payloads/user/reconnaissance/squachwatch/lib/remoteid.sh
+++ b/payloads/user/reconnaissance/squachwatch/lib/remoteid.sh
@@ -119,3 +119,130 @@ RIDAWK
 # stdin = tcpdump -t -nn -xx text -> the lines above; at most SW_RID_MAX_DRONES D lines (0 = no cap)
 _sw_rid_decode_awk() { awk -v max="${SW_RID_MAX_DRONES:-32}" "$(_sw_rid_awk_src)"; }
 
+# --- From the decoder's lines to detections and remoteid.csv rows (spec §6.3, §6.5) ---
+# Formatters: builtins only, bash integer arithmetic (no floats), answer in REPLY.
+sw_rid_coord() {   # $1 = raw 1e7 int, $2 = decimals (1-7) -> REPLY; "" when $1 is empty
+  local r="$1" sign="" a frac
+  case "$r" in -*) sign="-"; a="${r#-}" ;; *) a="$r" ;; esac
+  case "$a" in ''|*[!0-9]*) REPLY=""; return ;; esac
+  printf -v frac '%07d' $(( a % 10000000 ))
+  REPLY="$sign$(( a / 10000000 )).${frac:0:$2}"
+}
+sw_rid_alt() {     # $1 = raw uint16 encoding -> REPLY metres (enc * 0.5 - 1000), one decimal
+  case "$1" in ''|*[!0-9]*) REPLY=""; return ;; esac
+  local d=$(( $1 * 5 - 10000 )) sign="" a
+  case "$d" in -*) sign="-"; a="${d#-}" ;; *) a="$d" ;; esac
+  REPLY="$sign$(( a / 10 )).$(( a % 10 ))"
+}
+sw_rid_m() {       # $1 = raw uint16 encoding -> REPLY whole metres, rounded (the screen)
+  case "$1" in ''|*[!0-9]*) REPLY=""; return ;; esac
+  local d=$(( $1 * 5 - 10000 ))
+  if [ "$d" -ge 0 ]; then REPLY=$(( (d + 5) / 10 )); else REPLY=-$(( (5 - d) / 10 )); fi
+}
+sw_rid_mps() {     # $1 = centi-m/s -> REPLY whole m/s, rounded (the screen)
+  case "$1" in ''|*[!0-9]*) REPLY=""; return ;; esac
+  REPLY=$(( ($1 + 50) / 100 ))
+}
+sw_rid_mps2() {    # $1 = centi-m/s -> REPLY m/s, two decimals (the CSV)
+  case "$1" in ''|*[!0-9]*) REPLY=""; return ;; esac
+  printf -v REPLY '%d.%02d' $(( $1 / 100 )) $(( $1 % 100 ))
+}
+sw_rid_dmps() {    # $1 = signed deci-m/s -> REPLY m/s, one decimal (the CSV)
+  local d="$1" sign="" a
+  case "$d" in -*) sign="-"; a="${d#-}" ;; *) a="$d" ;; esac
+  case "$a" in ''|*[!0-9]*) REPLY=""; return ;; esac
+  REPLY="$sign$(( a / 10 )).$(( a % 10 ))"
+}
+sw_rid_text() {    # $1 = lowercase hex -> REPLY = text, cleaned by sw_sanitize_ident (the one boundary)
+  local h="$1" e="" i
+  for (( i = 0; i + 1 < ${#h}; i += 2 )); do e+="\\x${h:i:2}"; done
+  printf -v REPLY '%b' "$e"
+  REPLY="${REPLY%"${REPLY##*[! ]}"}"
+  sw_sanitize_ident "$REPLY"
+}
+_sw_rid_name() {   # $1 = table, $2 = code -> REPLY = the standard's name, or the code when not in the table
+  REPLY="$2"
+  case "$1:$2" in
+    id:0) REPLY=none ;; id:1) REPLY=serial ;; id:2) REPLY=caa ;; id:3) REPLY=utm ;; id:4) REPLY=session ;;
+    ua:0) REPLY="" ;; ua:1) REPLY=aeroplane ;; ua:2) REPLY=multirotor ;; ua:3) REPLY=gyroplane ;; ua:4) REPLY=vtol ;;
+    ua:5) REPLY=ornithopter ;; ua:6) REPLY=glider ;; ua:7) REPLY=kite ;; ua:8) REPLY="free balloon" ;;
+    ua:9) REPLY="captive balloon" ;; ua:10) REPLY=airship ;; ua:11) REPLY=parachute ;; ua:12) REPLY=rocket ;;
+    ua:13) REPLY=tethered ;; ua:14) REPLY="ground obstacle" ;; ua:15) REPLY=other ;;
+    st:0) REPLY=undeclared ;; st:1) REPLY=ground ;; st:2) REPLY=airborne ;; st:3) REPLY=emergency ;; st:4) REPLY=failure ;;
+    hr:0) REPLY=takeoff ;; hr:1) REPLY=ground ;;
+    pl:0) REPLY=takeoff ;; pl:1) REPLY=live ;; pl:2) REPLY=fixed ;;
+  esac
+}
+# A D line's 24 fields, each checked before use (no leading zeros either: bash reads those as octal)
+_sw_rid_line_ok() {
+  local n='-?[1-9][0-9]{0,9}|0' u='[1-9][0-9]{0,4}' h='([0-9a-f]{2})'
+  [[ "$mac" =~ ^[0-9a-f]{12}$ && "$rssi" =~ ^(-?[1-9][0-9]{0,2}|0)?$ && "$forms" =~ ^[1-7]$ ]] || return 1
+  [[ "$it1" =~ ^([0-9]|1[0-5])?$ && "$it2" =~ ^([0-9]|1[0-5])?$ && "$ua" =~ ^([0-9]|1[0-5])?$ ]] || return 1
+  [[ "$st" =~ ^([0-9]|1[0-5])?$ && "$hr" =~ ^[01]?$ && "$pt" =~ ^[0-3]?$ ]] || return 1
+  [[ "$ih1" =~ ^$h{0,20}$ && "$ih2" =~ ^$h{0,20}$ && "$oi" =~ ^$h{0,20}$ && "$si" =~ ^$h{0,23}$ ]] || return 1
+  [[ "$la" =~ ^($n)?$ && "$lo" =~ ^($n)?$ && "$pa" =~ ^($n)?$ && "$po" =~ ^($n)?$ ]] || return 1
+  [[ "$ag" =~ ^($u)?$ && "$ab" =~ ^($u)?$ && "$ht" =~ ^($u)?$ && "$pl" =~ ^($u)?$ ]] || return 1
+  [[ "$sp" =~ ^(0|[1-9][0-9]{0,4})?$ && "$vs" =~ ^(-?[1-9][0-9]{0,2}|0)?$ && "$hd" =~ ^(0|[1-9][0-9]{0,2})?$ ]]
+}
+# sw_rid_records <now> <loot dir>: stdin = the decoder's lines (only D lines are used) -> one remoteid.csv row
+# per drone, and one detection per drone on stdout:
+#   drone_rid|Drone|high|surveillance|wifi|<MAC>|<ID or empty>|<rssi>|<airframe>TAB<motion>TAB<pilot>
+sw_rid_records() {
+  local now="$1" csv="${SW_RID_FILE:-$2/remoteid.csv}" gps="" gps_read=0 line tabs
+  local tag mac rssi forms it1 ih1 it2 ih2 ua st la lo ag ab ht hr sp vs hd pt pa po pl oi si extra
+  local MAC idt id idt2 id2 form air motion pilot detail
+  local LC_ALL=C
+  while IFS= read -r line || [ -n "$line" ]; do
+    [ "${line:0:2}" = $'D\t' ] || continue
+    tabs="${line//[^$'\t']/}"; [ "${#tabs}" -eq 24 ] || continue
+    # TAB is whitespace to `read`, so runs of empty fields would collapse: split on | (no field holds one)
+    IFS='|' read -r tag mac rssi forms it1 ih1 it2 ih2 ua st la lo ag ab ht hr sp vs hd pt pa po pl oi si extra <<< "${line//$'\t'/|}"
+    _sw_rid_line_ok || continue
+    sw_stopped && return 0
+    if [ "$gps_read" -eq 0 ]; then gps="$(GPS_GET 2>/dev/null | tr ' ' ',')"; gps_read=1; fi
+    sw_wifi_colonize "$mac"; MAC="$REPLY"
+    # the drone's ID: its serial number when it sends one (ID type 1), else its first Basic ID
+    if [ "$it2" = 1 ] && [ "$it1" != 1 ]; then idt="$it2"; sw_rid_text "$ih2"; id="$REPLY"; idt2="$it1"; sw_rid_text "$ih1"; id2="$REPLY"
+    else idt="$it1"; sw_rid_text "$ih1"; id="$REPLY"; idt2="$it2"; sw_rid_text "$ih2"; id2="$REPLY"; fi
+    # the owner's own drone (ignore.txt: drone:<ID>, or drone:<MAC> when it sends no ID) leaves no trace
+    sw_ignored "drone_rid|Drone|high|surveillance|wifi|$MAC|$id|$rssi" "${SW_IGNORE_SET:-}" && continue
+    form=""; [ $(( forms & 1 )) -ne 0 ] && form=beacon
+    [ $(( forms & 2 )) -ne 0 ] && form="${form:+$form+}nan"; [ $(( forms & 4 )) -ne 0 ] && form="${form:+$form+}parrot"
+    # the screen and alert detail: airframe, motion, pilot
+    air=""; [ -n "$ua" ] && { _sw_rid_name ua "$ua"; air="$REPLY"; }
+    motion=""
+    if [ -n "$ht" ]; then sw_rid_m "$ht"; motion="${REPLY}m up"
+    elif [ -n "$ag" ]; then sw_rid_m "$ag"; motion="alt ${REPLY}m"; fi
+    [ -n "$sp" ] && { sw_rid_mps "$sp"; motion="${motion:+$motion, }${REPLY}m/s"; }
+    pilot="no pilot location"
+    if [ -n "$pa" ] && [ -n "$po" ]; then
+      case "$pt" in 0) pilot="takeoff point" ;; 1) pilot="pilot (live)" ;; 2) pilot="pilot (fixed)" ;; *) pilot="pilot" ;; esac
+      sw_rid_coord "$pa" 5; pilot+=" $REPLY"; sw_rid_coord "$po" 5; pilot+=",$REPLY"
+    fi
+    detail="$air"$'\t'"$motion"$'\t'"$pilot"
+    _sw_rid_csv_row
+    printf 'drone_rid|Drone|high|surveillance|wifi|%s|%s|%s|%s\n' "$MAC" "$id" "$rssi" "$detail"
+  done
+}
+# one remoteid.csv row from sw_rid_records' variables (dynamic scope); the header is written first
+_sw_rid_csv_row() {
+  local r c
+  [ -f "$csv" ] || printf '%s\n' "time,form,mac,rssi,id_type,id,id2_type,id2,ua_type,status,lat,lon,alt_geo_m,alt_baro_m,height_m,height_ref,speed_mps,vspeed_mps,heading_deg,pilot_loc,pilot_lat,pilot_lon,pilot_alt_m,operator_id,self_id,gps" > "$csv"
+  r="$now,$form,$MAC,$rssi"
+  if [ -n "$id" ]; then _sw_rid_name id "$idt"; r+=",$REPLY"; else r+=","; fi
+  _sw_csv_cell "$id"; r+=",$REPLY"
+  if [ -n "$id2" ]; then _sw_rid_name id "$idt2"; r+=",$REPLY"; else r+=","; fi
+  _sw_csv_cell "$id2"; r+=",$REPLY"
+  r+=",$air"
+  if [ -n "$st" ]; then _sw_rid_name st "$st"; r+=",$REPLY"; else r+=","; fi
+  sw_rid_coord "$la" 7; r+=",$REPLY"; sw_rid_coord "$lo" 7; r+=",$REPLY"
+  sw_rid_alt "$ag"; r+=",$REPLY"; sw_rid_alt "$ab"; r+=",$REPLY"; sw_rid_alt "$ht"; r+=",$REPLY"
+  if [ -n "$hr" ]; then _sw_rid_name hr "$hr"; r+=",$REPLY"; else r+=","; fi
+  sw_rid_mps2 "$sp"; r+=",$REPLY"; sw_rid_dmps "$vs"; r+=",$REPLY"; r+=",$hd"
+  if [ -n "$pt" ]; then _sw_rid_name pl "$pt"; r+=",$REPLY"; else r+=","; fi
+  sw_rid_coord "$pa" 7; r+=",$REPLY"; sw_rid_coord "$po" 7; r+=",$REPLY"; sw_rid_alt "$pl"; r+=",$REPLY"
+  sw_rid_text "$oi"; _sw_csv_cell "$REPLY"; r+=",$REPLY"
+  sw_rid_text "$si"; _sw_csv_cell "$REPLY"; r+=",$REPLY"
+  _sw_csv_cell "$gps"; r+=",$REPLY"
+  printf '%s\n' "$r" >> "$csv"
+}
```

- [ ] **Step 4: Run the suite: all green, nothing stray.**

Run: `bash test/run.sh 2>&1 | tail -1` → `PASS=1006 FAIL=0`. Then `bash test/run.sh 2>&1 | grep -v -E '^(== |  FAIL|-----|PASS=)'` must print nothing (a stray line is a test that leaks output, or a missing function called somewhere).

- [ ] **Step 5: Commit.**

```bash
git add payloads/user/reconnaissance/squachwatch/lib/ignore.sh payloads/user/reconnaissance/squachwatch/lib/log.sh payloads/user/reconnaissance/squachwatch/lib/remoteid.sh test/helpers/rid.sh test/ignore_test.sh test/remoteid_test.sh
TZ=UTC git -c user.name=Ziggy -c user.email=79704039+therealziggy@users.noreply.github.com commit -F - <<'EOF'
remoteid: drone lines become detections and a flight-track CSV

sw_rid_records checks each decoder line, turns its numbers into units
and its hex into cleaned text, skips the owner's own drone (drone:<ID>
in ignore.txt), writes one remoteid.csv row per drone per lap and prints
a 9-field drone_rid detection. log.sh gains _sw_csv_cell, the same CSV
cell without a fork.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
git log -1 --format=%B | grep -cF 'Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>'
```
Expected last output: `1`.

---

### Task 4: The per-lap capture (`sw_rid_start` / `sw_rid_collect`), the tcpdump stub, Stop safety

**Files:**
- `$SQ/lib/remoteid.sh`
- `test/remoteid_test.sh`
- `test/stubs/tcpdump`

**Interfaces:**
- Consumes: `_sw_rid_awk_src`, `sw_rid_records` (Tasks 2-3); `sw_stopped`; `LOG`.
- Produces: `_sw_rid_filter` (REPLY = the BPF filter), `sw_rid_health_note <status> <now>`, `sw_rid_start <now>`
  (starts the capture, sets `SW_RID_PID`, `SW_RID_CAP`, `SW_RID_ERR`) and `sw_rid_collect <now> <loot dir>` (must
  run in the SAME shell as `sw_rid_start`: it waits for the PID). `test/stubs/tcpdump` models the Pager's tcpdump
  (`SW_FAKE_TCPDUMP`, `SW_FAKE_TCPDUMP_LINK`, `SW_FAKE_TCPDUMP_FAIL`; honours `-i` and `-c`; logs its command line
  to `SW_STUB_LOG`).

- [ ] **Step 1: Write the failing tests.** Apply this task's FIRST patch (see "Applying the patches"):

```diff
diff --git a/test/remoteid_test.sh b/test/remoteid_test.sh
index 673f449..f90adf5 100644
--- a/test/remoteid_test.sh
+++ b/test/remoteid_test.sh
@@ -198,3 +198,99 @@ assert_empty "$(sw_test_rid_line | SW_MAIN_PID="$_rd" _recs)" rid_rec_stopped_no
 assert_eq "$([ -e "$_rl/remoteid.csv" ] && echo written)" "" rid_rec_stopped_no_csv
 rm -rf "$_rl"; unset _rl _det _v _rd; unset -f _recs _csv1
 
+# --- the per-lap capture (test/stubs/tcpdump models the Pager's tcpdump) ---
+_cap_dir="$(mktemp -d)"; _cap_loot="$(mktemp -d)"
+# _cap FIXTURE [VAR=VALUE...]: one 1-second capture window in its own shell, run as a lap runs it
+# (sw_rid_start and sw_rid_collect in the same shell). FIXTURE "" = a capture with no frames.
+_cap() { local fx="$1"; shift
+  env SW_TMP_DIR="$_cap_dir" SW_REMOTE_ID=1 SW_RID_SECONDS=1 SW_RID_IFACE=wlan1mon \
+      SW_FAKE_TCPDUMP="${fx:+$_RFIX/$fx.txt}" "$@" bash -c '
+    source "$1/lib/match.sh"; source "$1/lib/wifi.sh"; source "$1/lib/log.sh"; source "$1/lib/ble.sh"; source "$1/lib/ignore.sh"; source "$1/lib/remoteid.sh"
+    sw_rid_start 1700000000; sw_rid_collect 1700000000 "$2"' _ "$SW_ROOT" "$_cap_loot"; }
+_cap_state() { head -1 "$_cap_dir/sw_rid.state" 2>/dev/null; }
+_cap_reset() { rm -f "$_cap_dir"/sw_rid.* "$_cap_loot/remoteid.csv"; : > "$SW_STUB_LOG"; }
+
+# a beacon capture: one drone detection and a remoteid.csv row; only the health state is left behind
+_cap_reset; _out="$(_cap beacon)"
+assert_contains "$_out" "drone_rid|Drone|high|surveillance|wifi|80:E1:26:AA:BB:CC|0000FSWTEST000000001|-47|" cap_beacon_detection
+assert_contains "$(tail -1 "$_cap_loot/remoteid.csv")" "1700000000,beacon,80:E1:26:AA:BB:CC,-47,serial," cap_beacon_csv_row
+assert_eq "$(_cap_state)" "ok" cap_beacon_status_ok
+assert_empty "$(ls -A "$_cap_dir" | grep -v '^sw_rid\.state$')" cap_leaves_no_capture_files
+# tcpdump ran read only (-p), on the configured interface, without clock times (-t), with the frame cap
+assert_contains "$(grep '^tcpdump ' "$SW_STUB_LOG")" "tcpdump -i wlan1mon -p -l -t -nn -xx -c 1500 type mgt subtype beacon or (wlan[0] & 0xfc = 0xd0 and wlan addr1 51:6f:9a:01:00:00)" cap_tcpdump_args
+
+# an ordinary beacon only: no drone, no WARN, and the capture was judged healthy (it ran)
+_cap_reset; _out="$(_cap quiet)"
+assert_empty "$(printf '%s\n' "$_out" | grep '^drone_rid')" cap_quiet_no_drone
+assert_eq "$(_cap_state)" "ok" cap_quiet_status_ok
+assert_empty "$(grep -F 'WARN' "$SW_STUB_LOG")" cap_quiet_no_warn
+# no frames at all (a place with no WiFi) is ok too: "listening on" proves the capture ran
+_cap_reset; _cap "" >/dev/null
+assert_eq "$(_cap_state)" "ok" cap_no_frames_is_ok
+
+# a capture that never starts: one WARN, not one per lap; then a green line once it works again
+_cap_reset; _cap beacon SW_FAKE_TCPDUMP_FAIL=1 >/dev/null
+assert_eq "$(_cap_state)" "capture_failed" cap_failed_status
+assert_eq "$(grep -c 'WiFi capture failed' "$SW_STUB_LOG")" "1" cap_failed_warns
+_cap beacon SW_FAKE_TCPDUMP_FAIL=1 >/dev/null
+assert_eq "$(grep -c 'WiFi capture failed' "$SW_STUB_LOG")" "1" cap_failed_warns_once
+_cap beacon >/dev/null
+assert_contains "$(cat "$SW_STUB_LOG")" "Remote ID capture recovered" cap_failed_then_recovered
+
+# a link type that is not 802.11 + radiotap: a WARN, and no drone from those bytes
+# (control: the same fixture under the Pager's link type gives the drone, cap_beacon_detection)
+_cap_reset; _out="$(_cap beacon SW_FAKE_TCPDUMP_LINK='EN10MB (Ethernet)')"
+assert_eq "$(_cap_state)" "not_understood" cap_wrong_link_status
+assert_contains "$(cat "$SW_STUB_LOG")" "WiFi capture not understood" cap_wrong_link_warns
+assert_empty "$(printf '%s\n' "$_out" | grep '^drone_rid')" cap_wrong_link_no_drone
+
+# the frame cap: tcpdump stops at -c frames; one WARN per SW_COOLDOWN, and what was heard still counts
+_cap_reset; _out="$(_cap multi SW_RID_MAX_FRAMES=1)"
+assert_eq "$(_cap_state)" "capped" cap_capped_status
+assert_eq "$(grep -c 'hit its frame limit' "$SW_STUB_LOG")" "1" cap_capped_warns
+assert_eq "$(printf '%s\n' "$_out" | grep -c '^drone_rid')" "1" cap_capped_reports_what_it_heard
+_cap multi SW_RID_MAX_FRAMES=1 >/dev/null
+assert_eq "$(grep -c 'hit its frame limit' "$SW_STUB_LOG")" "1" cap_capped_warns_once_per_cooldown
+# ...and again once the cooldown has passed (SW_COOLDOWN=0: every capped lap may warn)
+_cap multi SW_RID_MAX_FRAMES=1 SW_COOLDOWN=0 >/dev/null
+assert_eq "$(grep -c 'hit its frame limit' "$SW_STUB_LOG")" "2" cap_capped_warns_again_after_cooldown
+
+# more drones than SW_RID_MAX_DRONES: the strongest are reported, the rest counted on one line
+_cap_reset; _out="$(_cap multi SW_RID_MAX_DRONES=1)"
+assert_eq "$(printf '%s\n' "$_out" | grep -c '^drone_rid')" "1" cap_drone_cap_one_detection
+assert_contains "$_out" "|0000FSWTEST000000001|" cap_drone_cap_keeps_strongest
+assert_contains "$(cat "$SW_STUB_LOG")" "LOG magenta ...and 1 more drones (Remote ID flood?)" cap_drone_cap_more_line
+
+# SW_REMOTE_ID=0: no tcpdump at all (control: cap_tcpdump_args, where the stub logged itself)
+_cap_reset; _cap beacon SW_REMOTE_ID=0 >/dev/null
+assert_empty "$(grep '^tcpdump ' "$SW_STUB_LOG")" cap_off_runs_no_tcpdump
+
+# A Stop during the window: the main shell is gone when the window ends. The capture is dropped unread,
+# nothing is reported or written, and its files go. Control: the capture did start (the stub logged).
+_cap_reset; sleep 30 & _fm=$!
+_out="$(env SW_TMP_DIR="$_cap_dir" SW_REMOTE_ID=1 SW_RID_SECONDS=1 SW_FAKE_TCPDUMP="$_RFIX/beacon.txt" SW_MAIN_PID="$_fm" bash -c '
+  source "$1/lib/match.sh"; source "$1/lib/wifi.sh"; source "$1/lib/log.sh"; source "$1/lib/ble.sh"; source "$1/lib/ignore.sh"; source "$1/lib/remoteid.sh"
+  sw_rid_start 1700000000
+  kill "$3"; while [ -e "/proc/$3" ] && [ "$(cut -d" " -f3 "/proc/$3/stat" 2>/dev/null)" != Z ]; do sleep 0.01; done
+  sw_rid_collect 1700000000 "$2"' _ "$SW_ROOT" "$_cap_loot" "$_fm")"
+wait "$_fm" 2>/dev/null
+assert_contains "$(cat "$SW_STUB_LOG")" "tcpdump -i wlan1mon" cap_stopped_control_capture_started
+assert_empty "$(printf '%s\n' "$_out" | grep '^drone_rid')" cap_stopped_reports_nothing
+assert_eq "$([ -e "$_cap_loot/remoteid.csv" ] && echo written)" "" cap_stopped_writes_no_csv
+assert_empty "$(ls -A "$_cap_dir")" cap_stopped_leaves_no_files
+
+# The Pager's Stop kills the main shell only, so the capture's helpers must end on their own: SIGKILL the
+# shell that started a capture, then watch tcpdump (the stub) end within SW_RID_SECONDS + 2 s.
+_pids="$_cap_dir/stub.pids"; : > "$_pids"
+env SW_TMP_DIR="$_cap_dir" SW_REMOTE_ID=1 SW_RID_SECONDS=1 SW_STUB_PIDS="$_pids" bash -c '
+  source "$1/lib/match.sh"; source "$1/lib/wifi.sh"; source "$1/lib/log.sh"; source "$1/lib/ble.sh"; source "$1/lib/ignore.sh"; source "$1/lib/remoteid.sh"
+  sw_rid_start 1700000000; sleep 30' _ "$SW_ROOT" 2>/dev/null &
+_sp=$!
+for _i in $(seq 100); do [ -s "$_pids" ] && break; sleep 0.05; done
+kill -9 "$_sp" 2>/dev/null; wait "$_sp" 2>/dev/null
+_alive() { local p n=0; while read -r p; do kill -0 "$p" 2>/dev/null && n=$((n + 1)); done < "$_pids"; echo "$n"; }
+# control: tcpdump was alive when its shell died, so "none left" below is not vacuous
+assert_eq "$(_alive)" "1" cap_orphan_control_alive_after_kill
+SECONDS=0; while [ "$(_alive)" != 0 ] && [ "$SECONDS" -lt 10 ]; do sleep 0.2; done
+assert_eq "$(_alive)" "0" cap_orphan_ends_by_itself
+rm -rf "$_cap_dir" "$_cap_loot"; unset _cap_dir _cap_loot _out _fm _pids _sp _i; unset -f _cap _cap_state _cap_reset _alive
diff --git a/test/stubs/tcpdump b/test/stubs/tcpdump
new file mode 100755
index 0000000..e57445f
--- /dev/null
+++ b/test/stubs/tcpdump
@@ -0,0 +1,32 @@
+#!/usr/bin/env bash
+# test/stubs/tcpdump — models the Pager's tcpdump 4.99.5 for the Remote ID capture (lib/remoteid.sh).
+#   SW_FAKE_TCPDUMP        a fixture (tcpdump -t -nn -xx text) printed as the capture; unset = no frames
+#   SW_FAKE_TCPDUMP_LINK   the link type it reports (default the Pager's: IEEE802_11_RADIO ...)
+#   SW_FAKE_TCPDUMP_FAIL=1 the capture never starts: an error and exit 1, no "listening on" line
+# As the real tool does: "listening on ..." on stderr, at most -c N frames on stdout, then it runs until
+# TERM/INT (the payload's timeout) or the -c limit, and reports "N packets captured" on stderr on the way
+# out. Self-limiting (30 s) if orphaned.
+echo "${0##*/} $*" >> "${SW_STUB_LOG:-/dev/null}"
+[ -n "${SW_STUB_PIDS:-}" ] && echo "$$" >> "$SW_STUB_PIDS"
+iface=wlan1mon max=0 prev=""
+for a in "$@"; do
+  case "$prev" in -i) iface="$a" ;; -c) max="$a" ;; esac
+  prev="$a"
+done
+if [ -n "${SW_FAKE_TCPDUMP_FAIL:-}" ]; then
+  echo "tcpdump: $iface: No such device exists" >&2
+  exit 1
+fi
+echo "tcpdump: verbose output suppressed, use -v[v]... for full protocol decode" >&2
+echo "listening on $iface, link-type ${SW_FAKE_TCPDUMP_LINK:-IEEE802_11_RADIO (802.11 plus radiotap header)}, snapshot length 262144 bytes" >&2
+n=0
+if [ -n "${SW_FAKE_TCPDUMP:-}" ]; then
+  # one frame = a header line and its hex lines; at most -c frames, as tcpdump stops there
+  awk -v max="$max" '$1 !~ /^0x[0-9a-f]+:$/ { f++ } max > 0 && f > max { exit } { print }' "$SW_FAKE_TCPDUMP"
+  n="$(awk -v max="$max" '$1 !~ /^0x[0-9a-f]+:$/ { f++ } END { print (max > 0 && f > max) ? max : f + 0 }' "$SW_FAKE_TCPDUMP")"
+fi
+summary() { printf '%s packets captured\n%s packets received by filter\n0 packets dropped by kernel\n' "$n" "$n" >&2; }
+if [ "$max" -gt 0 ] && [ "$n" -ge "$max" ]; then summary; exit 0; fi
+trap 'summary; exit 0' TERM INT
+end=$((SECONDS + 30)); while [ "$SECONDS" -lt "$end" ]; do sleep 0.05; done
+summary
```

- [ ] **Step 2: Run the suite and see the new tests fail.**

Run: `bash test/run.sh 2>&1 | tail -1`
Expected: `PASS=1015 FAIL=22`. The failures are exactly these new tests: `cap_beacon_detection`, `cap_beacon_csv_row`, `cap_beacon_status_ok`, `cap_tcpdump_args`, `cap_quiet_status_ok`, `cap_no_frames_is_ok`, `cap_failed_status`, `cap_failed_warns`, `cap_failed_warns_once`, `cap_failed_then_recovered`, `cap_wrong_link_status`, `cap_wrong_link_warns`, `cap_capped_status`, `cap_capped_warns`, `cap_capped_reports_what_it_heard`, `cap_capped_warns_once_per_cooldown`, `cap_capped_warns_again_after_cooldown`, `cap_drone_cap_one_detection`, `cap_drone_cap_keeps_strongest`, `cap_drone_cap_more_line`, `cap_stopped_control_capture_started`, `cap_orphan_control_alive_after_kill`. Other output is expected at this step too: the rest of multi-line failure messages, and errors such as `command not found` or `No such file or directory` for what this task has not added yet.

- [ ] **Step 3: Implement.** Apply this task's SECOND patch:

```diff
diff --git a/payloads/user/reconnaissance/squachwatch/lib/remoteid.sh b/payloads/user/reconnaissance/squachwatch/lib/remoteid.sh
index 26a5656..4fbeb69 100644
--- a/payloads/user/reconnaissance/squachwatch/lib/remoteid.sh
+++ b/payloads/user/reconnaissance/squachwatch/lib/remoteid.sh
@@ -246,3 +246,88 @@ _sw_rid_csv_row() {
   _sw_csv_cell "$gps"; r+=",$REPLY"
   printf '%s\n' "$r" >> "$csv"
 }
+# --- The per-lap capture: a bounded tcpdump window, run like btmon in lib/ble.sh (spec §6.1, §7.2) ---
+# The kernel filter: beacons, and action frames sent to NAN's address. BPF cannot look inside a beacon's
+# element list, so the decoder picks out the Remote ID beacons. ("subtype action" does not parse on the
+# Pager's libpcap; the frame-control byte does.)
+_sw_rid_filter() { REPLY='type mgt subtype beacon or (wlan[0] & 0xfc = 0xd0 and wlan addr1 51:6f:9a:01:00:00)'; }
+
+# A WARN when the capture's status changes, like the BLE note; "capped" at most once per SW_COOLDOWN and
+# never a "recovered" line after it. $1 = ok | capture_failed | not_understood | capped, $2 = now (epoch).
+sw_rid_health_note() {
+  local st="$1" now="$2" sf="${SW_RID_STATE_FILE:-${SW_TMP_DIR:-/tmp}/sw_rid.state}" prev="" capt="" cd="${SW_COOLDOWN:-600}"
+  [ -f "$sf" ] && { read -r prev; read -r capt; } < "$sf"
+  case "$cd" in ''|*[!0-9]*) cd=600 ;; esac
+  [[ "$capt" =~ ^[1-9][0-9]{0,11}$ ]] || capt=""
+  case "$st" in
+    capped)
+      if [ -z "$capt" ] || [ "$now" -lt "$capt" ] || [ $(( now - capt )) -ge "$cd" ]; then
+        LOG yellow "WARN: WiFi capture hit its frame limit (beacon flood?) — Remote ID partly blind" 2>/dev/null
+        capt="$now"
+      fi ;;
+    ok) case "$prev" in capture_failed|not_understood) LOG green "Remote ID capture recovered" 2>/dev/null ;; esac ;;
+    capture_failed) [ "$prev" = capture_failed ] || LOG yellow "WARN: WiFi capture failed — Remote ID over WiFi OFF" 2>/dev/null ;;
+    not_understood) [ "$prev" = not_understood ] || LOG yellow "WARN: WiFi capture not understood — Remote ID over WiFi OFF" 2>/dev/null ;;
+  esac
+  printf '%s\n%s\n' "$st" "$capt" > "$sf"
+}
+
+# $1 = the lap's start (epoch). Starts this lap's capture in the background and leaves SW_RID_PID,
+# SW_RID_CAP and SW_RID_ERR for sw_rid_collect, which must run in the SAME shell (it waits for the PID).
+# Read only: -p, and never -I: recon keeps the interface. -l so no line sits in a buffer at a signal, -t so
+# no clock time is printed. It ends by itself: timeout TERMs tcpdump after SW_RID_SECONDS (awk then reaches
+# the end of its input and prints its lines), or -c stops it; an orphaned capture still ends within
+# SW_RID_SECONDS + 2 s. Nothing here is ever found or stopped by name.
+sw_rid_start() {
+  SW_RID_PID=""; SW_RID_CAP=""; SW_RID_ERR=""
+  [ "${SW_REMOTE_ID:-0}" = 1 ] || return 0
+  command -v tcpdump >/dev/null 2>&1 || return 0
+  sw_stopped && return 0
+  local now="$1" secs="${SW_RID_SECONDS:-12}" maxf="${SW_RID_MAX_FRAMES:-1500}" maxd="${SW_RID_MAX_DRONES:-32}" cap err
+  [[ "$secs" =~ ^[1-9][0-9]{0,4}$ ]] || secs=12
+  [[ "$maxf" =~ ^[1-9][0-9]{0,6}$ ]] || maxf=1500
+  [[ "$maxd" =~ ^(0|[1-9][0-9]{0,3})$ ]] || maxd=32
+  cap="$(mktemp "${SW_TMP_DIR:-/tmp}/sw_rid.XXXXXX")" || { sw_rid_health_note capture_failed "$now"; return 0; }
+  err="$(mktemp "${SW_TMP_DIR:-/tmp}/sw_rid.XXXXXX")" || { rm -f "$cap"; sw_rid_health_note capture_failed "$now"; return 0; }
+  _sw_rid_filter
+  nice -n 10 timeout -k 2 "$secs" tcpdump -i "${SW_RID_IFACE:-wlan1mon}" -p -l -t -nn -xx -c "$maxf" "$REPLY" 2>"$err" \
+    | nice -n 10 awk -v max="$maxd" "$(_sw_rid_awk_src)" > "$cap" 2>/dev/null &
+  SW_RID_PID=$!; SW_RID_CAP="$cap"; SW_RID_ERR="$err"
+}
+
+# $1 = the lap's start (epoch), $2 = the loot dir. Waits for this lap's capture, notes its health, prints
+# its drones as finished detections (like an evil twin, they skip the matcher) and removes its files.
+sw_rid_collect() {
+  local now="$1" loot="$2" pid="${SW_RID_PID:-}" cap="${SW_RID_CAP:-}" err="${SW_RID_ERR:-}"
+  SW_RID_PID=""; SW_RID_CAP=""; SW_RID_ERR=""
+  [ -n "$pid" ] || return 0
+  wait "$pid" 2>/dev/null
+  # stopped during the window: drop the capture unread and report nothing (a relaunch owns the screen now)
+  if sw_stopped; then rm -f "$cap" "$err"; return 0; fi
+  local l started=0 radio=0 pkts="" frames=0 understood=0 more=0 tag ridf maxf="${SW_RID_MAX_FRAMES:-1500}" st
+  [[ "$maxf" =~ ^[1-9][0-9]{0,6}$ ]] || maxf=1500
+  while IFS= read -r l || [ -n "$l" ]; do
+    case "$l" in
+      "listening on "*) started=1; case "$l" in *"link-type IEEE802_11_RADIO "*) radio=1 ;; esac ;;
+      [0-9]*" packets captured") pkts="${l%% *}" ;;
+    esac
+  done < "$err"
+  while IFS= read -r l || [ -n "$l" ]; do
+    case "$l" in S$'\t'*) IFS='|' read -r tag frames understood ridf more <<< "${l//$'\t'/|}" ;; esac
+  done < "$cap"
+  [[ "$frames" =~ ^[0-9]{1,9}$ ]] || frames=0; [[ "$understood" =~ ^[0-9]{1,9}$ ]] || understood=0
+  [[ "$more" =~ ^[0-9]{1,9}$ ]] || more=0; [[ "$pkts" =~ ^[0-9]{1,9}$ ]] || pkts=""
+  if [ "$started" -ne 1 ]; then st=capture_failed
+  elif [ "$radio" -ne 1 ]; then st=not_understood                                   # not 802.11 + radiotap
+  elif [ -n "$pkts" ] && [ "$frames" -lt "$pkts" ]; then st=not_understood          # frames lost on the way
+  elif [ "$frames" -ge 5 ] && [ "$understood" -eq 0 ]; then st=not_understood       # the format changed
+  elif [ -n "$pkts" ] && [ "$pkts" -ge "$maxf" ]; then st=capped
+  else st=ok; fi                                                                    # a lap with no frames too
+  sw_rid_health_note "$st" "$now"
+  # bytes captured under any other link type are not 802.11 frames: no drones from them
+  if [ "$radio" -eq 1 ]; then
+    sw_rid_records "$now" "$loot" < "$cap"
+    [ "$more" -gt 0 ] && LOG magenta "...and $more more drones (Remote ID flood?)" 2>/dev/null
+  fi
+  rm -f "$cap" "$err"
+}
```

- [ ] **Step 4: Run the suite: all green, nothing stray.**

Run: `bash test/run.sh 2>&1 | tail -1` → `PASS=1037 FAIL=0`. Then `bash test/run.sh 2>&1 | grep -v -E '^(== |  FAIL|-----|PASS=)'` must print nothing (a stray line is a test that leaks output, or a missing function called somewhere).

- [ ] **Step 5: Commit.**

```bash
git add payloads/user/reconnaissance/squachwatch/lib/remoteid.sh test/remoteid_test.sh test/stubs/tcpdump
TZ=UTC git -c user.name=Ziggy -c user.email=79704039+therealziggy@users.noreply.github.com commit -F - <<'EOF'
remoteid: a bounded per-lap capture, Stop-safe, with health notes

sw_rid_start runs tcpdump read-only (-p) on the recon radio for
SW_RID_SECONDS under its own timeout, through the decoder; sw_rid_collect
waits for it in the same shell, notes its health once per change (the
frame cap once per cooldown), reports its drones and removes its files.
A stopped payload's capture is dropped unread, an orphaned one ends by
itself, and nothing is found or killed by name.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
git log -1 --format=%B | grep -cF 'Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>'
```
Expected last output: `1`.

---

### Task 5: A drone on screen and in the ledger (`alert.sh`, `log.sh`, `follow.sh`)

**Files:**
- `$SQ/lib/alert.sh`
- `$SQ/lib/follow.sh`
- `$SQ/lib/log.sh`
- `test/alert_test.sh`
- `test/follow_test.sh`

**Interfaces:**
- Consumes: the 9-field drone detection (Task 3).
- Produces: `sw_emit` reads 9 fields; for `drone_rid` it shows `Drone '<ID>'` (or `Drone (no ID)`), a second
  screen line (motion and pilot), and the alert body (airframe and motion, then the pilot); its ledger key is
  `drone|drone_rid:<ID>` (the ID alone), or the address when there is no ID. `sw_log_write` and
  `sw_follow_update` read the ninth field cleanly.

- [ ] **Step 1: Write the failing tests.** Apply this task's FIRST patch (see "Applying the patches"):

```diff
diff --git a/test/alert_test.sh b/test/alert_test.sh
index b352b65..abfd435 100644
--- a/test/alert_test.sh
+++ b/test/alert_test.sh
@@ -261,6 +261,48 @@ sw_seen_prune "$_s8" 1100 600
 assert_eq "$(grep -a -c 'evil_twin:Caf' "$_s8")" "1" prune_keeps_non_utf8_name_line
 rm -rf "$_L8" "$_s8"; unset _L8 _s8 _t
 
+# A drone is named by its Remote ID, with a detail line and a two-line alert body (spec 2026-10-01 §4)
+_L7="$(mktemp -d)"; sw_log_init "$_L7"; _s7="$(mktemp)"; : > "$_s7"; : > "$SW_STUB_LOG"
+_drone="drone_rid|Drone|high|surveillance|wifi|80:E1:26:AA:BB:CC|0000FSWTEST000000001|-47|multirotor"$'\t'"87m up, 12m/s"$'\t'"pilot (live) 47.39800,8.54102"
+sw_emit "$_drone" 1000 600 "$_s7" "$_L7"
+assert_contains "$(cat "$SW_STUB_LOG")" "LOG magenta Drone '0000FSWTEST000000001' 80:E1:26:AA:BB:CC -47dBm" drone_line_names_id
+assert_contains "$(cat "$SW_STUB_LOG")" "LOG magenta   87m up, 12m/s, pilot (live) 47.39800,8.54102" drone_detail_line
+assert_contains "$(cat "$SW_STUB_LOG")" "ALERT Drone '0000FSWTEST000000001'
+multirotor, 87m up, 12m/s
+pilot (live) 47.39800,8.54102
+80:E1:26:AA:BB:CC -47dBm" drone_alert_body
+assert_contains "$(cat "$SW_STUB_LOG")" "LED M 200" drone_alert_magenta_led
+assert_contains "$(tail -1 "$_L7/detections.csv")" ',drone_rid,"Drone",high,surveillance,wifi,80:E1:26:AA:BB:CC,"0000FSWTEST000000001",-47,' drone_csv_row_without_detail
+# one drone = one Remote ID: the same ID at a new address is the same drone, with no second row or alert...
+: > "$SW_STUB_LOG"
+sw_emit "drone_rid|Drone|high|surveillance|wifi|80:E1:26:11:22:33|0000FSWTEST000000001|-50|multirotor"$'\t\t'"no pilot location" 1001 600 "$_s7" "$_L7"
+assert_eq "$(grep -c ',drone_rid,' "$_L7/detections.csv")" "1" drone_new_address_same_id_no_row
+assert_empty "$(grep '^ALERT' "$SW_STUB_LOG")" drone_new_address_same_id_no_alert
+# ...though its screen line still prints (the live "still here" signal)
+assert_contains "$(cat "$SW_STUB_LOG")" "LOG magenta Drone '0000FSWTEST000000001' 80:E1:26:11:22:33 -50dBm" drone_new_address_still_on_screen
+assert_contains "$(cat "$_s7")" "drone|drone_rid:0000FSWTEST000000001|1000" drone_ledger_key_is_the_id
+# control: a different ID at that address is a different drone
+sw_emit "drone_rid|Drone|high|surveillance|wifi|80:E1:26:11:22:33|0000FSWTEST000000002|-50|multirotor"$'\t\t'"no pilot location" 1002 600 "$_s7" "$_L7"
+assert_eq "$(grep -c ',drone_rid,' "$_L7/detections.csv")" "2" drone_other_id_new_row
+assert_contains "$(cat "$SW_STUB_LOG")" "ALERT Drone '0000FSWTEST000000002'" drone_other_id_alerts
+# a drone that sends no ID says so and is keyed by its address
+: > "$SW_STUB_LOG"
+sw_emit "drone_rid|Drone|high|surveillance|wifi|80:E1:26:44:55:66||-60|multirotor"$'\t\t'"no pilot location" 1003 600 "$_s7" "$_L7"
+assert_contains "$(cat "$SW_STUB_LOG")" "LOG magenta Drone (no ID) 80:E1:26:44:55:66 -60dBm" drone_no_id_line
+assert_contains "$(cat "$_s7")" "80:E1:26:44:55:66|drone_rid|1003" drone_no_id_keyed_by_address
+# the per-lap screen cap hides both of a drone's lines, never its alert
+: > "$SW_STUB_LOG"
+SW_EMIT_NOLOG=1 sw_emit "drone_rid|Drone|high|surveillance|wifi|80:E1:26:77:88:99|0000FSWTEST000000003|-55|multirotor"$'\t'"87m up"$'\t'"no pilot location" 1004 600 "$_s7" "$_L7"
+assert_empty "$(grep '^LOG ' "$SW_STUB_LOG")" drone_nolog_hides_both_lines
+assert_contains "$(cat "$SW_STUB_LOG")" "ALERT Drone '0000FSWTEST000000003'" drone_nolog_alert_unchanged
+# control: every other kind keeps one screen line and its two-line alert
+: > "$SW_STUB_LOG"
+sw_emit "hacker_flipper|Flipper Zero|high|attacker|ble|80:E1:26:00:00:09|Flipper aa|-60" 1005 600 "$_s7" "$_L7"
+assert_eq "$(grep -c '^LOG ' "$SW_STUB_LOG")" "1" plain_kind_one_screen_line
+assert_contains "$(cat "$SW_STUB_LOG")" "ALERT Flipper Zero
+80:E1:26:00:00:09 -60dBm" plain_kind_alert_unchanged
+rm -rf "$_L7" "$_s7"; unset _L7 _s7 _drone
+
 # --- ledger pruning (spec 2026-09-23 §7) ---
 _P="$(mktemp -d)"; _pf="$_P/seen.db"
 printf '%s\n' 'AA:00:00:00:00:01|old_cat|1000' 'AA:00:00:00:00:02|new_cat|1500' '*|kind_old|1000' '*|kind_new|1550' 'garbage-line' 'AA:00:00:00:00:03|bad_ts|12x4' > "$_pf"
diff --git a/test/follow_test.sh b/test/follow_test.sh
index f073220..e924882 100644
--- a/test/follow_test.sh
+++ b/test/follow_test.sh
@@ -103,3 +103,11 @@ assert_empty "$_o" floor_negative_85_gates_control
 rm -rf "$_F3"; unset _F3 _tf3 _strong40 _weak95 _t _o
 
 rm -rf "$_T"; unset _T _tf _D _E _W _before _out _rc _body
+
+# a record with a 9th field (drones carry one) parses too: the signal stops at the next |
+_f9="$(mktemp)"; : > "$_f9"
+_o="$(sw_follow_update "tracker_tile|Tile|med|tracker|ble|AA:00:00:00:00:F9|t|-60|x	y	z" 1000 "$_f9" 0 300)"
+assert_eq "${_o##*|}" "-60" follow_ninth_field_signal_clean
+# control: the update did escalate (the check above read a real line)
+assert_contains "$_o" "tracker_tile_follow|" follow_ninth_field_control_escalated
+rm -f "$_f9"; unset _f9 _o
```

- [ ] **Step 2: Run the suite and see the new tests fail.**

Run: `bash test/run.sh 2>&1 | tail -1`
Expected: `PASS=1044 FAIL=12`. The failures are exactly these new tests: `drone_line_names_id`, `drone_detail_line`, `drone_alert_body`, `drone_csv_row_without_detail`, `drone_new_address_same_id_no_row`, `drone_new_address_same_id_no_alert`, `drone_new_address_still_on_screen`, `drone_ledger_key_is_the_id`, `drone_other_id_alerts`, `drone_no_id_line`, `drone_nolog_alert_unchanged`, `follow_ninth_field_signal_clean`. Other output is expected at this step too: the rest of multi-line failure messages, and errors such as `command not found` or `No such file or directory` for what this task has not added yet.

- [ ] **Step 3: Implement.** Apply this task's SECOND patch:

```diff
diff --git a/payloads/user/reconnaissance/squachwatch/lib/alert.sh b/payloads/user/reconnaissance/squachwatch/lib/alert.sh
index 0ac6071..f51fb9d 100644
--- a/payloads/user/reconnaissance/squachwatch/lib/alert.sh
+++ b/payloads/user/reconnaissance/squachwatch/lib/alert.sh
@@ -65,8 +65,8 @@ sw_emit() {
   # When given, a repeat full-screen alert may be HELD; the CSV row and log line never are.
   local det="$1" now="$2" cd="$3" sf="$4" loot="$5"
   local snz="${6:-}" snz_after="${7:-0}" snz_margin="${8:-7}" snz_reset="${9:-1800}"
-  local cat label conf tclass radio mac ident rssi
-  IFS='|' read -r cat label conf tclass radio mac ident rssi <<EOF
+  local cat label conf tclass radio mac ident rssi detail
+  IFS='|' read -r cat label conf tclass radio mac ident rssi detail <<EOF
 $det
 EOF
   local color; color="$(sw_color_for "$tclass")"
@@ -75,6 +75,18 @@ EOF
   # copied, so it names that network: "Evil twin 'HomeNet'" (spec 2026-09-29 §6.4).
   local shown="$label"
   [ "$cat" = evil_twin ] && shown="$label '$ident'"
+  # A drone is named by its Remote ID, or says it sent none (spec 2026-10-01 §4). Its detail, from
+  # lib/remoteid.sh (airframe TAB motion TAB pilot), adds a second screen line and the alert's body.
+  local dline="" abody=""
+  if [ "$cat" = drone_rid ]; then
+    if [ -n "$ident" ]; then shown="$label '$ident'"; else shown="$label (no ID)"; fi
+    local d_air="${detail%%$'\t'*}" d_rest="${detail#*$'\t'}" d_motion d_pilot
+    d_motion="${d_rest%%$'\t'*}"; d_pilot="${d_rest#*$'\t'}"
+    dline="$d_motion"; [ -n "$d_pilot" ] && dline="${dline:+$dline, }$d_pilot"
+    abody="$d_air"; [ -n "$d_motion" ] && abody="${abody:+$abody, }$d_motion"
+    [ -n "$abody" ] && abody="$abody"$'\n'
+    [ -n "$d_pilot" ] && abody="$abody$d_pilot"$'\n'
+  fi
   # The cooldown is evaluated ONCE, for every confidence level, and gates persistence.
   # It used to gate only the alert, so the loot CSV gained a row per device PER LAP
   # (~every 15s, unbounded) and a device matching two rules wrote two identical rows.
@@ -82,15 +94,21 @@ EOF
   # An evil twin's evidence is the network it copies, so each copied name is reported on its own:
   # one radio copying several names, or decoys around a real target, cannot hide one behind another
   # (spec 2026-09-29, user decision). The kind cooldown below still buzzes once for all of them.
-  local rkey="$cat"
+  local rkey="$cat" rmac="$mac"
   [ "$cat" = evil_twin ] && rkey="$cat:$ident"
-  sw_should_report "$mac" "$rkey" "$now" "$cd" "$sf" && fresh=0
+  # One drone = one Remote ID (user decision 2026-10-01): its key leaves out the address, which can
+  # change. A drone that sends no ID is keyed by its address, like any device.
+  if [ "$cat" = drone_rid ] && [ -n "$ident" ]; then rmac=drone; rkey="$cat:$ident"; fi
+  sw_should_report "$rmac" "$rkey" "$now" "$cd" "$sf" && fresh=0
   [ "$fresh" -eq 0 ] && sw_log_write "$loot" "$det" "$now"
   # The colored log line still prints every lap: it is the operator's live "still here"
   # signal, and unlike the CSV it does not accumulate on disk. A lap loop that has already
   # shown enough lines of this kind sets SW_EMIT_NOLOG=1 for the call (spec 2026-09-23 §5):
   # only this line is skipped, never the CSV row or the alert.
-  [ -n "${SW_EMIT_NOLOG:-}" ] || LOG "$color" "$shown $mac$rssitag" 2>/dev/null
+  if [ -z "${SW_EMIT_NOLOG:-}" ]; then
+    LOG "$color" "$shown $mac$rssitag" 2>/dev/null
+    [ -n "$dline" ] && LOG "$color" "  $dline" 2>/dev/null
+  fi
   # Full alert + hardware additionally requires high confidence, and (when snooze is on)
   # the device must not have used up its free alerts without coming closer.
   if [ "$fresh" -eq 0 ] && [ "$conf" = high ]; then
@@ -119,7 +137,7 @@ EOF
       [ "$gate" -eq 2 ] && note="
 snoozing: re-alerts only if closer"
       ALERT "$shown
-$mac$rssitag$note" 2>/dev/null
+$abody$mac$rssitag$note" 2>/dev/null
       sw_hw_notify "$tclass"
     fi
   fi
diff --git a/payloads/user/reconnaissance/squachwatch/lib/follow.sh b/payloads/user/reconnaissance/squachwatch/lib/follow.sh
index 6e52374..b96775b 100644
--- a/payloads/user/reconnaissance/squachwatch/lib/follow.sh
+++ b/payloads/user/reconnaissance/squachwatch/lib/follow.sh
@@ -24,7 +24,8 @@ sw_follow_update() {
   tclass="${r%%|*}"; r="${r#*|}"
   radio="${r%%|*}";  r="${r#*|}"
   mac="${r%%|*}";    r="${r#*|}"
-  ident="${r%%|*}";  rssi="${r#*|}"
+  ident="${r%%|*}";  r="${r#*|}"
+  rssi="${r%%|*}"
   [ "$tclass" = tracker ] || return 0
   # Follow floor (spec 2026-09-23 §6): a sighting weaker than SW_FOLLOW_MIN_RSSI does not count,
   # so a stationary neighbour's tracker heard through a wall never "follows" you at home. It
diff --git a/payloads/user/reconnaissance/squachwatch/lib/log.sh b/payloads/user/reconnaissance/squachwatch/lib/log.sh
index be102ee..e7ab5be 100644
--- a/payloads/user/reconnaissance/squachwatch/lib/log.sh
+++ b/payloads/user/reconnaissance/squachwatch/lib/log.sh
@@ -31,8 +31,8 @@ sw_log_write() {
   local dir="$1" det="$2" now="$3" gps
   [ -f "$dir/detections.csv" ] || sw_log_init "$dir"   # self-init if caller skipped sw_log_init
   gps="$(GPS_GET 2>/dev/null | tr ' ' ',' )"   # stub prints SW_FAKE_GPS; device prints coords
-  local cat label conf tclass radio mac ident rssi
-  IFS='|' read -r cat label conf tclass radio mac ident rssi <<EOF
+  local cat label conf tclass radio mac ident rssi detail
+  IFS='|' read -r cat label conf tclass radio mac ident rssi detail <<EOF
 $det
 EOF
   # Quote/escape the free-text + attacker-influenced fields. gps must be quoted because real
```

- [ ] **Step 4: Run the suite: all green, nothing stray.**

Run: `bash test/run.sh 2>&1 | tail -1` → `PASS=1056 FAIL=0`. Then `bash test/run.sh 2>&1 | grep -v -E '^(== |  FAIL|-----|PASS=)'` must print nothing (a stray line is a test that leaks output, or a missing function called somewhere).

- [ ] **Step 5: Commit.**

```bash
git add payloads/user/reconnaissance/squachwatch/lib/alert.sh payloads/user/reconnaissance/squachwatch/lib/follow.sh payloads/user/reconnaissance/squachwatch/lib/log.sh test/alert_test.sh test/follow_test.sh
TZ=UTC git -c user.name=Ziggy -c user.email=79704039+therealziggy@users.noreply.github.com commit -F - <<'EOF'
alert/log/follow: a drone is named by its Remote ID, with telemetry

sw_emit reads a ninth, display-only field: a drone is "Drone '<ID>'" (or
"Drone (no ID)"), with a second screen line and a two-line alert body,
and its ledger key is its ID alone, so a changing address stays one
drone. log.sh and follow.sh read the ninth field cleanly.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
git log -1 --format=%B | grep -cF 'Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>'
```
Expected last output: `1`.

---

### Task 6: Into the lap: settings, wiring, health, Stop, guards (`payload.sh`)

**Files:**
- `$SQ/payload.sh`
- `test/payload_test.sh`
- `test/perf_test.sh`
- `test/portability_test.sh`

**Interfaces:**
- Consumes: `sw_rid_start` / `sw_rid_collect` (Task 4).
- Produces: `payload.sh` loads `remoteid`; settings `SW_REMOTE_ID` (1), `SW_RID_IFACE` (wlan1mon), `SW_RID_SECONDS`
  (12), `SW_RID_MAX_FRAMES` (1500), `SW_RID_MAX_DRONES` (32), `SW_RID_FILE` ($SW_LOOT_DIR/remoteid.csv);
  `sw_scan_once` opens the window as the producer group's first step and collects it as its last; the health
  check warns when tcpdump or the interface is missing (`SW_SYSFS_NET` test seam); `sw_clear_tmp` sweeps
  `sw_rid.*`, `sw_cleanup` removes `sw_rid.state`.

- [ ] **Step 1: Write the failing tests.** Apply this task's FIRST patch (see "Applying the patches"):

```diff
diff --git a/test/payload_test.sh b/test/payload_test.sh
index 981b522..c2519c5 100644
--- a/test/payload_test.sh
+++ b/test/payload_test.sh
@@ -8,6 +8,9 @@ export SW_LOOT_DIR="$(mktemp -d)"
 export SW_SEEN_FILE="$(mktemp)"; : > "$SW_SEEN_FILE"
 export SW_TMP_DIR="$(mktemp -d)"               # RAM-state seam: keeps track.db out of the real /tmp
 export SW_TEST_SOURCE=1                      # tells payload.sh not to auto-run main
+# Laps here do not capture WiFi frames (each would wait out a Remote ID window); the Remote ID lap
+# tests below turn it on, and its default (on) is read in a clean process.
+export SW_REMOTE_ID=0
 # The COMMITTED fixture's timestamps age with the repo, so pin the window off for the
 # pipeline assertions below. The window itself is tested in wifi_test.sh against a DB
 # rebuilt at test time.
@@ -123,6 +126,7 @@ rm -rf "$_hb2"; unset _hb2 _hbd
 # own helpers end by themselves (ble_test.sh: ble_orphans_end_by_themselves). killall and
 # pkill are stubs that record calls, so the suite never kills real processes on the dev box.
 _ct="$(mktemp -d)"; : > "$_ct/sw_ble.AbC123"; : > "$_ct/sw_ble.state"; : > "$_ct/sw_recon.AbC123"; : > "$_ct/keep.me"; : > "$SW_STUB_LOG"
+: > "$_ct/sw_rid.XyZ789"; : > "$_ct/sw_rid.state"
 # precondition: here these names resolve to the recording stubs, never to the real tools
 _kst="$(command -v killall pkill | sed 's|.*/test/stubs/||' | tr '\n' ' ')"
 assert_eq "$_kst" "killall pkill " cleanup_kill_tools_are_stubs
@@ -133,11 +137,12 @@ assert_eq "$(grep -cE '^(killall|pkill) probe-control$' "$SW_STUB_LOG")" "2" cle
 : > "$SW_STUB_LOG"
 ( SW_TMP_DIR="$_ct" sw_cleanup )
 assert_empty "$(grep -E '^(killall|pkill) ' "$SW_STUB_LOG")" cleanup_kills_nothing_by_name
-# It removes the BLE health state and any recon DB copy, but leaves a BLE capture to the lap that
-# owns it: a lap still running when Stop came reads its capture again (the health check), and
-# removes it itself on every path. The next start sweeps anything a lap could not.
-assert_empty "$(ls "$_ct" | grep -E '^(sw_ble\.state|sw_recon\.)')" cleanup_removes_state_and_db_copy
+# It removes the BLE and Remote ID health states and any recon DB copy, but leaves the BLE and Remote
+# ID captures to the lap that owns them: a lap still running when Stop came reads its capture again (the
+# health check), and removes it itself on every path. The next start sweeps anything a lap could not.
+assert_empty "$(ls "$_ct" | grep -E '^(sw_ble\.state|sw_rid\.state|sw_recon\.)')" cleanup_removes_state_and_db_copy
 assert_eq "$(ls "$_ct" | grep -c '^sw_ble\.AbC123$')" "1" cleanup_leaves_a_live_laps_capture
+assert_eq "$(ls "$_ct" | grep -c '^sw_rid\.XyZ789$')" "1" cleanup_leaves_a_live_laps_rid_capture
 assert_contains "$(ls "$_ct")" "keep.me" cleanup_leaves_other_files   # control: it is not rm -rf
 rm -rf "$_ct"; unset _ct _kst
 # ...and nothing in the payloads finds or kills processes by name at all: a startup "kill the
@@ -392,18 +397,21 @@ rm -rf "$_kt"; unset -f _sw_run_failing_scan; unset _kt _kw _rc
 # Name-agnostic: whatever temp files a lap leaves when it dies before its own cleanup (here every
 # `rm` is shadowed, so nothing is removed), sw_clear_tmp removes them all. A capture, state or DB
 # copy renamed out of the sweep's globs fails this.
-_lt="$(mktemp -d)"
+_lt="$(mktemp -d)"; _ll="$(mktemp -d)"
 (
   export SW_TMP_DIR="$_lt"
   rm() { :; }
   sw_wifi_records "$FIX/recon.db" >/dev/null
   SW_FAKE_BTMON="$FIX/btmon_synthetic.txt" sw_ble_scan 1 hci0 >/dev/null
+  export SW_REMOTE_ID=1 SW_RID_SECONDS=1 SW_FAKE_TCPDUMP="$FIX/rid/beacon.txt"
+  sw_rid_start 1700000000; SW_RID_FILE= sw_rid_collect 1700000000 "$_ll" >/dev/null
 )
-# control: the lap did leave its files (DB copy, BLE capture, BLE state), so "none left" is not vacuous
-assert_eq "$(ls -A "$_lt" | wc -l | tr -d ' ')" "3" sweep_lap_leaves_three_temp_files
+# control: the lap did leave its files (DB copy, BLE capture, BLE state, Remote ID capture, its tcpdump
+# messages and its state), so "none left" is not vacuous
+assert_eq "$(ls -A "$_lt" | wc -l | tr -d ' ')" "6" sweep_lap_leaves_six_temp_files
 ( SW_TMP_DIR="$_lt" sw_clear_tmp )
 assert_empty "$(ls -A "$_lt")" sweep_clears_every_temp_file_a_lap_leaves
-rm -rf "$_lt"; unset _lt
+rm -rf "$_lt" "$_ll"; unset _lt _ll
 # --- the Pager's Stop (measured 2026-09-27 with a probe payload launched from the menu) ---
 # Stop sends SIGINT and then SIGKILL, ~1 s later, to the payload's MAIN shell only; the lap's
 # subshells get no signal at all. So the trap must run at once, not after the lap, and a lap
@@ -743,10 +751,82 @@ assert_eq "$(env -u SW_EVIL_TWIN bash -c 'SW_TEST_SOURCE=1 . "$1"/payload.sh >/d
 rm -rf "$_tw"; unset _tw _twdb _twd; unset -f _tw_lap _tw_reset
 # --- end evil twin ---
 
+# --- Remote ID over WiFi in the lap (spec 2026-10-01) ---
+_RFIX2="$(cd "$(dirname "${BASH_SOURCE[0]}")/fixtures" && pwd)/rid"
+_rid_reset() { rm -f "$SW_LOOT_DIR/detections.csv" "$SW_LOOT_DIR/remoteid.csv" "$SW_TMP_DIR"/sw_rid.*; : > "$SW_SEEN_FILE"; sw_log_init "$SW_LOOT_DIR"; : > "$SW_STUB_LOG"; }
+# _rid_lap FIXTURE: one lap with the capture on (a 1 s window), no recon DB and no BLE devices
+_rid_lap() { SW_REMOTE_ID=1 SW_RID_SECONDS=1 SW_FAKE_TCPDUMP="$_RFIX2/$1.txt" SW_RECON_DB=/nonexistent/recon.db SW_BLE_CMD=true sw_scan_once; }
+_rid_reset; _rid_lap beacon
+# the lap collects its capture once the window ends (it waits for it, in the shell that started it)
+assert_contains "$(cat "$SW_STUB_LOG")" "ALERT Drone '0000FSWTEST000000001'" rid_lap_alerts
+assert_contains "$(cat "$SW_STUB_LOG")" "LOG magenta   87m up, 12m/s, pilot (live) 47.39800,8.54102" rid_lap_detail_line
+assert_contains "$(cat "$SW_LOOT_DIR/remoteid.csv")" ",beacon,80:E1:26:AA:BB:CC,-47,serial," rid_lap_track_row
+assert_contains "$(cat "$SW_LOOT_DIR/detections.csv")" ',drone_rid,"Drone",high,surveillance,wifi,80:E1:26:AA:BB:CC,"0000FSWTEST000000001",-47,' rid_lap_detections_row
+assert_empty "$(ls -A "$SW_TMP_DIR" | grep '^sw_rid\.' | grep -v '^sw_rid\.state$')" rid_lap_leaves_no_capture
+# the next lap: no second alert or detections row (the cooldown), but a second flight-track row
+_rid_lap beacon
+assert_eq "$(grep -c '^ALERT Drone' "$SW_STUB_LOG")" "1" rid_lap_second_lap_no_second_alert
+assert_eq "$(grep -c ',beacon,' "$SW_LOOT_DIR/remoteid.csv")" "2" rid_lap_track_row_every_lap
+# the owner's own drone (drone:<ID> in ignore.txt) leaves no trace in the lap either
+_rid_reset; SW_IGNORE_SET=" DRONE:0000FSWTEST000000001 " _rid_lap beacon
+assert_empty "$(grep -F 'Drone' "$SW_STUB_LOG")" rid_lap_ignored_drone_silent
+assert_eq "$([ -e "$SW_LOOT_DIR/remoteid.csv" ] && echo written)" "" rid_lap_ignored_drone_no_track_row
+# SW_REMOTE_ID=0: no capture at all (control: rid_lap_alerts, which had one)
+_rid_reset; SW_REMOTE_ID=0 SW_FAKE_TCPDUMP="$_RFIX2/beacon.txt" SW_RECON_DB=/nonexistent/recon.db SW_BLE_CMD=true sw_scan_once
+assert_empty "$(grep '^tcpdump ' "$SW_STUB_LOG")" rid_lap_off_no_capture
+# a lap of a stopped payload starts no capture and reports no drone
+bash -c 'exit 0' & _rd=$!; wait "$_rd"
+_rid_reset; SW_MAIN_PID="$_rd" _rid_lap beacon
+assert_empty "$(grep -E '^(tcpdump|ALERT|LOG) ' "$SW_STUB_LOG")" rid_lap_stopped_no_capture_no_report
+# the defaults, read in a clean process (a test that sets a value cannot see its default)
+assert_eq "$(env -u SW_REMOTE_ID -u SW_RID_IFACE -u SW_RID_SECONDS -u SW_RID_MAX_FRAMES -u SW_RID_MAX_DRONES -u SW_RID_FILE -u SW_LOOT_DIR \
+  bash -c 'SW_TEST_SOURCE=1 . "$1"/payload.sh >/dev/null 2>&1; echo "$SW_REMOTE_ID|$SW_RID_IFACE|$SW_RID_SECONDS|$SW_RID_MAX_FRAMES|$SW_RID_MAX_DRONES|$SW_RID_FILE"' _ "$SW_ROOT")" \
+  "1|wlan1mon|12|1500|32|/root/loot/squachwatch/remoteid.csv" payload_rid_defaults
+# health: the capture needs tcpdump and the recon radio's interface (spec 2026-10-01 §7.1). A PATH with
+# only what the check needs (the btmon stub too, so tcpdump is the only thing missing).
+_rn="$(mktemp -d)"; mkdir "$_rn/net" "$_rn/bin"; : > "$_rn/net/wlan1mon"
+_stubs="$(cd "$(dirname "${BASH_SOURCE[0]}")/stubs" && pwd)"
+for _t in LOG sqlite3 btmon; do ln -s "$_stubs/$_t" "$_rn/bin/$_t"; done
+for _t in bash cp date mktemp rm python3; do ln -s "$(command -v "$_t")" "$_rn/bin/$_t"; done
+: > "$SW_STUB_LOG"; PATH="$_rn/bin" SW_REMOTE_ID=1 SW_SYSFS_NET="$_rn/net" sw_healthcheck >/dev/null 2>&1
+assert_contains "$(cat "$SW_STUB_LOG")" "WARN: tcpdump missing — Remote ID over WiFi OFF" health_rid_tcpdump_missing
+ln -s "$_stubs/tcpdump" "$_rn/bin/tcpdump"
+: > "$SW_STUB_LOG"; PATH="$_rn/bin" SW_REMOTE_ID=1 SW_SYSFS_NET="$_rn/net" SW_RID_IFACE=wlan9mon sw_healthcheck >/dev/null 2>&1
+assert_contains "$(cat "$SW_STUB_LOG")" "WARN: wlan9mon missing — Remote ID over WiFi OFF" health_rid_iface_missing
+# control: both there, no Remote ID WARN
+: > "$SW_STUB_LOG"; PATH="$_rn/bin" SW_REMOTE_ID=1 SW_SYSFS_NET="$_rn/net" sw_healthcheck >/dev/null 2>&1
+assert_empty "$(grep -F 'Remote ID' "$SW_STUB_LOG")" health_rid_control_all_present
+# ...and none when Remote ID is off, even with the interface missing
+: > "$SW_STUB_LOG"; PATH="$_rn/bin" SW_REMOTE_ID=0 SW_SYSFS_NET="$_rn/net" SW_RID_IFACE=wlan9mon sw_healthcheck >/dev/null 2>&1
+assert_empty "$(grep -F 'Remote ID' "$SW_STUB_LOG")" health_rid_off_silent
+rm -rf "$_rn"; unset _rn _stubs _t _rd
+# The Pager's Stop during the Remote ID window (spec 2026-10-01 §7.3): the trap runs within the grace,
+# and the lap that was running reports nothing when its window ends, and leaves no capture behind.
+_rs="$(mktemp -d)"; : > "$SW_STUB_LOG"
+SW_TEST_SOURCE= SW_SEEN_FILE="$_rs/seen.db" SW_LOOT_DIR="$_rs/loot" SW_TMP_DIR="$_rs" SW_SLEEP=1 SW_HEALTH_EVERY=0 \
+  SW_BLE_CMD=true SW_RECON_DB=/nonexistent/recon.db SW_REMOTE_ID=1 SW_RID_SECONDS=3 SW_FAKE_TCPDUMP="$_RFIX2/beacon.txt" \
+  python3 -c 'import os, signal as s, sys; [s.signal(n, s.SIG_DFL) for n in (s.SIGINT, s.SIGPIPE, s.SIGXFSZ)]; os.execvp("bash", ["bash"] + sys.argv[1:])' \
+  "$SW_ROOT/payload.sh" >/dev/null 2>&1 &
+_sp=$!
+for _i in $(seq 80); do ls "$_rs" | grep -qE '^sw_rid\.[A-Za-z0-9]{6}$' && break; sleep 0.1; done
+_inwin="$(ls "$_rs" | grep -qE '^sw_rid\.[A-Za-z0-9]{6}$' && echo yes || echo no)"
+kill -INT "$_sp"
+for _i in $(seq 20); do kill -0 "$_sp" 2>/dev/null || break; sleep 0.05; done    # the ~1 s grace
+_alive="$(kill -0 "$_sp" 2>/dev/null && echo yes || echo no)"
+{ kill -KILL "$_sp"; wait "$_sp"; } 2>/dev/null; _rc=$?
+assert_eq "$_inwin" "yes" stop_rid_control_was_in_the_window
+assert_eq "$_alive/$_rc" "no/0" stop_rid_trap_runs_within_the_grace
+sleep 4                                   # the lap that was running: its 3 s window runs out
+assert_empty "$(grep -E '^(ALERT|VIBRATE|RINGTONE) ' "$SW_STUB_LOG")" stop_rid_lap_never_alerts
+assert_empty "$(grep -F 'Drone' "$SW_STUB_LOG")" stop_rid_lap_reports_nothing
+assert_empty "$(ls "$_rs" | grep -E '^sw_rid\.')" stop_rid_leaves_no_files
+rm -rf "$_rs"; unset _rs _sp _i _inwin _alive _rc _RFIX2; unset -f _rid_reset _rid_lap
+# --- end Remote ID ---
+
 rm -rf "$SW_LOOT_DIR" "$SW_SEEN_FILE"
 
 rm -rf "$SW_TMP_DIR"
-unset SW_RECON_DB SW_BLE_CMD SW_LOOT_DIR SW_SEEN_FILE SW_TEST_SOURCE SW_RECENCY_SECS SW_FOLLOW_SECS SW_FOLLOW_GAP SW_TRACK_FILE SW_IGNORE_FILE SW_IGNORE_SET SW_TMP_DIR SW_SNOOZE_AFTER SW_SNOOZE_MARGIN_DB SW_SNOOZE_RESET_SECS SW_SNOOZE_FILE SW_KIND_COOLDOWN SW_LOG_PER_KIND SW_FOLLOW_MIN_RSSI SW_EVIL_TWIN
+unset SW_RECON_DB SW_BLE_CMD SW_LOOT_DIR SW_SEEN_FILE SW_TEST_SOURCE SW_RECENCY_SECS SW_FOLLOW_SECS SW_FOLLOW_GAP SW_TRACK_FILE SW_IGNORE_FILE SW_IGNORE_SET SW_TMP_DIR SW_SNOOZE_AFTER SW_SNOOZE_MARGIN_DB SW_SNOOZE_RESET_SECS SW_SNOOZE_FILE SW_KIND_COOLDOWN SW_LOG_PER_KIND SW_FOLLOW_MIN_RSSI SW_EVIL_TWIN SW_REMOTE_ID SW_RID_IFACE SW_RID_SECONDS SW_RID_MAX_FRAMES SW_RID_MAX_DRONES SW_RID_FILE
 
 # --- config defaults (regression: a lib default must not pre-empt the payload's) ---
 # lib/wifi.sh used to run `: "${SW_RECENCY_SECS:=0}"`, and payload.sh sources its libs
diff --git a/test/perf_test.sh b/test/perf_test.sh
index 10608e5..e786ab0 100644
--- a/test/perf_test.sh
+++ b/test/perf_test.sh
@@ -96,4 +96,24 @@ done
 assert_contains "$(_sw_body "$SW_ROOT/lib/eviltwin.sh" sw_evil_twin_scan)" "sqlite3 -readonly" twin_query_read_only
 assert_contains "$(_sw_body "$SW_ROOT/lib/eviltwin.sh" sw_evil_twin_scan)" "AS MATERIALIZED" twin_query_one_pass
 
+# 8) Remote ID (spec 2026-10-01): the per-drone bash is builtins only (the frames themselves are read by
+#    one awk pass per lap), the decoder keeps its budget, and the capture never touches the interface.
+source "$SW_ROOT/lib/remoteid.sh"
+for _fn in sw_rid_coord sw_rid_alt sw_rid_m sw_rid_mps sw_rid_mps2 sw_rid_dmps sw_rid_text _sw_rid_name _sw_rid_line_ok _sw_rid_csv_row; do
+  assert_contains "$(_sw_body "$SW_ROOT/lib/remoteid.sh" "$_fn")" "$_fn()" "forkfree_found_$_fn"
+  assert_empty "$(_sw_body "$SW_ROOT/lib/remoteid.sh" "$_fn" | grep -nE '\$\([^(]|`|(^|[^a-z_])(tr|sed|cut|awk|grep) ')" "forkfree_$_fn"
+done
+assert_contains "$(_sw_body "$SW_ROOT/lib/remoteid.sh" sw_rid_start)" " -p -l -t -nn -xx " rid_capture_read_only
+assert_empty "$(_sw_body "$SW_ROOT/lib/remoteid.sh" sw_rid_start | grep -nE '(^|[^-])-I( |$)|iw |iwconfig|ifconfig|ip link')" rid_capture_never_reconfigures
+# control: the same grep sees a planted -I
+assert_contains "$(printf 'tcpdump -I -i wlan1mon\n' | grep -nE '(^|[^-])-I( |$)|iw |iwconfig|ifconfig|ip link')" "-I" rid_reconfigure_grep_works
+# LATENCY BUDGET for the decoder: 1,500 frames (1,200 ordinary beacons + 300 Remote ID) in one pass
+_rfx="$(cd "$(dirname "${BASH_SOURCE[0]}")/fixtures" && pwd)/rid"; _big="$(mktemp)"
+{ for _i in $(seq 1200); do cat "$_rfx/quiet.txt"; done; for _i in $(seq 300); do cat "$_rfx/beacon.txt"; done; } > "$_big"
+SECONDS=0; _o="$(_sw_rid_decode_awk < "$_big")"; _el=$SECONDS
+# positive control first: every frame was read (else the timing is vacuous)
+assert_contains "$_o" "S	1500	1500	300	0" rid_perf_control_all_frames_read
+if [ "$_el" -lt 5 ]; then pass; else fail "rid_perf_budget: 1500 frames took ${_el}s (budget 5s)"; fi
+rm -f "$_big"; unset _rfx _big _i _o _el
+
 unset _fn _sw_body _sw_sigs _sw_bulk _sw_out _sw_elapsed _sw_t3sigs _sw_bulk_ble _sw_out_ble _sw_el_ble _sw_pad _i _l _t0 _t1 _t2 _sw_o1 _sw_o2 _plain _padded
diff --git a/test/portability_test.sh b/test/portability_test.sh
index 9b160ef..1897279 100644
--- a/test/portability_test.sh
+++ b/test/portability_test.sh
@@ -14,3 +14,9 @@ assert_empty "$(grep -rn "['\"]\[:" "$SW_THEMES")" no_posix_tr_classes_in_themes
 assert_empty "$(grep -rn 'XXXXXX\.' "$SW_THEMES")" no_mktemp_suffix_in_themes
 assert_empty "$(grep -rn 'head -c' "$SW_THEMES")" no_head_c_in_themes
 assert_contains "$(ls "$SW_THEMES/SquachWatch")" "install.sh" portability_walk_reads_themes
+
+# lib/remoteid.sh's awk must not use 0x.. literals: BusyBox awk and mawk do not parse them. Comments, and
+# the tcpdump filter (a tcpdump expression, not awk), are left out of the check.
+assert_empty "$(sed 's/#.*//' "$SW_PAYLOADS/user/reconnaissance/squachwatch/lib/remoteid.sh" | grep -vF "REPLY='type mgt" | grep -nE '(^|[^0-9a-zA-Z_])0x[0-9a-fA-F]')" remoteid_no_hex_literals
+# control: the check does see a planted literal
+assert_contains "$(printf 'if (b(i) == 0xfa) x\n' | sed 's/#.*//' | grep -nE '(^|[^0-9a-zA-Z_])0x[0-9a-fA-F]')" "0xfa" remoteid_hex_check_works
```

- [ ] **Step 2: Run the suite and see the new tests fail.**

Run: `bash test/run.sh 2>&1 | tail -1`
Expected: `PASS=1093 FAIL=12`. The failures are exactly these new tests: `cleanup_removes_state_and_db_copy`, `sweep_lap_leaves_six_temp_files`, `rid_lap_alerts`, `rid_lap_detail_line`, `rid_lap_track_row`, `rid_lap_detections_row`, `rid_lap_second_lap_no_second_alert`, `rid_lap_track_row_every_lap`, `payload_rid_defaults`, `health_rid_tcpdump_missing`, `health_rid_iface_missing`, `stop_rid_control_was_in_the_window`. Other output is expected at this step too: the rest of multi-line failure messages, and errors such as `command not found` or `No such file or directory` for what this task has not added yet.

- [ ] **Step 3: Implement.** Apply this task's SECOND patch:

```diff
diff --git a/payloads/user/reconnaissance/squachwatch/payload.sh b/payloads/user/reconnaissance/squachwatch/payload.sh
index 0998275..d3fa1bb 100644
--- a/payloads/user/reconnaissance/squachwatch/payload.sh
+++ b/payloads/user/reconnaissance/squachwatch/payload.sh
@@ -19,7 +19,7 @@ SW_HOME="${PAYLOAD_HOME:-$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )}"
 SW_HOME="${SW_HOME%/}"
 # Without its libs every lap is a silent no-op (each step is "command not found"), so a
 # lib that won't load stops the payload loudly instead of letting it run blind.
-for l in match wifi ble alert log follow ignore snooze eviltwin; do
+for l in match wifi ble alert log follow ignore snooze eviltwin remoteid; do
   . "$SW_HOME/lib/$l.sh" || { LOG red "ERROR: can't load $SW_HOME/lib/$l.sh — SquachWatch NOT running" 2>/dev/null; exit 1; }
 done
 
@@ -78,6 +78,20 @@ done
 # the recency window (600 s when that window is off) reports each open copy as an evil twin, with a
 # full alert like any other high-confidence find. 1 = on; anything else turns it off.
 : "${SW_EVIL_TWIN:=1}"
+# Remote ID over WiFi (spec 2026-10-01): each lap a short, read-only tcpdump window on the recon radio
+# decodes the Remote ID that drones broadcast (their ID, position, height, speed and the pilot's
+# location) into a full alert, plus a row per lap in remoteid.csv. 1 = on; anything else turns it off.
+: "${SW_REMOTE_ID:=1}"
+# The radio it listens on: the recon radio, whose channel hopping it rides (it never retunes it).
+: "${SW_RID_IFACE:=wlan1mon}"
+# The capture window in seconds. It starts with the lap and normally ends before the BLE scan does.
+: "${SW_RID_SECONDS:=12}"
+# At most this many frames per lap (it reads every nearby beacon, so a beacon flood must not eat the
+# CPU), and this many drones per lap (the strongest; the rest are counted on one line; 0 = no cap).
+: "${SW_RID_MAX_FRAMES:=1500}"
+: "${SW_RID_MAX_DRONES:=32}"
+# The flight-track log: one row per drone per lap in which it was heard.
+: "${SW_RID_FILE:=$SW_LOOT_DIR/remoteid.csv}"
 
 SW_SIGS="$(sw_load_signatures "$SW_HOME/signatures.db")"
 SW_IGNORE_SET="$(sw_load_ignore "$SW_IGNORE_FILE")"
@@ -109,6 +123,15 @@ sw_healthcheck() {
   if ! command -v btmon >/dev/null 2>&1; then
     _sw_health_warn "WARN: btmon missing — BLE detection OFF"; degraded=1
   fi
+  # Remote ID over WiFi (spec 2026-10-01 §7.1) captures with tcpdump on the recon radio: without either,
+  # no capture ever starts. (Recon itself stopping is the stale-DB WARN above.) SW_SYSFS_NET is a test seam.
+  if [ "${SW_REMOTE_ID:-0}" = 1 ]; then
+    if ! command -v tcpdump >/dev/null 2>&1; then
+      _sw_health_warn "WARN: tcpdump missing — Remote ID over WiFi OFF"; degraded=1
+    elif [ ! -e "${SW_SYSFS_NET:-/sys/class/net}/${SW_RID_IFACE:-wlan1mon}" ]; then
+      _sw_health_warn "WARN: ${SW_RID_IFACE:-wlan1mon} missing — Remote ID over WiFi OFF"; degraded=1
+    fi
+  fi
   # Every WiFi check reads a copy of the recon DB in ${SW_TMP_DIR:-/tmp}. When no copy can be made
   # (a full /tmp, say) the WiFi sweep and the evil-twin check skip every lap, so that is a WARN. On
   # the copy runs the evil-twin check's own probe: a DB that stops recording what the check needs (a
@@ -177,12 +200,17 @@ sw_scan_once() {
   # skipped this lap, and the health check says why.
   sw_recon_snapshot "$SW_RECON_DB" && snap="$REPLY"
   {
+    # The Remote ID capture window opens first, so it spans the whole lap, and in THIS shell, which must
+    # also be the one that collects it: it waits for the capture's PID (spec 2026-10-01 §6.1).
+    sw_rid_start "$now"
     # Evil twins are finished detections, so they skip the matcher (spec 2026-09-29 §6.3). They
     # come first: the check is one query, and its alert need not wait for the BLE scan.
     [ -n "$snap" ] && [ "${SW_EVIL_TWIN:-0}" = 1 ] && sw_evil_twin_scan "$snap" "$now"
     # The copy goes as soon as the WiFi sweep has read it, before the BLE scan.
     { if [ -n "$snap" ]; then sw_wifi_records_in "$snap"; sw_recon_drop "$snap"; fi; _sw_ble_records; } \
       | sw_match_stream "$SW_SIGS"
+    # Drones are finished detections too: collected once the BLE scan is over (spec 2026-10-01 §6.1)
+    sw_rid_collect "$now" "$SW_LOOT_DIR"
   } | {
         # Per-lap screen counters (spec 2026-09-23 §5). They live in this pipeline subshell,
         # so they reset every lap.
@@ -212,22 +240,23 @@ sw_scan_once() {
   [ -n "$snap" ] && sw_recon_drop "$snap"
 }
 
-# The scanner's temp files: BLE captures (sw_ble.XXXXXX), the BLE health state (sw_ble.state)
-# and the recon DB copies (sw_recon.XXXXXX, 5.6 MB each on a real Pager, and growing), all in RAM
+# The scanner's temp files: BLE captures (sw_ble.XXXXXX), the BLE health state (sw_ble.state), the
+# Remote ID captures and their health state (sw_rid.XXXXXX, sw_rid.state) and the recon DB copies
+# (sw_recon.XXXXXX, 5.6 MB each on a real Pager, and growing), all in RAM
 # on the Pager; and the ledger prune's temp copy (seen.db.sw-prune-tmp.XXXXXX), in the loot dir on flash,
 # where a leftover would outlive a reboot. Only sw_main runs this, before its own first prune.
-sw_clear_tmp() { rm -f "${SW_TMP_DIR:-/tmp}"/sw_ble.* "${SW_TMP_DIR:-/tmp}"/sw_recon.* "$SW_SEEN_FILE".sw-prune-tmp.?????? 2>/dev/null; }
+sw_clear_tmp() { rm -f "${SW_TMP_DIR:-/tmp}"/sw_ble.* "${SW_TMP_DIR:-/tmp}"/sw_recon.* "${SW_TMP_DIR:-/tmp}"/sw_rid.* "$SW_SEEN_FILE".sw-prune-tmp.?????? 2>/dev/null; }
 
-# On exit (the Pager's Stop, a Ctrl-C, a TERM): remove the BLE health state, any recon DB copy and
-# the ledger prune's temp copy (only this shell prunes, and a Stop can land between the prune's
-# mktemp and its mv), but leave BLE captures to the lap that owns them. A lap still running reads
-# its capture again for the health check, and it removes the capture itself on every path
-# (sw_stopped); the next start sweeps whatever a lap could not. Nothing is killed here: btmon and
-# hcitool each run under their own `timeout` (lib/ble.sh), so an orphan ends within seconds by
-# itself, while killing by NAME would also stop another program's btmon or hcitool (another
-# payload, an SSH session).
+# On exit (the Pager's Stop, a Ctrl-C, a TERM): remove the BLE and Remote ID health states, any recon
+# DB copy and the ledger prune's temp copy (only this shell prunes, and a Stop can land between the
+# prune's mktemp and its mv), but leave BLE and Remote ID captures to the lap that owns them. A lap
+# still running reads its capture again for the health check, and it removes the capture itself on
+# every path (sw_stopped); the next start sweeps whatever a lap could not. Nothing is killed here:
+# btmon, hcitool and tcpdump each run under their own `timeout` (lib/ble.sh, lib/remoteid.sh), so an
+# orphan ends within seconds by itself, while killing by NAME would also stop another program's
+# btmon, hcitool or tcpdump (another payload, an SSH session).
 sw_cleanup() {
-  rm -f "${SW_TMP_DIR:-/tmp}"/sw_ble.state "${SW_TMP_DIR:-/tmp}"/sw_recon.* "$SW_SEEN_FILE".sw-prune-tmp.?????? 2>/dev/null
+  rm -f "${SW_TMP_DIR:-/tmp}"/sw_ble.state "${SW_TMP_DIR:-/tmp}"/sw_rid.state "${SW_TMP_DIR:-/tmp}"/sw_recon.* "$SW_SEEN_FILE".sw-prune-tmp.?????? 2>/dev/null
   exit 0
 }
 
```

- [ ] **Step 4: Run the suite: all green, nothing stray.**

Run: `bash test/run.sh 2>&1 | tail -1` → `PASS=1105 FAIL=0`. Then `bash test/run.sh 2>&1 | grep -v -E '^(== |  FAIL|-----|PASS=)'` must print nothing (a stray line is a test that leaks output, or a missing function called somewhere).

- [ ] **Step 5: Commit.**

```bash
git add payloads/user/reconnaissance/squachwatch/payload.sh test/payload_test.sh test/perf_test.sh test/portability_test.sh
TZ=UTC git -c user.name=Ziggy -c user.email=79704039+therealziggy@users.noreply.github.com commit -F - <<'EOF'
payload: run the Remote ID capture each lap; settings and health

The lap opens the capture window first and collects it last, in the
same producer shell. New settings SW_REMOTE_ID (on), SW_RID_IFACE,
SW_RID_SECONDS, SW_RID_MAX_FRAMES, SW_RID_MAX_DRONES and SW_RID_FILE;
the health check warns when tcpdump or the interface is missing; the
start sweep and the exit trap handle the capture's files.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
git log -1 --format=%B | grep -cF 'Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>'
```
Expected last output: `1`.

---

### Task 7: Docs: README and the device findings

**Files:**
- `README.md`
- `docs/superpowers/P0-findings.md`

**Interfaces:**
- Consumes: everything above (docs only; no code changes, the count stays 1105).
- Produces: README (the lib list, the `SW_REMOTE_ID` setting, the `drone:` ignore lines, "What it detects", the
  test count, the status paragraph) and a `## Remote ID over WiFi (2026-10-01)` section in
  `docs/superpowers/P0-findings.md`.

- [ ] **Step 1: Apply the docs patch** (this task's only patch):

```diff
diff --git a/README.md b/README.md
index d80f4ae..16260ce 100644
--- a/README.md
+++ b/README.md
@@ -11,7 +11,7 @@ A port/homage of [SquachWatch-CYD](https://github.com/skizzophrenic/SquachWatch-
 **1. The always-on scanner** — a user payload at `payloads/user/reconnaissance/squachwatch/`:
 - `payload.sh` — the scan loop (launch it from the Pager's Payloads → reconnaissance menu; stop it with the Pager's cancel button).
 - `signatures.db` — the fingerprint list (see below).
-- `lib/` — `match.sh` (signature matching + `sw_sanitize_ident`), `wifi.sh` (recon.db read), `ble.sh` (btmon capture + parse), `alert.sh` (dedupe + emit + LED/haptics), `log.sh` (CSV loot log), `follow.sh` (tracker-following escalation), `ignore.sh` (your own devices), `snooze.sh` (AUTO SNOOZE), `eviltwin.sh` (the evil-twin check).
+- `lib/` — `match.sh` (signature matching + `sw_sanitize_ident`), `wifi.sh` (recon.db read), `ble.sh` (btmon capture + parse), `alert.sh` (dedupe + emit + LED/haptics), `log.sh` (CSV loot log), `follow.sh` (tracker-following escalation), `ignore.sh` (your own devices), `snooze.sh` (AUTO SNOOZE), `eviltwin.sh` (the evil-twin check), `remoteid.sh` (Remote ID over WiFi: the per-lap capture and its decoder).
 
 Each lap it reads the WiFi recon DB and does a short BLE scan, matches both against the signatures, de-dupes, and on a new high-confidence hit fires a full-screen alert + buzz + LED, at most once per *kind* of device per window (`SW_KIND_COOLDOWN` below — a flood of one kind interrupts once, not once per device). Every new sighting (any confidence) also writes a row to `/root/loot/squachwatch/detections.csv`, GPS-tagged when a fix is available.
 
@@ -25,7 +25,8 @@ Two settings keep a lap cheap and the loot file bounded:
 - `SW_KIND_COOLDOWN` (default 600): one full-screen alert + buzz per *kind* of device (e.g. "Flipper Zero") per window, and only for **high**-confidence detections (see the Signatures section below). A flood of new high-confidence devices of one kind, such as a room full of real Flippers or several Flock cameras appearing at once, buzzes once; a BLE Spam flood of name-only fake Flippers is **med** confidence and never buzzes at all — that's 0 times, not once. Every device still gets its CSV row (and a screen line, up to the per-lap cap; see `SW_LOG_PER_KIND` below). "Following you" alerts are exempt (they have AUTO SNOOZE). Your own devices (your Flipper, say) belong in `ignore.txt` below: left out, a device that stays near you re-alerts every window and spends the kind's one buzz on itself, so a stranger's device of the same kind arriving in that window would only be logged, not buzz. Set `0` to turn it off.
 - `SW_LOG_PER_KIND` (default 3): per lap, at most this many screen lines per kind **and confidence level** of device, then one `...and N more <label>` line, so a flood can't scroll everything else off the screen. A real high-confidence device (e.g. your actual Flipper) gets its own allowance separate from a same-kind med/low flood (e.g. a BLE Spam name-only flood), so it's never folded behind the fakes. Every device still gets its CSV row. `0` = no cap.
 - `SW_EVIL_TWIN` (default 1): the evil-twin check, ported from SquachWatch-CYD. An evil twin is a fake copy of a WiFi network, usually open (no password), set up to lure phones and laptops onto it. Each lap, a network name that is offered both open and password-protected within `SW_RECENCY_SECS` (600 s when that is 0) makes every open copy an evil twin: a full-screen alert naming the network (`Evil twin 'HomeNet'` and the copy's address), the buzz, the red LED, and a CSV row with category `evil_twin`. The usual cooldowns and screen cap apply. Names must match exactly, capitals included, and hidden networks are skipped. `0` turns the check off. Every copied name gets its own CSV row, even when one radio copies several names, and a screen line up to the usual `SW_LOG_PER_KIND` per lap (then "...and N more Evil twin"); several twins at once still buzz only once per `SW_KIND_COOLDOWN`, and that alert names the first one found, so the CSV is the full list. A plain address in `ignore.txt` never silences an evil twin, because the attacker chooses the address it broadcasts and could copy your router's or your Flipper's. To silence one open copy on purpose (your own Pager's open access point while you test, say), add a line `evil_twin:<its address>`; never add your own router's address that way, or a copy made under it would be silenced too. Limits: a copy that matches the real network's password setting is not caught, and that includes an open copy of an open café hotspot, the most common public-WiFi trick (CYD has the same limit); a copy of a hidden network is not caught either; both copies must be heard within the window; a nearby router switched from open to protected during its setup alerts once; and your own Pager, running its open access point under the name of a nearby protected network, is reported, because that is an evil twin. The health check cannot tell when a firmware update keeps the recon DB's columns but changes what their values mean.
-- `/root/loot/squachwatch/ignore.txt`: your own devices, and any companion's Tile or SmartTag you know about, one MAC per line (`#` comments allowed). They're skipped entirely, so your own Tile never alerts. It's read at launch. Put your own Flipper (or any other hacker tool you own) in here too: it isn't skipped by the kind cooldown the way it is by this file, so left out, it re-alerts every `SW_KIND_COOLDOWN` window and spends the kind's one buzz on itself — a stranger's Flipper arriving in that same window would then only be logged, never buzz. A plain address here never silences an evil twin; a line `evil_twin:<address>` silences that one evil twin and nothing else (see `SW_EVIL_TWIN` above).
+- `SW_REMOTE_ID` (default 1): listens for drones that broadcast **Remote ID** over WiFi, the public "licence plate" most drones must now send. Each lap a short, read-only capture on the recon radio decodes the drone's ID (usually its serial number), what it is, where it is (position, height, speed, heading) and **where its pilot is** (or where it took off), as a full-screen alert with the buzz and the magenta LED: `Drone '<ID>'`, then the airframe, height and speed, then the pilot's location, then its address. A second screen line repeats the height, speed and pilot. Every lap in which a drone is heard also adds a row to `remoteid.csv` in the loot folder: its flight track, with the Pager's own GPS fix when a GPS is attached. It decodes both WiFi forms of Remote ID (beacons, which DJI uses, and NAN frames) and Parrot's own beacon. One drone is one ID: a drone whose WiFi address changes stays one drone, with one alert per `SW_COOLDOWN`. The capture rides the recon scan's channel hopping instead of taking a radio, so it hears a drone only while the scan is on that drone's channel: a drone that stays around is caught within a few laps, one that passes in seconds may be missed. Remote ID is not signed, so a detection means "something here broadcasts drone Remote ID", and every position is what the broadcast claims. To silence your own drone, add `drone:<its ID>` to `ignore.txt` (a plain address never silences a drone, since its address can change). `0` turns it off. Also: `SW_RID_SECONDS` (the capture window, default 12), `SW_RID_MAX_FRAMES` (at most 1500 frames per lap; a beacon flood that reaches it gets one WARN per `SW_COOLDOWN`) and `SW_RID_MAX_DRONES` (at most 32 drones per lap, the strongest; the rest are counted on one line; `0` = no cap). `remoteid.csv` records where other people's drones and pilots were: keep it private.
+- `/root/loot/squachwatch/ignore.txt`: your own devices, and any companion's Tile or SmartTag you know about, one MAC per line (`#` comments allowed). They're skipped entirely, so your own Tile never alerts. It's read at launch. Put your own Flipper (or any other hacker tool you own) in here too: it isn't skipped by the kind cooldown the way it is by this file, so left out, it re-alerts every `SW_KIND_COOLDOWN` window and spends the kind's one buzz on itself — a stranger's Flipper arriving in that same window would then only be logged, never buzz. A plain address here never silences an evil twin or a drone: a line `evil_twin:<address>` silences that one evil twin and nothing else (see `SW_EVIL_TWIN` above), and a line `drone:<its ID>` silences that drone (or `drone:<address>` for one that sends no ID; see `SW_REMOTE_ID` above).
 
 If the recon DB stops updating, every sweep would return zero rows and look exactly like "all clear" — so the scanner detects that case explicitly and logs a warning instead, re-checking every `SW_HEALTH_EVERY` laps. The same goes for the evil-twin check: if the recon DB stops recording what that check reads (each network's security, signal, address or hidden flag, after a firmware change, say), it warns "evil-twin check is blind" instead of quietly finding nothing. And if no copy of the recon DB can be made (a full `/tmp`, say), which leaves WiFi detection with nothing to read, it warns "can't copy the recon DB". With the evil-twin check on, a recon DB that still reads as damaged on a second, fresh copy warns too (a single damaged copy is usually one taken while the DB was being written).
 
@@ -94,7 +95,7 @@ Add a detection by adding a line — no code changes. Lines starting with `#` ar
 - `ble_mfr|004c:12:25`: a whole-segment prefix, so `004c` = any Apple, `004c:12` = any Find My, and `004c:12:25` = separated Find My only.
 - `ble_uuid|fd5a` (the UUID as a service UUID or under service data), `ble_uuid|feaa:41` (service data whose first byte is `41`), and `ble_uuid|3100-3500` (a range).
 
-**What it detects** (83 active rules, 42 switched off): Flock Safety devices, Axon body cameras, Motorola and Genetec plate readers, Wyze/Hikvision/Verkada/Avigilon/Axis cameras and Amazon devices, Ring doorbells, Bluetooth card-skimmer modules, camera glasses (Ray-Ban Meta, Snap), Raven gunshot sensors, drones broadcasting Remote ID, personal trackers (Apple Find My and AirTags in setup mode, Samsung SmartTag, Tile, Google Find My) and hacker tools (Flipper Zero, WiFi Pineapple and Pager, ESP deauthers). Beyond the signatures, a behaviour check catches **evil twins**: an open copy of a nearby password-protected network (see `SW_EVIL_TWIN` above). Each family's comment in `signatures.db` names its source.
+**What it detects** (83 active rules, 42 switched off): Flock Safety devices, Axon body cameras, Motorola and Genetec plate readers, Wyze/Hikvision/Verkada/Avigilon/Axis cameras and Amazon devices, Ring doorbells, Bluetooth card-skimmer modules, camera glasses (Ray-Ban Meta, Snap), Raven gunshot sensors, drones broadcasting Remote ID (over WiFi they are decoded: the drone's ID, where it is and where its pilot is), personal trackers (Apple Find My and AirTags in setup mode, Samsung SmartTag, Tile, Google Find My) and hacker tools (Flipper Zero, WiFi Pineapple and Pager, ESP deauthers). Beyond the signatures, a behaviour check catches **evil twins**: an open copy of a nearby password-protected network (see `SW_EVIL_TWIN` above). Each family's comment in `signatures.db` names its source.
 
 ## Tests
 
@@ -104,7 +105,7 @@ A zero-dependency offline harness runs the whole detection engine on a normal Li
 bash test/run.sh
 ```
 
-Every detection test pairs a known-hit case with a clean case, and the load-bearing ones are proven to fail against a deliberately-broken variant (no vacuous passes). As of this writing: **874 assertions, all passing** (also as root).
+Every detection test pairs a known-hit case with a clean case, and the load-bearing ones are proven to fail against a deliberately-broken variant (no vacuous passes). As of this writing: **1105 assertions, all passing** (also as root).
 
 ## Status & roadmap
 
@@ -120,6 +121,8 @@ This is **core v1**: WiFi + name-based BLE detection, native alerts, offline-tes
 
 **Evil twin** (2026-09-29): each lap, a network name that is offered both open and password-protected reports every open copy as an evil twin (see `SW_EVIL_TWIN` above). This is SquachWatch-CYD's test without CYD's same-maker exemption. Replayed over months of a real Pager's recon history (about 4,600 access points), the check reports exactly one event, the one real evil twin in it (no other network name in that history was ever seen both open and protected, at any time); CYD's rule reports nothing there, because that copy used the real router's own address. On the Pager the new build's laps are about 0.7 s (3%) longer than the previous build's, measured side by side in the same place. The same work closed a hole in the WiFi reader: a network name holding a line break could forge a second, fake device (a fake Flock camera with a full alert, say). Line breaks are now removed from names before they are read. The final reviews then hardened it: a plain address in `ignore.txt` no longer silences an evil twin, every copied name gets its own CSV row, the health check also covers missing columns and a `/tmp` too full for the DB copy, and names are read byte by byte on the WiFi and Bluetooth paths, because a name ending in the first byte of a multi-byte character made the next device's line vanish (confirmed on the Pager). The cooldown ledger is read as bytes too, and the name cleaning also strips the Unicode control characters a UTF-8 locale used to count as control characters. A last review made the health check judge network names only when five or more networks are in view (the Pager now and then records an unnamed network as visible). Installed and checked on the Pager on 2026-10-01 (see `docs/superpowers/P0-findings.md`).
 
+**Remote ID over WiFi** (2026-10-01): drones that broadcast Remote ID in WiFi beacons (the standard ASD-STAN element `FA:0B:BC`/`0x0D`, which DJI uses, and Parrot's `90:3A:E6`) or in WiFi NAN frames are decoded: their ID, airframe, position, height, speed and heading, and the pilot's location, as a high-confidence alert with the buzz, plus a per-lap flight track in `remoteid.csv` (see `SW_REMOTE_ID` above). Bluetooth Remote ID stays a presence-only rule. The frame checks follow the SquachWatch-CYD fork's OpenDroneID reader, and the message layout and units are those of opendroneid-core-c, the reference library. Each lap a read-only `tcpdump` window on the recon radio (`-p`; it never reconfigures the radio) feeds one awk pass, so the recon database, the radio and the access point are left alone. That pass writes only numbers or hex, so a spoofed broadcast (Remote ID is not authenticated) cannot forge a field, and it decodes byte-identically on the Pager's BusyBox awk and the dev box's awk. The tests decode frames built by opendroneid-core-c itself (`tools/rid_fixtures/build.sh`, dev box only) and printed by the real tcpdump. Before any code was written, the whole plan was proven on a copy of the repository. The live test needs a real Remote ID drone; the official OpenDroneID OSM phone app is the second opinion.
+
 Deferred to their own phases:
 - **Drone Remote-ID over WiFi** — needs monitor-mode (`wlan1mon`) frame parsing, its own subsystem.
 - **An in-app skin** — the CYD look now ships as the optional theme above. Showing it only inside SquachWatch isn't possible with the Pager's theme system today, which applies one theme to the whole device.
diff --git a/docs/superpowers/P0-findings.md b/docs/superpowers/P0-findings.md
index 7b26682..dee9c2c 100644
--- a/docs/superpowers/P0-findings.md
+++ b/docs/superpowers/P0-findings.md
@@ -579,3 +579,33 @@ Checked on the Pager for the evil-twin design (`specs/2026-09-29-squachwatch-evi
 gave exactly one `Evil twin` row (high, wifi, the open copy's address, -24 dBm) and nothing for the protected
 radios; it is the only evil-twin row in the loot; the menu's Stop ended with `Payload completed`. Still to
 do: the run with a hostile-looking name (quotes, `%s`, `$(x)`), deferred by the user.
+
+## Remote ID over WiFi (2026-10-01)
+
+Checked on the Pager and in a planning spike for the Remote ID design
+(`specs/2026-10-01-squachwatch-remote-id-wifi-design.md`):
+
+- **tcpdump is stock:** tcpdump 4.99.5 and libpcap 1.10.5 are in the firmware image (`/rom/usr/bin/tcpdump`;
+  opkg `tcpdump 4.99.5-r1`), so every Pager has them. The recon radio `wlan1mon` is link type
+  `IEEE802_11_RADIO`; `-xx` prints the whole frame, starting with the radiotap header (read its length
+  from bytes 2-3, little endian, to find the 802.11 header; 56 bytes on this radio).
+- **Filter syntax:** this libpcap rejects `type mgt subtype action` ("can't parse filter expression:
+  syntax error"). The frame-control byte works: `wlan[0] & 0xfc = 0xd0`, and `wlan[]` offsets are taken
+  after the radiotap header (the compiled filter reads its length). A first probe that hid tcpdump's
+  stderr counted that error as "0 action frames": always compile a filter with `tcpdump -d` first.
+- **BPF cannot walk a beacon's element list** (it has no loops), so the kernel filter narrows the capture
+  to beacons plus action frames sent to NAN's address, and awk finds the Remote ID beacons.
+- **Rates and cost (the author's home, recon hopping):** 137 and 194 beacons in two 20 s samples (7 to 10 a
+  second); 1 action frame of any kind in 20 s. Hex-dumping every beacon for 20 s through an awk join:
+  2.03 s user + 0.35 s system CPU, about 12% of the CPU (how it splits between tcpdump and awk is a
+  Phase 0 measurement).
+- **tcpdump's own health lines:** `listening on <iface>, link-type ...` on start and `N packets captured`
+  on exit (TERM included; a KILL skips it), both on stderr.
+- **Radios:** phy1 = `wlan1mon` (monitor), hopped by `pineapd --recon` across 2.4 and 5 GHz; phy0 = `wlan0`
+  (station) plus `wlan0mon`, on the station's channel.
+- **awk:** mawk and BusyBox awk do not parse `0x..` numeric literals, so the decoder compares decimal
+  bytes. The full decode was byte-identical on both, over frames from opendroneid-core-c run through the
+  real tcpdump.
+- **The reference library** (opendroneid-core-c, commit `6484f26545d4f012682524e2d843fab0fbdc0b34`) needs
+  four files to build its frames (`opendroneid.c`, `opendroneid.h`, `wifi.c`, `odid_wifi.h`), and it
+  stamps the generating machine's uptime into every beacon's timestamp: the fixture generator zeroes it.
```

- [ ] **Step 2: Run the suite** (docs only, so nothing changes): `bash test/run.sh 2>&1 | tail -1` → `PASS=1105 FAIL=0`.

- [ ] **Step 3: Privacy check, then commit.** Every address in the added lines must be a made-up one or a protocol constant; the command must print only `privacy-grep exit=1`:

```bash
git diff | grep -n -E '^\+.*(/home/|([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})' | grep -v -E '80:E1:26|AA:BB:CC|FA:0B:BC|90:3A:E6|51:6F:9A'; echo "privacy-grep exit=$? (1 = clean)"
```

```bash
git add README.md docs/superpowers/P0-findings.md
TZ=UTC git -c user.name=Ziggy -c user.email=79704039+therealziggy@users.noreply.github.com commit -F - <<'EOF'
docs: Remote ID over WiFi in the README and the device findings

The README gains the SW_REMOTE_ID setting, the drone: ignore lines, the
new lib and a status paragraph; P0-findings records the device and
spike facts (stock tcpdump, the filter syntax, BPF's limit, the rates
and cost, awk's decimal literals, the reference library's uptime
stamp).

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
git log -1 --format=%B | grep -cF 'Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>'
```
Expected last output: `1`.

---

## After the tasks (the controller)

1. **Whole-branch review** by two independent reviewers: one general, and one adversarial (`feedback_security_fix_adversarial_review`), briefed to break the decoder with hostile frames end to end and to try a Stop at every step of `sw_rid_start` and `sw_rid_collect`. The hostile frames to try: a malformed frame before a good one; element and pack lengths that run past the frame; a pack count of 0 or 10, or a wrong message size; a NAN control byte that lies about its optional fields; IDs holding `|`, commas, quotes, line breaks, `%s`, `$(x)` or a zero byte; coordinates out of range; a network name holding `-1dBm signal` and a fake address. Fold in what survives. Then re-run the whole mutation matrix (every earlier mutant, not only the new fix's), in parallel copies of the repository (`git ls-files -z | xargs -0 cp --parents -t <dir>`), never in the checkout a reviewer is reading.
2. **Root run:** `unshare -r bash test/run.sh` ends `FAIL=0` too.
3. **On the Pager, only with the user's OK: Phase 0 first** (read only, nothing installed; the spec's §9). Use launcher-faithful runs (`swprobe.sh`: the launcher header, verbs stubbed), so the user's running SquachWatch is not disturbed. Check:
   - that the Pager's tcpdump prints the fixture pcaps exactly as the dev box does;
   - that `-p` really is read-only (the recon DB keeps growing during a capture);
   - the tcpdump-versus-awk cost per frame, and `SW_RID_MAX_FRAMES` set so a lap at the cap stays in budget;
   - that `SW_RID_SECONDS` ends the window before the BLE scan;
   - the channel coverage around channel 6 and on channel 149;
   - that awk's frame count equals tcpdump's `packets captured` after a TERM.

   Record the results in `P0-findings.md`.
4. **Install, only with the user's OK:** stage the files on the same file system, `mv` them into place and md5 every file (`payload.sh` and `lib/{remoteid,alert,ignore,log,follow}.sh`). Then run one launcher-faithful lap, A/B against the current build: it should arm with no WARN and no Remote ID status line, take the lap time Phase 0 predicted, and end on Stop with `Payload completed`.
5. **Live test, with a real Remote ID drone only.** SquachWatch only listens; no made-up drone is ever broadcast. Near a drone that broadcasts Remote ID over WiFi (a current DJI, say), expect:
   - one `Drone '…'` alert with the buzz, plus the detail line;
   - a `remoteid.csv` row per lap;
   - the official **OpenDroneID OSM** phone app showing the same ID, position and pilot.

   With no drone at hand, the live test waits.
6. **Push, only with the user's OK.** First run the pre-push privacy scan from the evil-twin round:
   - scp the Pager's recon DB into the session scratchpad and take every real address and name from it;
   - intersect them with `git log -p origin/main..main` (addresses normalised to 12 hex digits, names whole-word);
   - also search for local paths, metadata, trailers and clock, epoch and time-zone hints;
   - add positive controls (plant one real token and confirm the scan catches it);
   - delete the copy afterwards.

   Only when the scan finds nothing, and the pre-push hook passes (refs = only `main`), run `git push`.

## Self-review notes

- **Spec coverage:**
  - capture (§6.1) → Task 4, wired in Task 6;
  - decoder (§6.2) → Task 2;
  - records and `remoteid.csv` (§6.3, §6.5) → Task 3;
  - shared libraries (§6.4) → Tasks 3 and 5;
  - settings (§6.6), health (§7.1) and the lap → Task 6;
  - capture health (§7.2) and Stop/orphans (§7.3) → Task 4, and Task 6 for the payload-level Stop;
  - hostile input (§7.4) → Tasks 2 and 3, plus the adversarial review;
  - CPU (§7.5) → Task 6's budget, plus Phase 0;
  - fixtures and tests (§8) → Tasks 1–6;
  - Phase 0, deploy and live test (§9, §10) → the controller;
  - privacy (§11) → Tasks 1 and 7, plus the controller;
  - limits (§12) → the README (Task 7).
  
  Every transport (ASD-STAN, NAN, Parrot) has a fixture and a decode test.
- **Names:** the D-line contract is fixed once (above) and used identically by the decoder, `sw_rid_records`, `_sw_rid_line_ok` and `sw_test_rid_line`. The detection is `drone_rid|Drone|high|surveillance|wifi|MAC|ID|rssi|detail` in Tasks 3–6. The `SW_RID_*` names match across `payload.sh`, `lib/remoteid.sh` and the tests.
- **No placeholders:** every step is an exact patch or command with its expected output, measured in the dry run.
