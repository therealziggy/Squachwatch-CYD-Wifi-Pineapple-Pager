# P0 — On-Device Verification Findings

**Device:** WiFi Pineapple Pager, reached at **`172.16.52.1`** (USB-C ethernet `enx001337a9dd3e`, Hak5 OUI `00:13:37`). SSH via web shell (`root@pager:~#`). Verified 2026-09-21.

## Confirmed
- **recon.db** at `/root/recon/recon.db` (populated: 8181 type=8 APs, 9613 type=4 clients). The `/tmp`-copy read works.
- **`ssid` table schema** (order): `hash INT, wifi_device INT, scan INT, type INT, bssid TEXT, ssid BLOB, hidden INT, time INT, signal INT, freq INT, channel INT, encryption INT`. `wifi_device` table: `hash INT (PK), scan, mac TEXT, time, signal, freq, packets`.
  - `type` 8 = AP/beacon, 4 = client/probe (matches design).
  - **MAC/BSSID stored colonless 12-hex UPPERCASE** (`C1D2A17785EE`) — `sw_wifi_colonize` (12hex→colon) is correct.
  - **APs: `ssid.bssid == wifi_device.mac`. CLIENTS: `ssid.bssid` is EMPTY** — the device MAC is only in `wifi_device.mac`. → the WiFi query MUST join `wifi_device` and use `w.mac`. **FIXED** in `lib/wifi.sh`.
  - **`ssid.ssid` is a BLOB** → must `CAST(ssid AS TEXT)`. **FIXED**.
- **Tooling present:** `sqlite3`, `jq`, `hcitool`, `bluetoothctl`, **`btmon`** (→ Tier-3 raw-BLE-adv is buildable), plus GNU bash 5.2.32 (mipsel).
- **DuckyScript verbs present:** ALERT, LOG, RINGTONE, VIBRATE, LED, GPS_GET, START_SPINNER, STOP_SPINNER, PAYLOAD_GET_CONFIG, PAYLOAD_SET_CONFIG. **`TITLE` is MISSING** (not used by any production payload — harmless).
- **LED syntax:** `LED <COLOR> <0-255>` and `LED OFF` work; colors `B`, `M`, `Y`, `R` all return rc 0 (magenta/yellow accepted — `sw_hw_notify` is correct). Physical LEDs in sysfs: `/sys/class/leds/{a,b}-button-led`, `{up,down,left,right}-led-{red,green,blue}`, `buzzer`. Vibrator: `/sys/class/gpio/vibrator/value` (exists).
- **`oui.txt`** at `/lib/hak5/oui.txt` (+ `/rom/...`, ~1.2MB): **colon-form OUIs, TAB-separated, vendor in FIELD 2** (`00:00:00\tXEROX CORPORATION`). The client vendor lookup previously stripped colons + read field 3 (always "Unknown") — **FIXED** (colon key, `^`-anchored, `cut -f2`); added `SW_OUI_FILE` test seam + fixture.
- **Interfaces:** `wlan1mon`, `wlan0mon`, `wlan0` (monitor iface `wlan1mon` present for future Tier-4 drone work). BLE on `hci0` (scan works).
- **Space:** `/mmc` 3.5G total, ~3.1G free.
- **Live target for smoke:** a BLE device `80:E1:26:FA:D6:22 "MyFlipper"` is in range — OUI `80:E1:26` = Flipper Zero (user's own), matches `ble_oui|80:E1:26` → expected `hacker_flipper` detection.

## Gaps found & fixed (all with non-vacuous regression tests)
1. WiFi query: join `wifi_device` for `w.mac` (clients have empty bssid) + `CAST(ssid AS TEXT)` (BLOB). Fixture updated (empty client bssid makes the join load-bearing); reverting to `s.bssid` now fails `wifi_client_record`.
2. Client vendor lookup: real `oui.txt` is colon-form/TAB/field-2; reverting to the old form now fails `client_vendor_lookup`.

## Not blocking
- `_pineap RECON APS format=json` works (alt enumeration) but the engine uses the DB directly — no change.
- `od`/`cat -A` absent (BusyBox) — probe-only, irrelevant to payloads.

## Tier-3 gate: **GREEN** — `btmon` present, so AirTag/Find My/SmartTag/iBeacon/gunshot-UUID detection is buildable next.

## Additional device-only bugs found during on-device smoke (all fixed + guarded)
These passed locally (GNU userland) but failed on the Pager (BusyBox). A new
`test/portability_test.sh` statically guards #2 and #3 so they can't return.
1. **`mktemp` suffix:** BusyBox `mktemp` rejects a template with a suffix after `XXXXXX`
   (`mktemp /tmp/sw_recon.XXXXXX.db` → "Invalid argument"). The DB copy silently failed →
   `sw_wifi_records` returned nothing. Fixed: `mktemp /tmp/sw_recon.XXXXXX` (trailing X's).
2. **sqlite3 column separator:** the real sqlite3 CLI defaults to `|`-separated output, but
   the python test shim used TAB — so tab-parsing grabbed the whole row as the MAC (8 garbled
   fields). Fixed: build ONE column in SQL via `w.mac||char(9)||s.signal||char(9)||CAST(ssid AS TEXT)`
   with SSID last → separator-agnostic and immune to any bytes inside an SSID.
3. **BusyBox `tr` has no POSIX `[:class:]`:** `tr -d '[:cntrl:]'` deleted the literal letters
   c/n/t/r/l (not control chars), and `tr '[:lower:]' '[:upper:]'`/`_sw_lower` didn't fold case —
   so sanitize AND all case-insensitive matching (Pineapple SSID, Flipper-by-name, Flock names)
   silently failed on-device. Fixed: ranges `a-z`/`A-Z` and octal `\001-\037\177` for controls.

## On-device smoke — PASS (Pager 172.16.52.1, 2026-09-22)
- Live BLE scan detected the real Flipper `80:E1:26:FA:D6:22 "MyFlipper"` → `hacker_flipper`.
- WiFi path reads real recon.db (join+CAST, char(9)); positive control (temp sig for a real
  in-range OUI) fired; all sampled records well-formed (4 fields).
- sanitize strips `\t\r|` keeping letters (`abcdcontrol`); case-insensitive SSID + BLE-name
  matches fire (`MyPINEAPPLEnet`→pineapple, `My Flipper`→flipper).
- emit→log wrote a correct 10-column loot row (GPS "0,0,0,0" quoted as one cell); cooldown recorded.
- Real `sw_emit` fired a full-screen ALERT + ringtone + LED for the Flipper (rc 0, non-blocking).

## Permanent install + PERF BLOCKER (2026-09-22)

**Install:** payloads now permanently installed on the Pager (survives reboot):
`/root/payloads/user/reconnaissance/squachwatch/` (payload.sh +x, lib/, signatures.db) and
`/root/payloads/alerts/<event>/squachwatch_*/payload.sh` for all 4 events. Verified: the stock
Hak5 payloads (`example`, `deduplicate`, `handshake-ssid`, `hashtopolis-autocrack`) are **intact
alongside** ours — the layout is `alerts/<event>/<payload_name>/payload.sh`, so `scp -r` merges
and overwrites nothing. `bash -n` clean on-device for payload.sh + all 5 libs.

### 🔴 BLOCKER: a full WiFi sweep takes ~5 hours per lap (designed: ~15s)
Measured on-device (bash 5.2.32, N=200 synthetic rows, **positive control = 1 flock_alpr hit**,
so the matcher was provably live):

| stage | 200 rows | per row | implied 18,098 rows |
|---|---|---|---|
| A `sw_wifi_records` (colonize+sanitize) | 27s | 135 ms | ~41 min |
| B `sw_match_stream` (20 sigs) | 180s | 900 ms | ~4.5 h |
| **total** | **207s** | **1.04 s** | **~5.2 h** |

The full-sweep column is a linear model, but it is corroborated by a direct measurement: stage A
over the real DB **did not finish in 15 minutes** (`timeout 900` → exit 124), consistent with ~41 min.

**Cause = fork storm, not algorithm.** Every helper shells out via `printf | tr | sed | cut`:
- per row: `sw_wifi_colonize` (3 forks) + `sw_sanitize_ident` (2)
- per row in matching: `sw_oui` (3) + `_sw_lower` (2)
- **per row PER SIGNATURE**: the pattern is re-lowered/re-uppered inside the loop (~2 forks × 20 sigs = 40)

≈45 forks/row × 18,098 rows ≈ **800k forks per lap** on a 580 MHz MIPS CPU. This is ledger
follow-up #9 ("per-record pattern re-lowering perf") — measured, it is not a nice-to-have.

**Why the smoke test missed it:** the 2026-09-22 smoke sampled records and used a temporary
signature for an in-range OUI; it never timed a full sweep. Positive-control discipline caught
*correctness*, but nothing asserted a *latency budget*.

**Fix direction (not yet implemented):** make the hot path fork-free using bash builtins —
`${mac^^}` + slicing for colonize, `${s//|/}` + glob-class deletion for sanitize, `${s,,}` for
lowering — and **pre-lower each signature once at load time** instead of per row per signature.
`sw_sanitize_ident` is a security boundary (Finding-1 pipe evasion), so any rewrite needs the
adversarial review + the existing regression tests, not just a green suite.

### ✅ RESOLVED — verified on device 2026-09-22 (after the fork-free + recency fixes)

| | before | after |
|---|---|---|
| rows considered | 20,392 (all history) | 91 (600 s window) |
| `sw_wifi_records` | did not finish in 15 min | 1 s |
| full sweep (records + match) | ~18,700 s (~5.2 h, modelled) | **6 s** |

Same probe, same device, positive control `flock_hits=1` in both runs, so the matcher was
provably live and `detections=0` means "nothing hostile in range", not "matcher dead".
`stale_rc=1` (DB healthy) and `health_rc=0`. The CSV cooldown gate was exercised on-device
with a low-confidence detection: 3 emits inside the cooldown wrote 1 row, and an emit past
it wrote a second — with no ALERT or hardware notify on any of them.

**Bug this verification caught (offline tests could not):** `lib/wifi.sh` defaulted
`SW_RECENCY_SECS` with `:=0`, and `payload.sh` sources its libs *before* its own config
block — so the operational default of 600 never applied and the first on-device run swept
all 20,346 rows and timed out. `test/payload_test.sh` pins the window explicitly for its
pipeline assertions, which is precisely why it was blind to the real default. Fixed by
removing the lib-level `:=` (each use reads `${SW_RECENCY_SECS:-0}`) and adding
`payload_default_recency_window`, which sources payload.sh in a clean process and asserts
the default is 600.

## 🔴→✅ BLE path was silently blind: `hcitool lescan` loses its output on SIGTERM (2026-09-22)

Found while spiking Tier-3. `sw_ble_scan` ran `timeout 12 hcitool … lescan`, and `timeout`
sends **SIGTERM** by default. hcitool keeps its device lines in a stdio buffer and flushes
them only on a clean **SIGINT** exit, so on SIGTERM every device line was lost: the output
file held just the `LE Scan ...` header and the BLE path returned zero records.

Reproduced 2/2 with `btmon` running alongside as the positive control (btmon saw the Flipper
10–12 times per run in both cases):

| signal | btmon reports | lescan lines | Flipper via lescan |
|---|---|---|---|
| TERM | 26 / 31 | 1 / 1 (header only) | 0 / 0 |
| INT  | 27 / 26 | 28 / 27 | 10 / 12 |

It is **intermittent**, not total: the scanner did catch the Flipper once earlier the same
day. The most likely cause (inferred, not proven) is that a busier radio fills the buffer
and forces a flush before the kill.

Fix: `timeout -s INT -k 2`. The `-k 2` covers the new risk SIGINT introduces: an hcitool
that ignored SIGINT would otherwise hang the lap forever, so it is hard-killed 2s later.
The device's `timeout` is GNU and supports both flags (verified: a process ignoring INT died
at 3+2 = 5s, rc 137). After the fix, on-device `sw_ble_scan` returned 4–5 records including
the Flipper, 2/2.

Tests: `test/stubs/hcitool` now **models the device's behaviour** (lines only on SIGINT,
lost on SIGTERM), and two harness self-checks pin that model so the scan assertions can't
pass for the wrong reason. `ble_scan_bounded_if_int_ignored` guards the backstop and was
proven RED without `-k` (hung until the outer 10s guard, rc 124). `test/stubs/hciconfig` is
a no-op so the suite never touches the dev box's own Bluetooth adapter.

## Tier-3 on-device verification (2026-09-23)

Full suite green (`PASS=223 FAIL=0`) before deploy. Device: `root@172.16.52.1` (WiFi Pineapple
Pager, reachable). Payload deployed via `scp -r` to
`/root/payloads/user/reconnaissance/squachwatch`.

### Step 1 — Full suite green, then deploy: **PASS**
`bash test/run.sh` → `PASS=223 FAIL=0`. `scp -r` deploy succeeded. On-device syntax check:
no `SYNTAX FAIL` for `payload.sh` or any `lib/*.sh`. `ls lib/` →
`alert.sh ble.sh follow.sh ignore.sh log.sh match.sh wifi.sh` — exact match.

### Step 2 — Real lap's BLE records carry tokens (spec §9.3): **PASS**
```
ble|F9:C1:A3:83:F0:48||-95|mfr:004c:12:25
ble|D4:06:74:62:37:27|InfiniTime|-93|
ble|C5:AF:F3:28:7E:59||-99|mfr:004c:12:2
ble|80:E1:26:FA:D6:22|MyFlipper|-70|uuid:3082
records=4 seconds=14 state=ok
```
Flipper record matches exactly (`80:E1:26:FA:D6:22|MyFlipper|…|uuid:3082`). `state=ok`.
`seconds=14`, inside the expected 13–15 s window. `mfr:` and `uuid:` tokens both present.
No `sd:` token appeared in this particular 12 s window — no device advertising service data
was in range at that moment; this is environment-dependent (nothing in the code path
distinguishes token types), not treated as a failure.

### Step 3 — Matches against the real signatures (spec §9.1, §9.2): **PASS**
```
ble|F9:C1:A3:83:F0:48||-95|mfr:004c:12:25
ble|C5:AF:F3:28:7E:59||-101|mfr:004c:12:2
---
tracker_findmy|Apple Find My (separated)|med|tracker|ble|F9:C1:A3:83:F0:48||-95
hacker_flipper|Flipper Zero|high|attacker|ble|80:E1:26:FA:D6:22|MyFlipper|-70
```
A real separated Find My device (`mfr:004c:12:25`) was in range, so §9.1 ran (not NOT RUN).
The `mfr:004c:12:25` record produced exactly one `tracker_findmy|…|med|tracker` detection;
the `mfr:004c:12:2` record (near-owner prefix) produced none, confirming the whole-segment
prefix match in `lib/match.sh` (`ble_mfr`) rejects `004c:12:2` as a match for `004c:12:25`.
The Flipper produced `hacker_flipper|…|high|attacker`. All three assertions match the
brief exactly. (The ssh command's own exit code was 1 — the last BLE record processed by
`sw_match_stream` in that lap did not hit any signature, so the loop's final comparison was
false; this is normal shell behaviour, not a script defect, and doesn't affect the output
above.)

### Step 4 — Follow fires for real (spec §9.4): **PASS** — this buzzed the Pager (expected/approved)
```
--- csv
time,category,label,confidence,threat_class,radio,mac,ident,rssi,gps
1700000000,tracker_findmy,"Apple Find My (separated)",med,tracker,ble,F9:C1:A3:83:F0:48,"",-96,"0,0,0,0"
1700000000,hacker_flipper,"Flipper Zero",high,attacker,ble,80:E1:26:FA:D6:22,"MyFlipper",-70,"0,0,0,0"
1700000077,tracker_findmy_follow,"Apple Find My (separated) — following you 1+ min",high,tracker,ble,F9:C1:A3:83:F0:48,"",-97,"0,0,0,0"
--- track
F9:C1:A3:83:F0:48|tracker_findmy|1700000000|1700000117
```
Presence rows for both the Find My tracker and the Flipper, plus a `tracker_findmy_follow`
row with `high` confidence and label `"… — following you 1+ min"` after the tracker stayed
in range past `SW_FOLLOW_SECS=60`. Matches the brief exactly.
`/tmp/sw_verify_loot` left on the device for the user to inspect, per the brief.

### Step 5 — Scan-failure warning fires on the device (spec §9.5): **FAIL** (partial — see detail)
```
records=[ble|F9:C1:A3:83:F0:48||-97|mfr:004c:12:25
ble|D4:06:74:62:37:27|InfiniTime|-91|] state=scan_failed
```
`state=scan_failed` matched the expected value — the bogus `hci9` interface correctly drove
`sw_btmon_health` down the failure path (no `Status: Success` completion for
`LE Set Scan Enable` on that interface). **But `records` was NOT empty** as the brief
expected (`records=[]`): 2 real records were captured anyway. Root cause (inferred, not
proven, not fixed — this task changes no code): `btmon` is a system-wide HCI monitor, not
scoped to the interface named on the `hcitool` command line; `bluetoothd -n` is running on
the device (confirmed via `ps w`) and `hci0` shows live RX traffic independent of this
command (`hciconfig -a hci0` RX byte counter incrementing between two back-to-back calls a
few seconds apart), consistent with BlueZ's own background LE scanning. So a bogus interface
correctly fails the scan-enable command and correctly flips the health state, but does not
stop ambient advertisements already arriving via `hci0` from showing up in the same capture.
This is a real deviation from the brief's expected output, reported as-is per the honesty
rule — not adjusted, not silently accepted.
On-screen `WARN: BLE scan failed to start` — **unconfirmed (needs a user glance)**, could not
be verified from this session; the state-file check above is the only verification done.

### Step 6 — No leftovers: **PASS** (after ruling out a self-match artifact)
The literal command from the brief (grep pattern and echo fallback both inside one
`ssh … '…'` argument) returned a spurious hit: `ps w`'s own listing of the invoking
`ash -c "…"` process shows that process's full command-line text, which includes the
literal fallback string `"no stray btmon/hcitool"` — the grep pattern then matched its own
command line, not a real process. A clean re-check (plain `ps w`, filtered locally,
no fallback text in the remote command) showed no `btmon`/`hcitool` process on the device.
`ls /tmp/sw_ble.*` found nothing (no leftover capture files; no `sw_ble.state` remained
either, having been removed by Step 5's own cleanup — both are acceptable per the brief).
`/tmp/sw_verify_loot/` still present (`detections.csv`, `seen.db`, `track.db`), left in place
for the user to inspect.

### Step 7 — Real-capture fixture replacement (spec §9.6): **NOT RUN**
Gated per the task instructions — not run, and nothing was advertised from this desktop's
Bluetooth adapter. Pending the user's explicit decision (the controller will ask). Fixture
values for SmartTag / Tile / Google Find My remain spec-inferred.

### Summary
S1 PASS · S2 PASS · S3 PASS · S4 PASS (buzzed the Pager, as approved) · S5 FAIL (state
detection correct; ambient records leaked through a bogus-interface scan, as detailed above)
· S6 PASS · S7 NOT RUN (gated). No code was changed by this task.

## 🔴→✅ Launched from the Pager UI, the scanner loaded NOTHING (2026-09-23)

**Symptom** (first launch from Payloads → reconnaissance; every earlier on-device run was
`bash payload.sh` over SSH): the screen repeated `WARN: no signatures loaded — nothing will
match` + `SquachWatch DEGRADED` about once a minute.

**Root cause:** the Pager does not run a payload in place. `/pineapple/pineapple` writes a
COPY to `/tmp/payload-<random>.sh` with a header injected after line 1 (`PATH="$PATH:/mmc/bin:…"`
+ `. /lib/hak5/commands.sh` + `. /lib/hak5/pineapple.sh` + `. /lib/pineapple/payloads.sh`),
starts it with an environment of ONLY `PAYLOAD_HOME=<real dir>/` + `_PAYLOAD_HOME` (trailing
slash; no PATH, no HOME), cds into the real dir (`/mmc/root/…`) and runs `/bin/bash` on the copy.
`SW_HOME` came from `BASH_SOURCE` → `/tmp` → all 8 `. lib/*.sh` failed (non-fatal in bash) → no
functions, empty `SW_SIGS`, every lap a silent no-op ("command not found" + the 3 s sleep). That
is why the WARN came every ~60 s (20 laps) instead of the ~7 min real laps take. The WARN also
UNDER-reported: `sw_wifi_stale_db` was itself missing (rc 127 reads as "not stale"), so it said
"no signatures" while ALL detection was off.

**Fix:** `SW_HOME="${PAYLOAD_HOME:-<BASH_SOURCE dir>}"` (trailing `/` stripped), and a lib that
won't load now does `LOG red "… NOT running"` + `exit 1` instead of looping blind. Guarded by
`payload_launcher_copy_loads_libs_and_sigs` + 3 fail-loud asserts in `test/payload_test.sh`, each
half mutation-proven. **Verified on device** using the launcher's own header bytes: old copy →
`SW_HOME=/tmp`, 0 signatures; new copy → the real dir, 27 signatures; copy with no home → red
ERROR + exit 1.

**Device facts:** `PAYLOAD_HOME=%s`, `_PAYLOAD_HOME=%s`, `payload-*.sh` and `PAYLOAD EXITED: %d`
are format strings in the launcher binary, so the variable is deliberate (whether Hak5 documents
it as stable is unconfirmed). Every tool we call resolves to the same binary under the launcher's
bare environment as under SSH (GNU `timeout` 9.3 included). `LOG` from ANY shell, SSH included,
prints on the running payload's screen, so shadow it in probes. `LOG red` exists in all 3
installed themes (`color_palette` in `theme.json`). Hak5's stock `hashtopolis-autocrack` finds
its folder the same `BASH_SOURCE` way, so it likely has this bug too.
**Rule: an on-device check must launch through the Pager UI (or a launcher-faithful copy), not
`bash payload.sh`.**

## Noise control on-device (2026-09-26, Pager launched from the menu)

Branch `squachwatch-noise-control` at `0a4ba65` (426/426 tests, as the normal user AND as root via `unshare -r`).

| Step | Expected | Observed |
|---|---|---|
| Deploy | device == HEAD | `DEVICE == HEAD (0a4ba65)` for all 10 payload files |
| `local -A` in a pipeline group (first use of associative arrays on the device) | `x=2 y=1` | `x=2 y=1` (bash 5.2.32) |
| Silent dry-run lap (real radio, verbs shadowed, temp loot) | libs + defaults load, one lap | 27 sigs, `600/3/-85`, health rc 0, lap 18 s; the real Flipper → 1 alert; a -95 dBm Find My logged only |
| Menu relaunch | green "armed" | armed (user) |
| Real Flipper alone | exactly one popup | T+0 popup, `80:E1:26:FA:D6:22` at -66 |
| After 10 min | (per-device cooldown ends) | T+10 min popup, the SAME real Flipper at -61. An own device re-alerts every `SW_COOLDOWN`, which is why the README says to list your own devices in `ignore.txt` |
| BLE Spam at T+10.5 min | no popup (the flood is med; the real Flipper is in cooldown) | **0 popups** (was 9 in one lap on 09-23); 16 fake-Flipper + 3 fake-AirTag-setup rows, all `med`. Only 2 `high` rows in the whole run, both the real Flipper |
| Follow floor | the weak Find My never starts a follow clock | `F7:B4:B5:93:C5:ED` (Apple Find My, separated) was present every lap at -93..-96 dBm for 13+ min and is **absent** from `/tmp/sw_track.db`. Control: the 3 strong fake AirTag-setup trackers ARE in it. No follow alert fired |
| Ledger pruning | oldest entry < ~1200 s after 20+ laps; pre-run entries gone | 25 lines, oldest 778 s old. The file was rewritten (mode 0600 from mktemp+mv); entries from 09-23/24 were dropped at startup. The CSV still keeps its 19 older rows (never discarded) |

Not verifiable from logs: the `...and N more` screen line (LOG output goes to the screen only). It is covered by the offline tests and the real-capture fixture.
Device clock: `/dev/rtc0` present and ntpd running, so the backward-clock case (fail-open) is unlikely but handled.

## CYD signature port on-device (2026-09-26)

**Matcher cost on the Pager** (MT7628AN, bash 5.2.32, measured in a bare `env -i` shell like the launcher's):

| Measurement | Result |
|---|---|
| Each rule, per record, before the index | ~2.15 ms (plus ~23 ms fixed per record): 200 records took 16.0 s with 27 rules and 56.6 s with 124 |
| Handing the signature TEXT to a bash function (`f(){ local r="$1" s="$2"; [ "${C-}" = "$s" ]…; }`, 200 calls) | 1 byte: 1.4 ms/call · 6,153 bytes (the 83 shipped rules): 28.9 ms/call · 9,493 bytes (all 125): 43.2 ms/call, i.e. ~4.5 µs per byte per call |

The second row was a surprise: `sw_match_stream` passed the whole text to `sw_match_record` for every record,
so ~40% of each record's time went on copying the rule file. It is why the first indexed build got 23% slower
with the 42 weak rules switched on, although the index gave each record the same candidates. Fix: the stream
prepares once and matches each record through `_sw_match_prepared`, which takes only the record.
Guarded by `perf_text_size_independent` (dev box: 600 never-matching padding rules made a 500-record stream
about 3x slower before, ~1.15x after).

**Benchmark** (`tools/bench_match.sh`, 100 WiFi + 100 BLE records from a fixed seed, two runs each):

| Code | Rules | Time |
|---|---|---|
| before the port (the installed 2026-09-24 build) | 27 | 16.30 s / 16.31 s |
| index only (first build) | 83 | 14.46 s / 14.18 s / 14.43 s |
| index only (first build), every `#off` rule enabled | 125 | 17.75 s / 17.71 s / 17.55 s |
| index + prepare-once (shipped) | 83 | 8.94 s / 9.08 s |
| index + prepare-once, every `#off` rule enabled | 125 | 9.02 s / 8.98 s |

So the shipped matcher is ~1.8x faster than before the port while checking 3x the rules, and switching the
weak rules on costs under 1%.

**Install + verify (2026-09-26):**

| Step | Expected | Observed |
|---|---|---|
| Backup | a full copy of the running install, outside `/root/payloads` (so the UI does not list it twice) | `/root/squachwatch-backup-2026-09-26/`, identical to the install (checksums) |
| Install | device == branch head | all 10 payload files' `sha256sum` equal to the repository's; modes restored (payload.sh 755, the rest 644) |
| Launcher-faithful silent lap (the launcher's own header injected after line 1, only `PAYLOAD_HOME` in the environment, screen/sound/LED verbs shadowed, temp loot) | real folder found, 83 signatures, index loaded, healthy | `SW_HOME` = the real `/mmc/root/...` folder, 83 signatures, `_sw_candidates` present, health rc 0, lap 19 s, 0 stderr lines; one far separated Find My (-97 dBm) logged at med (no alert) |
| Benchmark of the installed copy | as the shipped row above | 8.84 s (83 rules), 9.05 s (125 rules) |

To roll back: `rm -rf /root/payloads/user/reconnaissance/squachwatch && cp -a /root/squachwatch-backup-2026-09-26 /root/payloads/user/reconnaissance/squachwatch`.
Still to do by hand: a launch from the Pager's menu with the user present.
