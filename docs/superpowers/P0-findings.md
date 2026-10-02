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

## Stopping the payload (2026-09-27)

**First sign: the exit handler did not run.** In a real menu run (launched, then stopped about a minute later)
the launcher logged `[PAYLOAD] Payload process <pid> killed` and then `Error in payload …: exited with -1`
(Go's code for a process that ended by a signal; had `trap sw_cleanup EXIT INT TERM` run, the payload would
have exited 0), and `/tmp/sw_ble.state`, which `sw_cleanup` deletes, was still there 16 minutes later.

**Measured with a probe payload launched from the menu** (it logged every signal it received, with
microsecond timestamps, while a child subshell heartbeated like a lap): Stop sends **SIGINT to the payload's
main shell only, then SIGKILL about 1 s later** (SIGINT 11.13 s after launch, last heartbeat 11.96 s, no EXIT
trap). The child got no signal at all and ran on until its own 20 s bound. The payload runs in the launcher's
own process group (pgrp 1, sid 1), with only SIGQUIT ignored (`SigIgn` 0x4). The launcher logs
`Payload completed` for an exit 0 and `exited with -1` for a death by signal.

**What that meant before `e8af38a`:**
- The INT trap waited behind the foreground lap, so the SIGKILL usually came first and nothing was cleaned up
  (the trap won only when Stop landed near the end of a lap or pause; one real stop was logged `Payload completed`).
- The lap that was running went on in its subshells for up to ~15 s after Stop, and could still alert, buzz,
  log and write CSV rows. On-device what-if: after a main-shell-only SIGKILL mid-scan, the lap ran on for ~11 s
  and fired ALERT + VIBRATE and wrote 2 CSV rows.
- A relaunch within that window swept the running lap's capture, and that lap then put a false
  "WARN: BLE scan failed to start" on the new run's screen (reproduced offline in review).
- `killall hcitool btmon` in `sw_cleanup` (when the trap did run: Ctrl-C or TERM over SSH) stopped every
  btmon/hcitool on the device, including another payload's own monitor.

**Fixes:**
- `1820d3d` and its review follow-ups (`845b482`): nothing is found or killed by name
  (`no_kill_by_name_in_payloads`, which also rejects `pidof`/`pgrep`); `sw_cleanup` only removes the temp
  files; `sw_main` also clears them at startup (`sw_clear_tmp`, checked name-agnostically by
  `sweep_clears_every_temp_file_a_lap_leaves`); the recon DB copy lives in `${SW_TMP_DIR:-/tmp}` next to the
  BLE capture. The helpers' own `timeout`s end an orphaned helper (`ble_orphans_end_by_themselves`).
- `e8af38a`: the lap and the pause between laps run in the background under `wait`, so the trap runs at once
  on the SIGINT and the payload exits 0 inside the grace. `sw_stopped` (true once the main shell is gone,
  counting a not-yet-reaped zombie as gone; `sw_main` sets the PID it checks, so an inherited
  `SW_MAIN_PID` cannot silence a run) makes a lap still running go quiet: it never starts a scan or resets
  the adapter, drops its capture without reporting scan health (checked after the scan and after the
  parse), and emits nothing more, including the "following you" escalation of the detection it was on.
  The exit trap removes the health state and DB copies but leaves BLE captures to the lap that owns them.
  The startup sweep stays as the backstop. An independent review of the first version found the zombie
  window, the trap deleting a live lap's capture, the inherited `SW_MAIN_PID` and the unguarded follow
  escalation; each is fixed with a test. Stand-in commands kill a stand-in main shell at the exact moment
  under test, so the tests do not depend on timing. Each part is mutation-proven
  (`stop_trap_runs_within_the_grace`, `stop_during_pause_runs_trap_within_the_grace`,
  `stopped_lap_emits_nothing`, `follow_stopped_mid_report_no_escalation`, `ble_stopped_payload_starts_no_scan`,
  `ble_stopped_mid_scan_*`, `ble_stopped_mid_parse_*`, `ble_stopped_zombie_main_counts_as_gone`,
  `cleanup_leaves_a_live_laps_capture`, `main_ignores_inherited_main_pid`).
- The health check (review item M5 of `e8af38a`): at startup and every `SW_HEALTH_EVERY` laps it copies
  the recon DB and counts its rows twice, and it ran in the foreground, so a Stop there waited for the step
  under way. On the Pager (33.6k rows, 2026-09-27) the check took 0.43–0.56 s, its longest step 0.24–0.36 s,
  well inside the grace. But each count reads every row, and the DB grew from about 20k rows (09-22) to
  33.6k (09-27), so a step would in time outlast the grace; the SIGKILL would then leave the DB copy in
  RAM until the next start. The check now runs in the background under `wait` as well. A check left running
  by a Stop gets a wrong answer: the exit trap removes its DB copy, the sqlite3 CLI then creates an empty
  file for the second count, and a healthy DB reads as "not updating" (reproduced offline with a fresh DB,
  and on the Pager against its real DB). Two fixes, each enough for that case: every WARN of the check goes
  through `sw_stopped` (`_sw_health_warn`; `health_warns_only_through_the_stop_guard` rejects a bare `LOG`
  in the check), and `sw_wifi_stale_db` reads a copy that vanished or came back empty as "unknown", not
  "stale" (`stale_db_vanished_copy_*`). A test-local `sqlite3` holds the check's first count for 3 s on a
  chosen call, so the Stop lands inside the check, and each run's log is read only after the check left
  running has ended. Each part is mutation-proven: either check back in the foreground fails its own
  `stop_during_{startup,periodic}_health_check_*` tests; the guard ignoring `sw_stopped` fails
  `health_warn_silent_once_stopped` (the Stop tests alone cannot show it: there the copy is always gone
  before the check decides, so the empty-copy check already answers "unknown", and the guard is what
  silences a WARN that needs no copy, such as "btmon missing"); the empty-copy check removed, or moved
  between the two counts, fails `stale_db_vanished_copy_not_flagged`; with both removed, the Stop tests'
  "reports nothing" fail as well. The ledger prune stays in the foreground: it is builtins apart from
  `date`, `mktemp` and `mv`, so the trap never waits long for it.
- The first moments and the ledger prune (the two optional follow-ups from the M5 review). With no trap,
  bash drops a SIGINT that lands during a foreground command (it takes the command's normal exit to mean
  the command handled it) or, inside a command substitution, dies from it; neither is a clean exit. On the
  Pager the libs and signatures took 251–272 ms to load and the startup steps before the old trap another
  96–112 ms, and a Stop in there was either ignored until the SIGKILL (it even printed "armed" after the
  Stop) or ended the run by signal (`exited with -1`). The top of `payload.sh` now sets a plain `exit 0`
  trap (nothing has been started or written yet; skipped when a test sources the file, or a Ctrl-C of the
  suite would end it with status 0), and `sw_main` replaces it with the full trap as its first step. The
  ledger prune's temp copy now has a name no one would type, `seen.db.sw-prune-tmp.XXXXXX` (the old
  `seen.db.XXXXXX` also matched a hand-made `seen.db.backup`, and a first try, `seen.db.prune.XXXXXX`, a
  `seen.db.prune.before`). The exit trap removes it (a Stop can land between the prune's `mktemp` and `mv`,
  and only the main shell prunes), and so does the startup sweep (a crash or a power cut; the loot dir is
  on flash). And the prune's two loops no longer `continue`: bash drops a trapped SIGINT that lands while a
  loop continues or breaks (bash 5.2, x86: 53 of 300 Stops lost in a `|| continue` loop, 0 of 300 written
  with `if`; the real prune over a 20,000-line expired ledger lost 3 of 150 before and 0 of 150 after), and
  `main_shell_code_never_continues_or_breaks` keeps both out of every function the main shell runs. Test-local
  `touch` and `mktemp` hold a startup step for 0.3 s so the Stop lands inside it, and a test-local `grep`
  holds the signature load (`stop_while_loading_*` for INT and TERM, `stop_in_first_moments_*`,
  `stop_in_prune_*`, the last also checking that the ledger and look-alike files survive); the
  force-killed-run sweep test seeds a stranded temp copy (`main_clears_killed_runs_ledger_temp`,
  `main_clear_keeps_the_ledger_and_look_alikes`), and `payload_sourced_sets_no_signal_trap` pins the
  test-source guard. Two independent reviews, one of them adversarial on data safety (1,650 randomized
  Stops: the ledger always ended untouched or exactly pruned, `detections.csv` never changed), found nothing
  blocking; their follow-ups are folded in.

**On-device probes of the fixes** (staging copies, the launcher's own header, the screen/sound/LED verbs
shadowed, separate temp and loot dirs; the installed payload, the real loot and the real `/tmp` were untouched):

| Case | Before (`3cc7432`) | After (`1820d3d` / `e8af38a`) |
|---|---|---|
| TERM to the payload while ANOTHER program's `btmon` runs | the other `btmon` was killed | the other `btmon` kept running |
| SIGKILL to the whole process group mid-scan, then a relaunch | the capture, the stale state and a stranded DB copy all still there | all three cleared at startup; our orphaned helpers ended by their own `timeout` within 12 s |
| The measured Stop (SIGINT, SIGKILL 1 s later) in the middle of lap 2's scan (lap 1 healthy) | — | exit 0 **104 ms** after SIGINT, no SIGKILL needed; **0** verb calls after SIGINT; the lap's helpers ended 10 s later; no temp files |
| The measured Stop during the pause between laps | — | exit 0 **45 ms** after SIGINT; 0 verb calls after; no temp files |
| `timeout -s INT … hcitool lescan` from a background job, like the lap's | — | rc 124: stopped by the INT (the scan is switched off cleanly), not by the `-k` KILL |

Menu launch of the `845b482` build: armed, the real Flipper on the first lap (one CSV row), the old
`sw_ble.state` cleared at startup, and the stop logged `Payload completed` with `/tmp` left clean.

The health-check fix on the Pager, the same way (no BLE scan, so the adapter of the payload running at
the time was never touched; the check's first count held 3 s by a wrapper around the real `sqlite3`):

| Case | Before (`e8af38a`) | After |
|---|---|---|
| The measured Stop inside the startup check | still alive 1 s after the SIGINT: SIGKILLed, the DB copy left in the temp dir | exit 0 **89 ms** after SIGINT; 0 verb calls after; no temp files |
| The measured Stop inside a periodic check (`SW_HEALTH_EVERY=1`) | SIGKILLed after 1 s, the DB copy left behind | exit 0 **56 ms** after SIGINT; 0 verb calls after; no temp files |
| The same Stop with either fix alone (the WARN guard, or the empty-copy check) | — | nothing after the Stop |
| The same Stop with neither fix | — | a false "WARN: recon DB not updating" after the Stop (the real DB was fresh) |
| The Stop inside the real startup check (nothing held) | exit 0 100 ms after SIGINT | exit 0 133 ms after SIGINT |

The last row is one run each: both exit well inside the grace, and the figure depends on where in the
check the Stop lands, so it does not mean the new code is slower.

The first moments and the ledger prune on the Pager, the same way, measured on the final code of this fix
(each step held 0.3 s by a wrapper around the real BusyBox tool, so every "after" figure includes that hold):

| Case | Before (`7375687`) | After |
|---|---|---|
| The measured Stop while the libs and signatures load | died by the SIGINT (`exited with -1`) | exit 0 **317 ms** after SIGINT; 0 verb calls after |
| The measured Stop during the startup `touch` of the ledger | ignored: still alive 1 s later, SIGKILLed, and "armed" was printed after the Stop | exit 0 **331 ms** after SIGINT; 0 verb calls after |
| The measured Stop between the startup prune's `mktemp` and `mv` (an expired ledger line, next to `seen.db.backup`, `seen.db.bak`, `seen.db.1234567`, `seen.db.prune.before`) | died by the SIGINT; its temp copy `seen.db.XXXXXX` left in the loot dir | exit 0 **314 ms** after SIGINT; the loot dir exactly as before (ledger unchanged, look-alikes kept) |
| A stranded `seen.db.sw-prune-tmp.XXXXXX` from an earlier crash, then a start and a Stop | — | swept at startup; the ledger (pruned as usual, by the rewritten loops) and the look-alikes kept; exit 0 152 ms after SIGINT |

**Remaining:**
- After a Stop mid-lap, the lap that goes on holds the payload's stdout/stderr until it winds down (up to
  one scan). The launcher removed its `payload_log` receiver 18 s after the probe's stop, when the probe's
  heartbeating child finally exited, so it waits for end-of-file there. Whether a relaunch inside that window
  works has not been tried (SIGKILLed laps on the older builds held it the same way).
- After a Stop mid-scan, the lap's `hcitool` runs out its `timeout` (up to 12 s) and then switches LE scanning
  off. A relaunch inside that window could lose part of its first scan with no WARN (reasoned from BlueZ, not
  measured).
- A power cut or crash in the middle of a follow/snooze rewrite can strand a tiny `sw_track.db.XXXXXX` /
  `sw_snooze.db.XXXXXX` in `/tmp`. These are not swept (a lap orphaned by a Stop may still be writing them
  when the next run starts), but `/tmp` is RAM, so a reboot clears them, and a Stop does not leave them,
  because the lap finishes the detection it is on before going quiet. The ledger prune's temp copy, which
  lives on flash, is removed by the exit trap and swept at startup (Fixes, last bullet). A temp copy
  under the OLD name (`seen.db.XXXXXX`, from builds before this fix) is never swept, on purpose: it can't
  be told apart from a hand-made `seen.db.backup`. The Pager had none on 2026-09-28.
- Bash can still drop a Stop that lands in the last instant of a command substitution the main shell runs
  (x86, bash 5.2: 37 of 300 lost in a loop of `x=$(dirname …)`, 26 of 300 with `$(date +%s)`, 0 of 300 with
  the same command run directly). At startup those are the signature and ignore-list loads, `$(dirname …)`
  and `$(date +%s)`, and in a prune rewrite `$(mktemp …)`. Such a Stop is ignored until the SIGKILL (logged
  `exited with -1`); nothing is lost, and the next start sweeps any leftover. Removing the startup ones means
  loading the signatures and the ignore list without a command substitution; `$(mktemp …)` would remain.
  Nothing before the launcher's own header (sourced ahead of line 2) can be covered at all.
- Two runs at once (a menu run plus a `bash payload.sh` over SSH) can remove each other's in-flight ledger
  temp copy: that run's prune then fails with one "can't prune" WARN and leaves the ledger as it was. The
  menu itself runs one payload at a time.
- A Stop in the very instant the health check reports can still let that one status line through (seen on
  x86, also at `7375687`): a check left running asks `sw_stopped` while the exit trap is still removing
  files, so the main shell still counts as alive. Never an alert or a buzz. A possible fix: `sw_cleanup`
  first writes a stop flag with a builtin (`: > "${SW_TMP_DIR:-/tmp}/sw_stop.$$"`), `sw_stopped` also checks
  for it, and `sw_clear_tmp` sweeps it; a check-then-act can only narrow that window, not close it.
- Scope: SquachWatch no longer kills other programs' Bluetooth tools, but its per-lap
  `hciconfig down/reset/up` still interrupts their scans.

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
- `recon.db` uses a rollback journal (`PRAGMA journal_mode` = `delete`, header bytes 18 and 19 = 1, no
  `-wal`/`-shm` next to it). A read-only open of a WAL-mode copy would leave `-wal` and `-shm` files
  behind; `sw_recon_drop` removes them anyway, in case a firmware update switches the mode.
- bash's `read`, in a UTF-8 locale, swallows the line break after a byte that starts a multi-byte
  character, so the next line merges into the current one. The Pager's bash 5.2.32 (musl) does this by
  default, with no locale set (checked 2026-09-29); `LC_ALL=C`, even as `local LC_ALL=C` in a function,
  stops it, on the Pager and on the dev box. Before the fix a name ending in such a byte hid the next
  device's line; every loop whose lines end with a free-text name (the WiFi reader, the twin check, the
  btmon parser) now reads in the C locale.
- The test stand-in for sqlite3 now prints values as the Pager's CLI does: raw bytes, cut at the first
  NUL. The old one failed a whole query on a name that is not UTF-8 (the author's history holds one such
  access-point name, five counting names that clients probed for) and printed NUL bytes the real CLI never prints.
- Replaying the author's whole recon history (`tools/replay_evil_twin.sh`: 1,286 minutes that hold
  beacon data, 600 s window) finds exactly one open copy, which fired in 7 minutes. It is the Pager's own
  open access point, run on its first day under the name and address of the owner's router. CYD's rule
  finds nothing in the same history, because its same-maker exemption covers that copy. Ignoring
  capitals would add 22 false finds: a venue's open guest network on 23 radios next to a protected
  network with the same name in other capitals. A replay is a lower bound (each row keeps only its last
  sighting in a session), so the whole history was also counted directly: exactly one visible, named
  network was ever seen both open and protected, in any session, and it is that same one. Re-run with the
  final code and the byte-faithful stand-in (1,336 minutes by then): the same single copy.
- The second review round (2026-09-30): in the C locale bash's `[[:cntrl:]]` covers only ASCII control
  characters and DEL, where the Pager's default (UTF-8) locale also counted the C1 controls and U+2028/U+2029;
  the name cleaning now strips those explicitly. GNU grep in a UTF-8 locale hides a line holding a byte that is
  not UTF-8 ("binary file matches"; the Pager's BusyBox grep does not), and bash's `[[ =~ ]]` does not match
  such a line in a UTF-8 locale: since an evil twin's cooldown key holds its name, the ledger is read as bytes.
  A damaged copy of the recon DB ("malformed" and the like) is usually one taken during a write, so the health
  check looks at a fresh copy before warning that the DB is damaged.
- The third review (2026-10-01): the Pager now and then records a blank-named beacon as not hidden: 12 of
  the 7,117 visible beacon rows in the author's history, from 4 radios, never more than 3 in one window.
  Replaying the second round's rule (visible rows, none named = blind) over the window of each of the 1,366
  minutes with beacon data found no false WARN, but 43 of those windows held a single visible row, so one
  such row alone in a quiet spot would trip it. Names are now judged only with five or more visible rows
  (937 of the 1,366 windows). Left as they are (minor): the name cleaning strips the C1 controls and
  U+2028/U+2029 in one pass, so a doubled sequence (`c2 c2 85 85`) leaves one behind (not a regression:
  `c829e01` stripped none; whether the Pager's screen breaks a line on them is untested); the tests of
  names that are not UTF-8 only bite when the suite runs in a UTF-8 locale; the damaged-DB WARN needs
  `SW_EVIL_TWIN=1`; a Stop that lands on the first `...and N more` line still lets the other kinds'
  summary lines print. "Usually one taken during a write" above is reasoned: on the install day none of
  20 plain copies of the live DB was damaged (table below).

**Evil-twin install + verify (2026-10-01, `1a31508`):**

| Step | Expected | Observed |
|---|---|---|
| Install | device == branch head | the 7 changed files swapped in by rename (payload.sh 755, the rest 644); all 11 payload files' md5 equal to the repository's |
| Launcher-faithful silent run, health check every lap (the launcher's header after line 1, only `PAYLOAD_HOME` in the environment, screen/sound/LED verbs shadowed, temp loot) | armed, no WARN, no evil twin at home | armed, 0 WARN, 0 stderr lines, no evil twin; the owner's Flipper gave one alert and one CSV row, then only its log line; lap 23.7 s |
| The same at the default health cadence | as above | laps 22.2–22.6 s |
| Lap time side by side, same place, alternating runs (the previous build run from RAM, not installed) | the new checks cost well under a second | `c829e01` 20.7–21.5 s (mean 21.0), `1a31508` 20.9–22.5 s (mean 21.7): about +0.7 s a lap, every change of this branch included. The laps are longer than in the tables above because of the place (the previous build takes as long there), not the code |
| Menu-style Stop (SIGINT to the main shell only) | exit 0 well inside the launcher's 1 s | exit 0 in 31–94 ms over 6 runs; no temp files or processes left, `/tmp` clean |
| What the Pager's sqlite3 CLI prints for a damaged copy (the health check looks for these words) | "not a database", "malformed" | a junk file: `Error: in prepare, file is not a database (26)`; a torn copy: `Error: in prepare, database disk image is malformed (11)` |
| Plain copies of the live recon DB while recon writes | rarely damaged | 0 of 20 (0.5 s apart) |

**Live test (2026-10-01, the user, launched from the menu):** an open copy of the user's own protected network
gave exactly one `Evil twin` row (high, wifi, the open copy's address, -24 dBm) and nothing for the protected
radios; it is the only evil-twin row in the loot; the menu's Stop ended with `Payload completed`. Still to
do: the run with a hostile-looking name (quotes, `%s`, `$(x)`), deferred by the user.

## Remote ID over WiFi (2026-10-01)

Checked on the Pager and in a planning spike for the Remote ID design
(`specs/2026-10-01-squachwatch-remote-id-wifi-design.md`):

- **tcpdump is stock:** tcpdump 4.99.5 and libpcap 1.10.5 are in the firmware image (`/rom/usr/bin/tcpdump`;
  opkg `tcpdump 4.99.5-r1`), so every Pager has them. The recon radio `wlan1mon` is link type
  `IEEE802_11_RADIO`; `-xx` prints the whole frame, starting with the radiotap header (read its length
  from bytes 2-3, little endian, to find the 802.11 header; 56 bytes on this radio).
- **Filter syntax:** this libpcap rejects `type mgt subtype action` ("can't parse filter expression:
  syntax error"). The frame-control byte works: `wlan[0] & 0xfc = 0xd0`, and `wlan[]` offsets are taken
  after the radiotap header (the compiled filter reads its length). A first probe that hid tcpdump's
  stderr counted that error as "0 action frames": always compile a filter with `tcpdump -d` first.
- **BPF cannot walk a beacon's element list** (it has no loops), so the kernel filter narrows the capture
  to beacons plus action frames sent to NAN's address, and awk finds the Remote ID beacons.
- **Rates and cost (the author's home, recon hopping):** 137 and 194 beacons in two 20 s samples (7 to 10 a
  second); 1 action frame of any kind in 20 s. Hex-dumping every beacon for 20 s through an awk join:
  2.03 s user + 0.35 s system CPU, about 12% of the CPU (Phase 0 split it between tcpdump and awk: check 3
  below).
- **tcpdump's own health lines:** `listening on <iface>, link-type ...` on start; on exit (TERM included; a
  KILL skips them, and so does a TERM that finds tcpdump stuck writing to the pipe: Phase 0, check 6)
  `N packets captured` (`1 packet captured` for exactly one), `N packets received by filter` and
  `N packets dropped by kernel`, all on stderr. SquachWatch reads the first, the captured count and the drop
  count (the wording, from tcpdump's source, was seen on the Pager in Phase 0).
- **Radios:** phy1 = `wlan1mon` (monitor), hopped by `pineapd --recon` across 2.4 and 5 GHz; phy0 = `wlan0`
  (station) plus `wlan0mon`, on the station's channel.
- **awk:** mawk and BusyBox awk do not parse `0x..` numeric literals, so the decoder compares decimal
  bytes. The full decode was byte-identical on both, over frames from opendroneid-core-c run through the
  real tcpdump.
- **The reference library** (opendroneid-core-c, commit `6484f26545d4f012682524e2d843fab0fbdc0b34`) needs
  four files to build its frames (`opendroneid.c`, `opendroneid.h`, `wifi.c`, `odid_wifi.h`), and it
  stamps the generating machine's uptime into every beacon's timestamp: the fixture generator zeroes it.

### Phase 0 on the Pager (2026-10-02)

The spec's six Phase 0 checks (§9) and the ones the reviews added, read only. Everything ran from a temporary
folder in `/tmp` holding the branch's code (`205d8a2`) and the installed build (`1a31508`), each copy
md5-checked against its commit; nothing was installed and nothing under `/root` was written; the screen, sound
and LED commands were stubbed; every capture was `tcpdump -p`; and only processes this session had started were
signalled, found by their PIDs. The user's own SquachWatch was not running, the installed build's 11 files kept
their md5 from start to end, and at the end the temporary folder was gone and no process was left. One place
(the author's home), so every rate below is that place's. Each result says whether it was **measured** on the
Pager, **modelled** (worked out from measured numbers) or **reasoned**.

1. **Text parity — holds (measured).** The Pager's tcpdump 4.99.5 prints all 12 fixture pcaps byte for byte as
   committed (md5), as the dev box's 4.99.4 does.
2. **Read only, really — holds (measured).** A 60 s `-p` capture on `wlan1mon` heard 439 beacons (7.3 a second),
   none dropped by the kernel. Recon kept writing as usual: 53 recon rows were seen in the minute inside the
   capture, against 53 to 65 in the minutes around it, and its newest row stayed 10 to 14 s old (one capture
   minute: no change beyond normal variation, not a precise rate). The interface's flags, its type (monitor) and
   the channel hopping never changed; promiscuous mode was already on before any capture (the system sets it at
   boot), so `-p` changes nothing either way.
3. **Cost — measured; 1500 frames a lap broke the budget.** Per ordinary beacon (mean 405 bytes with its 56-byte
   radiotap header): tcpdump 1.76 ms, the decoder 13.4 to 13.7 ms (its 46 ms start-up left out); in the real
   pipeline 16.6 ms, the two adding up within about 5%. So about 88% is the decoder, and a 12 s window at home
   (62 to 83 frames) costs 1.0 to 1.4 s of CPU, 8 to 12% of it. `nice` works: nice 10 on `timeout`, tcpdump and
   awk in every window, and a nice-10 busy loop got 1/9.4 of a nice-0 one's CPU (the scheduler's weights predict
   9.3). Crafted frames (built only by repeating or editing committed fixture text; the decoder alone): the
   reference Remote ID beacon 22.9 ms, the NAN frame 23.5 ms, the six-message `full` frame 34.2 ms, a dense one
   (nine messages, a new address each) 52.6 to 55.8 ms, a 2 KB frame 179 ms, a 4 KB frame 430 to 503 ms, and that
   4 KB frame cut to 1024 bytes 59 ms. A lap of 1500 ordinary beacons would take about 23 s of CPU (modelled),
   against the spec's "about 5 s at the cap". **User decision:** `SW_RID_MAX_FRAMES` 300 (about 4.6 s at the cap
   for ordinary beacons of this size, modelled; 3.6 to 4.8 times the frames a window heard here) and `-s 1024`
   (check 7: it cut no beacon here). No frame cap holds 5 s against crafted Remote ID frames (300 dense ones would
   take about 16 s, modelled). What bounds such a lap is the window, since the decoder only gets the CPU the lap
   leaves it (nice 10), and the 64 KB pipe after it (about 0.6 s of decoding for ordinary beacons, about 3.6 s for
   dense Remote ID frames, modelled); frames beyond that wait in the kernel and are lost, and that lap is now
   partly blind with its WARN (check 6). With a `drone:` line in ignore.txt, the drone cap's ranking adds about 10
   to 13% to the decoder on the dev box's BusyBox awk, so about 5.1 s at the cap (modelled; to be measured on the
   Pager, below).
4. **Lap time — holds at home (measured; the Bluetooth overlap modelled).** Old build against new, alternating,
   laps after "armed" only. With the Bluetooth scan stubbed to nothing, a new lap is bound by the window: 12 s
   plus a 0.22 to 0.45 s tail (the TERM, tcpdump's exit, awk's end, the collect), and +1.25 to +1.37 s of CPU a
   lap. With the Bluetooth scan modelled as a 13 s idle stage where the real scan sits (no adapter touched):
   **+0.40 and +0.50 s a lap** (the budget is 1 s) and +1.7 s of CPU; the WiFi sweep ran 0.37 to 0.42 s slower,
   as the decoder at nice 10 still takes up to about 10% of a busy CPU. Reasoned from the stage times, not
   measured against a real scan: the window ends 12.2 to 12.45 s into the lap, while a real Bluetooth scan starts
   after the sweep (2.3 to 3.4 s in) and lasts at least 13 s, so it ends about 3 s or more after the window.
   `SW_RID_SECONDS=12` holds. Every run: no stderr line, Stop → exit 0 in 31 to 111 ms (10 runs), no process or
   temp file left.
5. **Channel coverage — measured.** 180 s, 6129 frames (their radiotap channel only), with `iw` sampled 237
   times alongside: recon hops over 36 channels across 2.4 and 5 GHz,
   each visited about every 7.6 s for about 0.21 s, never twice in a row. Within two channels of 6 (4 to 8):
   about 14% of the time; on channel 149: about 2 to 3%. **Catch rate (reasoned from these, not measured with a
   drone):** a drone on channel 6 that sends its Remote ID every T seconds is heard in one visit with a chance of
   about min(1, 0.21/T). Ten times a second: about 2 frames a visit, nearly every 12 s window. Once a second:
   about 21% a visit, 31% a window and 85% within a minute. Plus some reception on the neighbouring channels (not
   measured); check 9's blinks add about 1.9% of deaf time.
6. **Capture parity — holds normally; the summary was lost whenever tcpdump was stuck on the pipe (measured).**
   In normal windows awk's frame count equals tcpdump's `packets captured` (5 of 5 windows of 62 to 83 frames;
   also 439 of 439 in 60 s and 626 of 626 in 90 s), the summary printed after the TERM every time, in the wording
   SquachWatch reads. But when the decoder was 64 KB or more behind at the window's end (two busy loops at nice
   0; or awk paused so that the pipe filled, in both such runs), tcpdump, asleep writing to the pipe, ended at
   once at the TERM with `Unable to write output: Interrupted system call` and **no summary**; on SIGPIPE,
   `Broken pipe`, exit status 14, no summary either. The frame it was writing was cut, and awk still counted it,
   so this never gives a false "frames short". But with no `packets captured` line the frame-cap and lost-frame
   checks could not run, so the lap read `ok`. **Fixed** (fix round 4): a capture that started on radiotap and
   printed no summary is `lost`, the yellow "partly blind" WARN.
7. **Kernel drops, frame sizes, signal, FCS — hold (measured).** 0 packets dropped by the kernel in every summary
   printed (up to 6129 frames in 180 s). Beacon sizes, radiotap header included (439 beacons from 39
   transmitters): smallest 182 bytes, median 414, 90th percentile 450, largest 526; none over 1024 (so `-s 1024`
   would have cut nothing), 2.3% over 512 (one transmitter). Every radiotap header carries a dBm signal (439 of
   439 beacons, 2833 of 2833 frames of all kinds), and tcpdump prints it first on the header line. The FCS flag
   was never set (3272 frames), so the decoder's 4 bytes of slack are never used on this radio. The bad-FCS flag
   was never set either: a frame that fails its checksum should not reach the decoder as one more ID (inferred
   from how mac80211 hands such frames up; no positive control is possible passively).
8. **Awk parity — holds (measured).** The decoder's output (md5) is identical on the Pager's BusyBox awk, the dev
   box's mawk and the dev box's BusyBox awk for all 65 fixture files (12 + 53 hostile) and 6 whole streams at
   drone caps 32, 0 and 1 (28 different outputs, none empty).
9. **`/sys/class/net/wlan1mon` — there while recon runs, but the interface blinks (measured).** It exists
   throughout (so the startup check passes), but goes down for about 0.57 s every 30.6 s (three periods of 551 to
   587 ms in 90 s; it is not re-created). A capture already running across a blink is unaffected (626 of 626
   frames, its summary printed); one that starts inside one fails (`That device is not up`): 1 of 30 test starts
   and 1 of about 31 probe laps, so about 1.9% of laps, a false "Remote ID over WiFi OFF" about every 17
   minutes. **Fixed** (fix round 4): one failed lap is only noted; the OFF line needs two in a row.

**Still to do on the Pager, with the user:**

- Install, then the launcher-faithful silent run (armed, no WARN, lap time as in check 4).
- The hostile-ID probe with the real `LOG` and `ALERT`: whether quotes, `%s`, `$(x)` and `\` in a drone ID show as
  plain text.
- A real menu Stop during a capture window.
- The window against a real Bluetooth scan (Phase 0 modelled the scan as a 13 s idle stage).
- The drone cap's ranking with a `drone:` line in ignore.txt during a flood lap: its cost on the Pager (modelled
  in check 3 at about +10 to 13%, about 5.1 s at the cap).
- The live test, with a real Remote ID drone only (SquachWatch only listens: no made-up drone is ever broadcast
  to test it), with the OpenDroneID OSM phone app as the second opinion: the real catch rate, and how many
  different Basic IDs a real drone sends from one address in a lap (more than two, a session ID that changes
  say, would mean the owner can never silence it).
