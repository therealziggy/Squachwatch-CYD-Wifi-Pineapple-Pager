# SquachWatch-Pager — Design Spec

**Date:** 2026-09-21
**Status:** Approved (design), pending implementation plan
**Author:** ziggy + Claude
**Working name:** SquachWatch-Pager (a port/homage of [SquachWatch-CYD](https://github.com/skizzophrenic/SquachWatch-CYD) by skizzophrenic, targeting the Hak5 WiFi Pineapple Pager)

---

## 1. Purpose

Re-create SquachWatch — an always-on detector that alerts you to the wireless
signatures of surveillance devices, personal trackers, and hacker/attack tools
around you — as native WiFi Pineapple Pager payloads.

**End goal: full parity** with SquachWatch's ~20 detection categories, delivered
in effort tiers. **UI:** native Pager widgets first; a framebuffer "vaporwave"
skin (mascot, gradients, gauges) is a later phase. **Verification:** built and
tested against a real Pager over SSH.

### Why this is feasible (established during research)
- The Pager's PineAP engine continuously maintains a SQLite recon database at
  `/root/recon/recon.db` (tables incl. `ssid`, `wifi_device`, `scan`; `ssid.type`
  4=probe/client, 5=probe-response, 8=beacon/AP; `encryption` = packed bitmask).
  A payload enumerates all APs/clients from it — no custom sniffer needed.
- Bluetooth works out of the box: `hcitool lescan`, `bluetoothctl`, `hci0`
  (no extra packages for name-based BLE).
- A writable raw framebuffer exists at `/dev/fb0` (222x480, RGB565, LE) for the
  later custom-UI phase.
- The platform ships an OUI vendor DB at `/lib/hak5/oui.txt`.
- Multiple community payloads already implement pieces (Flock_Detect,
  flipper_detector, find_hackers, SkimmerScanner, device_profiler,
  recondb_reporting) and are reused/adapted.

### Non-goals
- Not reproducing SquachWatch's exact TFT rendering code (different platform).
- Framebuffer aesthetic is out of scope for v1 (Phase 6).
- Drone Remote-ID is explicitly a stretch (Phase 5), not core v1.

---

## 2. Architecture (Approach A)

One long-running **user payload** ("the scanner") watches both radios against a
single **signature file**, plus a handful of tiny **native alert payloads** that
piggyback the Pager's free event triggers. All detectors share a bash library and
the signature file, so each unit stays small and independently testable. The
engine is factored so single-category payloads can be spun out later (upstream PRs).

```
squachwatch-pager/
├── payloads/
│   ├── user/reconnaissance/squachwatch/
│   │   ├── payload.sh                 # the always-on scan loop
│   │   ├── signatures.db              # the fingerprint list (Section 3)
│   │   └── lib/
│   │       ├── wifi.sh                # recon.db read + WiFi matching
│   │       ├── ble.sh                 # hcitool/btmon read + BLE matching
│   │       ├── match.sh               # signature loading + match dispatch
│   │       ├── alert.sh               # ALERT/LOG/RINGTONE/VIBRATE/LED + throttle
│   │       └── log.sh                 # CSV + human log + GPS tag
│   └── alerts/
│       ├── deauth_flood_detected/squachwatch_deauth/payload.sh
│       ├── handshake_captured/squachwatch_handshake/payload.sh
│       ├── pineapple_client_connected/squachwatch_client/payload.sh
│       └── pineapple_auth_captured/squachwatch_auth/payload.sh
├── tools/     # local dev: fixture builders, (later) RGB565 converter
├── test/      # local harness + fixtures (sample recon.db, BLE dumps)
└── README.md
```

Trade-off considered and rejected: a **suite of independent per-category payloads**
(Approach B) is easier to PR individually but is not SquachWatch — it lacks the
single always-on "is anything around me" monitor. We keep B's modularity *inside*
A via the shared lib.

---

## 3. Signature model

One pipe-delimited line per fingerprint (grep-friendly, avoids fragile bash):

```
match_type|pattern|category|label|confidence|threat_class
```

- `match_type`: `wifi_oui` · `wifi_ssid_sub` · `ble_name_sub` · `ble_oui` ·
  `ble_company` · `ble_uuid`
- `pattern`: e.g. `70:C9:4E`, `pineapple`, `Penguin-`, `0x09C8`, a service UUID
- `category` / `label`: e.g. `flock_alpr` / `Flock Falcon camera`
- `confidence`: `high|med|low`
- `threat_class`: `surveillance|tracker|attacker` (drives alert color/behavior)

Matching paths:
- `wifi_*` matches run against rows read from `recon.db`.
- `ble_name_sub`/`ble_oui` run against `hcitool lescan` output (MAC + local name).
- `ble_company`/`ble_uuid` require **raw BLE advertisement** parsing
  (manufacturer/company ID + service UUIDs are NOT in `lescan` output) — gated on
  the Phase-0 spike (Section 6).

---

## 4. Detection catalog (full parity, tiered by effort)

### Tier 1 — Reusable (adapt a community payload, fold into engine)
| Category | Method | Source |
|---|---|---|
| Flock ALPR cameras / plate readers | `wifi_oui` + `ble_name` | Flock_Detect (+69-entry OUI list) |
| Flipper Zero | `ble_name`/`ble_oui` | flipper_detector, find_hackers |
| WiFi Pineapple / Pager | `wifi_ssid_sub` | find_hackers |
| Deauth floods | native `deauth_flood_detected` | repo example |
| Evil-twin / rogue AP / karma | recon.db SSID-vs-BSSID logic | find_hackers |
| Card skimmers | `ble_name` + signatures | SkimmerScanner |
| Client device profiling (OUI→vendor) | native `client_connected` | device_profiler |

### Tier 2 — New but easy (add signature lines; flows through name/OUI path)
Ring doorbells (`wifi_oui`), Meta/Ray-Ban glasses (`ble_name`/`wifi_oui`),
Tile trackers (`ble_name`/`ble_uuid`), Axon body cams (`wifi_oui`/`ble_name`).
Work = compiling verified fingerprints (SquachWatch's open lists + public OUI data).

### Tier 3 — New + needs raw BLE adv parsing (gated on Phase-0 spike)
Apple AirTag / Find My, Samsung SmartTag, Google Find My Network, iBeacons,
ShotSpotter/Raven gunshot sensors (service UUID). These broadcast no name →
`ble_company`/`ble_uuid`. Ship iff Phase-0 confirms `btmon`/raw-adv tooling;
otherwise marked "documented, pending tooling."

### Tier 4 — New + hard (own subsystem, stretch)
Drone Remote-ID over WiFi: vendor-specific IEs / NAN action frames, NOT in
recon.db — needs live monitor-mode capture on `wlan1mon` (tcpdump/tshark parse).
Scoped as **Phase 5 stretch**, isolated so it cannot block the other 19 categories.

---

## 5. Scan engine, alerting, and event payloads

### Scan loop (`while true`; `trap` cleanup → kill hcitool, flush state, `exit 0`)
1. **WiFi sweep (cheap, every lap):** `cp /root/recon/recon.db /tmp/sw.db` and
   query the copy — sidesteps the "database is locked" error when the Recon GUI is
   open (recondb_reporting pattern). Pull APs (`type=8`) + clients (`type=4`),
   derive OUI from BSSID/MAC, match `wifi_oui` + `wifi_ssid_sub`. `_pineap RECON
   APS format=json` is a fallback if Phase-0 shows it's cleaner.
2. **BLE sweep (~15s, dominates wall-clock):** reset `hci0`, `hcitool lescan
   --duplicates` for names/MACs → `ble_name_sub`/`ble_oui`; if Phase-0 green, a
   parallel `btmon`/raw capture feeds `ble_company`/`ble_uuid`.
3. **Match → dedupe → alert.** Seen-cache keyed by `MAC+category` with a re-alert
   cooldown (default ~10 min), persisted to `/root/loot/squachwatch/seen.db` so a
   restart doesn't re-spam. (Bash associative arrays are OK on this firmware —
   find_hackers/device_profiler use them in production.)

### Alerting (native widgets, from `threat_class`)
- Color: surveillance→magenta, tracker→yellow, attacker→cyan (`LOG <color>`).
- New + high confidence: full-screen `ALERT` + `RINGTONE` + `VIBRATE` + `LED` flash.
- Repeat / low confidence: colored `LOG` line only.
- Global rate-limit so a crowded room summarizes instead of machine-gunning ALERTs.
- Log: CSV + human log to `/root/loot/squachwatch/` (time, MAC, category, label,
  confidence, RSSI, SSID); GPS-tag via `GPS_GET` when a fix exists.

### Config
Cadence, BLE window, cooldown, armed `threat_class`es — via `PAYLOAD_SET_CONFIG`
/vars; tunable without editing code.

### The 4 native alert payloads (Tier 1 free events)
Each tiny, sources `alert.sh`, emits a class-appropriate alert + log line:
- `deauth` → attacker
- `handshake` → informational
- `client_connected` → OUI-profile (reuse device_profiler) AND cross-check client
  MAC against signatures (known tracker/camera associating)
- `auth_captured` → attacker

### Robustness rules (hard-won from community payloads)
Keep bash simple; avoid `grep -P`; always `exit 0`; rely on the built-in cancel
button; `trap` cleanup for hcitool/temp/console. Correct interfaces: BLE `hci0`,
WiFi monitor `wlan1mon` (NOT `wlan1`). `TEXT_PICKER` reportedly non-functional in
current firmware — avoid depending on it.

---

## 6. Verification (Phase 0, over SSH) — before any detection code

Produce a short "confirmed facts" doc the build relies on:
- `recon.db` real schema; `/tmp`-copy beats the lock; is `_pineap RECON APS
  format=json` available and what shape?
- BLE: `hciconfig`/`hcitool`/`bluetoothctl` present; `hci0` up; `lescan` works.
  **Tier-3 SPIKE:** is `btmon` or raw-adv available (company-ID/UUID)? → go/no-go
  on AirTag-class detection.
- Which DuckyScript verbs exist as executables (`ALERT`, `LOG`+colors, `RINGTONE`,
  `VIBRATE`, `LED` syntax, `PROMPT`, `PAYLOAD_*_CONFIG`); vibrator/LED sysfs paths;
  `oui.txt` format; `sqlite3`/`jq` presence (opkg if missing); `wlan1mon` (P5);
  free space in `/root`.

---

## 7. Testing strategy

The engine is split so its logic is testable off-device.
- **Local harness** (dev box): craft fixture `recon.db` files + captured
  `hcitool`/`btmon` output; run `match.sh`/`wifi.sh`/`ble.sh` against them; assert
  exact detections.
- **Positive controls, MANDATORY:** every detection test pairs a known-hit fixture
  that MUST fire with a clean fixture that MUST stay silent, and the matcher is
  proven to FAIL when the signature is removed (no vacuous greens). On-device,
  where a real Flock camera isn't available, the positive control is a temporary
  signature matching a device we DO have (e.g. own phone OUI), fired then removed.
- **On-device smoke** after each phase: launch on the real Pager, trigger what's
  triggerable, confirm alert + log + haptic.

---

## 8. Phases (each: build → local tests w/ positive controls → on-device smoke → commit)

- **P0** on-device recon + Tier-3 spike
- **P1** skeleton + signature engine + WiFi path + Tier-1 WiFi (Flock OUI,
  Pineapple, evil-twin) + local harness
- **P2** BLE name path + Tier-1 BLE (Flock BLE, Flipper, skimmers) + the 4 native
  alert payloads
- **P3** Tier-2 signature expansion (Ring, glasses, Tile, body cams)
- **P4** Tier-3 raw-adv (AirTag/Find My/SmartTag/Google/iBeacon/gunshot) — if P0 green
- **P5** (stretch) drone Remote-ID monitor-mode subsystem
- **P6** (later) framebuffer vaporwave skin + mascot

---

## 9. Open risks / notes
- Tier-3 hinges entirely on Phase-0 raw-adv finding. If negative, ~5 categories
  become "pending tooling" (name-based BLE + all WiFi still ship).
- Tier-4 (drone Remote-ID) is the only category needing monitor-mode frame parsing;
  isolated by design.
- Long-running bash loop must be crash-resistant and must not wedge `hci0`.
- recon.db copy cost per lap is acceptable at low cadence; re-evaluate if large.
- Legitimate/ethical use: this is a defensive surveillance-awareness tool; payloads
  carry authorized-use disclaimers, consistent with the Hak5 repo.

## 10. Attribution
Port/homage of SquachWatch-CYD (skizzophrenic). Reuses patterns/data from Hak5
community payloads: Flock_Detect (colonelpanichacks et al.), flipper_detector
(nemanjan00), find_hackers (NULLFaceNoCase), SkimmerScanner (Adam Glenn),
device_profiler (z3r0l1nk), recondb_reporting (Digs). Credit retained in each
adapted file.
