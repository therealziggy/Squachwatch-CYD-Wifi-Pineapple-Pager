# SquachWatch-Pager — Port SquachWatch-CYD's signatures + an indexed matcher (design)

**Date:** 2026-09-26 · **Status:** part 1 approved in brainstorming; part 2 auto-approved (see §12)
**Parent specs:** `2026-09-21-squachwatch-pager-design.md` (core v1),
`2026-09-22-squachwatch-tier3-ble-adv-design.md` (Tier-3), `2026-09-23-squachwatch-noise-control-design.md`
**Source ported:** SquachWatch-CYD `src/signatures.cpp`, `src/detection.cpp`, `docs/DETECTIONS.md`
at commit `ecaff618e67b9c67121174937d0145c7567e1585` (GPL-3.0, same as this project).

## 1. Goal

Bring the Pager's device fingerprints up to what SquachWatch-CYD detects today, grade them the way CYD
grades them, fix the rules of ours that CYD's registry audit shows are over-graded, and do it without
making a scan lap any slower on the Pager's 580 MHz MIPS CPU.

In plain terms: 27 rules become 83 active rules plus 42 weak ones shipped switched off, and the matcher
gets an index so each device is only checked against the rules that could possibly fit it.

## 2. Findings that shape this design

**CYD today (read at the pinned commit).** CYD grades every fingerprint by who owns it, checked against
the IEEE MA-L registry and the Bluetooth SIG lists. Its rule (`include/signatures.h`):

| Grade | Meaning |
|---|---|
| high | Registered to the company that makes the product, or an exact self-identifying signature |
| med | Registered to a parent much broader than the product (Amazon owns Ring, and also Echo, Kindle…) |
| low | A module/chip vendor inside everything (Espressif, Lite-On, Realtek…), an unregistered block, or a locally administered (self-assigned) address |

CYD holds about 119 fingerprints: 77 MAC prefixes, 15 Bluetooth service IDs, 12 names, 8 WiFi-name
prefixes, 7 Bluetooth company IDs, plus behaviour detectors (evil twin, deauth flood, pwnagotchi, iBeacon).

**Registry check (done for this design).** Every prefix was looked up in the IEEE registry (a local
2022 copy, the nmap 2024 list, and maclookup.app for newer blocks). CYD's attributions held. Newer blocks
verified online: `B4:1E:52` = Flock Safety, `0C:FA:22` = Flipper Devices, the 13 Ring LLC blocks,
`B8:E2:8C` = Motorola Solutions Malaysia.

**Eight of OUR current "high" Flock rules are chip-vendor prefixes, not Flock's:**
`70:C9:4E`, `3C:91:80`, `D8:F3:BC`, `14:5A:FC` (Lite-On), `08:3A:88` (Universal Global Scientific, an
ODM), `58:8E:81`, `EC:1B:BD`, `90:35:EA` (Silicon Labs). CYD grades the Lite-On ones low. Any laptop or
gadget built on those chips would raise a full-screen "Flock" alert today.

**CYD dropped our Flipper prefix `80:E1:26` as "not in the IEEE registry".** It is not a registration:
Flipper firmware builds its BLE address from the STM32 chip's IDs, `ble_mac[3..5] = device_id (0x26),
ST company ID bytes (0xE1, 0x80)` (flipperzero-firmware `targets/f7/furi_hal/furi_hal_version.c`), so a
Flipper's address always starts `80:E1:26`. Our real captures confirm it. ST's own reference code
derives `00:80:E1:26:…` instead, so the shifted `80:E1:26` form is Flipper-firmware specific (likely,
not proven unique).

**Flipper's exact service IDs are safe against BLE Spam.** In all three real captures
(`test/fixtures/btmon_*.txt`) the `0x308x` service ID appears only on the real Flipper, never on the
607 spoofed BLE Spam addresses.

**Speed is the real constraint (measured on a real Pager, MT7628AN, bash 5.2.32, bare launcher-like
environment).** 200 records (100 WiFi + 100 BLE) through `sw_match_stream`:

| Rule set | Time | Per record |
|---|---|---|
| today's 27 rules | 16.0 s | 80 ms |
| 124 rules (27 + 97 synthetic), no index | 56.6 s | 283 ms |

That is ~2.15 ms per rule per record plus ~23 ms fixed. The matcher tests every rule against every
record, so the port without an index would make laps ~2.5× slower (83 active rules), and a BLE Spam
flood (607 addresses) would take minutes per lap.

**Noise on real data.** On one real Pager's recon history, the new active rules matched almost nothing.
The weak generic-chip rules would have logged a few ordinary routers every 10 minutes. That is why the
weak group ships switched off (§12).

## 3. The rule set

Format unchanged: `match_type|pattern|category|label|confidence|threat_class`. Only `high` raises the
full-screen alert (unchanged). New match type `wifi_ssid_pre` (§6.1). Each family gets a comment with
its source.

### 3.1 Active rules (83)

```
# ---- Flock Safety (surveillance) ----
ble_name_sub|penguin|flock_battery|Flock Penguin battery|high|surveillance
ble_name_sub|pigvision|flock_alpr|Flock Pigvision device|high|surveillance
ble_name_sub|fs ext battery|flock_battery|Flock external battery|high|surveillance
ble_name_sub|flock|flock_generic|Flock device|med|surveillance
wifi_oui|B4:1E:52|flock_generic|Flock Safety device|high|surveillance
wifi_ssid_pre|flock-|flock_generic|Flock setup network|high|surveillance
ble_name_sub|flock_setup|flock_generic|Flock setup|high|surveillance
ble_mfr|09c8|flock_generic|Flock device (XUNTONG radio)|high|surveillance
# ---- Axon body cameras ----
wifi_oui|00:25:DF|surveillance_axon|Axon / Taser device|high|surveillance
wifi_ssid_pre|ab2-|surveillance_axon|Axon body camera|high|surveillance
wifi_ssid_pre|ab3-|surveillance_axon|Axon body camera|high|surveillance
wifi_ssid_pre|ab4-|surveillance_axon|Axon body camera|high|surveillance
wifi_ssid_pre|axon-|surveillance_axon|Axon device network|high|surveillance
ble_name_sub|axon|surveillance_axon|Axon device|high|surveillance
# ---- Plate readers (ALPR) ----
wifi_oui|00:04:7D|surveillance_alpr|Motorola plate reader / police|high|surveillance
wifi_oui|00:18:85|surveillance_alpr|Motorola plate reader / police|high|surveillance
wifi_oui|00:1F:92|surveillance_alpr|Motorola plate reader / police|high|surveillance
wifi_oui|4C:CC:34|surveillance_alpr|Motorola plate reader / police|high|surveillance
wifi_oui|B8:E2:8C|surveillance_alpr|Motorola plate reader / police|high|surveillance
wifi_oui|00:BF:15|surveillance_alpr|Genetec plate reader|high|surveillance
wifi_oui|0C:BF:15|surveillance_alpr|Genetec plate reader|high|surveillance
# ---- Cameras ----
wifi_oui|2C:AA:8E|surveillance_camera|Wyze camera|high|surveillance
wifi_oui|D0:3F:27|surveillance_camera|Wyze camera|high|surveillance
wifi_oui|7C:78:B2|surveillance_camera|Wyze camera|high|surveillance
wifi_oui|34:D2:70|surveillance_camera|Amazon device (possible camera)|med|surveillance
wifi_oui|F0:27:2D|surveillance_camera|Amazon device (possible camera)|med|surveillance
wifi_oui|C0:56:E3|surveillance_camera|Hikvision camera|high|surveillance
wifi_oui|44:19:B6|surveillance_camera|Hikvision camera|high|surveillance
wifi_oui|28:57:BE|surveillance_camera|Hikvision camera|high|surveillance
wifi_oui|E0:A7:00|surveillance_camera|Verkada camera|high|surveillance
wifi_oui|70:1A:D5|surveillance_camera|Avigilon Alta device|high|surveillance
wifi_oui|00:40:8C|surveillance_camera|Axis camera|high|surveillance
wifi_oui|B8:A4:4F|surveillance_camera|Axis camera|high|surveillance
# ---- Ring ----
wifi_oui|FC:65:DE|surveillance_ring|Amazon / Ring device|med|surveillance
wifi_oui|68:37:E9|surveillance_ring|Amazon / Ring device|med|surveillance
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
wifi_ssid_pre|ring-|surveillance_ring|Ring setup network|med|surveillance
# ---- Card skimmers (classic serial-Bluetooth modules) ----
ble_name_sub|hc-03|surveillance_skimmer|Possible card skimmer (HC-03)|high|surveillance
ble_name_sub|hc-05|surveillance_skimmer|Possible card skimmer (HC-05)|high|surveillance
ble_name_sub|hc-06|surveillance_skimmer|Possible card skimmer (HC-06)|high|surveillance
ble_name_sub|rn42|surveillance_skimmer|Possible card skimmer (RN42)|high|surveillance
ble_name_sub|bt04-a|surveillance_skimmer|Possible card skimmer (BT04-A)|high|surveillance
ble_uuid|1101|surveillance_skimmer|Possible card skimmer (serial port)|high|surveillance
# ---- Camera glasses ----
ble_uuid|fd5f|surveillance_glasses|Ray-Ban Meta glasses|med|surveillance
ble_mfr|01ab|surveillance_glasses|Meta device (glasses or headset)|med|surveillance
ble_mfr|058e|surveillance_glasses|Meta device (glasses or headset)|med|surveillance
ble_mfr|0d53|surveillance_glasses|Luxottica (Ray-Ban) device|med|surveillance
ble_mfr|03c2|surveillance_glasses|Snap Spectacles|med|surveillance
# ---- Raven gunshot sensors (CYD's five exact IDs; replaces our 3100-3500 range) ----
ble_uuid|3100|surveillance_raven|Raven gunshot sensor (possible)|low|surveillance
ble_uuid|3200|surveillance_raven|Raven gunshot sensor (possible)|low|surveillance
ble_uuid|3300|surveillance_raven|Raven gunshot sensor (possible)|low|surveillance
ble_uuid|3400|surveillance_raven|Raven gunshot sensor (possible)|low|surveillance
ble_uuid|3500|surveillance_raven|Raven gunshot sensor (possible)|low|surveillance
# ---- Drones (ASTM F3411 Remote ID over Bluetooth) ----
ble_uuid|fffa|surveillance_drone|Drone (Remote ID)|med|surveillance
# ---- Trackers (unchanged; Tier-3 design) ----
ble_name_sub|tile|tracker_tile|Tile tracker|med|tracker
ble_mfr|004c:12:25|tracker_findmy|Apple Find My (separated)|med|tracker
ble_mfr|004c:07:other|tracker_airtag_setup|Apple AirTag (setup mode)|med|tracker
ble_uuid|fd5a|tracker_smarttag|Samsung SmartTag|med|tracker
ble_uuid|feed|tracker_tile|Tile|med|tracker
ble_uuid|feec|tracker_tile|Tile|med|tracker
ble_uuid|feaa:41|tracker_gfmd|Google Find My (separated)|med|tracker
# ---- Hacker tools ----
ble_name_sub|flipper|hacker_flipper|Flipper Zero|med|attacker
ble_oui|80:E1:26|hacker_flipper|Flipper Zero|high|attacker
ble_uuid|3081|hacker_flipper|Flipper Zero|high|attacker
ble_uuid|3082|hacker_flipper|Flipper Zero|high|attacker
ble_uuid|3083|hacker_flipper|Flipper Zero|high|attacker
ble_mfr|0e29|hacker_flipper|Flipper Zero|high|attacker
wifi_oui|0C:FA:22|hacker_flipper|Flipper Devices hardware|high|attacker
wifi_ssid_pre|pineapple_|hacker_pineapple|WiFi Pineapple setup network|med|attacker
wifi_ssid_sub|pager_open|hacker_pager|WiFi Pineapple Pager|med|attacker
wifi_ssid_pre|pwned|hacker_deauther|ESP deauther network|med|attacker
```

Counts: Flock 8, Axon 6, plate readers 7, cameras 12, Ring 16, skimmers 6, glasses 5, Raven 5,
drone 1, trackers 7, hacker tools 10 = **83**. Existing lines keep their text except where §5 says
otherwise. The existing comments in `signatures.db` (Flipper name-only reasoning, Find My / 0x07 notes,
Google Find My, Raven) are kept and updated, not dropped.

### 3.2 Weak rules, switched off (42)

Written as comment lines with the exact prefix `#off ` (a `#`, the word `off`, one space) followed by a
complete, valid rule. `sw_load_signatures` already strips every `#` line, so they never load.
Uncommenting = deleting the `#off ` prefix. All are `low` (log only when enabled). Each family's weak
lines sit directly under that family's active lines, below a comment saying why they are off.

```
#off wifi_oui|24:0A:C4|flock_chip|Possible Flock (ESP32 chip)|low|surveillance
  (same label, category, grade for the other 14 Espressif blocks: 30:AE:A4 24:6F:28 CC:50:E3
   DC:54:75 E8:9F:6D 8C:AA:B5 34:85:18 AC:67:B2 84:F3:EB B4:E6:2D CC:DB:A7 94:B9:7E A4:CF:12 C0:49:EF)
#off wifi_oui|70:C9:4E|flock_chip|Possible Flock (Lite-On chip)|low|surveillance
  (same for the other 9 Lite-On blocks: 3C:91:80 D8:F3:BC 14:5A:FC 80:30:49 74:4C:A1 24:B2:B9
   D0:39:57 00:F4:8D E0:0A:F6)
#off wifi_oui|D4:AD:FC|flock_chip|Possible Flock (Intellirocks chip)|low|surveillance
#off wifi_oui|B8:35:32|flock_chip|Possible Flock (unregistered prefix)|low|surveillance
#off wifi_oui|82:6B:F2|flock_chip|Possible Flock (self-assigned MAC)|low|surveillance
#off wifi_oui|00:A0:D8|flock_chip|Possible Flock (Spectra-Tek prefix)|low|surveillance
#off wifi_oui|08:3A:88|flock_chip|Possible Flock (USI chip)|low|surveillance
#off wifi_oui|58:8E:81|flock_chip|Possible Flock battery (Silicon Labs chip)|low|surveillance
  (same for EC:1B:BD and 90:35:EA)
#off wifi_oui|E4:05:40|surveillance_axon|Possible Axon (unregistered prefix)|low|surveillance
#off wifi_oui|28:24:FF|surveillance_axon|Possible Axon (Wistron NeWeb chip)|low|surveillance
#off wifi_oui|B8:D7:AF|surveillance_camera|Possible Wyze camera (Murata chip)|low|surveillance
#off wifi_oui|00:E0:4C|surveillance_camera|Possible camera (Realtek chip)|low|surveillance
#off wifi_oui|BC:DD:C2|surveillance_camera|Possible Arlo camera (ESP32 chip)|low|surveillance
#off wifi_oui|4C:69:05|surveillance_camera|Possible Blink camera (unregistered prefix)|low|surveillance
#off wifi_oui|A4:C1:38|surveillance_camera|Possible camera (Telink chip)|low|surveillance
#off wifi_oui|02:C0:CA|hacker_pineapple|Possible Hak5 device (self-assigned MAC)|low|attacker
#off wifi_oui|02:13:37|hacker_pineapple|Possible Hak5 device (self-assigned MAC)|low|attacker
```

Counts: Flock 33 (15 Espressif, 10 Lite-On, 8 others), Axon 2, cameras 5, Hak5 2 = **42**, one line
each in the file. The category `flock_liteon` is renamed `flock_chip` (it now holds every chip-vendor
Flock prefix, and both of its old rules move into this switched-off group).

### 3.3 Deliberately not ported

- **CYD's three skimmer MAC prefixes** (`20:13:00`, `98:D3:00`, `00:1A:7D`): Bluetooth Classic module
  prefixes that CYD checks only against WiFi traffic (`lookupOui` is called from the WiFi path only), so
  they can never match, in CYD or here. Two of them are not registered blocks at all.
- **iBeacon:** btmon decodes an iBeacon without a `Data:` line, so our parser emits no token for it
  (parser work), and CYD ships it switched off anyway.
- **Behaviour detectors** (evil twin, deauth flood, pwnagotchi): not signatures. Deauth floods are
  already covered by the Pager's native alert payload `squachwatch_deauth`. Pwnagotchi needs raw beacon
  parsing (the Tier-4 subsystem). Evil twin could be a future recon.db detector.
- **Remote ID decoding** (drone serial, drone and pilot position): goes with Tier-4 (Remote ID over
  WiFi), which needs the same message decoder. This port only detects presence.

## 4. Deviations from CYD (and why)

1. **Trackers** keep the Tier-3 behaviour (separation-aware Find My / Google, log + "following you"
   escalation). CYD alerts on every Tile and SmartTag on sight.
2. **Flipper `80:E1:26`** stays high: firmware-derived, confirmed on real hardware (§2).
3. **Raven:** CYD's five exact IDs replace our `3100-3500` range (which covered 1,025 IDs). Grade stays
   `low` (Tier-3 decision; log-only either way).
4. **The generic "flock" name rule stays `med`** (CYD: high). The word is too common for a full alert.
5. **Name rules are substrings** (CYD compares its Bluetooth-module names exactly). This is slightly
   broader, and it catches module defaults like `RN42-1A2B`.
6. **All weak rows ship switched off** (CYD logs them and, by default, even alerts on them). §12.

## 5. Behaviour changes the user will notice

- **Fewer false alarms:** the 8 over-graded Flock chip prefixes stop alerting (switched off).
- **Pineapple:** a network whose name merely *contains* "pineapple" no longer alerts. Only the default
  setup-network prefix `Pineapple_` is logged (med, CYD's grade: anyone can name their WiFi that).
- **Ring's WiFi-name rule** becomes a prefix (`Ring-…`), so `Spring-5G` no longer matches, and its
  label becomes "Ring setup network".
- **New full-screen alerts:** Flock Safety's own prefix and setup network/name/radio ID, Axon body
  cameras, Motorola/Genetec plate readers, Wyze/Hikvision/Verkada/Avigilon/Axis cameras, 13 Ring
  prefixes, Bluetooth skimmer modules, Flipper's exact IDs. Still at most one buzz per kind (category)
  per `SW_KIND_COOLDOWN` (600 s).
- **New log-only lines:** drones, camera glasses, Amazon devices, deauther networks.

## 6. Matcher changes (`lib/match.sh`)

### 6.1 `wifi_ssid_pre`

Case-insensitive **prefix** match on the sanitized SSID, mirroring `wifi_ssid_sub`:
`[ "$radio" = wifi ] && [ -n "$ident" ] && [ -n "$norm" ]` and `case "$lident" in "$norm"*)`. Pattern
normalized to lowercase in `sw_prepare_sigs` (the existing default branch). `signatures_test.sh`'s
known-types list gains it. `wifi_ssid_sub` is unchanged.

### 6.2 The index

`sw_prepare_sigs` (runs once per signature set) additionally builds:

- `SW_IX`, one associative array (`declare -gA`), key → space-separated rule indices:
  - `w:<OUI>` for `wifi_oui`, `b:<OUI>` for `ble_oui` (OUI uppercase, as normalized today);
  - `m:<company>` for `ble_mfr` whose first `:`-segment is exactly 4 lowercase hex;
  - `u:<uuid>` for `ble_uuid` of shape `xxxx` or `xxxx:bb` (key = the 4-hex UUID).
- `SW_SCAN_WIFI`: indices of all `wifi_ssid_sub` / `wifi_ssid_pre` rules.
- `SW_SCAN_BLE`: indices of all `ble_name_sub` rules, `ble_uuid` ranges, and any `ble_mfr` / `ble_uuid`
  pattern that does not fit a key shape above (a malformed rule still gets the full check, so it
  behaves exactly as today).
- Unknown match types are indexed nowhere (today they never hit either).

A new fork-free helper `_sw_candidates <radio> <oui> <adv>` fills the global sparse indexed array
`SW_CAND` with the candidate rule indices: for `wifi`, `SW_IX[w:<oui>]` plus `SW_SCAN_WIFI`. For `ble`,
it takes `SW_IX[b:<oui>]` and `SW_SCAN_BLE`, then for each advertisement token adds `SW_IX[m:<company>]`
(from `mfr:<company>:…`) or `SW_IX[u:<uuid>]` (from `uuid:<uuid>` and `sd:<uuid>:<byte>`). Any other
radio gives no candidates. Every key is namespaced (`w:` `b:` `m:` `u:`), so a key is never empty, which
avoids bash's "bad array subscript" abort on empty or odd tokens such as `sd::41`.

`sw_match_record` then iterates `"${!SW_CAND[@]}"`, which bash returns in ascending index order (= file
order), and runs the **unchanged** per-rule body. Correctness therefore reduces to one property: *the
candidate set contains every rule that could hit this record.* §6.2's key choice guarantees it for each
match type (a `ble_mfr` rule can only hit a token with the same company; a `ble_uuid` exact or
first-byte rule only a token with the same UUID; OUI rules only their OUI), and the differential test
in §8 checks it. Tie-breaking (strongest per category, first-listed on a tie) and the output format are
unchanged.

`SW_SIGS_CACHE` behaviour is unchanged: the index is rebuilt only when the signature text changes.

### 6.3 Performance target

- **Deterministic (machine-independent):** with the real signature set, a WiFi record whose OUI
  matches no rule gets exactly `len(SW_SCAN_WIFI)` = 9 candidates, and a token-less BLE record exactly
  `len(SW_SCAN_BLE)` = 13 candidates (not 83). Asserted in tests.
- **Dev box:** existing `test/perf_test.sh` budgets stay (500 records < 5 s), and its static fork-free
  checks cover `_sw_candidates`.
- **On the Pager (acceptance):** the same 200-record benchmark (§2) with the new active set must take
  **≤ 16.0 s** (today's time with 27 rules). Also measured with every `#off` rule enabled (125 rules);
  it must stay within 10% of the active-set time. Results recorded in `docs/superpowers/P0-findings.md`.

## 7. Files touched

- `payloads/user/reconnaissance/squachwatch/lib/match.sh`: `wifi_ssid_pre`, index, `_sw_candidates`.
- `payloads/user/reconnaissance/squachwatch/signatures.db`: §3.
- `test/match_test.sh`, `test/signatures_test.sh`, `test/perf_test.sh`, `test/payload_test.sh`,
  `test/e2e_test.sh` (only where §5 changes an expectation), new `test/helpers/match_ref.sh`.
- `test/fixtures/recon.db` + `tools/build_fixture_db.py` only if a payload test needs an active Flock
  prefix instead of the switched-off `70:C9:4E` (synthetic rows only; rebuild into a fresh file).
- `README.md` (Signatures, Status & roadmap, Credits), `docs/superpowers/P0-findings.md` (Pager timings).

## 8. Testing

- **Per family, positive + negative control:** each family has a record that hits (exact category,
  label, confidence) and a near miss that must not hit: `LAB2-GUEST` vs `ab2-`, `Spring-5G` vs `ring-`,
  `MyPineappleNet` vs `pineapple_`, `uuid:3101` vs Raven, `mfr:004d:…` vs Apple rules, `uuid:3084` vs
  Flipper, company `0fba` (the wrong Flipper ID other projects copied) vs Flipper.
- **Differential test (the index proof):** `test/helpers/match_ref.sh` holds the pre-change
  `sw_match_record` verbatim (renamed `sw_match_record_ref`, taken from `git show 756ac91`). For every
  record parsed from every fixture (`btmon_*.txt` via `sw_btmon_parse`, `recon.db` via
  `sw_wifi_records`), plus hostile records (empty fields, `sd::41`, empty/odd MACs, unknown radio,
  tokens with uppercase or wrong length), the new `sw_match_record` output must equal the reference's,
  byte for byte, under three signature sets: the real active set, the real set with every `#off` rule
  enabled, and a synthetic set with every match type including ranges, first-byte UUIDs and malformed
  patterns. A positive control proves the harness can fail: a deliberately broken index (drop one key)
  makes it fail.
- **Switched-off rules stay valid:** every `#off ` line, once uncommented, passes the format/type
  checks and hits a synthetic record built from its own prefix. Exactly 83 rules load, exactly 42 `#off`
  lines exist.
- **Registry guards:** no active `wifi_oui`/`ble_oui` rule with the locally administered bit (0x02 of
  the first octet) above `low` (CYD's rule), and none of the 8 formerly over-graded Flock chip prefixes is
  active.
- **Existing suites:** all 426 current assertions keep passing, apart from the expectations §5 changes on
  purpose. Each such change is named in its commit message.
- **Real captures:** the three real btmon fixtures produce exactly the same detections as before. None
  of the new Bluetooth IDs appear in them except Flipper's `0x3082`, and that lands in the same
  `hacker_flipper` category, so the real Flipper stays one high detection.

## 9. Deploy and verify (on the user's Pager, approved 2026-09-26)

1. Back up the installed scanner to `/root/squachwatch-backup-2026-09-26/`. It goes outside
   `/root/payloads` so the Pager UI does not list a duplicate payload.
2. Install the new `payloads/user/reconnaissance/squachwatch/` (the alert payloads are unchanged), then
   check that every file's `sha256sum` on the Pager equals the repo's.
3. Run a launcher-faithful lap: the Pager launcher's copy-to-`/tmp` plus injected header, with only
   `PAYLOAD_HOME` in the environment, as in `docs/superpowers/P0-findings.md`. It must load 83 signatures
   and finish a lap with no errors.
4. Run the §6.3 on-device benchmark and record it.
5. Left for the user: a real launch from the Pager menu, walking past something with a Flipper. The
   restore command for the backup is written into the final report.

## 10. Privacy (public repository)

No new real captures. Any new fixture is synthetic (`AA:00:…`-style addresses). Commits use `TZ=UTC`
with the noreply identity. No clock times, no epochs next to local dates, no local paths. Nothing is
pushed: the user reviews and pushes (their decision for this job).

## 11. Out of scope

Everything in §3.3; CYD's non-signature features (regulars, WATCH/hunt, mesh, pet); Bluetooth Classic
inquiry scanning (CYD never switched its own on); the framebuffer skin.

## 12. Decisions taken while the user was away

The user approved part 1 (the rule set, §3–§5) and asked me to take my recommended option for anything
else. Taken that way:

- **Weak rules:** included but switched off (the user chose this before leaving).
- **Approach A** (data + index), chosen by the user; B (data only, ~2.5× slower laps) and C (awk
  rewrite of the matcher core) rejected.
- **Index shape (§6.2)** with namespaced keys, and the unchanged per-rule body. This keeps the proof
  obligation to "the candidates contain every possible hit", which a byte-for-byte differential test
  checks.
- **Grades:** CYD's shipped grades throughout, e.g. plate readers `high` as in CYD's code (its prose
  calls them medium), and the XUNTONG radio ID `high` (CYD's FLOCK grade; it names a module supplier, so
  if it ever false-alarms, drop it to `med`).
- **Categories:** CYD's types become `surveillance_*` / `hacker_*` categories (kind cooldown and CSV
  key), so a street of cameras still buzzes once per 10 minutes. Existing categories are kept, except
  `flock_liteon` → `flock_chip`.
- **Pager:** install with a backup, verify over USB; **GitHub:** commit locally, no push.
