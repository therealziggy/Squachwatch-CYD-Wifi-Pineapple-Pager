# SquachWatch-Pager — Tier-3: raw BLE advertisement detection (design)

**Date:** 2026-09-22 · **Status:** approved in brainstorming, pending spec review
**Parent spec:** `2026-09-21-squachwatch-pager-design.md` (§3 match types, §4 Tier 3, §8 P4)

## 1. Goal

Detect personal trackers that broadcast no name (Apple Find My / AirTag, Samsung SmartTag,
Tile, Google Find My Device network) and Raven gunshot sensors, from raw BLE advertisements,
without turning the Pager into a device that screams in every café.

**Decisions made in brainstorming:**
- **Two-tier alerting for trackers.** Any tracker *separated from its owner* → yellow `LOG` +
  CSV row (`med`, no buzz). The full-screen `ALERT` + buzz fires only when the **same**
  tracker stays with you for a sustained period (default 15 min).
- **Scope:** Find My, SmartTag, Tile, Google Find My (full two-tier) + Raven as a
  `low`-confidence log only. iBeacon excluded.
- **Architecture A:** `btmon` becomes the single BLE data source for **all** BLE matchers.
- **Ignore list** for the owner's own devices.

## 2. Findings that shape this design (on-device, 2026-09-22)

- `btmon` 5.72 is present and decodes advertisements, including manufacturer data:
  `Company: Apple, Inc. (76)` / `Type: Unknown (18)` / `Data: <hex>`. 16-bit service UUIDs
  keep their value (`Unknown (0x3082)`); **128-bit UUID values are NOT printed** (only
  `Vendor specific`). **Service data is rendered as `Service Data: <name> (0xfcf1)` followed
  by an indented `Data: <hex>` line**, verified in the live capture (a real `0xFCF1`
  advertiser; noticed during planning 2026-09-23).
- **Live Find My devices in range, both shapes:** type `0x12` with a **25-byte** payload
  (`F9:C1:A3:83:F0:48`, the separated-from-owner form) and a **2-byte** payload `0000`/`0002`
  (the near-owner form). Also an Apple **type 16** "nearby info" device (an iPhone or
  similar), which must never match. Raw capture: `test/fixtures/btmon_live_2026-09-22.txt`.
- btmon also logs HCI commands, so a scan that never started is observable:
  `LE Set Scan Parameters … Status: Command Disallowed (0x0c)` vs `LE Set Scan Enable … Status: Success (0x00)`.
- `hcitool lescan` **loses all device lines on SIGTERM** (fixed in `cc37ac6`, `timeout -s INT -k 2`).
  With architecture A its output is discarded anyway: it only switches scanning on.
- A Flipper advertises a 16-bit UUID in `0x3081`–`0x3083` (by case colour), just below the Raven range, so hobby devices
  do live in that unassigned space.

## 3. Capture and records

**Per lap** (`sw_ble_scan`): reset `hci0` (`down`/`reset`/`up`), start
`timeout -k 2 $((secs+3)) btmon > ${SW_TMP_DIR:-/tmp}/sw_ble.XXXXXX &` (TERM, not INT: a
background job in a non-interactive shell starts with SIGINT *ignored*, and btmon exits
cleanly on TERM; amended 2026-09-23 during planning), run
`timeout -s INT -k 2 "$secs" hcitool -i hci0 lescan --duplicates >/dev/null`, stop btmon,
parse the file **once**, delete it. btmon's own timeout means an orphaned btmon (payload
SIGKILLed mid-lap) still dies within `secs+5` s instead of filling RAM-backed `/tmp`.

**Parser** (`sw_btmon_parse`, **one awk pass**, no per-line shell work): a record boundary
is each `Address:` line (one HCI event may carry several reports); both
`LE Advertising Report` and `LE Extended Advertising Report` are accepted. All sightings of
a MAC within the lap merge into **one record**: first non-empty name wins, and RSSI is the
**strongest** seen.

**Record format** (BLE gains an optional 5th field; WiFi records are unchanged):

```
ble|<MAC>|<name>|<rssi>|<tokens>
ble|F9:C1:A3:83:F0:48||-97|mfr:004c:12:25
ble|80:E1:26:FA:D6:22|MyFlipper|-79|uuid:3082
```

`<tokens>` is a space-separated, de-duplicated list built **only from parsed hex/decimal
fields**, so it can never contain `|`:

| token | from | example |
|---|---|---|
| `mfr:<company>:<type>:<len>` | manufacturer data; see the derivation rule below | `mfr:004c:12:25` |
| `uuid:<16-bit>` | 16-bit service UUID lists (partial or complete) | `uuid:fd5a` |
| `sd:<16-bit>:<first byte>` | service data | `sd:feaa:41` |

**`mfr` derivation.** `company` = btmon's decimal `Company: … (N)`, rendered as 4 lower-hex
(76 → `004c`). Then:
- if btmon prints a `Type: … (N)` line (it does for Apple): `type` = N as 2 lower-hex
  (18 → `12`), and `len` = the number of bytes on the following `Data:` line. btmon has
  already consumed Apple's type **and** length bytes, so `len` equals Apple's declared
  length: 25 for separated Find My, 2 for near-owner, both observed live;
- otherwise: `type` = the first byte of `Data:` and `len` = the remaining byte count.
Only Apple signatures use `len` in this phase.

The name still goes through `sw_sanitize_ident`. `sw_match_record` splits an optional 5th
field; everything in the hot path stays **fork-free** (the perf contract in `lib/match.sh`).

`sw_ble_parse` (the lescan-format parser) and `test/fixtures/lescan.txt` are **retired**;
the `SW_BLE_CMD` test seam now feeds btmon-format text through `sw_btmon_parse`.

## 4. Signature syntax (two new match types)

```
ble_mfr|004c:12:25|tracker_findmy|Apple Find My (separated)|med|tracker
ble_uuid|fd5a|tracker_smarttag|Samsung SmartTag|med|tracker
ble_uuid|feed|tracker_tile|Tile|med|tracker
ble_uuid|feec|tracker_tile|Tile|med|tracker
ble_uuid|feaa:41|tracker_gfmd|Google Find My (separated)|med|tracker
ble_uuid|3100-3500|surveillance_raven|Raven gunshot sensor (possible)|low|surveillance
```

- **`ble_mfr`** is a **whole-segment** prefix match on `mfr:` tokens: the token equals
  `mfr:<pattern>` **or** starts with `mfr:<pattern>:`. So `004c` = any Apple, `004c:12` = any
  Find My, `004c:12:25` = separated Find My only, and `004c:12:2` matches **only** the
  near-owner form. A plain string prefix would be a bug: `004c:12:2` would also match
  `004c:12:25`.
- **`ble_uuid`** has three forms, chosen by the pattern's shape:
  - `xxxx` matches a `uuid:xxxx` token **or** any `sd:xxxx:*` token;
  - `xxxx:bb` matches `sd:xxxx:bb` only. This is what keeps Eddystone beacons (`feaa:10`
    etc.) from reading as Google Find My;
  - `lo-hi` is an inclusive numeric range over `uuid:` and `sd:` UUIDs, compared with
    `$((16#…))`.
- Patterns are compared case-insensitively (normalised once in `sw_prepare_sigs`).
- `ble_name_sub` and `ble_oui` are unchanged and now read btmon-sourced names/MACs.
- The v1 `ble_name_sub|tile` line **stays** (name-advertising Tiles), so a Tile that both
  names itself and advertises `0xFEED` yields one `tracker_tile` row per cooldown, not two
  (same mac+category → one cooldown key).

## 5. Follow detection (`lib/follow.sh`)

State file `$SW_LOOT_DIR/track.db`, one line per tracker: `mac|category|first_seen|last_seen`.
`sw_follow_update <detection> <now> <trackfile>` runs for every detection whose
`threat_class` is `tracker`:

1. Unknown `(mac, category)` → `first = last = now`.
2. Known and `now − last ≤ SW_FOLLOW_GAP` → `last = now`.
3. Known and `now − last > SW_FOLLOW_GAP` → reset `first = last = now` (it left; not continuous).
4. If `last − first ≥ SW_FOLLOW_SECS` → print an **extra** detection:
   category `<category>_follow`, label `<label> — following you <N>+ min`,
   confidence **`high`**, same class/radio/mac/ident/rssi. `sw_emit` then fires the full
   ALERT; the mac+category cooldown gives it its own independent re-alert window.

Every rewrite drops entries with `now − last > SW_FOLLOW_GAP`, so the file stays bounded
by the number of trackers seen in the last few minutes. The rewrite goes via a temp file +
`mv` so a kill mid-write cannot truncate state. Raven is `surveillance` class and never
enters follow.

## 6. Ignore list

`$SW_LOOT_DIR/ignore.txt`, one MAC per line (`#` comments allowed, case-insensitive). A
detection whose MAC is listed is dropped **before** follow and emit: no log, no CSV, no
alert. It lives in the loot dir so a payload redeploy never overwrites it. Loaded once at
startup into a lookup string (fork-free membership test per detection), so edits take
effect on the next launch. A missing file means an empty list.

## 7. Failure modes (a blind BLE path must never read as "all clear")

| failure | detection | signal |
|---|---|---|
| `btmon` missing | `command -v btmon` in `sw_healthcheck` | `WARN: btmon missing — BLE detection OFF`, degraded |
| scan never started (e.g. `Command Disallowed`) | no `LE Set Scan Enable` … `Status: Success` in the lap's capture | `WARN: BLE scan failed to start` logged **on state change** (ok→failed and failed→ok), state kept in `/tmp/sw_ble.state` |
| btmon's text format changed (parser no longer understands it) | the capture contains `Advertising Report` lines but `sw_btmon_parse` produced **zero** records | `WARN: BLE capture not understood — BLE detection OFF`, logged on state change like the row above |
| btmon orphaned by a SIGKILLed payload | btmon runs under its own `timeout -k` | dies within `secs+5` s |
| temp files left by a kill | `sw_cleanup` | kills `hcitool` **and** `btmon`, removes `/tmp/sw_ble.*` (also closes the v1 temp-file leak) |

## 8. Testing (offline; positive control on every negative)

- **Fixtures:** real blocks cut from `btmon_live_2026-09-22.txt` (Flipper; Find My separated
  `004c:12:25`; Find My near-owner `004c:12:2`; Apple type 16; 128-bit vendor device; the
  scan-enable Success lines). **Synthetic** blocks, labelled as such in a header comment, for
  SmartTag, Tile, Google Find My, an Eddystone URL frame, Raven, a multi-report event, an
  extended report, a name arriving only in a `SCAN_RSP`, and a `Command Disallowed` capture.
- **Parser:** one record per MAC; tokens exactly as §3; strongest RSSI wins; name from scan
  response; `|` in a name is stripped; multi-report and extended events both parsed.
- **Matchers, where the false positives live:** near-owner Find My must **not** match
  `004c:12:25`, **and** a `004c:12:2` rule must **not** match the separated `004c:12:25`
  token (whole-segment prefix); Apple type 16 must **not** match; Eddystone `feaa:10` must **not** match
  `feaa:41`; Flipper `0x3081`–`0x3083` must **not** match `3100-3500` while `0x3100` and `0x3500`
  **do**; each rule also has a "signature removed → no match" control.
- **Follow** (explicit `now` values): escalates at exactly `SW_FOLLOW_SECS`, not before; gap
  resets; prune; follow alert independent of the presence cooldown; a kill between temp
  write and `mv` leaves the old state intact.
- **Ignore list:** a listed MAC emits nothing, and the same detection with an unlisted MAC
  does emit (control).
- **Scan-start health:** a `Command Disallowed` fixture triggers the warning once; a
  following Success fixture triggers the recovery line once; repeated failures don't spam.
- **Format health:** a capture with advertising reports in an unrecognised layout triggers
  "capture not understood"; an empty-but-valid capture (scan OK, no devices) does **not**
  (a quiet room is not a fault).
- **Perf:** `perf_test.sh` is extended with BLE records carrying tokens (still < 5 s for
  500 records), and `sw_btmon_parse` over a ~30k-line synthetic capture gets its own
  budget. The static fork-free guard covers the new matcher code.
- **`test/stubs/btmon`:** prints a fixture capture and runs until INT/TERM, so
  `sw_ble_scan` runs end-to-end, including the cleanup path.

## 9. On-device verification (before the phase is called done)

1. The live separated Find My device → a `tracker_findmy` presence row (`med`, no buzz).
2. The near-owner Find My device and the Apple type-16 device → no row (negative controls).
3. The Flipper is still detected (name and OUI) via the btmon path (regression).
4. Follow fires against a real tracker using a shortened `SW_FOLLOW_SECS` for the test run.
   **This buzzes the Pager.**
5. A failed scan drives the real `scan_failed` path and the warning must appear. Since
   `sw_ble_scan` always resets `hci0`, the plan induces it with a nonexistent interface
   (`hci9`) instead of skipping the reset.
6. **Needs the user's OK first (optional):** have the desktop's Bluetooth adapter (or a phone
   running nRF Connect) briefly advertise SmartTag / Tile / Google Find My / Eddystone packets.
   The service-data *format* is already verified (§2), so this only confirms the specific
   UUID / frame *values*.

## 10. Limits and confidence

- Follow detection needs the **same MAC** to persist. Separated AirTags hold an address for
  about a day and Tiles use static addresses (**likely**, published research). Google Find My
  rotates about every 17 min (**inferred** from its spec), borderline against a 15-min
  window. SmartTag rotation is **unknown**.
- **Time-only:** with no GPS fix, sitting still for 15 min next to someone's lost AirTag
  alerts. Apple's own detection also requires a location change.
- `feaa:41` = Google Find My "separated" is **inferred** from Google's spec, not
  device-verified. Raven `3100-3500` comes from SquachWatch-CYD, not device-verified, hence
  `low`.
- The parser depends on btmon 5.72's text format. A format change surfaces through the
  "capture not understood" and scan-start health signals (§7) rather than silently. A
  change that still parses but drops one field (e.g. `Type:`) would **not** be caught by
  them; the real-capture fixtures pin today's format so an upgrade shows up as a test diff.

## 11. Config

| var | default | meaning |
|---|---|---|
| `SW_BLE_SECONDS` | 12 | BLE scan length per lap (existing) |
| `SW_FOLLOW_SECS` | 900 | continuous presence before a tracker escalates to "following" |
| `SW_FOLLOW_GAP` | 300 | max gap between sightings that still counts as continuous |
| `SW_IGNORE_FILE` | `$SW_LOOT_DIR/ignore.txt` | MACs to drop before follow/emit |

All defaults live in `payload.sh`'s config block. **Libraries must not `:=` a default**:
that is exactly how `SW_RECENCY_SECS` was silently pinned to 0. Each default gets a
clean-process test like `payload_default_recency_window`.

## 12. Non-goals (this phase)

128-bit UUIDs; iBeacon; GPS movement checks; drone Remote-ID (Tier 4); `seen.db` pruning
(v1 open minor, unchanged).
