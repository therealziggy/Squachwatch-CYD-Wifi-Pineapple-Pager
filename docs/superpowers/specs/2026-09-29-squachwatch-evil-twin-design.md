# SquachWatch-Pager — Evil-twin detector (design)

**Date:** 2026-09-29 · **Status:** approved in brainstorming (scope, approach, and all three design sections)
**Parent specs:** `2026-09-21-squachwatch-pager-design.md` (core v1, which lists "Evil-twin / rogue AP /
karma" as a recon.db detector), `2026-09-23-squachwatch-noise-control-design.md` (the gates this reuses),
`2026-09-26-squachwatch-cyd-signature-port-design.md` (§3.3 left evil twin as "a future recon.db detector")
**Source ported (logic, not code):** SquachWatch-CYD `include/detection.h` (the AP table comment),
`src/detection.cpp` (`noteApBeacon`, `sameVendor`), `src/signatures.cpp` (`confidenceFor`) and
`src/detection_info.cpp` (the EVILTWIN text), at commit `13aa836889997f77a0949814e2eba1fa3dd026e6`. The
evil-twin logic has not changed since it was added in `5a9c877`.

## 1. Goal

Warn when someone near you is running a fake copy of a WiFi network: the same name, but open (no password)
while the real one needs a password. That is how "evil twin" hotspots lure phones and laptops, often with a
fake login page that asks for the WiFi password.

SquachWatch already reads the Pager's recon database every lap. The check is one more query on the same
copy: no new scanning, no new radio use.

Out of scope for this round (user decision, 2026-09-29): "karma" radios that pose as many networks at once
(§12).

## 2. Findings that shape this design

### 2.1 How CYD does it

- CYD keeps a small table: the first BSSID seen for each SSID, with the Privacy bit it advertised
  (encrypted or not). A later beacon for the same SSID is flagged EVILTWIN when it comes from different
  hardware (`sameVendor`: the OUI, with the locally administered bit masked) **and** disagrees about
  encryption.
- Why the encryption test: "same SSID, different BSSID" is every mesh network and every dual-band access
  point (CYD saw it fire constantly on a real mesh), and even "same SSID, different OUI" over-fires. A mesh
  never disagrees with itself about security. The practical attack is an open twin of an encrypted network,
  which is exactly what a captive "evil portal" is.
- CYD states two costs: an attacker who matches the encryption walks past; and whichever BSSID is seen
  first becomes the baseline, so a rogue that is already up when you arrive is recorded as legitimate and
  the real access point is what trips the alert.
- Graded HIGH ("specific and hard to fake"), drawn in the same red as DEAUTH and counted under HACK. Names
  are compared exactly (`strncmp`, 32 bytes). Only named beacons are considered, and pwnagotchi beacons are
  skipped (their SSID is throwaway).

### 2.2 What the recon database holds (checked on the Pager, 2026-09-29)

- `ssid` table: one row per radio, network name and recon session. `time` is when the row was last seen in
  that session (the current session's rows keep updating). `type` 8 = beacon (access point), 4 = client,
  5 = a name a client probed for (no BSSID and no security value, so it is of no use here). For access points
  `bssid` is always filled: the colonless 12-hex MAC, stored as a BLOB, like `ssid`.
- `hidden` is 1 for hidden networks. The Pager de-cloaks some of them, so a hidden row can carry a name
  learned from a probe response.
- `encryption` is a 64-bit bit field written by `pineapd`: **0 = open**, and any other value = protected.
  The low bits carry WEP / WPA / WPA2 / WPA3 and the higher bits the ciphers and key-management suites; the
  most common value, `17184063752`, is a WPA2 personal network. Only the 0 / non-0 split is used here, so
  the full layout (which Hak5 does not document) is not needed. It is never NULL on beacon rows in the
  author's database.

### 2.3 Replay of real history

The author's full Pager recon history (about 4,600 access points, over several months) was replayed with a
600 s window at every minute that holds beacon data (1,286 minutes):

| Rule | Fires on |
|---|---|
| Same name, different radio | 187 names |
| Same name, different maker (OUI) | 84 names |
| Same name, security bit fields differ | 30 names |
| CYD's rule (different maker **and** open vs protected) | 0 |
| **This design** (open vs protected, any radios, exact name) | **1: the one real evil twin** |
| This design, but ignoring capitals | 23: the real one plus 22 false (a venue's open guest network on 23 radios next to a protected network with the same name in other capitals) |

The one real event: on the Pager's first day, the Pager itself broadcast an **open copy of the owner's
home network under the router's own address** at −8 dBm, while the real protected network was logged at
−74 dBm. CYD's maker check exempts the same address (and the same maker), so CYD's rule misses exactly this
case. Copying the real router's address is also the easy choice for an attacker, because it defeats any
check that compares addresses.

## 3. The rule

Every lap, on the lap's copy of the recon database:

1. Take the beacon rows (`type = 8`) seen in the window: `time` within the last `SW_RECENCY_SECS` seconds
   before the lap started (600 by default). When that window is switched off (`0` = sweep the whole
   database) or is not a whole number without a leading zero, the twin check uses 600 s, because "at the
   same time" needs a window. (A leading zero would make bash read the number as octal.)
2. Keep only visible, named networks: `hidden = 0`, and a name that is neither empty nor made only of zero
   bytes. Skip rows with no security value.
3. Group the rows by the exact name, byte for byte (capitals, spaces and all).
4. A name with at least one open row (`encryption = 0`) and at least one protected row
   (`encryption <> 0`) is twinned. Each radio that offers it **open** is reported once, with its latest
   signal. A radio that offers the same name both open and protected within the window is reported too
   (the same-address copy of §2.3).

There is no "first seen is the real one" baseline. Both sides are in the database at once, so the open copy
is the one named, whichever appeared first (this removes the CYD limitation described in §2.1).

## 4. What the user sees

- The detection, in the existing 8-field format:
  `evil_twin|Evil twin|high|attacker|wifi|<open copy's MAC>|<network name>|<its signal>`
- Screen line, in the attacker colour (cyan): `Evil twin 'HomeNet' AA:BB:CC:00:00:01 -38dBm`
- Full-screen alert, with the buzz and the red LED: `Evil twin 'HomeNet'`, then
  `AA:BB:CC:00:00:01 -38dBm` on the next line.
- CSV row: category `evil_twin`, label `Evil twin`, confidence `high`, class `attacker`, radio `wifi`, the
  open copy's MAC, the network name (the ident column) and its signal.
- The existing gates, unchanged:
  - `SW_COOLDOWN`: one alert and one CSV row per open copy (MAC + category) per 600 s. A radio that is the
    open copy of two names at once gets a screen line for each, but one CSV row per window (the ledger key
    is its MAC + category).
  - `SW_KIND_COOLDOWN`: several twins at once buzz once.
  - `SW_LOG_PER_KIND`: 3 screen lines per lap, then `...and N more Evil twin`.
  - `ignore.txt`: silences an open copy by its MAC.
  - AUTO SNOOZE and "following you" do not apply: an evil twin is not a tracker.
- New setting `SW_EVIL_TWIN` (default `1`; `0` turns the check off, so no query runs at all).
- The user's own Pager: running the Pager's open access point under the name of a nearby protected network
  **is** an evil twin and is reported; `ignore.txt` silences it.

## 5. Deviations from CYD, and why

1. **No maker exemption.** CYD never flags two radios from the same maker (the same OUI with the locally
   administered bit masked). That exemption hides the same-address copy, the only real evil twin in the
   replay (§2.3), and it buys nothing: the replay holds no legitimate open-vs-protected pair from any radios.
2. **No first-seen baseline.** Both sides are compared on every lap, and the open copy is always the one
   reported.
3. **A time window instead of a 24-entry table.** "At the same time" means both were seen within the
   window. A legitimate change of a router's security (open to protected) ends by itself once the old row
   ages out of the window; CYD re-baselines when the same BSSID changes.
4. **Colour.** Our attacker class (cyan screen line, red LED), which is where our other hacker-tool finds
   go. CYD draws it red.

The same as CYD: exact name matching, a HIGH grade, named beacons only, and the encryption mismatch as the
test that separates a twin from a normal network.

## 6. Design

### 6.1 New `lib/eviltwin.sh`

- `sw_evil_twin_scan <db copy> <now>` runs ONE read-only query (`sqlite3 -readonly`) that does the grouping
  inside SQLite, then turns each result row into a detection line using builtins only (`sw_wifi_colonize`,
  `sw_sanitize_ident`), with no fork per row. A row whose MAC is not 12 hex characters or whose signal is
  not an integer is skipped.
- Each result row is ONE column, `mac<TAB>signal<TAB>name`, joined in SQL with `char(9)`, with the name
  LAST. The reason is the same as for `sw_wifi_records`: the CLI's column separator differs between the
  Pager and the test shim, and a name can hold tabs or pipes.
- The query (its exact text is pinned by the tests):

  ```sql
  WITH w AS (
    SELECT bssid, ssid, signal, time, encryption FROM ssid
    WHERE type = 8 AND hidden = 0 AND time >= <since>
      AND encryption IS NOT NULL AND ltrim(hex(ssid), '0') <> ''
  ),
  twin AS (
    SELECT ssid FROM w GROUP BY ssid
    HAVING sum(encryption = 0) > 0 AND sum(encryption <> 0) > 0
  )
  SELECT line FROM (
    SELECT w.bssid || char(9) || w.signal || char(9) || CAST(w.ssid AS TEXT) AS line, max(w.time)
    FROM w JOIN twin ON w.ssid = twin.ssid
    WHERE w.encryption = 0
    GROUP BY w.bssid, w.ssid
  );
  ```

  `max(w.time)` makes SQLite take `line` (so the signal) from each open copy's latest row. `ssid` and
  `bssid` are BLOBs, so grouping and `=` compare bytes exactly. `<since>` is the lap's start time minus the
  window (§3 rule 1), and both are checked to be whole numbers before use: they are the only values that go
  into the SQL text.

### 6.2 One database copy per lap

Today `sw_wifi_records <db>` copies the 6 MB database to `${SW_TMP_DIR:-/tmp}/sw_recon.XXXXXX`, reads it and
deletes it. This splits into `sw_recon_snapshot <db>` (mktemp + cp, path in `REPLY`) and a reader that
takes an existing copy. `sw_scan_once` takes one snapshot when the lap starts; the WiFi signature reader and
the twin check both read it, and the lap removes it when it ends. `sw_wifi_records <db>` keeps its current
behaviour (copy, read, delete) for the tests and tools. Cleanup after a Stop or a crash does not change: the
exit trap and the startup sweep already remove `sw_recon.*`.

### 6.3 Into the detection stream

Twin detections are finished detections, so they join the stream AFTER `sw_match_stream` and pass through
the same per-detection loop as everything else: `sw_stopped`, `sw_ignored`, `_sw_emit_capped`, `sw_emit`.
`sw_follow_update` returns nothing for them (it only acts on the tracker class).

### 6.4 Showing the network name

In `sw_emit`, for category `evil_twin` only, the text shown is `<label> '<ident>'`, both in the screen line
and as the alert's first line. Other categories do not change. The `...and N more` line in
`_sw_emit_capped` keeps the plain label.

### 6.5 Config (`payload.sh`)

`: "${SW_EVIL_TWIN:=1}"` with a comment. The check runs only when the value is exactly `1`. The library sets
no default of its own (the recency-window lesson: payload.sh sources its libs before its config block).

## 7. Failure handling

- **Hostile names.** The attacker chooses the name. It is cleaned by `sw_sanitize_ident` (pipes and control
  characters removed) before it goes into the pipe-delimited detection line; it is the last field of the
  query output; the CSV's formula guard (`_sw_csv_field`) already covers the ident column; it is never
  evaluated, and it reaches `LOG` and `ALERT` only as a quoted argument.
- **Read-only open.** `sqlite3 -readonly` means a copy that disappears under a running lap (the exit trap
  after a Stop removes it) is never recreated as an empty file. That was the 2026-09-28 health-check bug.
  The Pager's sqlite3 (3.46.1) supports the flag. The test shim gains it too and models the Pager: with
  `-readonly`, a missing file is an error and is not created.
- **Blind-spot health check.** A check that silently finds nothing must never read as "all clear". When
  `SW_EVIL_TWIN=1`, the health check (at startup and every `SW_HEALTH_EVERY` laps) runs one more count on its
  database copy: the named, visible beacon rows in the window, and how many of them carry a security value.
  If there are such rows but none has a value, or the count fails on a readable copy (a renamed column, for
  instance), it reports `WARN: evil-twin check is blind (the recon DB no longer records network security)`
  and the run is DEGRADED. A copy that vanished (a Stop) counts as "unknown", not blind, with the same guard
  `sw_wifi_stale_db` uses, and `_sw_health_warn` stays silent once the payload is stopped. With no rows in
  the window there is no verdict: the existing "recon DB not updating" warning covers that case.
- **Stop.** Nothing new is needed. The lap already runs under `wait`, and the emit loop checks `sw_stopped`
  before every report.
- **Speed.** One extra query per lap on the shared copy (no second copy). Target: less than 1 s added per lap
  on the Pager, measured before install. The per-row formatting is fork-free, and `perf_test.sh` checks it.

## 8. Testing

Offline, with `bash test/run.sh`. A new `test/eviltwin_test.sh` builds a small database per case with
python3, using the REAL schema (`bssid` and `ssid` as BLOBs, `encryption` holding real bit-field values)
and made-up MACs only.

| Case | Expected |
|---|---|
| Protected `HomeNet` plus an open `HomeNet` on another radio | one detection: the open copy's MAC, its latest signal, the name |
| One radio offering `HomeNet` both open and protected in the window | one detection (the same-address copy) |
| Mesh or dual-band: three radios, all protected, same name | nothing |
| Names that differ only in capitals, one open and one protected | nothing |
| A hidden protected radio plus a visible open one with the same name (the OWE "Enhanced Open" transition shape) | nothing |
| The open copy last seen just outside the window, then just inside it | nothing, then one detection |
| Rows with no security value | ignored |
| Names holding a pipe, a tab, control characters, or a leading `=` | still exactly one well-formed line; the CSV cell is guarded |
| Two open copies of one name | two detections, one buzz (kind cooldown) |
| `SW_EVIL_TWIN=0` | no query and nothing emitted |
| `SW_EVIL_TWIN` default | `1`, read by sourcing payload.sh in a clean process |
| Database without the `encryption` column, or all values NULL | blind-spot WARN and DEGRADED |
| Healthy database | no blind-spot WARN |
| Snapshot removed before the query (a Stop) | nothing reported and no file created |
| A whole lap (e2e) over a twin database | exactly one CSV row, one ALERT, and the LED / ringtone / vibrate calls |

**Mutation proofs** (each must turn at least one test red):
- drop the open-vs-protected test (the mesh fires)
- compare names ignoring capitals (the capitals case fires)
- re-add CYD's maker exemption (the same-address copy goes silent)
- drop the window (the stale copy fires)
- drop the `hidden = 0` filter (the Enhanced Open case fires)
- drop the name sanitizing (a hostile name splits the line)

**Existing tests.** The per-lap copy change keeps the wifi, payload, e2e, perf and portability tests green.

**Real-history replay** (local only; the data is never committed). `tools/replay_evil_twin.sh <recon.db>`
(no data in the repo) runs the real `sw_evil_twin_scan` minute by minute. On the author's database it must
report exactly the one real event of §2.3. Its numbers go into `P0-findings.md` with no names or addresses.

## 9. Deploy and verify on the Pager (needs the user)

1. Before install: time the query on the Pager's real database (a read-only copy in `/tmp`, removed
   afterwards).
2. Install, only with the user's OK. Then run a silent launcher-faithful lap with the verbs stubbed: no twin
   in the normal environment, lap time within budget, no health warnings.
3. The user launches from the menu at home: no twin alerts.
4. Live test (the user): an open network under the same name as a protected network the user owns. For
   example, give the Pager's own open access point the name of the phone's (protected) hotspot. Expect
   `Evil twin '<name>'` within a lap or two, then turn the open network off. The Pager does hear its own
   access point: the real event in the replay was the Pager's own open access point.
5. Push only with the user's OK, after the privacy check in §10.

## 10. Privacy (public repository)

- Made-up MACs and network names only, in tests, fixtures and docs. The real history appears only as counts:
  no names, addresses, dates or times from it.
- Commits are made with `TZ=UTC`, the author `Ziggy <79704039+therealziggy@users.noreply.github.com>`, and one
  `Co-Authored-By` trailer. Before any push, `git log -p origin/main..main` is searched for local paths and
  real data.

## 11. Known limits (they go in the README)

- A copy that matches the real network's password setting is not caught. That includes an open copy of an
  open café hotspot, the most common public-WiFi trick. CYD has the same limit.
- Both copies must be heard within the same window (10 minutes by default).
- It can't prove which box is lying. It reports the open one, because only the open one can lure a device.
- A twin of a hidden network is not caught: hidden radios are skipped so that Enhanced Open transition
  networks (an open radio plus a hidden protected radio with the same name) never read as twins. CYD
  cannot see hidden names either.
- A nearby router switched from open to protected during its setup triggers one alert.
- A venue that deliberately offers one name both open and protected is reported; `ignore.txt` silences it by
  address.
- The user's own Pager, running its open access point under a nearby protected network's name, is reported.
  It is an evil twin.

## 12. Out of scope

- **Karma or SSID-pool radios** (one radio, many names): user decision on 2026-09-29, evil twin only. Notes
  for a later round: in the replay no radio showed more than 2 names in any 10 minutes; the risk is
  enterprise access points that put several names on one address; it needs a real capture to set a
  threshold.
- **Memory of names that were protected on earlier days** (brainstorming approach C): rejected. Factory
  default names collide across places.
- **Decoding the full encryption bit field** (e.g. to recognise Enhanced Open): not needed. Its transition
  mode hides the protected radio, and rule 2 skips hidden radios.
- **Look-alike names** (a trailing space, homoglyphs): exact matching only, as in CYD.
- **Pwnagotchi and Remote ID beacons:** they are not in recon.db (raw frames, the Tier-4 subsystem).
