# SquachWatch-Pager — Noise control: floods, one buzz per kind, follow floor (design)

**Date:** 2026-09-23 · **Status:** approved in brainstorming, pending spec review
**Parent specs:** `2026-09-21-squachwatch-pager-design.md` (core v1),
`2026-09-22-squachwatch-tier3-ble-adv-design.md` (Tier-3: follow, snooze, BLE records)

## 1. Goal

Keep the Pager usable when many devices of one kind appear at once (a Flipper running BLE
Spam, a hacker con full of real Flippers), stop the cooldown ledger growing forever, and stop
a weak, stationary tracker (a neighbour's) from raising a "following you" alert at home, all
without dropping any detection from the loot CSV.

**Decisions made in brainstorming (user, 2026-09-23):**
- **Buzz policy:** one full-screen alert + buzz per *kind* of device per 10 min. Later new
  devices of that kind within the window are logged silently (screen line + CSV row).
- **Screen:** per lap, at most 3 lines per kind, then one `...and N more <label>` line.
- **Follow floor:** the follow timer ignores sightings weaker than −85 dBm (a setting).
- **Approach A:** small gates inside the existing per-lap loop and `sw_emit`, reusing the
  existing ledger function. Rejected: B (two-pass lap, so the alert could carry the flood
  count; it restructures the most-tested code) and C (random-address awareness; see §14).
- Decided without asking (reuse, or no product choice involved): CYD's name-only rule (§3.2),
  strongest-match-wins (§3.1, required by §3.2), ledger pruning (§7).

## 2. Findings that shape this design

**Field test, 2026-09-23 (a few minutes of scanning), from the loot CSV (Pager UI launch):**
- Real Flipper `80:E1:26:FA:D6:22` ("MyFlipper"): 1 row, 1 alert (matched by `ble_oui`).
- The phone's Tile / SmartTag / Google Find My adverts: 1 med row each.
- **BLE Spam, ONE lap:** 9 × `hacker_flipper` **high** (9 random MACs, name
  `Flipper 🐬`, matched by `ble_name_sub|flipper`) + 4 × `tracker_airtag_setup` med
  (random MACs). That is **9 full-screen alerts and 9 buzzes in one lap.**
- A real separated Apple Find My (`F4:46:D0:F4:1A:D0`) at **−95 dBm** was present every lap for
  3 min. `lib/follow.sh` is time-only, so a device like this would escalate to "following you"
  after `SW_FOLLOW_SECS` while the Pager sits at home (inferred; it was only seen for 3 min).

**Mechanism (code read):**
- `sw_should_report` keys the cooldown on `mac|category`, so every random MAC is "fresh",
  and base detections go through `sw_emit` without AUTO SNOOZE.
- `sw_should_report` only appends to `seen.db`; nothing ever prunes it.
- `sw_match_record` prints one detection **per matching rule**, in `signatures.db` order. When
  two rules of one category hit the same record, the first one takes the `mac|category`
  cooldown slot; the second is "not fresh" and prints a duplicate log line.

**SquachWatch-CYD (github skizzophrenic/SquachWatch-CYD, read 2026-09-23):**
- **Reuse:** a HACKER device matched by BLE name alone is `MED_CONF`, and by UUID/company-ID
  it is `HIGH_CONF` (`src/detection.cpp`:
  `det.conf = matchedByName ? Confidence::MED_CONF : Confidence::HIGH_CONF;`).
  `docs/DETECTIONS.md` rates the Flipper name Medium because "the owner can change it".
- **Improve (no CYD equivalent):** CYD has no flood handling. It dedupes on MAC + type
  (`memcmp(_log[slot].mac, d.mac, 6) == 0 && _log[slot].type == d.type`), has no
  random-address handling, and lets each iBeacon alert ("dozens of alerts in a row",
  `src/ui_beaconwarn.cpp`). Its "auto quiet" is the per-device AUTO SNOOZE already ported.
  It has no RSSI floor and no automatic following detection.
- **Hardware differs:** its flood code (`SCAN_PASSIVE_ABOVE = 300` adverts/s, heap-pressure
  flushes) protects ESP32 RAM. Nothing to port.

## 3. Matching (`lib/match.sh`, `signatures.db`)

### 3.1 One detection per record per category, strongest wins
`sw_match_record` emits at most **one** detection per category for a record: the hit with
the highest confidence (`high` > `med` > `low`); on a tie, the rule listed first in
`signatures.db`. Detections of *different* categories are unaffected. Output order is the
order in which each category was first hit.

- This does not change which `(record, category)` pairs are detected. It only removes
  duplicates, and §9 proves it with an old-vs-new differential over every fixture.
- It stays fork-free: `match.sh`'s per-record PERF CONTRACT and `test/perf_test.sh` apply.
- Side effect: a device matching two rules of one category prints one log line, not two.

### 3.2 A Flipper matched by name alone is `med` (CYD)
`ble_name_sub|flipper|hacker_flipper|Flipper Zero|med|attacker` (was `high`), with a comment
citing CYD. A device matched only by a "…flipper…" name gets a cyan line and a CSV row and
never buzzes. A Flipper matched by its hardware prefix (`ble_oui|80:E1:26`, high) still
alerts, and so does a stock Flipper named "Flipper <x>", which matches both rules (§3.1).
Only the BLE-name hacker rule changes, because CYD applies the rule to BLE names only
(`lookupBtName`).

## 4. One full alert per kind per window (`lib/alert.sh`, `sw_emit`)

A *kind* is a detection category (`hacker_flipper`, `flock_alpr` and `flock_battery` are
three kinds). After the existing `fresh && conf = high` check, a **base** detection may
interrupt only if its kind has not interrupted within `SW_KIND_COOLDOWN` seconds:

```
sw_should_report "*" "$cat" "$now" "$kind_cd" "$sf"   # key "*|<category>" in the same ledger
```

This is the **last** gate, so the kind's time is recorded only when an alert actually fires.
- **Exempt:** categories ending in `_follow`. Each follower is a separate possible stalker,
  and AUTO SNOOZE already limits it per device. A follow alert is never held by this gate.
- **A held alert changes nothing else:** the device is still fresh, so it still gets its CSV
  row and its log line (subject to §5).
- **Policy location:** `sw_emit` reads `${SW_KIND_COOLDOWN:-0}` at the point of use (0 or empty
  = off, so direct callers and existing unit tests keep today's behaviour). `payload.sh` owns
  the default: `: "${SW_KIND_COOLDOWN:=600}"`. No `:=` in a lib (P0 lesson, 2026-09-22).
- **Ledger key safety:** MAC keys are 17 characters and never `*`, so `grep -F "*|cat|"`
  cannot match a device line. The trailing `|` keeps `hacker_flipper` from matching
  `hacker_flipper_follow`, the same property the device keys rely on today.
- **Steady state:** two Flippers present continuously now buzz once per 10 min in total,
  not once per device. That follows from the chosen policy.

## 5. Screen cap (`payload.sh`, `sw_scan_once`)

`sw_scan_once`'s loop already runs once per lap in the pipeline's subshell. It keeps per-lap
counters keyed by **category AND confidence** (bash associative arrays on the composite key
`"<category>|<confidence>"`: lines shown, lines hidden, first label, first threat class), not
by category alone. This is so a lap's real high-confidence detections of a kind get their own
allowance and their own summary line, separate from a med/low flood of that same category —
the case that mattered in practice: the user's real Flipper (`ble_oui`, high) must never be
folded behind a BLE-Spam name-only flood of fake Flippers (`ble_name_sub`, med) in scan order,
and a summary line for one group must never borrow the other group's count. For every
`sw_emit` call in the loop (base detections that pass the ignore filter, and follow
detections):
- if the (category, confidence) group has already shown `SW_LOG_PER_KIND` lines this lap, the
  loop calls `SW_EMIT_NOLOG=1 sw_emit …` (a call-scoped variable). `sw_emit` then skips
  **only** its `LOG` line. CSV row, cooldown, alert and follow update are unchanged. The loop
  counts it as hidden.
- After the loop, each (category, confidence) group with a hidden count *n* > 0 prints
  `LOG <colour> "...and <n> more <label>"`, using the label and colour (`sw_color_for`) of that
  group's first detection in the lap, in order of first appearance. Two groups of the same
  category (e.g. the real high-confidence Flippers and the med name-only flood) can each
  overflow independently and each print their own summary line — both read `Flipper Zero`
  since the label comes from the detection, not the group key, but each count is correct for
  its own group.
- Follow detections (`<cat>_follow`) are their own category, so they have their own count.
- The "first 3" are in scan order, not sorted by signal.
- The text is plain ASCII `...`. The Pager's font showed our `—` as `-` in the 2026-09-23
  screenshot, and `…` is untested.
- The counters live in the lap's subshell, so they reset every lap.
- `sw_emit` reads `${SW_EMIT_NOLOG:-}`. Called anywhere else (unit tests, one-shot use), it
  logs exactly as today. `payload.sh` default: `: "${SW_LOG_PER_KIND:=3}"` (0 = no cap).

## 6. Follow floor (`lib/follow.sh`, `sw_follow_update`)

After the existing tracker-class check: if the floor is a **negative integer** and the
detection's RSSI is a number weaker than it, `sw_follow_update` returns 0 **without reading or
writing the state**, so the sighting does not count. Anything else the floor could hold —
unset, empty, `0`, a positive number like `85` (both natural guesses, since the sibling
settings use `0` = off), or garbage — means the floor is **off** (final review I6): an earlier
`${SW_FOLLOW_MIN_RSSI:=-85}` (with `:=`) replaced an explicitly-empty value with the default
too, so the documented "empty turns it off" never actually worked, and a plain `-?[0-9]+`
check on the floor accepted `0`/`85` as if they were real thresholds — silently disabling
follow detection, since a real tracker's RSSI (e.g. −40) reads as "weaker than 0 or 85" under
an ordinary numeric comparison.
- The floor is inclusive: exactly −85 counts.
- A missing or non-numeric RSSI **counts**, so a missing reading can never hide a tracker. This
  check is unchanged; only the floor's own validation is stricter.
- Weak sightings do not refresh `last_seen`. A tracker that stays weak longer than
  `SW_FOLLOW_GAP` restarts its clock at the next strong sighting: the existing gap check
  drops its entry on that read.
- The tracker's own presence line and CSV row are unaffected (`sw_emit` runs first).
- `follow.sh` reads `${SW_FOLLOW_MIN_RSSI:-}` and requires it to match `^-[1-9][0-9]*$` (a
  negative integer, no leading zero) to count as a floor. `payload.sh` default (unset-only, so
  an explicitly empty value stays empty): `: "${SW_FOLLOW_MIN_RSSI=-85}"`.
- The detection's RSSI is the strongest reading for that MAC in the lap's capture (parser).

## 7. Ledger pruning (`lib/alert.sh`, `sw_seen_prune`)

`sw_seen_prune <seenfile> <now> <keep_secs>` rewrites the ledger through
`mktemp "$sf.XXXXXX"` + `mv`, the same pattern as the follow and snooze state.
- It keeps a line only if the WHOLE line matches `key|category|<int>`, where `<int>` has no
  leading zero (`[1-9][0-9]{0,11}`, final review 2), and that timestamp is both `<= now` and
  satisfies `now − ts < keep_secs`. Checking only the last field used to let a torn line (two
  ledger appends fused into one by an interrupted write) survive, since its own last field
  could still be a valid recent int even though the line was garbage; a future-dated line
  (after a backward clock step) used to survive too, since `now − ts` is negative and trivially
  `< keep_secs`; a LEADING ZERO (e.g. `0800` or `09`) used to survive the shape check too, since
  it is still all-digits, but then reached bash arithmetic as an invalid octal literal and
  raised a fatal error. A bash arithmetic error like this only ever abandons the current
  top-level command (final review 3, T3) — but `sw_seen_prune` is reached from `sw_main`
  (`payload.sh`'s own last top-level command) with no subshell in between, so here that killed
  the whole payload, not just this one prune. All three are dropped now, the same shape
  `sw_should_report` requires before it does arithmetic on a stored timestamp (§8, final review
  I4 + m1, and final review 2). Older lines can no longer block anything either way, since
  `sw_should_report` only holds while `now − last < cooldown` for a validated timestamp.
- `payload.sh` passes `keep_secs = max(SW_COOLDOWN, SW_KIND_COOLDOWN)` and calls it in
  `sw_main` at startup and every `SW_HEALTH_EVERY` laps, next to the health check. The lap
  pipeline has finished by then, so there is no concurrent writer.
- **Two passes (final review 2):** a READ-ONLY first pass reads the ledger once to count how
  many lines a rewrite would drop and whether the file is missing its final newline (see
  below) — no `mktemp`, no temp file. Only when there is something to do (a line would be
  dropped, or the newline is missing) does a second pass open a temp file and perform the
  actual rewrite. A healthy, already-clean ledger costs one read and nothing else: no temp file
  is ever created for it, closing a gap in the round-1 no-op skip, which only proved the `mv`
  was skipped (same inode) while still silently creating, fully writing, and then unlinking a
  temp file every time.
- **Missing final newline (final review 2):** the read-only first pass also detects a ledger
  whose last line was not terminated with `\n` (a power cut, a hand edit). Previously this
  counted as "every line kept, nothing to do" and the file was left untouched, so the next
  append would fuse onto that unterminated last line — creating exactly the torn-line shape
  this function exists to clean up. A missing final newline now forces the rewrite even when
  every line is otherwise kept as-is; the rewrite always writes `\n`-terminated lines.
- **Unreadable ledger path (final review 2):** a path that exists but is not a plain, readable
  file (a directory; or, for a non-root process, permission-denied) is a failure, not "nothing
  to prune" — without an explicit check the read loop simply never runs (0 lines seen), which
  used to look exactly like an already-clean ledger: rc 0, no WARN. A genuinely MISSING ledger
  is still fine. This check is by file type and read permission, not by the loop's own exit
  status, so it is robust as both root (which can read a permission-denied file, so there is no
  bug to catch there) and non-root.
- **On failure** (the ledger path check above, `mktemp`, a write into the temp file, the temp
  file failing to even open, or `mv` fails), the ledger is left untouched, the temp file is
  removed, and `LOG yellow "WARN: can't prune <file> — it will keep growing"` fires, so it
  never fails silently. The whole rewrite goes through ONE open of the temp file (final review
  m3): an earlier version wrote with an append per kept line and `mv`'d unconditionally, so a
  write failure partway through (e.g. ENOSPC) went undetected and the ledger was still replaced
  — with a truncated or empty file. The temp file failing to even OPEN (final review 2, as
  opposed to a write into an already-open one failing) is caught the same way, on the rewrite
  loop's own redirect (`done < sf > tmp || wfail=1`; a loop's own exit status reflects a
  redirection that could not be set up at all). Without this, a temp path that exists but can't
  be opened for writing is worse than silent: `mv` only needs write permission on the
  *directory*, not the file, so an unconditional `mv` would still "succeed" and silently
  replace the real ledger with that stale, unwritten file. That is at most once per
  `SW_HEALTH_EVERY` laps.
- It stays a bash read loop with no per-line forks. The ledger stays at `SW_SEEN_FILE` on
  flash, so cooldowns survive a relaunch. One rewrite per ~10 min is negligible flash wear.

## 8. Failure modes and invariants

- **Ledger unwritable:** `sw_should_report`'s append fails and it still answers "fresh", so
  alerts fire. The kind gate errs toward **more** alerts, never silence, the same as the
  per-device cooldown today.
- **Clock steps, torn ledger lines, and leading zeros fail OPEN, never silent (final review
  I4 + m1, and final review 2).** `sw_should_report` validates its stored timestamp — a plain,
  NO-LEADING-ZERO integer, no greater than `now`, and closer than the cooldown — with a
  `[[ =~ ]]` check BEFORE any arithmetic touches it, and holds (returns 1) only when all
  three hold. Three ways that value can be wrong, all found by the final review against the
  real ledger format:
  - a **future timestamp**, e.g. after a backward clock step (the Pager has `/dev/rtc0` plus
    ntpd, so this is unlikely but possible), used to hold a device — or, with a `*|category`
    key, a **whole kind** — silent until the clock caught up, which can be as long as ~24 h;
  - a **torn line**, two ledger appends fused into one by an interrupted write (e.g.
    `AA:…|cat|1790266851C2:00:00:00:00:02|cat2|1790266901`), whose relevant field is not an
    integer at all. Reading it into `$((now - last))` used to raise a bash arithmetic error
    that **aborted the rest of the caller's lap**: other devices in that same lap silently lost
    their CSV row and log line, with nothing but a stderr line no one was reading;
  - a **leading zero** (final review 2, e.g. `0800` or `09`), still all-digits so it passed the
    original shape check, but read by bash arithmetic as an invalid octal literal (`8`/`9`
    don't exist in base 8). This raised the same class of fatal arithmetic error as a torn
    line, with the same consequence here (final review 3, T3): a bash arithmetic error only
    ever abandons the current top-level command, which inside `sw_scan_once`'s lap loop
    (`sw_should_report`'s real call site) costs the rest of that lap — and every lap the bad
    line survives, since the fresh append after the check never ran either — never the whole
    payload. (`sw_seen_prune`, reached directly from `sw_main` with no subshell in between, is
    the one call site where the same class of error really does end the payload — §7.)

  All three shapes are now simply treated as fresh, the same as no ledger entry at all — the
  failure mode is one extra alert, never a hold. `sw_seen_prune` applies the same shape check
  (`^[^|]+\|[^|]+\|[1-9][0-9]{0,11}$`, and the timestamp must be `<= now`), so future-dated,
  torn, and leading-zero lines are dropped on the next prune instead of lingering indefinitely.
- **Garbage RSSI:** the follow floor counts it (errs toward alerting).
- **Prune failure:** WARN, and the file is left unchanged (§7).
- **Invariants, asserted by tests:** (1) `low`/`med` never ALERT or buzz; (2) every fresh
  device gets its CSV row, since no rule in this spec suppresses a row; (3) a follow alert is
  never held by the kind cooldown.

## 9. Testing (offline; a positive control on every negative)

Each behaviour gets a should-hit case and a should-stay-quiet case. Load-bearing ones are
mutation-proven: break the code and the named test must fail.
1. **Strongest wins (`match_test.sh`):**
   - name(`med`) + prefix(`high`), same category → exactly one detection, `high`;
   - two same-confidence rules → one detection with the first rule's label;
   - different categories → both.
   - **Differential (one-off, recorded in the commit):** old (`HEAD`) vs new
     `sw_match_stream` over every fixture (`recon.db`, `btmon_synthetic`,
     `btmon_phone_2026-09-23`, `btmon_hostile`, the new spam fixture) → identical sorted
     `(mac, category)` sets.
   - Mutant: remove strongest-wins → the stock-Flipper test below fails.
2. **Flipper name rule:**
   - `signatures_test.sh`: the rule is `med`.
   - Pipeline: a name-only flood gives rows and no ALERT; a prefix-matched Flipper gives an
     ALERT; a stock Flipper (name + prefix) gives exactly one detection and an ALERT.
3. **Kind cooldown:**
   - 9 new high devices of one kind in a lap → exactly 1 ALERT and 9 CSV rows;
   - next lap, 9 more new devices → 0 ALERTs;
   - after `SW_KIND_COOLDOWN` → 1 ALERT;
   - another kind in the same lap → its own ALERT;
   - a `_follow` alert inside the window → still ALERTs.
   - Mutants: remove the gate / remove the `_follow` exemption → the matching test fails.
4. **Screen cap:**
   - 9 of a kind → exactly 3 device lines + `...and 6 more <label>`;
   - exactly 3 → no summary line;
   - two kinds → capped separately;
   - the next lap's counts restart;
   - hidden devices still get CSV rows.
5. **Follow floor:**
   - −95 dBm for longer than `SW_FOLLOW_SECS` → no follow detection;
   - −70 → follow;
   - exactly −85 → counts;
   - empty RSSI → counts;
   - weak for longer than the gap, then strong → the clock restarts.
6. **Pruning:**
   - an old line is removed **and** a recent line kept (both asserted, so an emptied file
     cannot pass);
   - both key shapes (`mac|cat`, `*|cat`) are handled;
   - a malformed line is dropped;
   - unwritable directory → WARN, file unchanged.
7. **Defaults in a clean process:** `SW_KIND_COOLDOWN=600`, `SW_LOG_PER_KIND=3`,
   `SW_FOLLOW_MIN_RSSI=-85`, read by sourcing `payload.sh` with nothing preset (P0 lesson:
   a test that pins a value cannot see its default).
8. **Existing tests that scan twice** (the snooze asserts in `payload_test.sh`, which
   expect a Flipper ALERT in lap 2) will be held by the kind cooldown. The plan pins
   `SW_KIND_COOLDOWN=0` on exactly those scans; item 7 covers the real default.
9. `test/perf_test.sh` (latency budget + static fork-free checks) and
   `test/portability_test.sh` stay green.

## 10. Real spam fixture

With the user running the same Flipper BLE Spam mode as on 2026-09-23 for about 15 s, capture
`btmon` on the Pager over SSH. Start the scan the way the payload does (`hciconfig`
down/reset/up, `hcitool lescan`, `btmon`) and stop it with SIGINT. Save the capture as
`test/fixtures/btmon_blespam_<date>.txt`, pinned as captured, like
`btmon_phone_2026-09-23.txt`.

Pinned expectations:
- it parses to at least 5 distinct MACs whose name contains "flipper";
- through the pipeline: 0 ALERTs from the name-only flood, at most 3 name-only Flipper lines
  per lap plus `...and N more Flipper Zero`, and one CSV row per distinct MAC. If the capture
  also contains the user's real Flipper (`ble_oui`, high), it gets its own line and its own
  per-lap allowance (§5, final review I1), separate from the name-only group's: with the real
  capture used in this suite, that is 4 Flipper lines total per lap (3 name-only + the real
  one's own line), plus the name-only group's own `...and N more Flipper Zero`.

It is the positive control shaped like the real threat (vacuous-probe lesson #39). BLE Spam
can trigger pop-ups on nearby phones, so keep such tests brief and away from other people.

## 11. On-device verification (through the Pager menu, not SSH)

1. Full suite green; deploy with `scp`; device files == `HEAD`.
2. The user relaunches from Payloads → reconnaissance. This is **not** `bash payload.sh` over
   SSH: the menu launcher runs a `/tmp` copy (P0 finding, 2026-09-23).
3. BLE Spam for ~30 s → no buzz from the name-only flood; per lap at most 3 name-only Flipper
   lines plus `...and N more Flipper Zero`; the CSV gains a row per distinct spam MAC. If the
   real Flipper's Bluetooth is also on (as in step 4), it adds its own Flipper line on top of
   those 3 (4 Flipper lines per lap total), since it has its own per-confidence allowance (§5).
4. The real Flipper's Bluetooth on → exactly one buzz (`Flipper Zero 80:E1:26:…`).
5. I read the loot CSV and `seen.db` over SSH: rows present, and no ledger entry older than
   `keep_secs` + `SW_HEALTH_EVERY` laps (about 20 min: the 10-min window plus up to 20 laps
   between prunes).

## 12. Config (defaults owned by `payload.sh`; libs read `${VAR:-off}` at the point of use)

| Variable | Default | Meaning |
|---|---|---|
| `SW_KIND_COOLDOWN` | `600` | One full alert + buzz per category per window (s). `0` = off. |
| `SW_LOG_PER_KIND` | `3` | Screen lines per category AND confidence per lap before `...and N more`. `0` = no cap. |
| `SW_FOLLOW_MIN_RSSI` | `-85` | The follow timer ignores sightings weaker than this: a negative number without a leading zero, e.g. `-85`; `-085`, `0`, `85`, or empty all turn it off. |

## 13. Limits and confidence

- **The −85 dBm floor is a judgment call** (inferred) from one evening's readings: close range
  −52…−75, the unknown Find My −95. A tracker hidden far from the user could read weaker than
  −85 and never escalate. It is a setting so it can be tuned.
- A second real device of a kind within 10 min does not buzz (it is logged). This is the
  chosen trade-off.
- **Your own devices belong in `ignore.txt` (user decision, 2026-09-23: docs only, no code
  change).** A device that stays near you (your own Flipper, say) re-alerts every
  `SW_KIND_COOLDOWN` window, which is the kind's one buzz: it takes that buzz for itself, so a
  stranger's device of the *same kind* arriving inside that window is still logged (screen
  line + CSV row) but does not buzz. Putting your own devices in `ignore.txt` avoids this,
  since an ignored device never reaches `sw_emit` at all. Residual case: a *stranger's* device
  that stays continuously nearby (not yours, so it can't go in `ignore.txt`) can still hog the
  kind's buzz the same way; other devices of that kind stay visible on screen (subject to
  §5's cap) and in the CSV the whole time, just silent. Possible future task, not built here:
  a per-device buzz limit — AUTO SNOOZE (§4's exempt case already has this) applied to every
  alert, not only "following you" ones — which would bound this without needing an
  ignore-list entry.
- A real Flipper advertising only under a random MAC with a "Flipper" name now logs without
  buzzing. Its hardware prefix is what alerts. CYD's company ID `0x0E29` and UUIDs
  `0x3081–0x3083` arrive with the signature port.
- `wifi_ssid_sub|pineapple` still alerts `high` on an SSID alone, which is spoofable in the
  same way. Revisit it in the signature port.
- The "first 3" lines are in scan order, and the alert text names one device, not the flood
  size (that is approach B).
- The ledger stays on flash. Pruning bounds its size but does not remove the writes.

## 14. Non-goals (this phase)

- Random-address awareness from btmon's address type (approach C): it changes the parser, a
  boundary whose adversarial review is still open, and real trackers also use random
  addresses, so distinct trackers would merge.
- A flood count inside the full-screen alert (approach B).
- CYD-style "regulars" (devices seen on 3 days) as a neighbour filter.
- A dedicated "BLE spam" detection category.
- The CYD signature port and the parser adversarial review, which remain separate items.
