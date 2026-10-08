# SquachWatch — a cheaper Remote ID decoder, and a frame cap of 700 (design, 2026-10-08)

Status: design approved by the user (2026-10-08). Builds on the Remote ID spec
(`2026-10-01-squachwatch-remote-id-wifi-design.md`, §6.1 to §7.5). Each number below says whether it was
**measured**, **modelled** (worked out from measured numbers) or **inferred**.

## 1. Why

- **Busy places.** On two walks on 2026-10-08 the Pager's recon heard 1,000 to 1,500 different access points
  per 10 minutes, against about 50 at home (measured: the recon database, counted by each access point's last
  sighting). At that density the 12 s Remote ID window very likely fills its 300-frame cap within seconds
  (inferred: those laps' counts were not recorded, and the WARN is only on the screen). tcpdump stops at the cap
  (`-c`), so the rest of the window hears nothing, and the lap shows the yellow "hit its frame limit" WARN.
- **The cap is there for the CPU.** An ordinary beacon costs the decoder 16.7 ms and tcpdump about 1.8 ms on the
  Pager (measured: 2026-10-08 and Phase 0), so 300 frames cost about 5.5 s of CPU a lap (modelled).
- **A slow decoder falls behind.** When the CPU is busy (the screen, the WiFi sweep), the decoder at nice 10
  falls behind, the pipe fills, tcpdump loses its summary and the lap reads `lost` (one such lap was seen on
  2026-10-08, right after a relaunch).

## 2. Where the decoder's time goes (measured on the Pager, 2026-10-08)

300 real ordinary beacons (427 KB of tcpdump text, about 26 hex lines each), the Pager's BusyBox awk, CPU (user +
system), mean of 3 runs. The beacons stayed in a temp folder on the Pager and were deleted.

| program (same input) | CPU | per beacon |
|---|---|---|
| reading the lines only | 0.07 s | 0.2 ms |
| + telling header lines from hex lines | 0.35 s | 1.2 ms |
| + reading the signal | 0.38 s | 1.3 ms |
| + joining the hex, field by field (today's way) | 3.6 s | 12 ms |
| **the whole decoder today** | **5.0 s** | **16.7 ms** |

So about 70% of the cost is the joining: each hex line is split into fields, and each 4-character field is
appended to the frame's string, about 210 appends per beacon. The decoding itself is cheap: the pre-test drops an
ordinary beacon right after its header checks.

Candidates, the whole decoder on the same input (two rounds, within 2% of each other; output identical to today's
on these 600 beacons and on all 68 fixtures, with and without a `drone:` key, on BusyBox awk and mawk):

| joining | per beacon | vs today |
|---|---|---|
| whole lines, then two pattern strips per frame | 7.9 ms | 2.1 times cheaper |
| **each line's text after tcpdump's fixed prefix, then one blank strip per frame** | **6.3 ms** | **2.7 times cheaper** |
| no strip at all (a stripped-down program, not a decoder: a floor) | about 3.9 ms | about 4 times |

(Programs that only joined, without decoding, varied from run to run: 2.6 s in one round, 5.6 s in the other.
They are not used.) The measured candidate cut every hex line and stripped blanks only; the design below adds a
check of the prefix's shape and strips tabs too, a little more per line, so its cost is measured again on the
Pager with the change (§4).

## 3. The change

### 3.1 The decoder (`lib/remoteid.sh`, `_sw_rid_awk_src`)

One regex rule, placed before the header rule, takes a line of exactly tcpdump's prefix with at least one hex word
and appends its text after the prefix; every other line goes on to the header rule and, if it is a hex line, to
today's field loop:

```awk
/^\t0x[0-9a-f][0-9a-f][0-9a-f][0-9a-f]:  / && NF > 1 { hex = hex substr($0, 11); next }
$1 !~ /^0x[0-9a-f]+:$/ { ... the header rule, as before ... next }
{ for (k = 2; k <= NF; k++) hex = hex $k }
```

(The regex has no `{4}` interval: BusyBox awk and mawk interval support is not relied on. `NF > 1` means a hex word
follows the prefix. The rule's `next` keeps the line from the two rules below it.)

and `decode()` first removes every blank and tab: `gsub(/[ \t]/, "", hex)`, before any other step.

Why the output does not change: the usual line is a tab, the 7-character offset (`0x`, four hex digits, `:`),
two spaces, then the frame's hex words separated by blanks. A line the regex matches has `0x` and its four digits
and `:` as its first field, so the header rule already left it to the hex-line rule, which joined its fields 2 to
NF. The regex fixes the prefix's shape exactly, so the cut at the 11th character falls where the fields begin;
joining the rest of the line and removing every blank and tab gives exactly the fields 2 to NF joined. A line the
regex does not match (another shape, or no hex word) takes the header rule and the field loop as before, which
leaves no blank or tab for the strip. A line with no hex words (a prefix and blanks only) added nothing in the
field loop; `NF > 1` keeps that, so a frame of only such lines never reaches `decode()`. tcpdump prints the offset
with `%04x`, and `-s 1024` keeps every offset under 0x400, so all of its output takes the new rule and decodes as
today. (The equality holds for text whose words are separated by blanks and tabs, which is all tcpdump prints.
BusyBox awk also splits fields on carriage return, vertical tab and form feed, which the strip does not remove, so
a line with one of them between its hex words could join differently; tcpdump never prints one, and no fixture has
one.)

### 3.2 The frame cap

`SW_RID_MAX_FRAMES` defaults to **700** (from 300): the default in `payload.sh`, and the fallbacks for an unset or
malformed value in `sw_rid_start` and `sw_rid_collect`. 700 frames cost about 5.6 s of CPU a lap at the cap
(6.3 + 1.8 ms a frame; modelled), about what 300 cost before, and a busy window is heard about 2.3 times longer
before it fills.

Unchanged: `SW_RID_SECONDS` 12, `-s 1024`, `SW_RID_MAX_DRONES` 32, and every health rule (`capped` when captured
reaches the cap; the slack of 5 + received/12; the rest of §7.2).

## 4. Testing

- **Differential:** every fixture (12 + 56 hostile) and the whole streams, at max 32, 0 and 1, without and with a
  `drone:` key: the decoder's output equals that of the same decoder with today's joining, kept in the test as the
  reference.
- **The fallback and the strip:** lines whose prefix has another shape (a five-digit offset, a blank instead of the
  tab, one blank after the colon) take the field loop; a usual line with a tab between its hex words takes the fast
  path and the strip. Each decodes as it does with the field loop alone.
- **The fast path is used:** a static check that the decoder holds the regex rule's exact line.
- **The cap:** the tests that assume 300 move to 700 (the payload's defaults, tcpdump's arguments, the capped lap
  at the default cap, the decoder's speed test's comment).
- **Mutants** (a new group): the fast path's shape checks loosened, the strip removed, the cap's default or a
  fallback left at 300: each must be caught.
- The full suite as user and as root; the whole mutation matrix on copies; the privacy scan before the push.
- **On the Pager** (each step with the user's OK): the install; one benchmark on 300 real beacons (the cost per
  beacon, and the output identical to the old decoder's); the decoder's awk parity on the Pager's BusyBox awk
  (fixtures and streams, with and without a key); a silent launcher-faithful run.

## 5. Docs

The README (the cap and its cost), the Remote ID spec (§6, §7.5, and a section on this change) and P0-findings
(the measurements in §2, and the checks on the Pager after the install).

## 6. Not in this change

- Reading the bytes without any strip (about 4 times cheaper, a rewrite of the decoder's byte addressing): later,
  and only if 700 is not enough in busy places.
- Counting the frames a window hears in busy places (a logged walk): optional, after this change.
- tcpdump's own cost (about 1.8 ms a frame).
