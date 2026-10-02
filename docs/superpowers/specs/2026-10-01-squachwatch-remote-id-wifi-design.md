# SquachWatch-Pager — Remote ID over WiFi (design)

**Date:** 2026-10-01 · **Status:** approved in brainstorming (scope, transports, alert grade, design), then
revised after fact-checking before this was written down. Every revision is listed in §2.5 for the user's
review of this spec.
**Parent specs:** `2026-09-21-squachwatch-pager-design.md` (core v1, which defers drone Remote ID to a later
tier), `2026-09-22-squachwatch-tier3-ble-adv-design.md` (the Bluetooth `fffa` presence rule and the
bounded-capture lifecycle copied here), `2026-09-23-squachwatch-noise-control-design.md` (the gates reused
here), `2026-09-29-squachwatch-evil-twin-design.md` (the "finished detection" path, and the category-specific
branches in `sw_emit` / `sw_ignored` that this extends).
**Sources (logic and formats, not code):** SquachWatch-CYD release v1.24.0 notes (upstream); the CYD fork's
pull request retrodroid32/SquachWatch-CYD#31 (`src/remote_id.cpp`: `validMessagePack`, `isWifiBeacon`,
`isWifiNanAction`; `src/detection.cpp`); opendroneid-core-c (`libopendroneid/wifi.c`, `opendroneid.h`) for
the frame layouts and message encodings; ASTM F3411-22a.

## 1. Goal

Most drones flown today must broadcast **Remote ID**: a public "digital licence plate" that says which drone
it is, where it is, and where its pilot is (or where it took off). Some drones broadcast it over Bluetooth
(SquachWatch already notices that, presence only, rule `fffa`); many, including DJI's current models,
broadcast it in **WiFi** frames.

When a drone nearby broadcasts Remote ID over WiFi, SquachWatch decodes it and shows and records:

- **which drone:** its ID (normally the manufacturer serial number) and airframe type;
- **where it is:** position, height, altitude, speed, vertical speed and heading;
- **where the pilot is:** the operator position, or the take-off point, as the drone reports it;

with a full alert and a buzz.

**User decisions (2026-10-01):** full telemetry; all three WiFi forms (the standard ASD-STAN beacon, WiFi NAN,
and Parrot's beacon); graded HIGH with a buzz, like a real threat. Approved with the design: one drone =
one ID (not one radio address); a separate `remoteid.csv` for the telemetry; signal strength stays the only
"how close" measure.

Out of scope for this round: §13 (decoding Bluetooth Remote ID is the natural next step).

## 2. Findings that shape this design

### 2.1 How CYD does it

- **Upstream CYD (v1.24.0, "Look Up"):** decodes Bluetooth Remote ID (Basic ID gives the serial and airframe
  type, Location the position and altitude, System "where the pilot is standing"), accumulating messages
  per address. Over WiFi, "beacons carrying the ASD-STAN vendor element (FA:0B:BC, type 0x0D) are logged as
  DRONE", named by the serial. No NAN, no Parrot.
- **The fork's pull request #31** adds strict framing checks, which this design copies byte for byte:
  - *Beacon:* walk the information elements from offset 36 (24-byte header + 12 bytes of fixed fields). A
    vendor element (ID `0xDD`, length ≥ 8) with the ASD-STAN OUI `FA:0B:BC` **and** type `0x0D`, or with
    Parrot's OUI `90:3A:E6` (any type byte). In both, the message pack starts after OUI (3) + type (1) +
    message counter (1), and must be **structurally valid**: the first byte's high nibble is `0xF`, the
    message size byte is 25, the count is 1 to 9, and 3 + 25 × count bytes fit inside the element. That
    check is what keeps Parrot's other vendor elements from becoming drones.
  - *NAN:* an action frame (`frame[0] & 0xFC == 0xD0`) addressed to `51:6F:9A:01:00:00`, then the bytes
    `04 09 50 6F 9A 13` (public action, vendor specific, Wi-Fi Alliance OUI, NAN type), then a **search**
    for the 6-byte service hash `88 69 19 9D 92 09` ("org.opendroneid.remoteid") anywhere after the NAN
    header, because "attribute layouts vary as optional NAN fields are present".
  - The radio identity is the transmitter address (addr2). The fork only **recognises** NAN and Parrot
    frames; it does not decode them.
- Both run on an ESP32 that owns its 2.4 GHz radio in promiscuous mode and parses every frame in C.
- CYD's "a ten-digit serial is LOW" rule is about Flock battery packs, not drones: not ported.

### 2.2 What the Pager offers (checked on the device, 2026-10-01)

- **The recon database cannot hold Remote ID.** Its `ssid` table stores a name, an address, security,
  signal and channel: no vendor elements, no raw frames. So Remote ID needs raw frames, unlike every other
  WiFi detection in the app.
- **tcpdump is stock.** tcpdump 4.99.5 and libpcap 1.10.5 are in the firmware image (`/rom/usr/bin/tcpdump`;
  opkg `tcpdump 4.99.5-r1`), so every Pager has them. Link type `IEEE802_11_RADIO` (radiotap). `-xx` prints
  the whole frame, starting with the radiotap header (version 0, then its length: 56 bytes here). tcpdump is
  also the only hex dumper on the device (no `od`, no `hexdump`: P0-findings).
- **Filter syntax:** this libpcap rejects `type mgt subtype action` ("syntax error"). The frame-control byte
  works: `wlan[0] & 0xfc = 0xd0`. `wlan[]` offsets are taken after the radiotap header (libpcap reads its
  length). The whole filter of §6.1 compiles.
- **Radios:** phy1 = `wlan1mon` (monitor), channel-hopped by `pineapd --recon` across 2.4 and 5 GHz (one
  8-second sample heard beacons on 10 different frequencies between 2412 and 5785 MHz). phy0 = `wlan0`
  (station) plus `wlan0mon`, which sits on the station's channel. Neither can be retuned without disturbing
  recon or the station link.
- **Tools:** BusyBox awk 1.36.1; bash 5.2 with `patsub_replacement` on (hex to bytes with builtins:
  `${h//??/\\x&}` then `printf -v … %b`); `nice` and `mkfifo` present.
- **On exit tcpdump reports** `N packets captured` / `received by filter` / `dropped by kernel` on stderr,
  and at start `listening on <iface>, link-type …`. Both are free health signals (§7.2).

### 2.3 Cost, measured on the Pager (the author's home, 2026-10-01)

- Beacons on `wlan1mon` while recon hops: 137 in 20 s, and 194 in another 20 s (about 7 to 10 a second).
  Action frames of any kind: 1 in 20 s.
- Hex-dumping every beacon for 20 s through an awk join that looks for the three Remote ID markers:
  2.03 s user + 0.35 s system CPU, about 12% of the CPU. The split between tcpdump and awk is not known yet
  (Phase 0, §9).
- A busier place has more beacons, and a beacon flood (a common attack tool) far more. Hence the caps in
  §6.1.

### 2.4 The Bluetooth capture this copies

Tier-3's btmon is **not** continuous: it runs for a bounded window each lap (`SW_BLE_SECONDS`, 12 s) under
its own `timeout`, so it ends by itself if the payload is killed, and the lap parses the capture after the
window. Nothing is ever stopped by name (`lib/ble.sh`).

### 2.5 Corrections to the brainstorming sketch (for the user's review)

1. *"An in-kernel filter picks out only Remote ID frames."* Wrong for beacons: the kernel filter (classic
   BPF) cannot loop, so it cannot search a beacon's variable list of elements. The kernel narrows the
   capture to beacons plus NAN-addressed action frames (that address is fixed, so NAN **is** matched
   exactly in the kernel); a text filter in awk then finds the Remote ID beacons. That costs CPU, so the
   capture is capped (§6.1, §7.5).
2. *"A continuous background capture, like btmon."* btmon is a bounded window per lap (§2.4). So is this
   capture: same lifecycle, same Stop safety.
3. *"DJI uses NAN."* Wrong: DJI's standard Remote ID (Mini 3 / 4 Pro, Mavic 3, Air 3) is broadcast in
   beacons, which the baseline beacon path covers. NAN stays in (user decision); it is nearly free.
4. *"CYD decodes beacons, DJI NAN and Parrot."* Upstream CYD recognises ASD-STAN beacons; NAN and Parrot
   recognition come from the fork, which does not decode them (§2.1).
5. *"The Pager has no GPS."* It has no built-in GPS, but `GPS_GET` returns a fix when a GPS is attached, and
   every CSV row already records it. `remoteid.csv` records it too (distance to the pilot stays out of
   scope).
6. A brainstorming probe reported "0 action frames in 20 s". That command was a syntax error with its
   stderr hidden: it never ran (§2.2). The re-run, with beacons as the positive control, is in §2.3.
7. *"An OpenDroneID transmitter app on a phone" and "an ESP32 running ArduRemoteID" as test transmitters.*
   Neither works: OpenDroneID publishes no Android transmitter (its only Android app is a receiver), Android
   does not let ordinary apps put data into beacons, and ArduRemoteID only relays what a flight controller
   sends it (no standalone mode is documented). §10 says how the live test is done instead.

## 3. The rule

A frame from the lap's capture **counts** when it is one of these, with every length checked against the
frame's end:

1. **Beacon, ASD-STAN or Parrot:** a vendor element as in §2.1, holding a structurally valid message pack.
2. **NAN:** an action frame to `51:6F:9A:01:00:00` with `04 09 50 6F 9A 13` after the header, and a
   Service Descriptor attribute (ID `0x03`, 2-byte little-endian length that fits the frame) whose service
   ID is the hash `88 69 19 9D 92 09`. Inside that attribute, after the service ID: instance ID (1),
   requestor instance ID (1), service control (1), then the optional fields the control byte announces (a
   2-byte binding bitmap if bit 6, a length-prefixed matching filter if bit 2, a length-prefixed service
   response filter if bit 3), then, if bit 4 says service info is present, its length (1) and the service
   info: message counter (1), then the message pack. The pack must be structurally valid and fit inside
   the service info. (The reference encoder uses control `0x10`, none of the optional fields: that is the
   layout the fixtures prove; frames using the optional fields are parsed by the same rules, untested
   against a real transmitter.)

Anything else, including a recognised frame whose pack fails the check, is ignored (it is counted for the
health check only).

Then, per lap:

- **The radio** is the transmitter address (addr2), as in CYD.
- **Messages decoded** (25 bytes each, the type in the first byte's high nibble): Basic ID (`0x0`),
  Location/Vector (`0x1`), Self-ID (`0x3`), System (`0x4`), Operator ID (`0x5`). Authentication (`0x2`) and
  unknown types are skipped. A pack that holds none of these still counts: Remote ID was heard.
- **Merging:** the frames of **one address** merge (the latest message of each type, the first two distinct
  Basic IDs that hold text, the strongest signal, every form it used). A Basic ID with no text takes no
  place, and one more distinct Basic ID flags the address (§6.2; user decision 2026-10-02, after the
  re-review). The decoder does **not** merge across addresses: that is
  left to the ID-keyed cooldown (§4), which already collapses a drone whose address changes to one alert,
  within a lap and across laps alike. The only visible effect of an address change inside a single lap is
  one extra `remoteid.csv` row that lap (both rows carry the same ID). This keeps the decoder a single
  streaming pass with small per-address state. (Decided during the spike, 2026-10-01: cross-address merge
  in awk would need a second pass and buys nothing the cooldown does not already give.)
- **The drone's ID** is the first Basic ID it sends that holds any text, a serial number (ID type 1,
  ANSI/CTA-2063-A) preferred: a serial when it sends one, else its first other Basic ID (a CAA registration,
  a UTM UUID or a session ID). The other one, if any, is its second ID. The text is cut at the first zero
  byte, cleaned, and trimmed of spaces at both ends: an ID left empty (an empty serial, or spaces and control
  bytes only) is **no ID**, so it gives way to the other one. A drone with no ID at all is known by its
  address. **When one of its two IDs is listed in `ignore.txt` and the other is not, the one not listed is
  its ID** (user decision 2026-10-02, after the re-review): named by the owner's own ID, the alert would read
  as the owner's drone with an ignore list that misfired. Its ID is the same everywhere: the screen, the
  alert, the ledger key, `detections.csv` and the `id` cell of `remoteid.csv` (the other one is `id2`).
- **Grade:** HIGH, class `surveillance` (magenta line and LED), with the buzz (user decision).

## 4. What the user sees

- **The detection**, in the existing format plus one new, optional, display-only ninth field:
  `drone_rid|Drone|high|surveillance|wifi|<MAC>|<ID, or empty>|<signal>|<detail>`
  The detail field holds three pieces separated by TAB (a byte that cannot occur inside them, because every
  piece of text in them went through `sw_sanitize_ident`): the airframe type, the motion
  (`87m up, 12m/s`) and the pilot (`pilot (live) 47.39776,8.54102`). Any piece may be empty. A drone whose
  address sent more IDs than the decoder keeps (the flag, §6.2) has `also sends other IDs` first in its motion
  piece, the piece shown both on the screen line and in the alert body (the airframe is only in the alert).
- **Screen lines** (magenta), the second one printed only with the first:
  `Drone '0000FSWTEST000000001' AA:BB:CC:00:00:02 -61dBm`
  `  87m up, 12m/s, pilot (live) 47.39776,8.54102`
  With no ID: `Drone (no ID) AA:BB:CC:00:00:02 -61dBm`. Flagged: `  also sends other IDs, 87m up, 12m/s, …`
  on the second line, and `multirotor, also sends other IDs, 87m up, 12m/s` in the alert.
- **Full alert**, with the buzz and the magenta LED:
  ```
  Drone '0000FSWTEST000000001'
  multirotor, 87m up, 12m/s
  pilot (live) 47.39776,8.54102
  AA:BB:CC:00:00:02 -61dBm
  ```
  - The pilot piece says what the System message says: `pilot (live)`, `takeoff point` or `pilot (fixed)`,
    or `no pilot location` when there is no System message or its position is unknown.
  - The motion piece prefers **height** (above take-off or above ground, as sent: "87m up") and falls back
    to the geodetic altitude ("alt 120m"). Any part the drone reports as unknown is left out.
  - Coordinates are shown to 5 decimals (about 1 m); `remoteid.csv` keeps all 7.
- **`detections.csv`:** the usual row (category `drone_rid`, label `Drone`, confidence `high`, class
  `surveillance`, radio `wifi`, the MAC, the ID in the ident column, the signal), one per drone per
  `SW_COOLDOWN`. The detail is not stored there.
- **`remoteid.csv`** (new, in the loot dir): **one row per drone per lap** in which it was heard, so a
  drone that stays around leaves its flight track (§6.5).
- **The existing gates:**
  - `SW_COOLDOWN`: one full alert and one `detections.csv` row per drone ID per 600 s. The ledger key is
    `drone|drone_rid:<ID>`, the ID alone, so a drone whose address changes stays one drone. A drone with no
    ID uses the usual `<MAC>|drone_rid` key.
  - `SW_KIND_COOLDOWN`: several drones within 600 s buzz once.
  - `SW_LOG_PER_KIND`: 3 drones on screen per lap (each with its detail line), then `...and N more Drone`.
  - `ignore.txt`: a drone is silenced only when **every** ID heard from its address (both Basic IDs the
    decoder keeps) is listed as `drone:<ID>`; a drone that sends no ID at all, by `drone:<MAC>`. A plain
    MAC line never silences one: a drone's address can change, and anyone can broadcast any address (the
    same reasoning as `evil_twin:<MAC>`). For the same reason one listed ID is not enough: a spoofer can
    send a copy of the owner's ID from another drone's address, and that must not hide the other drone
    (user decision 2026-10-02, after the final review). A drone that sends two IDs needs a line for each;
    `remoteid.csv` shows both. The screen and the alert show only the ID chosen in §3. An ignored drone
    gets no screen line and no row in either CSV. (`ignore.txt` lines lose their spaces and are upper-cased
    when loaded, so the ID is compared the same way.) The rule applies in `sw_rid_records`, which sees both
    IDs; the lap's emit loop does not check a drone again (its line carries only the one ID).
  - **Never silenced: an address that sent more IDs than are kept** (the flag, §6.2), whatever is listed (user
    decision 2026-10-02, after the re-review). The decoder keeps two IDs per address, and a spoofer whose
    frames are heard first can fill both places with IDs that the list silences: the owner's ID twice, under
    two ID types, as copies that only clean to it (lower case, a leading space, a control byte), or the
    owner's two listed IDs. The other drone's own ID is then a third, so whenever it is heard the address is
    flagged and the drone reported. With both kept IDs listed it is named by one of them (serial first, §3),
    and `also sends other IDs` tells the owner it is not theirs. With the empty-ID rule (§3: an ID with no
    text takes no place, so it cannot fill one), a copy of the owner's ID cannot hide another drone whose
    own, different ID is heard. Limits: a drone that sends no ID of its own can still be hidden by a copy of
    a listed ID sent from its address (the frames merge), and the owner's own drone is never silenced while
    its address sends three or more different IDs.
  - AUTO SNOOZE and "following you" do not apply: a drone is not a tracker.
- **Your own drone:** add `drone:<its ID>` to `ignore.txt`.
- **Bluetooth Remote ID** is unchanged: the `fffa` rule (`surveillance_drone`, med) stays presence only. A
  drone that broadcasts on both radios shows up once per radio (§12).
- **New settings:** §6.6.

## 5. Deviations from CYD, and why

1. **Full decode of all three WiFi forms.** Upstream CYD names WiFi drones by their serial; the fork only
   recognises NAN and Parrot. We decode every form fully (user decision: full telemetry).
2. **One drone = one ID.** CYD keeps its records per radio address; we key the cooldown, the ledger and the
   ignore list on the drone's ID, so a changing address does not make a new drone.
3. **HIGH with a buzz** (user decision). The fork grades drones "path-dependent"; upstream graded Bluetooth
   drones Medium.
4. **A bounded window per lap through recon's channel hopping**, not a radio of our own: the ESP32 owns its
   radio, while the Pager's recon radio belongs to `pineapd` (§2.2). Capture is therefore opportunistic
   (§12).
5. **Per-lap caps on frames and drones** (§6.1, §6.2): the flood and spoofing guard. CYD bounds its queues.
6. **A flight-track log** (`remoteid.csv`, a row per lap) besides the screen.

The same as CYD: the framing checks (byte for byte as the fork's `isWifiBeacon`, `isWifiNanAction` and
`validMessagePack`), the transmitter address as the radio identity, and the ID as the drone's name.

## 6. Design

### 6.1 Capture: new `lib/remoteid.sh`

`sw_rid_start` runs first in the lap's producer group (before the evil-twin check), only when
`SW_REMOTE_ID=1`, tcpdump exists and the payload has not been stopped:

- `mktemp` two files in `${SW_TMP_DIR:-/tmp}`: the capture `sw_rid.XXXXXX` and tcpdump's stderr
  `sw_rid.XXXXXX`. No temp space: status `capture_failed` (§7.2) and no capture this lap.
- Starts, in the background, and remembers the pipeline's PID:
  `nice -n 10 timeout -k 2 "$SW_RID_SECONDS" tcpdump -i "$SW_RID_IFACE" -p -l -t -nn -xx -c "$SW_RID_MAX_FRAMES" '<filter>' 2>"$err" | nice -n 10 awk '<frame filter + decoder>' > "$cap" &`
  - The kernel filter: `type mgt subtype beacon or (wlan[0] & 0xfc = 0xd0 and wlan addr1 51:6f:9a:01:00:00)`.
  - **Read only:** `-p` never puts the interface into promiscuous mode, and `-I` (monitor mode) is never
    used. The capture never changes the interface; recon keeps it.
  - `-l` writes each line at once (the hcitool lesson: no output may sit in a buffer when the process is
    signalled). `-t`: no clock times. `-nn`: no name lookups. Full frames (tcpdump's default snapshot
    length).
  - It **ends by itself**: `timeout` sends TERM after `SW_RID_SECONDS` (tcpdump exits cleanly on TERM;
    awk then reaches the end of its input and writes its results) and KILL 2 s later; or tcpdump stops
    after `SW_RID_MAX_FRAMES` frames (`-c`). Nothing is ever stopped by name.
  - `nice -n 10`: the lap's own work (btmon, the WiFi sweep, the matcher) comes first.

`sw_rid_collect` runs last in the same producer group, after the Bluetooth scan:

- `wait` for the PID. Stopped meanwhile (`sw_stopped`): remove both files, report nothing, return.
- Health (§7.2) from the stats line and the stderr file; then turn the drone records into detections
  (§6.3); remove both files.

**The window** starts with the lap and runs alongside the evil-twin check, the WiFi sweep and the Bluetooth
scan. The Bluetooth scan starts after the sweep and lasts about 13 s, so a window of `SW_BLE_SECONDS` (12 s)
normally ends first and the lap only gains the decode time. Phase 0 checks this and sets the default.

### 6.2 Frame filter and decoder: one awk program, streaming

It reads tcpdump's text (a header line per frame, beginning with the timestamp, then hex lines
`\t0x0000:  hhhh hhhh …`) and keeps only small per-frame state, so it never holds the capture in memory.

- **Every frame:** joins its hex; counts it (`frames`); reads the radiotap length (bytes 2 to 3, little
  endian) and the 802.11 frame control at that offset; counts it as `understood` when it is a beacon
  (`0x80`) or an action frame (`0xd0`) whose length is plausible. The 802.11 header is 24 bytes, or 28 when
  the Order bit (frame-control byte 1, bit 7) is set. The signal is the **first** `-NNdBm signal` on the
  header line: tcpdump prints the radiotap fields before any frame text, so a network name cannot supply
  it. A radiotap signal is one signed byte, so a match outside -128..127 (or written `-0`, or with a
  leading zero) came from frame text, a network name on a radio with no radiotap signal, and the frame has
  no signal. The address is addr2, read from the frame's bytes, never from text.
- **Cheap pre-test:** only a frame whose hex holds `fa0bbc0d`, `903ae6` or `8869199d9209` gets the full walk.
- **Full walk** (§3). An element that runs past the end of the frame ends the walk; elements before it
  still count (a trailing frame checksum ends the walk this way). At most 64 elements (beacon) or
  attributes (NAN) are walked per frame, so a frame cannot make the walk long: Remote ID after the 64th is
  not seen. One bad frame never stops the program or touches another frame's state.
- **Message decoding** (offsets within a 25-byte message; multi-byte fields little endian):
  - *Basic ID:* ID type = byte 1 high nibble, airframe type = low nibble, ID = bytes 2 to 21.
  - *Location/Vector:* status = byte 1 high nibble; flags in byte 1: bit 2 height type (0 above take-off,
    1 above ground), bit 1 heading +180, bit 0 speed multiplier; heading = byte 2 (+180); speed = byte 3 ×
    0.25 m/s, or × 0.75 + 63.75 with the multiplier; vertical speed = byte 4 (signed) × 0.5 m/s;
    latitude = bytes 5 to 8, longitude = bytes 9 to 12 (signed, × 1e-7°); barometric altitude = 13 to 14,
    geodetic altitude = 15 to 16, height = 17 to 18 (each × 0.5 − 1000 m).
  - *Self-ID:* description type = byte 1, text = bytes 2 to 24.
  - *System:* operator location type = byte 1 bits 0 to 1 (0 take-off, 1 live, 2 fixed); operator
    latitude = bytes 2 to 5, longitude = 6 to 9; operator altitude = 18 to 19 (× 0.5 − 1000 m).
  - *Operator ID:* type = byte 1, ID = bytes 2 to 21.
  - **Unknown values become empty fields, never numbers:** latitude and longitude both 0 (the standard's
    "unknown"), or out of range (latitude beyond ±90, longitude beyond ±180); an altitude or height encoded
    0 (−1000 m); speed byte 255 with the multiplier (255 m/s, "unknown"); a vertical speed of 63 m/s or
    more either way; a heading above 360.
  - **Text** (IDs, operator ID, self-ID) leaves awk as lowercase hex, cut at the first zero byte, with
    trailing spaces dropped. awk never turns attacker bytes into text.
- **Basic IDs, per address:** the first two distinct ones that hold text are kept, as `id` and `id2`
  (distinct: another text, as bytes before any cleaning, or another ID type). One with no text takes no
  place; it still gives the airframe when it is the address's first Basic ID. One more distinct ID sets the
  address's flag, forms bit 8: it sent more IDs than are kept (§4 says why such a drone is never silenced).
  The kept IDs heard again set nothing (added 2026-10-02, after the re-review).
- **Merging** as in §3 (per address only), keeping at most `SW_RID_MAX_DRONES` addresses per lap (the
  strongest signals); the rest are only counted (`more_drones`).
- **awk writes integers, empty, or lowercase hex only — never a float or decoded text.** Coordinates leave
  as the raw signed 1e7 int, altitudes/height as the raw `uint16` encoding, speed as centi-m/s, vertical
  speed as deci-m/s, heading in whole degrees; bash does the unit maths and the decimal formatting (§6.3).
  Byte comparisons in awk use **decimal** literals (`250`, not `0xFA`): mawk and BusyBox awk do not parse
  `0x..` constants (spike, 2026-10-01). This was proven on both awks and against the reference encoder.
- **Output, at the end of input:** one line per drone, then one stats line, LAST: a pass whose output has no
  stats line did not finish (§7.2). TAB-separated, and every field is a number, empty, or lowercase hex, so
  no field can shift another:
  `D mac rssi forms id_type id_hex id2_type id2_hex ua_type status lat lon alt_geo alt_baro height height_ref speed vspeed heading pilot_type pilot_lat pilot_lon pilot_alt operator_id_hex self_id_hex`
  `S frames understood rid_frames more_drones`
  (`forms` is a bit mask: the forms heard, 1 ASD-STAN beacon, 2 NAN, 4 Parrot beacon, plus 8 when the address
  sent more distinct Basic IDs than the two kept: a flag, not a form. So it is 1 to 15; the 8 was added on
  2026-10-02, the smallest change to the line, which keeps its 24 fields.)
- Runs unchanged on mawk (the dev box) and BusyBox awk 1.36.1 (the Pager): hex digits through a lookup
  table, no gawk-only functions; a signed 32-bit value is built from its four bytes in floating point.

### 6.3 From records to detections: `sw_rid_collect`, bash, builtins only

Per drone line (a handful per lap at most, never per frame):

- Read with `LC_ALL=C`; check the line's shape (exactly 24 fields, nothing after the last, and each field
  against its own pattern, `forms` 1 to 15); drop any other line (defence in depth, as in the evil-twin check).
- `sw_stopped`: stop here, write nothing (before the lap's one `GPS_GET`, shared by its drones).
- Hex text to bytes (a loop of builtins that writes each byte as `\xHH`, then `printf -v … %b`), then
  `sw_sanitize_ident`, the one cleaning boundary, then the spaces at both ends trimmed (after the cleaning, so
  a control byte cannot shield one).
- Choose the ID (§3); the ignore list (§4) checks both kept IDs: a silenced drone is skipped entirely, and a
  flagged one (forms bit 8) is never silenced. When exactly one of the two is listed, the other one becomes
  the ID (§3).
- Build the three detail pieces (§4); a flagged drone's motion piece starts with `also sends other IDs`.
- `sw_stopped` again, right before the row: a Stop during the GPS read (a gpsd query on the device) writes
  nothing either.
- Build and append its `remoteid.csv` row, and print the 9-field detection into the lap's detection stream
  (like an evil twin, it skips the matcher).

If the decoder counted more drones than it kept, one line in the drone colour says
`...and N more drones (Remote ID flood?)`, once per lap, unless the payload was stopped. (It is printed by
the capture code, so it shows above the drones it summarises; moving it to the emit loop is a later item.)

### 6.4 Changes to the shared libraries (small, category-specific, like the evil twin's)

- `sw_emit` (`lib/alert.sh`) reads nine fields. For `drone_rid`:
  - Shown name: `Drone '<ID>'`, or `Drone (no ID)`.
  - Ledger: `sw_should_report drone "drone_rid:<ID>"` when there is an ID (key `drone|drone_rid:<ID>`),
    else the usual MAC key. The ID holds no `|` and no line break (sanitized), so the key keeps the
    ledger's three-field shape that `sw_seen_prune` checks.
  - After the main screen line, the detail line (same colour, skipped under the same `SW_EMIT_NOLOG`).
  - The alert body: airframe type and motion on one line, the pilot on the next, then the usual
    `<MAC> <signal>` line.
- `sw_ignored` (`lib/ignore.sh`): for `drone_rid`, matches only ` DRONE:<ID> ` (the ID without spaces,
  upper case), or ` DRONE:<MAC> ` when there is no ID. `sw_rid_records` calls it once per ID heard (§4),
  and the lap's emit loop leaves `drone_rid` lines alone.
- `sw_log_write` (`lib/log.sh`) reads nine fields and writes the same ten columns as today.
- `sw_follow_update` (`lib/follow.sh`) cuts the signal at the next `|` (it returns before using it for
  anything but trackers, so this only keeps the parse honest).
- Every other reader takes a prefix of the fields and is unaffected.

### 6.5 `remoteid.csv`

Header:
`time,form,mac,rssi,id_type,id,id2_type,id2,ua_type,status,lat,lon,alt_geo_m,alt_baro_m,height_m,height_ref,speed_mps,vspeed_mps,heading_deg,pilot_loc,pilot_lat,pilot_lon,pilot_alt_m,operator_id,self_id,gps`

- `form`: `beacon`, `nan`, `parrot`, joined with `+` (the more-IDs flag is no form and is not written).
- `id`, `id2`: the drone's ID and its second ID, as chosen in §3, so `id` is the ID of its alert.
- Code fields are written as names from the standard's tables (`id_type`: none, serial, caa, utm, session;
  `ua_type`: none, aeroplane, multirotor, gyroplane, vtol, ornithopter, glider, kite, free balloon, captive
  balloon, airship, parachute, rocket, tethered, ground obstacle, other; `status`: undeclared, ground,
  airborne, emergency, failure; `height_ref`: takeoff, ground; `pilot_loc`: takeoff, live, fixed). A code
  outside the table is written as its number.
- Unknown values are empty cells. Coordinates keep 7 decimals.
- Free text (`id`, `id2`, `operator_id`, `self_id`, `gps`) goes through `_sw_csv_cell` (quotes and the
  spreadsheet-formula guard, the same cells `_sw_csv_field` writes for `detections.csv`, with builtins only).
- `ua_type` 0 is a declared "none" and is written `none`; an empty cell means no Basic ID was heard. (The
  screen leaves a declared "none" out.)
- Created with its header on first write. Written every lap a drone is heard, except for ignored drones,
  drones over the per-lap cap, and a stopped lap.

### 6.6 Config (`payload.sh`) and loading

- `SW_REMOTE_ID=1`: anything else turns it off (no capture runs at all).
- `SW_RID_IFACE=wlan1mon`.
- `SW_RID_SECONDS=12`: the capture window (Phase 0 confirms).
- `SW_RID_MAX_FRAMES=1500`: frames per lap (Phase 0 sets it from the measured cost).
- `SW_RID_MAX_DRONES=32`: drones per lap.
- `SW_RID_FILE=$SW_LOOT_DIR/remoteid.csv`.
- `remoteid` joins the libraries `payload.sh` loads. The library reads each setting as `${VAR:-default}` at
  the point of use, never with `:=` (payload.sh loads its libraries before its config block: the 2026-09-22
  gotcha).

## 7. Failure handling

### 7.1 Startup health check (`sw_healthcheck`, only when `SW_REMOTE_ID=1`)

- No tcpdump: `WARN: tcpdump missing — Remote ID over WiFi OFF`.
- No interface (`/sys/class/net/$SW_RID_IFACE` missing): `WARN: wlan1mon missing — Remote ID over WiFi OFF`
  (with the configured name).
- Recon stopped (so the radio no longer hops): the existing `recon DB not updating` WARN already covers it.

### 7.2 Per-lap capture status

Like the Bluetooth note: a WARN only when the status **changes**, silent `ok` on the first lap, and after an
OFF status a green "recovered" line in the next lap that captures, also when that lap is only partly blind
(re-review 2026-10-02). State file `${SW_TMP_DIR:-/tmp}/sw_rid.state`.

| Status | When | Line |
|---|---|---|
| `capture_failed` | no temp space, or tcpdump never printed `listening on` | `WARN: WiFi capture failed — Remote ID over WiFi OFF` |
| `not_understood` | the link type is not `IEEE802_11_RADIO`; or the decoder printed no stats line (it did not finish, also in a lap with no frames); or 5 or more frames arrived and none parsed as a beacon or action frame | `WARN: WiFi capture not understood — Remote ID over WiFi OFF` |
| `capped` | the frame cap was reached | `WARN: WiFi capture hit its frame limit (beacon flood?) — Remote ID partly blind` |
| `lost` | awk counted fewer frames than tcpdump's `packets captured` (output lost on the way), or tcpdump's `N packets dropped by kernel` is above 0 (the CPU did not keep up); both lines only when tcpdump printed them, which a KILL skips | `WARN: WiFi capture lost frames (CPU busy?) — Remote ID partly blind` |
| `ok` | otherwise, **including a lap with no frames at all** | |

- The rules are checked in that order (the first that applies wins).
- `capped` and `lost` (partly blind) share one WARN per `SW_COOLDOWN` and recover silently, so a busy spot
  right at the cap cannot flood the screen.
- An OFF status (`capture_failed`, `not_understood`) never comes with drones in the same lap; a partly
  blind one reports what was heard. So no line says Remote ID is OFF in a lap that reports a drone.
- tcpdump's summary is read in both its forms, `1 packet …` and `N packets …`.
- **A lap with no frames is `ok`.** There are places with no WiFi at all (fields, where drones fly), and
  `listening on` already proves the capture ran.
- **The positive control runs on real traffic:** every ordinary beacon must parse as a beacon, so the frame
  parser is checked on every lap without needing a drone (`not_understood`). The message decoder's positive
  control is the reference fixtures (§8).

### 7.3 Stop and orphans

- The capture ends by its own `timeout` and `-c`. Nothing is killed by name, and the exit trap starts no
  new work: `sw_cleanup` also removes `sw_rid.state`; `sw_clear_tmp` also sweeps `sw_rid.*`. Captures stay
  with the lap that owns them, as with Bluetooth.
- `sw_stopped` is checked before starting, after the wait (the capture is dropped unread, no health note),
  before each health line and before the state file is written, before the lap's `GPS_GET`, right before
  each `remoteid.csv` row (after that read), and before the flood line; the emit loop already checks it.
  (Not changed here, and declined on 2026-09-29: the emit path's own windows, `sw_emit` with no re-check
  before ALERT and the buzz, and the trap running twice.)
- A Stop during the window: the main shell exits at once (the existing `& wait $!`); the orphaned capture
  ends within `SW_RID_SECONDS` + 2 s; its files are swept at the next start.

### 7.4 Hostile input

Remote ID is not authenticated, and spoofing tools are public, so every byte is treated as hostile:

- every length and offset is bounds-checked, and one bad frame never ends the lap or hides a later frame
  (the Tier-3 lesson);
- strict pack check; every field range-checked, with the standard's "unknown" values (§6.2);
- text leaves awk as hex and becomes text only through `sw_sanitize_ident`, then `_sw_csv_cell` for the CSV;
- every record line is shape-checked before use;
- the signal comes from the header's first match only, the address from frame bytes only;
- caps on frames and on drones per lap.

### 7.5 CPU

- `nice -n 10`, the bounded window, and the frame cap.
- Budget (Phase 0 measures it, A/B against the current build like the evil-twin round): **at most 1 s added
  to a lap at the author's home** (the evil-twin round added 0.7 s), and a lap at the frame cap adds at most
  about 5 s of CPU.

## 8. Testing

- **Reference fixtures, not our own encoder.** A fixture generator on the dev box (`tools/rid_fixtures/`,
  never installed on the Pager) builds frames with **opendroneid-core-c** at a pinned commit (Apache-2.0,
  fetched and checksum-checked by the generator's build script, not vendored), wraps them in a radiotap
  header in a pcap file, and runs the **real tcpdump** on it (`-r … -t -nn -xx`) to produce the fixture
  text. The generator, the pcap files and the text are committed; the tests need neither the network nor a
  compiler. An encoder of our own would share any misreading of the standard with our decoder and pass
  anyway.
- **Fixtures:** ASD-STAN beacon, NAN, Parrot beacon; every decoded message type; the reference library's
  "unknown" values; several drones; one drone under two addresses; one drone in two forms; ordinary
  (synthetic) beacons for the `understood` counter; a quiet capture; a failed start (stderr only); a wrong
  link type; output cut short (fewer frames than `packets captured`).
- **Hostile frames** (built as `test/fixtures/rid/hostile/`: byte edits of the reference fixtures, kept as
  tcpdump text only, each edit written next to its test; `rid_hostile` decodes all the rejected ones before a
  good beacon): element lengths running past the frame; a pack with count 0 or 10,
  message size 24, or a declared size that does not fit; a NAN frame with the hash but a broken pack; the
  ASD-STAN OUI with a type other than `0x0D`; Parrot's OUI with a random payload; coordinates out of range;
  a beacon whose network name holds `-1dBm signal` and `SA:…`; IDs that are empty or blank, and copies of a
  listed ID (under another ID type, in lower case, after a space, with a control byte) sent before a real
  drone's, in laps (§4); and **a malformed frame before a good one**, where the good one must still decode.
  Each crafted frame decodes the same on BusyBox awk. Hostile ID **text** (`|`, commas, quotes, a line
  break, `%s`, `$(x)`, control bytes, bytes that are not UTF-8) is tested on decoder lines in bash
  (`sw_rid_records`), since the decoder passes any text on as hex.
- **Unit tests:** exact decoded values against the generator's inputs; units and unknown values; merging;
  caps; the shape gate; sanitizing; the ignore lines; the ID-only ledger key; `remoteid.csv` quoting and the
  formula guard.
- **End to end:** a payload lap with a **tcpdump stub that models the device** (`listening on … link-type
  IEEE802_11_RADIO` on stderr; prints the fixture; exits on TERM with `N packets captured`; honours `-c`; the
  failure modes above). It asserts the detection, both screen lines, the alert text, one `detections.csv`
  row per cooldown, one `remoteid.csv` row per lap, one drone across an address change, and the kind
  cooldown.
- **Stop:** a Stop inside the window exits 0 quickly, reports nothing afterwards, and leaves no files after
  the next start (the existing Stop harness).
- **Performance:** the decoder over 1,500 frames, 300 of them Remote ID, within a time budget on the dev box;
  plus the static check that bash forks nothing per frame (it only runs per drone).
- **Portability:** the awk program under mawk and the dev box's BusyBox awk; parity on the Pager is a Phase 0
  step.
- **Mutation:** each guard mutated must fail a test: the pack check, the bounds checks, the unknown-value
  handling, the sanitize call, the `drone:` ignore prefix, the ID-only ledger key, the shape gate, the
  first-signal rule, the empty-ID rule, the more-IDs flag and its never-silenced rule, the naming by the ID
  not listed. (Twelve checks in the decoder can never change its output: for each, another check catches the
  same input, or, for the cheap pre-test, it is only there for speed. They are marked "redundant" in the code
  and left out of this list, §15.)
- Every "nothing happened" assertion has a positive control in the same test: the fixture that must decode
  does.

## 9. Phase 0 on the Pager (the first plan task: read only, nothing installed)

1. **Text parity:** the Pager's tcpdump prints the fixture pcap exactly as the dev box's does (4.99.5 vs
   4.99.4).
2. **Read only, really:** `-p` captures on `wlan1mon` still see frames, and the recon database keeps
   growing at its usual rate during a capture.
3. **Cost split:** tcpdump alone versus tcpdump plus the awk program, per frame; set `SW_RID_MAX_FRAMES` so
   a lap at the cap stays inside the budget (§7.5); check that `nice` works.
4. **Window timing:** `SW_RID_SECONDS` such that the window normally ends before the Bluetooth scan; lap
   time A/B (the old build and the new, alternating).
5. **Channel coverage:** over a few minutes, the share of time `wlan1mon` is within two channels of channel 6,
   and on channel 149 (NAN's 5 GHz channel). That gives the expected catch rate for the README.
6. **Capture parity:** awk's frame count equals tcpdump's `packets captured` after a TERM (no output lost).

Results go into `docs/superpowers/P0-findings.md`.

## 10. Deploy and verify on the Pager (needs the user)

- Install as before: stage on the same file system, `mv` into place, md5 every file.
- A launcher-faithful silent run (`swprobe.sh`): armed, no WARN, no Remote ID status line, lap time as
  Phase 0 predicted.
- **Live test, with a real drone only.** SquachWatch only listens: no made-up drone is ever broadcast
  to test it. When a drone that broadcasts Remote ID over WiFi is around (a current DJI, say), run the
  payload near it. Until then the beacon, NAN and Parrot forms rely on the reference fixtures (§8),
  which are files only.
  - **A second opinion:** the official receiver app **OpenDroneID OSM** (Google Play) on the user's phone
    decodes beacons and NAN. During the live test it must show the same ID, position and pilot as
    SquachWatch. Its settings list what the phone can receive, and it shows when a drone is nearby.

  Expected: one Drone alert with the buzz, the detail line, a `remoteid.csv` row per lap, and Stop ending
  in `Payload completed`. With no source at hand, the live test waits (like the hostile-name evil-twin
  run).

## 11. Privacy (public repository)

- Fixtures are synthetic: generated by the reference encoder, made-up IDs (`0000FSWTEST000000001`),
  made-up addresses, coordinates of a public place.
- A real capture (the live test) is never committed as it is. **A real pilot's position must never reach
  the repository.** Scrub IDs, addresses (the HMAC map), drone and pilot coordinates and network names, and
  follow the usual checklist (UTC commits, no clock times, epochs or local paths).
- The README says `remoteid.csv` records where other people's drones and pilots were, so it should stay
  private.

## 12. Known limits (they go in the README)

- **Opportunistic:** it hears only what the recon radio's channel hopping visits, so a drone that passes in
  a few seconds can be missed (Phase 0 gives the number). With recon off, or limited to some bands, Remote
  ID over WiFi goes blind; recon off already raises a WARN.
- **Not proof of an aircraft:** Remote ID is not authenticated, so anyone can broadcast made-up drones. A
  detection means "something here is broadcasting drone Remote ID", and every position is what the
  transmitter claims.
- The pilot position may be the take-off point; the alert says which.
- No distance or bearing to the pilot. When a GPS is attached, each row records the Pager's own fix.
- Bluetooth Remote ID stays presence only (medium, no buzz); Bluetooth 5 long range is not covered. A drone
  on both radios shows up twice, once per radio.
- A drone that sends no ID is keyed by its address, so a new address means a new alert.
- At most `SW_RID_MAX_DRONES` drones per lap get rows and lines.
- A beacon flood hits the frame cap (with a WARN), and Remote ID is then partly blind. So is a lap whose
  frames were dropped by the kernel or lost on the way (a WARN of its own; the two share one per
  `SW_COOLDOWN`).
- At most 64 elements or attributes are read per frame: Remote ID after the 64th is not seen.
- A drone that sends two IDs is silenced only by a line for each (§4).
- A drone whose address sends three or more different IDs in a lap is never silenced, the owner's own
  included; and a drone that sends no ID of its own can be hidden by a copy of a listed ID sent from its
  address (§4).

## 13. Out of scope (later rounds)

- Decoding Bluetooth Remote ID with this decoder (btmon already captures the service data): the natural
  next step.
- Drone makers' address prefixes (the CYD fork's list) as plain signatures.
- Distance and bearing to the pilot when a GPS is attached.
- A second capture on `wlan0mon`, or taking a radio over for a dedicated channel-6 watch.
- Merging one drone heard on both Bluetooth and WiFi.
- DJI's older proprietary DroneID beacons (pre-Remote-ID models; not ASTM; CYD does not decode them either).
- Authentication messages (type 2), EU class and category, and the area fields (swarms).
- Karma radios (the evil-twin round's leftover; unrelated).

## 14. Notes from the verified dry run (2026-10-01, before implementation)

The implementation plan was proven in full on a copy of the repository before any task was dispatched:
every task left the suite green on its own (1,105 assertions at the end, none failing, also as root),
and deliberately broken variants of each guard were caught. That run settled these details, which the
plan follows:

1. **The fixtures carry no time.** tcpdump runs with `-t`, so their text holds no clock times, and the
   generator zeroes each beacon's 8-byte timestamp, where the reference library writes the generating
   machine's uptime. The fixtures come out byte-identical on every run and say nothing about the machine
   that made them. `build.sh` downloads four upstream files (`opendroneid.c`, `opendroneid.h`, `wifi.c`
   and `odid_wifi.h`, which `wifi.c` needs), each checked against its sha256.
2. **Ten fixtures:** beacon, nan, parrot, multi (two drones, the weaker one heard first, so "strongest
   first" is not the same as arrival order), unknowns, equator (latitude 0 with a real longitude is a
   place, not "unknown"), order (the Order bit's 4 extra header bytes), quiet (an ordinary beacon),
   truncated, badlink.
3. **`sw_rid_start` takes the lap's start time** and is the first step of the lap's producer group;
   `sw_rid_collect` is its last step, in the same shell, because it waits for the capture's PID. A wait
   from any other shell returns at once and would read the capture before its window ends.
4. **The ignore list is applied in `sw_rid_records`,** before any `remoteid.csv` row is written, so the
   owner's own drone leaves no row at all (the emit loop's check comes too late for the flight track).
5. **`_sw_csv_cell`** (`lib/log.sh`) gives `_sw_csv_field`'s quoting and formula guard in `REPLY`, with
   builtins only. `_sw_csv_field` now wraps it, so `detections.csv` is written exactly as before (a test
   compares the two on tricky values), and a drone's 26-cell row costs no fork per cell.
6. **Each D line is checked before use:** exactly 24 TABs, and every field against its own pattern,
   with no leading zeros (bash reads `0473977600` as octal and aborts the arithmetic). The line is split
   on `|` after its TABs are turned into `|`, because `read` treats TAB as whitespace and would merge
   runs of empty fields.
7. **A capture whose link type is not 802.11 + radiotap reports no drones,** only its `not_understood`
   WARN: those bytes are not 802.11 frames.
8. **`SW_SYSFS_NET`** (default `/sys/class/net`) is a test seam for the interface check (§7.1).
   **`SW_RID_MAX_DRONES=0` means no cap.**
9. **Tests load their own dependencies.** `test/remoteid_test.sh` sources every library that
   `lib/remoteid.sh` uses, so it passes on its own (it first passed only because an earlier test file
   had loaded `lib/match.sh`). `test/payload_test.sh` exports `SW_REMOTE_ID=0`, so its other laps don't
   each wait out a capture window, and unsets every `SW_RID_*` that `payload.sh` gives it: one of them
   had leaked a deleted folder into a later test file.

## 15. After the final review (2026-10-02)

Two reviews of the finished branch (one general, one adversarial: hostile frames and Stop timing) led to one
round of fixes, each described in place above:

1. **The ignore rule against a spoofer** at a drone's address: every ID heard must be listed (§4; user
   decision 2026-10-02).
2. **The ID:** the first one with any text, a serial preferred (§3); text trimmed after the cleaning (§6.3);
   airframe "none" written in `remoteid.csv` (§6.5); a D line with an extra field is dropped (§6.3).
3. **Stop:** checked again before each row, health line, state file and flood line (§7.3).
4. **Health:** kernel drops and a cut-short capture are `lost` (partly blind), a missing stats line is
   `not_understood`, and an OFF status never comes with drones (§7.2).
5. **The signal** is taken only in -128..127 (§6.2).
6. **Tests:** every decoder guard that can change the output is pinned by a crafted frame
   (`test/fixtures/rid/hostile/`, tcpdump text only), on mawk and BusyBox awk, and removing any one of them
   fails a test. Twelve cannot change the output (20,000 fuzzed frames decoded the same without each, while
   removing a real guard changed it): for each, another check catches the same input, or, for the cheap
   pre-test, it is only there for speed; each is marked "redundant" in the code.
   Two more reference frames (`full`: every message type the decoder reads, two IDs, airframe "other";
   `emptyserial`) come from the reference library like the first ten.
7. **Phase 0** gained the checks the reviews asked for (`P0-findings.md`, "Still to do on the Pager").

## 16. After the re-review of those fixes (2026-10-02)

The re-review found the ignore rule of §15 item 1 still beatable: a spoofer whose frames are heard first
fills the decoder's two ID places with IDs the list silences, so the real drone's own ID is never seen. The
user decided, and this round built, each described in place above:

1. **More IDs than kept:** a third distinct Basic ID from one address sets the flag, forms bit 8 (§6.2), and a
   flagged drone is never silenced; its alert and second screen line say `also sends other IDs` (§4).
2. **An ID with no text takes no place** (§3, §6.2), so it cannot fill one.
3. **The name:** when one of a drone's two IDs is listed and the other is not, the other names it (§3).
4. **Health:** after an OFF status, the green "recovered" line also in a partly blind lap (§7.2).
5. **Tests:** the re-review's four ways to hide a drone (the owner's ID with an empty one; the owner's ID
   under two ID types; one frame holding both; the owner's two listed IDs) and three copies that only clean
   to the owner's ID, each as a full lap that must alert, against a control lap with the real drone alone;
   the owner's own drone sending its IDs again and again stays silent. Every crafted frame is decoded on
   BusyBox awk too.
