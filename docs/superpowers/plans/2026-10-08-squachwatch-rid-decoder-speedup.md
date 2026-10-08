# SquachWatch — a cheaper Remote ID decoder and a frame cap of 700: Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Remote ID decoder about 2.7 times cheaper per ordinary beacon on the Pager, and raise the default
frame cap from 300 to 700 at about the same CPU budget.

**Architecture:** In `_sw_rid_awk_src` (`payloads/user/reconnaissance/squachwatch/lib/remoteid.sh`) the hex-line rule
appends each line's text after tcpdump's fixed 10-character prefix, and `decode()` strips blanks and tabs once per
frame; a line of any other shape keeps the old field loop, so the output does not change. `SW_RID_MAX_FRAMES`
defaults to 700 in `payload.sh` and in the fallbacks of `sw_rid_start` and `sw_rid_collect`. Design:
`docs/superpowers/specs/2026-10-08-squachwatch-rid-decoder-speedup-design.md`.

**Tech Stack:** bash 5.2; awk (mawk on the dev box, BusyBox 1.36.1 awk on the Pager); the repo's zero-dependency test
harness `test/run.sh` (it needs bash, python3 and busybox).

## Global Constraints

- Public repository: made-up IDs, MACs, network names and coordinates only; no real data, clock time, epoch or local
  path in any tracked file or commit message.
- The decoder's output must not change, for any input: the 12 fixtures in `test/fixtures/rid/` and the 56 in
  `test/fixtures/rid/hostile/` most of all.
- awk: no `0x..` literals in the decoder (BusyBox awk and mawk do not parse them); byte tests use decimal literals.
- Every commit: `TZ=UTC git -c user.name=Ziggy -c user.email=79704039+therealziggy@users.noreply.github.com commit -F -`,
  and the message ends with exactly one line `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`. Check after every commit:
  `git log -1 --format=%B | grep -cF 'Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>'` prints `1`.
- Work on `main`. No push, and no contact with the Pager: the controller does both, each with the user's OK.
- The tool shell may be zsh: run every script with `bash`.
- The patches below come from a dry run verified on 2026-10-08 and apply in order on top of `4c6fc56`. Extract each
  with `planpatch` (next section) and apply it with `git apply`; never retype one.

## Applying the patches

```bash
# planpatch FILE NAME: prints the patch fenced as ````diff NAME in FILE (this plan, or a task brief cut from it)
planpatch() { awk -v n="$2" '$0 == "````diff " n { p = 1; next } p && $0 == "````" { exit } p' "$1"; }
p="$(mktemp)"; planpatch docs/superpowers/plans/2026-10-08-squachwatch-rid-decoder-speedup.md t1-tests > "$p"; git apply --check "$p" && git apply "$p"; rm -f "$p"
```

Run one test file (faster than the whole suite) from the repo root:
`bash .superpowers/sdd/tools/minirun.sh "$PWD" remoteid_test.sh` (a local, git-ignored copy of `test/run.sh`'s harness;
if it is missing, `bash test/run.sh` runs every file). The whole suite: `bash test/run.sh`; besides the
`== x_test.sh ==` headers, the dashes and the last `PASS=... FAIL=...` line it must print nothing.

---

### Task 1: The decoder joins each hex line's text after tcpdump's prefix

**Files:**
- Modify: `payloads/user/reconnaissance/squachwatch/lib/remoteid.sh` (the hex-line rule of `_sw_rid_awk_src`; the
  first line of `decode()`)
- Modify: `test/remoteid_test.sh` (a new block just before `# --- crafted frames (spec §8)`)
- Modify: `docs/superpowers/P0-findings.md` (a new section before "Still to do on the Pager, with the user"),
  `docs/superpowers/specs/2026-10-08-squachwatch-rid-decoder-speedup-design.md` (its code block), `README.md`
  (the count, 1648 → 1664)

**Interfaces:**
- Consumes: `_sw_rid_awk_src` and `_sw_rid_decode_awk` (lib/remoteid.sh); in `test/remoteid_test.sh`, `_dec`, `_rf`,
  `$_RFIX` and `$_serial1`, defined earlier in that file; the harness's `pass`, `fail`, `assert_eq`,
  `assert_contains`, `assert_empty`.
- Produces: nothing new. The decoder's output is unchanged, so Task 2 relies on nothing from here.

- [ ] **Step 1: Write the tests** (patch `t1-tests`: the joining's two pins, the reference built from the decoder's own
  source with the old field loop and its controls, four variants of the reference beacon, and the 312-comparison
  differential on this machine's awk and BusyBox awk, with a control that the comparison sees a difference)

````diff t1-tests
diff --git a/test/remoteid_test.sh b/test/remoteid_test.sh
index f807a43..56ced29 100644
--- a/test/remoteid_test.sh
+++ b/test/remoteid_test.sh
@@ -142,6 +142,62 @@ assert_eq "$(_rf "$_o" operator_id)" "5357544553544f50455241544f523032" rid_full
 _o="$(_dec emptyserial)"
 assert_eq "$(_rf "$_o" id_type)/$(_rf "$_o" id_hex)/$(_rf "$_o" id2_type)/$(_rf "$_o" id2_hex)/$(_rf "$_o" ua_type)" "2/4653572d4341412d544553542d30303032///2" rid_emptyserial_empty_id_takes_no_place   # "FSW-CAA-TEST-0002"
 
+# The hex lines are joined from each line's text after tcpdump's prefix (a tab, "0x", four hex digits, ":", two
+# blanks), and decode() strips the blanks once per frame: on the Pager that costs 6.3 ms per ordinary beacon where
+# appending field by field cost 16.7 ms (spec 2026-10-08). The output must not change: the reference below is the
+# same decoder with the old joining, made here from the decoder's own source.
+_rid_new="$(_sw_rid_awk_src)"
+_rid_fast='{ if (substr($0, 1, 10) == "\t" $1 "  ") hex = hex substr($0, 11)
+  else for (k = 2; k <= NF; k++) hex = hex $k }'
+_rid_strip='  gsub(/[ \t]/, "", hex)                                    # the joining left blanks: one strip per frame
+'
+_rid_ref="${_rid_new/"$_rid_fast"/'{ for (k = 2; k <= NF; k++) hex = hex $k }'}"
+_rid_ref="${_rid_ref/"$_rid_strip"/}"
+assert_contains "$_rid_new" "$_rid_fast" rid_join_fast_path_in_the_decoder
+assert_contains "$_rid_new" "$_rid_strip" rid_join_strip_in_the_decoder
+# control: the reference is the old joining (else every comparison below is the decoder against itself)
+assert_empty "$(printf '%s\n' "$_rid_ref" | grep -F -e 'substr($0, 11)' -e 'gsub(/[ \t]/')" rid_join_reference_has_no_fast_path
+assert_contains "$_rid_ref" '{ for (k = 2; k <= NF; k++) hex = hex $k }' rid_join_reference_has_the_field_loop
+# Lines of another shape take the field loop, and a tab between the hex words goes in the strip: each variant of the
+# reference beacon decodes as the beacon does (control: each variant's text differs from the beacon's)
+_rid_vd="$(mktemp -d)"; _rid_want="$(_dec beacon)"
+assert_eq "$(_rf "$_rid_want" mac)/$(_rf "$_rid_want" id_hex)" "80e126aabbcc/$_serial1" rid_join_control_the_beacon_decodes
+for _v in "no_tab|s/^\t//" "one_blank|s/^\(\t0x[0-9a-f]*:\)  /\1 /" "short_offset|s/^\t0x0\([0-9a-f]\{3\}\):/\t0x\1:/" \
+          "tab_between_words|s/^\(\t0x[0-9a-f]*:  [0-9a-f]*\) /\1\t/"; do
+  sed "${_v#*|}" "$_RFIX/beacon.txt" > "$_rid_vd/${_v%%|*}.txt"
+  assert_eq "$(_sw_rid_decode_awk < "$_rid_vd/${_v%%|*}.txt")" "$_rid_want" "rid_join_${_v%%|*}_decodes_as_the_beacon"
+  if cmp -s "$_rid_vd/${_v%%|*}.txt" "$_RFIX/beacon.txt"; then fail "rid_join_${_v%%|*}_variant_differs"; else pass; fi
+done
+# The differential: every fixture, every hostile frame and the variants above, then the two whole streams at max 32,
+# 0 and 1, without and with a drone: key, on this machine's awk and on BusyBox awk: the decoder's output equals the
+# reference's (2 awks x 2 key sets x (72 files + 6 streams) = 312 comparisons)
+if command -v busybox >/dev/null 2>&1; then
+  _rid_bad=""; _rid_n=0
+  cat "$_RFIX"/*.txt > "$_rid_vd/stream_top"; cat "$_RFIX"/hostile/*.txt "$_RFIX/beacon.txt" > "$_rid_vd/stream_hostile"
+  for _awk in awk "busybox awk"; do
+    for _keys in " " " :0000FSWTEST000000001 "; do
+      for _f in "$_RFIX"/*.txt "$_RFIX"/hostile/*.txt "$_rid_vd"/*.txt; do
+        _rid_n=$((_rid_n + 1))
+        [ "$($_awk -v max=32 -v ignkeys="$_keys" "$_rid_ref" < "$_f")" = "$($_awk -v max=32 -v ignkeys="$_keys" "$_rid_new" < "$_f")" ] \
+          || _rid_bad="$_rid_bad ${_awk#busybox }:${_f##*/}"
+      done
+      for _s in stream_top stream_hostile; do for _m in 32 0 1; do
+        _rid_n=$((_rid_n + 1))
+        [ "$($_awk -v max="$_m" -v ignkeys="$_keys" "$_rid_ref" < "$_rid_vd/$_s")" = "$($_awk -v max="$_m" -v ignkeys="$_keys" "$_rid_new" < "$_rid_vd/$_s")" ] \
+          || _rid_bad="$_rid_bad ${_awk#busybox }:$_s:$_m"
+      done; done
+    done
+  done
+  assert_eq "$_rid_n" "312" rid_join_differential_count
+  assert_empty "$_rid_bad" rid_join_same_output_as_the_field_loop
+  # control: the same comparison sees a difference (the multi fixture's two drones at max 1 and at max 32)
+  [ "$(awk -v max=1 -v ignkeys=" " "$_rid_ref" < "$_RFIX/multi.txt")" != "$(awk -v max=32 -v ignkeys=" " "$_rid_new" < "$_RFIX/multi.txt")" ] \
+    && pass || fail "rid_join_differential_sees_a_difference"
+else
+  fail "rid_join_differential: busybox not installed (sudo apt install busybox)"
+fi
+rm -rf "$_rid_vd"; unset _rid_new _rid_fast _rid_strip _rid_ref _rid_vd _rid_want _v _rid_bad _rid_n _awk _keys _f _s _m
+
 # --- crafted frames (spec §8): test/fixtures/rid/hostile/ holds byte edits of the fixtures above, as tcpdump
 # text only (no pcap of them exists, and no tool makes them). Each edit is written next to its test: offsets
 # are tcpdump's 0x.. byte offsets, counted from the start of the radiotap header. Every case is decoded by this
````

- [ ] **Step 2: Run them against today's decoder**

Run: `bash .superpowers/sdd/tools/minirun.sh "$PWD" remoteid_test.sh`
Expected: last line `PASS=633 FAIL=2`; the two failures are `rid_join_fast_path_in_the_decoder` and
`rid_join_strip_in_the_decoder` (the other 14 new assertions are guards: before the change the reference and the
decoder are the same program).

- [ ] **Step 3: Change the decoder** (patch `t1-impl`)

````diff t1-impl
diff --git a/payloads/user/reconnaissance/squachwatch/lib/remoteid.sh b/payloads/user/reconnaissance/squachwatch/lib/remoteid.sh
index 5ce2cbf..e848b4b 100644
--- a/payloads/user/reconnaissance/squachwatch/lib/remoteid.sh
+++ b/payloads/user/reconnaissance/squachwatch/lib/remoteid.sh
@@ -48,9 +48,14 @@ $1 !~ /^0x[0-9a-f]+:$/ { if (hex != "") decode(); hex = ""; sig = ""
   if (match($0, /-?[0-9]+dBm signal/)) { sig = substr($0, RSTART, RLENGTH - 10)
     if (sig !~ /^(0|-?[1-9][0-9]?[0-9]?)$/ || sig + 0 < -128 || sig + 0 > 127) sig = "" }
   next }
-{ for (k = 2; k <= NF; k++) hex = hex $k }
+# The hex lines: each line's text after tcpdump's prefix (a tab, "0x", four hex digits, ":", two blanks), the
+# blanks stripped once per frame in decode(): on the Pager 6.3 ms per ordinary beacon, against 16.7 ms appending
+# field by field (spec 2026-10-08). A line of another shape takes the field loop: the output is the same either way.
+{ if (substr($0, 1, 10) == "\t" $1 "  ") hex = hex substr($0, 11)
+  else for (k = 2; k <= NF; k++) hex = hex $k }
 END { if (hex != "") decode(); emit() }
 function decode(  off, fc, hl, ie, id, ln, f, i, pk, steps) {
+  gsub(/[ \t]/, "", hex)                                    # the joining left blanks: one strip per frame
   frames++
   if (length(hex) % 2) return
   off = le16(2)                                              # the radiotap length = where 802.11 starts
````

- [ ] **Step 4: Run the tests again**

Run: `bash .superpowers/sdd/tools/minirun.sh "$PWD" remoteid_test.sh` → last line `PASS=635 FAIL=0`.
Run: `bash .superpowers/sdd/tools/minirun.sh "$PWD" perf_test.sh portability_test.sh` → last line `PASS=84 FAIL=0`.

- [ ] **Step 5: The docs** (patch `t1-docs`: the measurements in P0-findings, the design's code block without the
  redundant length check, the README's count)

````diff t1-docs
diff --git a/README.md b/README.md
index d2df720..f6c3349 100644
--- a/README.md
+++ b/README.md
@@ -105,7 +105,7 @@ An offline harness runs the whole detection engine on a normal Linux box (no Pag
 bash test/run.sh
 ```
 
-Every detection test pairs a known-hit case with a clean case, and the load-bearing ones are proven to fail against a deliberately-broken variant (no vacuous passes). As of this writing: **1648 assertions, all passing** (also as root).
+Every detection test pairs a known-hit case with a clean case, and the load-bearing ones are proven to fail against a deliberately-broken variant (no vacuous passes). As of this writing: **1664 assertions, all passing** (also as root).
 
 ## Status & roadmap
 
diff --git a/docs/superpowers/P0-findings.md b/docs/superpowers/P0-findings.md
index 08ef45b..e0af47e 100644
--- a/docs/superpowers/P0-findings.md
+++ b/docs/superpowers/P0-findings.md
@@ -804,6 +804,28 @@ payload it measures.
    WARN was most likely one lap whose nice-10 decoder fell behind while the screen was busy: a real, rare loss,
    reported as designed (inferred: that lap's counts were not recorded).
 
+### The decoder's cost per frame, and a cheaper joining (2026-10-08)
+
+Measured on the Pager: 300 real ordinary beacons (427 KB of tcpdump text, about 26 hex lines each), captured into a
+temp folder there and deleted after; BusyBox awk; CPU (user + system), mean of 3 runs; two rounds.
+
+| program (same input) | CPU | per beacon |
+|---|---|---|
+| reading the lines only | 0.07 s | 0.2 ms |
+| + telling header lines from hex lines | 0.35 s | 1.2 ms |
+| + reading the signal | 0.38 s | 1.3 ms |
+| + joining the hex, field by field | 3.6 s | 12 ms |
+| the whole decoder | 5.0 s | 16.7 ms |
+| the whole decoder, joining each line's text after tcpdump's prefix with one strip per frame | 1.9 s | 6.3 ms |
+
+About 70% of the cost was the joining (about 210 appends per beacon): the pre-test already drops an ordinary beacon
+right after its header checks. The last row is the measured candidate (no check of the prefix's shape, blanks only);
+the decoder now has both (spec `2026-10-08-squachwatch-rid-decoder-speedup-design.md`), and its output was
+identical to the old joining's on those 600 beacons and on all 68 fixtures. Programs that only joined, without
+decoding, varied from run to run (2.6 s in one round, 5.6 s in the other) and were not used. Why it mattered: on two
+walks that day recon heard 1,000 to 1,500 different access points per 10 minutes (about 50 at home), so a window
+there very likely filled its 300 frames within seconds (inferred), and the frame cap went to 700 with this change.
+
 **Still to do on the Pager, with the user** (done on 2026-10-08, above: the install, the silent run, the window
 against a real Bluetooth scan, the ranking's cost and awk parity, the slack's measurements at home, a menu Stop
 during a window and the hostile-ID probe):
diff --git a/docs/superpowers/specs/2026-10-08-squachwatch-rid-decoder-speedup-design.md b/docs/superpowers/specs/2026-10-08-squachwatch-rid-decoder-speedup-design.md
index 5b0f6bd..0ca8e11 100644
--- a/docs/superpowers/specs/2026-10-08-squachwatch-rid-decoder-speedup-design.md
+++ b/docs/superpowers/specs/2026-10-08-squachwatch-rid-decoder-speedup-design.md
@@ -56,10 +56,12 @@ The hex-line rule takes the line's text after tcpdump's prefix when the prefix h
 field loop otherwise:
 
 ```awk
-{ if (length($1) == 7 && substr($0, 1, 10) == "\t" $1 "  ") hex = hex substr($0, 11)
+{ if (substr($0, 1, 10) == "\t" $1 "  ") hex = hex substr($0, 11)
   else for (k = 2; k <= NF; k++) hex = hex $k }
 ```
 
+(The comparison can only hold when the offset field is 7 characters long, so it needs no length check of its own.)
+
 and `decode()` first removes every blank and tab: `gsub(/[ \t]/, "", hex)`, before any other step.
 
 Why the output does not change: the usual line is a tab, the 7-character offset (`0x`, four hex digits, `:`),
````

- [ ] **Step 6: The whole suite**

Run: `bash test/run.sh` → last line `PASS=1664 FAIL=0`, nothing else printed but the headers and the dashes.

- [ ] **Step 7: Commit**

```bash
git add payloads/user/reconnaissance/squachwatch/lib/remoteid.sh test/remoteid_test.sh docs/superpowers/P0-findings.md \
  docs/superpowers/specs/2026-10-08-squachwatch-rid-decoder-speedup-design.md README.md
TZ=UTC git -c user.name=Ziggy -c user.email=79704039+therealziggy@users.noreply.github.com commit -F - <<'EOF'
remoteid: join each hex line's text after tcpdump's prefix, one strip per frame

On the Pager about 70% of the decoder's 16.7 ms per ordinary beacon went to
joining tcpdump's hex field by field (about 210 appends per beacon). The
hex-line rule now appends each line's text after tcpdump's fixed prefix (a
tab, the offset, two blanks), and decode() strips blanks and tabs once per
frame: 6.3 ms per beacon for the measured candidate, with the same output.
A line of any other shape takes the old field loop.

Tests: the decoder against a reference built from its own source with the
old joining (every fixture, the hostile ones too, four variants and two
whole streams at max 32, 0 and 1, with and without a drone: key, on this
awk and on BusyBox awk: 312 comparisons, and a control that the comparison
sees a difference); variants of the reference beacon (no tab, one blank, a
three-digit offset, a tab between words) decode as the beacon does; the
rule and the strip are pinned. P0-findings gets the measurements. 1664
assertions.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
git log -1 --format=%B | grep -cF 'Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>'
```

Expected: the last command prints `1`.

---

### Task 2: The frame cap's default is 700

**Files:**
- Modify: `payloads/user/reconnaissance/squachwatch/payload.sh` (`SW_RID_MAX_FRAMES`'s default and its comment)
- Modify: `payloads/user/reconnaissance/squachwatch/lib/remoteid.sh` (the two fallbacks in each of `sw_rid_start` and
  `sw_rid_collect`)
- Modify: `test/remoteid_test.sh` (`cap_tcpdump_args` and its comment; the default-cap block, plus two new
  assertions), `test/payload_test.sh` (`payload_rid_defaults`), `test/perf_test.sh` (a comment)
- Modify: `README.md` (`SW_RID_MAX_FRAMES` and the count, 1664 → 1666),
  `docs/superpowers/specs/2026-10-01-squachwatch-remote-id-wifi-design.md` (§6, §7.5 and a new §22)

**Interfaces:**
- Consumes: Task 1's commit (the patches apply on top of it); `_cap`, `_cap_reset`, `_cap_state`, `$_fr` and
  `$SW_STUB_LOG` in `test/remoteid_test.sh`.
- Produces: `SW_RID_MAX_FRAMES` = 700 by default (unset, and for a value that is not a plain number).

- [ ] **Step 1: Write the tests** (patch `t2-tests`)

````diff t2-tests
diff --git a/test/payload_test.sh b/test/payload_test.sh
index 777aaf3..7166c99 100644
--- a/test/payload_test.sh
+++ b/test/payload_test.sh
@@ -937,7 +937,7 @@ assert_contains "$(cat "$SW_SEEN_FILE")" "80:E1:26:AA:BB:CC|drone_rid|" rid_lap_
 # the defaults, read in a clean process (a test that sets a value cannot see its default)
 assert_eq "$(env -u SW_REMOTE_ID -u SW_RID_IFACE -u SW_RID_SECONDS -u SW_RID_MAX_FRAMES -u SW_RID_MAX_DRONES -u SW_RID_FILE -u SW_LOOT_DIR \
   bash -c 'SW_TEST_SOURCE=1 . "$1"/payload.sh >/dev/null 2>&1; echo "$SW_REMOTE_ID|$SW_RID_IFACE|$SW_RID_SECONDS|$SW_RID_MAX_FRAMES|$SW_RID_MAX_DRONES|$SW_RID_FILE"' _ "$SW_ROOT")" \
-  "1|wlan1mon|12|300|32|/root/loot/squachwatch/remoteid.csv" payload_rid_defaults
+  "1|wlan1mon|12|700|32|/root/loot/squachwatch/remoteid.csv" payload_rid_defaults
 # health: the capture needs tcpdump and the recon radio's interface (spec 2026-10-01 §7.1). A PATH with
 # only what the check needs (the btmon stub too, so tcpdump is the only thing missing).
 _rn="$(mktemp -d)"; mkdir "$_rn/net" "$_rn/bin"; : > "$_rn/net/wlan1mon"
diff --git a/test/perf_test.sh b/test/perf_test.sh
index 4e5bb1e..a6486b1 100644
--- a/test/perf_test.sh
+++ b/test/perf_test.sh
@@ -111,8 +111,8 @@ assert_contains "$(_sw_body "$SW_ROOT/lib/remoteid.sh" sw_rid_start)" " -p -l -t
 assert_empty "$(_sw_body "$SW_ROOT/lib/remoteid.sh" sw_rid_start | grep -nE '(^|[^-])-I( |$)|iw |iwconfig|ifconfig|ip link')" rid_capture_never_reconfigures
 # control: the same grep sees a planted -I
 assert_contains "$(printf 'tcpdump -I -i wlan1mon\n' | grep -nE '(^|[^-])-I( |$)|iw |iwconfig|ifconfig|ip link')" "-I" rid_reconfigure_grep_works
-# LATENCY BUDGET for the decoder: 1,500 frames (1,200 ordinary beacons + 300 Remote ID) in one pass, five times
-# the default frame cap (300), so a decoder that slows down shows here first
+# LATENCY BUDGET for the decoder: 1,500 frames (1,200 ordinary beacons + 300 Remote ID) in one pass, more than
+# twice the default frame cap (700), so a decoder that slows down shows here first
 _rfx="$(cd "$(dirname "${BASH_SOURCE[0]}")/fixtures" && pwd)/rid"; _big="$(mktemp)"
 { for _i in $(seq 1200); do cat "$_rfx/quiet.txt"; done; for _i in $(seq 300); do cat "$_rfx/beacon.txt"; done; } > "$_big"
 SECONDS=0; _o="$(_sw_rid_decode_awk < "$_big")"; _el=$SECONDS
diff --git a/test/remoteid_test.sh b/test/remoteid_test.sh
index 56ced29..dde1568 100644
--- a/test/remoteid_test.sh
+++ b/test/remoteid_test.sh
@@ -786,11 +786,11 @@ assert_contains "$(tail -1 "$_cap_loot/remoteid.csv")" "1700000000,beacon,80:E1:
 assert_eq "$(_cap_state)" "ok" cap_beacon_status_ok
 assert_empty "$(ls -A "$_cap_dir" | grep -v '^sw_rid\.state$')" cap_leaves_no_capture_files
 # tcpdump ran read only (-p), on the configured interface, without clock times (-t), keeping only the first 1024
-# bytes of each frame (-s 1024), with the frame cap (300 by default). Phase 0 on the Pager (2026-10-02): no beacon
-# heard there came near 1024 bytes (the largest was 526), a crafted 4 KB frame cut to 1024 costs the decoder about 8
-# times less, and an ordinary beacon costs about 15 ms (16 to 18 ms on 2026-10-08), so 300 frames are about 4.6 to
-# 5.4 s of CPU (1500 were about 23 s)
-assert_contains "$(grep '^tcpdump ' "$SW_STUB_LOG")" "tcpdump -i wlan1mon -p -l -t -nn -xx -s 1024 -c 300 type mgt subtype beacon or (wlan[0] & 0xfc = 0xd0 and wlan addr1 51:6f:9a:01:00:00)" cap_tcpdump_args
+# bytes of each frame (-s 1024), with the frame cap (700 by default). Phase 0 on the Pager (2026-10-02): no beacon
+# heard there came near 1024 bytes (the largest was 526), and a crafted 4 KB frame cut to 1024 costs the decoder about
+# 8 times less. With the cheaper joining (spec 2026-10-08) an ordinary beacon costs the decoder about 6 ms and
+# tcpdump about 2 ms, so 700 frames are about 5.6 s of CPU, what 300 cost before
+assert_contains "$(grep '^tcpdump ' "$SW_STUB_LOG")" "tcpdump -i wlan1mon -p -l -t -nn -xx -s 1024 -c 700 type mgt subtype beacon or (wlan[0] & 0xfc = 0xd0 and wlan addr1 51:6f:9a:01:00:00)" cap_tcpdump_args
 # ...on the interface SW_RID_IFACE names, not a fixed one
 _cap_reset; _cap beacon SW_RID_IFACE=wlan7mon >/dev/null
 assert_contains "$(grep '^tcpdump ' "$SW_STUB_LOG")" "tcpdump -i wlan7mon -p " cap_tcpdump_follows_the_setting
@@ -999,15 +999,21 @@ assert_eq "$(grep -c 'hit its frame limit' "$SW_STUB_LOG")" "1" cap_capped_warns
 # ...and again once the cooldown has passed (SW_COOLDOWN=0: every capped lap may warn)
 _cap multi SW_RID_MAX_FRAMES=1 SW_COOLDOWN=0 >/dev/null
 assert_eq "$(grep -c 'hit its frame limit' "$SW_STUB_LOG")" "2" cap_capped_warns_again_after_cooldown
-# ...at the default cap, 300 (the quiet fixture's beacon 300 times, the setting unset), and with a setting that is
+# ...at the default cap, 700 (the quiet fixture's beacon 700 times, the setting unset), and with a setting that is
 # not a plain number ("abc"), which gives the default at both ends: tcpdump's -c and the count the lap is judged by.
 # (control: cap_five_beacons_status_ok, fewer frames than the cap)
-for _i in $(seq 300); do cat "$_RFIX/quiet.txt"; done > "$_fr"
+for _i in $(seq 700); do cat "$_RFIX/quiet.txt"; done > "$_fr"
 _cap_reset; _cap "$_fr" >/dev/null
 assert_eq "$(_cap_state)" "capped" cap_capped_at_the_default
 _cap_reset; _cap "$_fr" SW_RID_MAX_FRAMES=abc >/dev/null
-assert_contains "$(grep '^tcpdump ' "$SW_STUB_LOG")" " -c 300 " cap_frame_cap_setting_checked
+assert_contains "$(grep '^tcpdump ' "$SW_STUB_LOG")" " -c 700 " cap_frame_cap_setting_checked
 assert_eq "$(_cap_state)" "capped" cap_capped_setting_checked
+# ...and 300 frames, the cap before 2026-10-08, no longer fill it, at both ends (the setting unset, and "abc")
+for _i in $(seq 300); do cat "$_RFIX/quiet.txt"; done > "$_fr"
+_cap_reset; _cap "$_fr" >/dev/null
+assert_eq "$(_cap_state)" "ok" cap_three_hundred_frames_ok_at_the_default
+_cap_reset; _cap "$_fr" SW_RID_MAX_FRAMES=abc >/dev/null
+assert_eq "$(_cap_state)" "ok" cap_three_hundred_frames_ok_setting_checked
 rm -f "$_fr"
 # Frames the kernel dropped (tcpdump's "N packets dropped by kernel": the CPU did not keep up) leave Remote ID
 # partly blind: a WARN at most once per SW_COOLDOWN, like the frame cap, and what was heard still counts.
````

- [ ] **Step 2: Run them against the cap of 300**

Run: `bash .superpowers/sdd/tools/minirun.sh "$PWD" remoteid_test.sh payload_test.sh perf_test.sh`
Expected: last line `PASS=977 FAIL=5`; the failures are `cap_tcpdump_args`, `cap_frame_cap_setting_checked`,
`cap_three_hundred_frames_ok_at_the_default`, `cap_three_hundred_frames_ok_setting_checked` and
`payload_rid_defaults`.

- [ ] **Step 3: Change the default** (patch `t2-impl`)

````diff t2-impl
diff --git a/payloads/user/reconnaissance/squachwatch/lib/remoteid.sh b/payloads/user/reconnaissance/squachwatch/lib/remoteid.sh
index e848b4b..427dc82 100644
--- a/payloads/user/reconnaissance/squachwatch/lib/remoteid.sh
+++ b/payloads/user/reconnaissance/squachwatch/lib/remoteid.sh
@@ -423,9 +423,9 @@ sw_rid_start() {
   [ "${SW_REMOTE_ID:-0}" = 1 ] || return 0
   command -v tcpdump >/dev/null 2>&1 || return 0
   sw_stopped && return 0
-  local now="$1" secs="${SW_RID_SECONDS:-12}" maxf="${SW_RID_MAX_FRAMES:-300}" maxd="${SW_RID_MAX_DRONES:-32}" cap err keys
+  local now="$1" secs="${SW_RID_SECONDS:-12}" maxf="${SW_RID_MAX_FRAMES:-700}" maxd="${SW_RID_MAX_DRONES:-32}" cap err keys
   [[ "$secs" =~ ^[1-9][0-9]{0,4}$ ]] || secs=12
-  [[ "$maxf" =~ ^[1-9][0-9]{0,6}$ ]] || maxf=300
+  [[ "$maxf" =~ ^[1-9][0-9]{0,6}$ ]] || maxf=700
   [[ "$maxd" =~ ^(0|[1-9][0-9]{0,3})$ ]] || maxd=32
   # no temp file: never the interface's blink, so OFF at once (sw_rid_health_note)
   cap="$(mktemp "${SW_TMP_DIR:-/tmp}/sw_rid.XXXXXX")" || { sw_rid_health_note capture_failed "$now" at_once; return 0; }
@@ -446,8 +446,8 @@ sw_rid_collect() {
   wait "$pid" 2>/dev/null
   # stopped during the window: drop the capture unread and report nothing (a relaunch owns the screen now)
   if sw_stopped; then rm -f "$cap" "$err"; return 0; fi
-  local l started=0 radio=0 pkts="" recv="" drops="" loop=0 stats=0 frames=0 understood=0 more=0 tag ridf maxf="${SW_RID_MAX_FRAMES:-300}" st
-  [[ "$maxf" =~ ^[1-9][0-9]{0,6}$ ]] || maxf=300
+  local l started=0 radio=0 pkts="" recv="" drops="" loop=0 stats=0 frames=0 understood=0 more=0 tag ridf maxf="${SW_RID_MAX_FRAMES:-700}" st
+  [[ "$maxf" =~ ^[1-9][0-9]{0,6}$ ]] || maxf=700
   while IFS= read -r l || [ -n "$l" ]; do
     case "$l" in
       "listening on "*) started=1; case "$l" in *"link-type IEEE802_11_RADIO "*) radio=1 ;; esac ;;
diff --git a/payloads/user/reconnaissance/squachwatch/payload.sh b/payloads/user/reconnaissance/squachwatch/payload.sh
index 06e5701..3d0ae89 100644
--- a/payloads/user/reconnaissance/squachwatch/payload.sh
+++ b/payloads/user/reconnaissance/squachwatch/payload.sh
@@ -88,11 +88,12 @@ done
 # BLE scan (about 13 s) makes every lap longer.
 : "${SW_RID_SECONDS:=12}"
 # At most this many frames per lap (it reads every nearby beacon, so a beacon flood must not eat the
-# CPU: on the Pager an ordinary beacon costs about 15 to 18 ms to capture and decode, so 300 frames are about 4.6
-# to 5.4 s of CPU, against the 60 to 100 a lap hears at home; 2026-10-02 and 2026-10-08), and this many drones
-# per lap (the strongest, those ignore.txt may silence chosen last; the rest are counted on one line; 0 = no cap,
-# in the order heard, which lets a flood of made-up drones cost each lap time and two CSV rows per drone).
-: "${SW_RID_MAX_FRAMES:=300}"
+# CPU: on the Pager an ordinary beacon costs about 8 ms to capture and decode (spec 2026-10-08), so 700 frames
+# are about 5.6 s of CPU, against the 60 to 100 a lap hears at home; a busy street likely fills 300), and this
+# many drones per lap (the strongest, those ignore.txt may silence chosen last; the rest are counted on one line;
+# 0 = no cap, in the order heard, which lets a flood of made-up drones cost each lap time and two CSV rows per
+# drone).
+: "${SW_RID_MAX_FRAMES:=700}"
 : "${SW_RID_MAX_DRONES:=32}"
 # The flight-track log: one row per drone per lap in which it was heard.
 : "${SW_RID_FILE:=$SW_LOOT_DIR/remoteid.csv}"
````

- [ ] **Step 4: Run the tests again**

Run: `bash .superpowers/sdd/tools/minirun.sh "$PWD" remoteid_test.sh payload_test.sh perf_test.sh`
Expected: last line `PASS=982 FAIL=0`.

- [ ] **Step 5: The docs** (patch `t2-docs`)

````diff t2-docs
diff --git a/README.md b/README.md
index f6c3349..88ee537 100644
--- a/README.md
+++ b/README.md
@@ -25,7 +25,7 @@ Two settings keep a lap cheap and the loot file bounded:
 - `SW_KIND_COOLDOWN` (default 600): one full-screen alert + buzz per *kind* of device (e.g. "Flipper Zero") per window, and only for **high**-confidence detections (see the Signatures section below). A flood of new high-confidence devices of one kind, such as a room full of real Flippers or several Flock cameras appearing at once, buzzes once; a BLE Spam flood of name-only fake Flippers is **med** confidence and never buzzes at all — that's 0 times, not once. Every device still gets its CSV row (and a screen line, up to the per-lap cap; see `SW_LOG_PER_KIND` below). "Following you" alerts are exempt (they have AUTO SNOOZE). Your own devices (your Flipper, say) belong in `ignore.txt` below: left out, a device that stays near you re-alerts every window and spends the kind's one buzz on itself, so a stranger's device of the same kind arriving in that window would only be logged, not buzz. Set `0` to turn it off.
 - `SW_LOG_PER_KIND` (default 3): per lap, at most this many screen lines per kind **and confidence level** of device, then one `...and N more <label>` line, so a flood can't scroll everything else off the screen. A real high-confidence device (e.g. your actual Flipper) gets its own allowance separate from a same-kind med/low flood (e.g. a BLE Spam name-only flood), so it's never folded behind the fakes. Every device still gets its CSV row. `0` = no cap.
 - `SW_EVIL_TWIN` (default 1): the evil-twin check, ported from SquachWatch-CYD. An evil twin is a fake copy of a WiFi network, usually open (no password), set up to lure phones and laptops onto it. Each lap, a network name that is offered both open and password-protected within `SW_RECENCY_SECS` (600 s when that is 0) makes every open copy an evil twin: a full-screen alert naming the network (`Evil twin 'HomeNet'` and the copy's address), the buzz, the red LED, and a CSV row with category `evil_twin`. The usual cooldowns and screen cap apply. On the screen a `\n` in the name shows as `\ n`: the Pager turns those two characters into a line break, so a name could otherwise add a line of its own (the CSV keeps the name as it is). Names must match exactly, capitals included, and hidden networks are skipped. `0` turns the check off. Every copied name gets its own CSV row, even when one radio copies several names, and a screen line up to the usual `SW_LOG_PER_KIND` per lap (then "...and N more Evil twin"); several twins at once still buzz only once per `SW_KIND_COOLDOWN`, and that alert names the first one found, so the CSV is the full list. A plain address in `ignore.txt` never silences an evil twin, because the attacker chooses the address it broadcasts and could copy your router's or your Flipper's. To silence one open copy on purpose (your own Pager's open access point while you test, say), add a line `evil_twin:<its address>`; never add your own router's address that way, or a copy made under it would be silenced too. Limits: a copy that matches the real network's password setting is not caught, and that includes an open copy of an open café hotspot, the most common public-WiFi trick (CYD has the same limit); a copy of a hidden network is not caught either; both copies must be heard within the window; a nearby router switched from open to protected during its setup alerts once; and your own Pager, running its open access point under the name of a nearby protected network, is reported, because that is an evil twin. The health check cannot tell when a firmware update keeps the recon DB's columns but changes what their values mean.
-- `SW_REMOTE_ID` (default 1): listens for drones that broadcast **Remote ID** over WiFi, the public "licence plate" that many drones must now send, in the US, the EU and elsewhere. Each lap a short, read-only capture on the recon radio decodes the drone's ID (usually its serial number), what it is, where it is (position, height, speed, heading) and **where its pilot is** (or where it took off), as a full-screen alert with the buzz and the magenta LED: `Drone '<ID>'`, then the airframe, height and speed, then the pilot's location, then its address. A second screen line repeats the height, speed and pilot. As with evil twins, a `\n` in the ID shows as `\ n` on the screen. The drone's own position and heading are only in `remoteid.csv`, not on the screen. Every lap in which a drone is heard adds a row to `remoteid.csv` in the loot folder: its flight track, with the Pager's own GPS fix when a GPS is attached. That file grows by a row per drone per lap and is never pruned: a flood of made-up drones adds up to `SW_RID_MAX_DRONES` rows a lap (roughly 1 MB an hour at the default 32). It decodes the three WiFi forms of Remote ID: the standard beacon (which DJI uses), the standard NAN frame (WiFi "Neighbor Awareness Networking", a broadcast meant for nearby phones) and Parrot's own beacon. One drone is one ID: a drone whose WiFi address changes stays one drone, with one alert per `SW_COOLDOWN`. The capture rides the recon scan's channel hopping instead of taking a radio, so it hears a drone only while the scan is on that drone's channel: on the Pager the scan visits 36 channels in turn, each for about a fifth of a second every 7.6 seconds (measured at home). So a drone on channel 6 that sends its Remote ID ten times a second is heard in nearly every lap, and one that sends it once a second in about one lap in three, and about two times in three within a minute (it listens for 12 s of each lap, and a lap takes about 21 to 23 s); that is worked out from the channel timings, not yet measured with a drone, and a drone that passes in seconds may be missed. Remote ID is not signed, so a detection means "something here broadcasts drone Remote ID", and every position is what the broadcast claims. To silence your own drone, add `drone:<its ID>` to `ignore.txt`. A drone that sends two IDs (a serial number and a registration, say; `remoteid.csv` shows both) needs a line for each: a WiFi drone stays silent only while **every** ID heard from its address is listed. Each lap, SquachWatch keeps the first two different IDs it hears from an address (an empty one does not count); if the address sends any more, the drone is never silenced, and its alert and second screen line say `also sends other IDs`. And when a lap hears more drones than `SW_RID_MAX_DRONES` (below), the ones your list may silence are the first left out. So copies of your drone's ID cannot hide another drone whose own ID is heard, whether they are sent from its address or from many louder ones: it is reported under one of the two IDs kept from its address (when only one of them is on your list, the other one; otherwise the first one heard, a serial number preferred, so a spoofer heard first can make it show one of the spoofer's IDs), with `also sends other IDs` whenever its address sent more than two different IDs. What this does not cover: a drone that sends no ID of its own can still be hidden by copies of yours sent from its address; your own drone cannot be silenced while its address sends three or more different IDs; a drone whose own ID differs from one on your list only in characters other than the letters A to Z and the digits (a dash, say; and if your list holds an ID with neither, every drone whose own ID has neither) is left out together with the listed ones, though it is reported whenever it is kept; `SW_RID_MAX_DRONES` or more other drones that your list does not silence (a flood of made-up ones, say), each heard at least as strongly, can still push a weaker drone out of the lap, but those are reported themselves (a flood you can see, with the `...and N more drones` line); and a beacon flood that reaches `SW_RID_MAX_FRAMES` leaves Remote ID partly blind, with a yellow WARN (below). When only one of a drone's two IDs is listed, the drone is named by the other one. One that sends no ID at all is silenced by `drone:<its address>`. A plain address line never silences a WiFi drone, since its address can change (the Bluetooth `Drone (Remote ID)` rule is an ordinary signature, which a plain address does silence: a drone heard on both radios needs both lines). `0` turns it off. The other settings: `SW_RID_IFACE` (the recon radio it listens on, default `wlan1mon`), `SW_RID_SECONDS` (the capture window, default 12; the lap waits for it, so a window longer than the Bluetooth scan, about 13 s, makes every lap longer), `SW_RID_MAX_FRAMES` (default 300 frames per lap: the Pager takes about 15 to 18 ms to read and decode an ordinary beacon, so 300 cost about 4.6 to 5.4 s of its CPU, while a lap at home hears 60 to 100; a very busy spot or a beacon flood that reaches it leaves Remote ID partly blind, with the yellow WARN. Someone who sends many large or Remote ID-heavy frames on purpose can make a lap a few seconds longer while the decoder catches up, but not blind it silently: when the decoder or tcpdump falls so far behind that frames are lost, the lap shows that same WARN. What still reads as fine is a small backlog, frames tcpdump had not got to when the window closed: up to 5 plus a twelfth of the frames it heard, about the window's last second at the default 12 s, a margin worked out on the dev box; on the Pager at home a normal lap leaves 0 to 2 such frames, and in very busy air, not measured yet, it may now and then show the WARN on a lap that was fine), `SW_RID_MAX_DRONES` (default 32 drones per lap, the strongest, those your list may silence chosen last; the rest are counted on one line; `0` = no cap, in the order heard, which is not advised: each made-up drone of a flood then costs the lap time and a row in both CSV files) and `SW_RID_FILE` (default `remoteid.csv` in the loot folder). Limits: only the first 1024 bytes of each frame are read (no beacon heard at home came near that: the largest was 526 bytes), and at most 64 elements (beacon) or attributes (NAN) per frame, so Remote ID placed beyond either is not seen; several drones within `SW_KIND_COOLDOWN` buzz once (each still gets its screen line and rows); a drone that sends no ID is known by its address, so a new address means a new alert; a drone on both radios shows up twice, once per radio; Bluetooth 5 long-range Remote ID is not heard; there is no distance or bearing to the pilot; with recon off, or limited to some bands, Remote ID over WiFi is blind (recon off already warns). `remoteid.csv` records where other people's drones and pilots were: keep it private.
+- `SW_REMOTE_ID` (default 1): listens for drones that broadcast **Remote ID** over WiFi, the public "licence plate" that many drones must now send, in the US, the EU and elsewhere. Each lap a short, read-only capture on the recon radio decodes the drone's ID (usually its serial number), what it is, where it is (position, height, speed, heading) and **where its pilot is** (or where it took off), as a full-screen alert with the buzz and the magenta LED: `Drone '<ID>'`, then the airframe, height and speed, then the pilot's location, then its address. A second screen line repeats the height, speed and pilot. As with evil twins, a `\n` in the ID shows as `\ n` on the screen. The drone's own position and heading are only in `remoteid.csv`, not on the screen. Every lap in which a drone is heard adds a row to `remoteid.csv` in the loot folder: its flight track, with the Pager's own GPS fix when a GPS is attached. That file grows by a row per drone per lap and is never pruned: a flood of made-up drones adds up to `SW_RID_MAX_DRONES` rows a lap (roughly 1 MB an hour at the default 32). It decodes the three WiFi forms of Remote ID: the standard beacon (which DJI uses), the standard NAN frame (WiFi "Neighbor Awareness Networking", a broadcast meant for nearby phones) and Parrot's own beacon. One drone is one ID: a drone whose WiFi address changes stays one drone, with one alert per `SW_COOLDOWN`. The capture rides the recon scan's channel hopping instead of taking a radio, so it hears a drone only while the scan is on that drone's channel: on the Pager the scan visits 36 channels in turn, each for about a fifth of a second every 7.6 seconds (measured at home). So a drone on channel 6 that sends its Remote ID ten times a second is heard in nearly every lap, and one that sends it once a second in about one lap in three, and about two times in three within a minute (it listens for 12 s of each lap, and a lap takes about 21 to 23 s); that is worked out from the channel timings, not yet measured with a drone, and a drone that passes in seconds may be missed. Remote ID is not signed, so a detection means "something here broadcasts drone Remote ID", and every position is what the broadcast claims. To silence your own drone, add `drone:<its ID>` to `ignore.txt`. A drone that sends two IDs (a serial number and a registration, say; `remoteid.csv` shows both) needs a line for each: a WiFi drone stays silent only while **every** ID heard from its address is listed. Each lap, SquachWatch keeps the first two different IDs it hears from an address (an empty one does not count); if the address sends any more, the drone is never silenced, and its alert and second screen line say `also sends other IDs`. And when a lap hears more drones than `SW_RID_MAX_DRONES` (below), the ones your list may silence are the first left out. So copies of your drone's ID cannot hide another drone whose own ID is heard, whether they are sent from its address or from many louder ones: it is reported under one of the two IDs kept from its address (when only one of them is on your list, the other one; otherwise the first one heard, a serial number preferred, so a spoofer heard first can make it show one of the spoofer's IDs), with `also sends other IDs` whenever its address sent more than two different IDs. What this does not cover: a drone that sends no ID of its own can still be hidden by copies of yours sent from its address; your own drone cannot be silenced while its address sends three or more different IDs; a drone whose own ID differs from one on your list only in characters other than the letters A to Z and the digits (a dash, say; and if your list holds an ID with neither, every drone whose own ID has neither) is left out together with the listed ones, though it is reported whenever it is kept; `SW_RID_MAX_DRONES` or more other drones that your list does not silence (a flood of made-up ones, say), each heard at least as strongly, can still push a weaker drone out of the lap, but those are reported themselves (a flood you can see, with the `...and N more drones` line); and a beacon flood that reaches `SW_RID_MAX_FRAMES` leaves Remote ID partly blind, with a yellow WARN (below). When only one of a drone's two IDs is listed, the drone is named by the other one. One that sends no ID at all is silenced by `drone:<its address>`. A plain address line never silences a WiFi drone, since its address can change (the Bluetooth `Drone (Remote ID)` rule is an ordinary signature, which a plain address does silence: a drone heard on both radios needs both lines). `0` turns it off. The other settings: `SW_RID_IFACE` (the recon radio it listens on, default `wlan1mon`), `SW_RID_SECONDS` (the capture window, default 12; the lap waits for it, so a window longer than the Bluetooth scan, about 13 s, makes every lap longer), `SW_RID_MAX_FRAMES` (default 700 frames per lap: the Pager takes about 8 ms to read and decode an ordinary beacon, so 700 cost about 5.6 s of its CPU, while a lap at home hears 60 to 100 and a busy street likely more than 300; a very busy spot or a beacon flood that reaches it leaves Remote ID partly blind, with the yellow WARN. Someone who sends many large or Remote ID-heavy frames on purpose can make a lap a few seconds longer while the decoder catches up, but not blind it silently: when the decoder or tcpdump falls so far behind that frames are lost, the lap shows that same WARN. What still reads as fine is a small backlog, frames tcpdump had not got to when the window closed: up to 5 plus a twelfth of the frames it heard, about the window's last second at the default 12 s, a margin worked out on the dev box; on the Pager at home a normal lap leaves 0 to 2 such frames, and in very busy air, not measured yet, it may now and then show the WARN on a lap that was fine), `SW_RID_MAX_DRONES` (default 32 drones per lap, the strongest, those your list may silence chosen last; the rest are counted on one line; `0` = no cap, in the order heard, which is not advised: each made-up drone of a flood then costs the lap time and a row in both CSV files) and `SW_RID_FILE` (default `remoteid.csv` in the loot folder). Limits: only the first 1024 bytes of each frame are read (no beacon heard at home came near that: the largest was 526 bytes), and at most 64 elements (beacon) or attributes (NAN) per frame, so Remote ID placed beyond either is not seen; several drones within `SW_KIND_COOLDOWN` buzz once (each still gets its screen line and rows); a drone that sends no ID is known by its address, so a new address means a new alert; a drone on both radios shows up twice, once per radio; Bluetooth 5 long-range Remote ID is not heard; there is no distance or bearing to the pilot; with recon off, or limited to some bands, Remote ID over WiFi is blind (recon off already warns). `remoteid.csv` records where other people's drones and pilots were: keep it private.
 - `/root/loot/squachwatch/ignore.txt`: your own devices, and any companion's Tile or SmartTag you know about, one MAC per line (`#` comments allowed). They're skipped entirely, so your own Tile never alerts. It's read at launch. Put your own Flipper (or any other hacker tool you own) in here too: it isn't skipped by the kind cooldown the way it is by this file, so left out, it re-alerts every `SW_KIND_COOLDOWN` window and spends the kind's one buzz on itself — a stranger's Flipper arriving in that same window would then only be logged, never buzz. A plain address here never silences an evil twin or a drone decoded over WiFi: a line `evil_twin:<address>` silences that one evil twin and nothing else (see `SW_EVIL_TWIN` above), and lines `drone:<its ID>`, one per ID it sends, silence that drone (or `drone:<address>` for one that sends no ID; see `SW_REMOTE_ID` above).
 
 If the recon DB stops updating, every sweep would return zero rows and look exactly like "all clear" — so the scanner detects that case explicitly and logs a warning instead, re-checking every `SW_HEALTH_EVERY` laps. The same goes for the evil-twin check: if the recon DB stops recording what that check reads (each network's security, signal, address or hidden flag, after a firmware change, say), it warns "evil-twin check is blind" instead of quietly finding nothing. And if no copy of the recon DB can be made (a full `/tmp`, say), which leaves WiFi detection with nothing to read, it warns "can't copy the recon DB". With the evil-twin check on, a recon DB that still reads as damaged on a second, fresh copy warns too (a single damaged copy is usually one taken while the DB was being written). Remote ID over WiFi has its own: at launch `tcpdump missing` or `wlan1mon missing` (the configured radio); and per lap, once until it changes, `WiFi capture failed` (when the capture fails to start two laps in a row: the recon radio switches off for about half a second every 30 seconds, and a capture that starts in that moment fails once; but at once when it cannot make its temp files in `/tmp`, or cannot keep its note of a failed lap there, as with a `/tmp` already full at launch) or `WiFi capture not understood` (both "Remote ID over WiFi OFF", followed by a green `Remote ID capture recovered` when it works again), or, at most once per `SW_COOLDOWN`, one of two "partly blind" lines: the frame limit (`beacon flood?`) or frames lost (`CPU busy?`, when tcpdump reports packets dropped by the kernel, when the decoder saw fewer than tcpdump captured, when tcpdump ended without its counts, or with only some of them, because the decoder had fallen behind, when tcpdump stopped with more frames it never got to than the small backlog `SW_RID_MAX_FRAMES` above allows, or when the capture ended early on an error). A lap that still reports a drone never says "OFF".
@@ -105,7 +105,7 @@ An offline harness runs the whole detection engine on a normal Linux box (no Pag
 bash test/run.sh
 ```
 
-Every detection test pairs a known-hit case with a clean case, and the load-bearing ones are proven to fail against a deliberately-broken variant (no vacuous passes). As of this writing: **1664 assertions, all passing** (also as root).
+Every detection test pairs a known-hit case with a clean case, and the load-bearing ones are proven to fail against a deliberately-broken variant (no vacuous passes). As of this writing: **1666 assertions, all passing** (also as root).
 
 ## Status & roadmap
 
diff --git a/docs/superpowers/specs/2026-10-01-squachwatch-remote-id-wifi-design.md b/docs/superpowers/specs/2026-10-01-squachwatch-remote-id-wifi-design.md
index 56be6d2..2faa917 100644
--- a/docs/superpowers/specs/2026-10-01-squachwatch-remote-id-wifi-design.md
+++ b/docs/superpowers/specs/2026-10-01-squachwatch-remote-id-wifi-design.md
@@ -446,9 +446,10 @@ Header:
 - `SW_REMOTE_ID=1`: anything else turns it off (no capture runs at all).
 - `SW_RID_IFACE=wlan1mon`.
 - `SW_RID_SECONDS=12`: the capture window (confirmed by Phase 0, §6.1).
-- `SW_RID_MAX_FRAMES=300`: frames per lap (user decision 2026-10-02, from the cost Phase 0 measured: about
-  4.6 s of CPU at the cap for ordinary beacons, about 5.4 s with the larger ones heard on 2026-10-08, where 1500
-  would take about 23 s; §7.5). A value that is not a plain number gives 300.
+- `SW_RID_MAX_FRAMES=700`: frames per lap. It was 300 (user decision 2026-10-02, from the cost Phase 0 measured:
+  about 4.6 s of CPU at the cap for ordinary beacons, where 1500 would take about 23 s); since 2026-10-08 it is 700,
+  with the cheaper decoder of §22 (about 5.6 s at the cap, modelled; §7.5). A value that is not a plain number gives
+  700.
 - `SW_RID_MAX_DRONES=32`: drones per lap.
 - `SW_RID_FILE=$SW_LOOT_DIR/remoteid.csv`.
 - `remoteid` joins the libraries `payload.sh` loads. The library reads each setting as `${VAR:-default}` at
@@ -584,6 +585,9 @@ Remote ID is not authenticated, and spoofing tools are public, so every byte is
   of Remote ID frames (dev box, below), whose floods cost about 7 to 16 s at 300 frames anyway (next bullet);
   ordinary beacons give it no address to rank. On the Pager (2026-10-08): +13 to 14% on such floods, and +4.8% on
   ordinary beacons, which comes from the key's length, not the ranking (a one-letter key costs nothing).
+- **Since 2026-10-08 the cap is 700** (§22): the cheaper joining costs the decoder 6.3 ms per ordinary beacon on the
+  Pager (measured, before its check of the prefix's shape), so 700 frames take about 5.6 s with tcpdump's share
+  (modelled), about what 300 took before.
 - **Crafted frames** cost more (Pager, decoder only): the reference Remote ID beacon 22.9 ms, a dense one (nine
   messages, a new address each) 52.6 to 55.8 ms, a 2 KB frame 179 ms, a 4 KB frame 430 to 503 ms. `-s 1024` cuts
   every frame to its first 1024 bytes, so that 4 KB frame costs 59 ms, about 8 times less, and no beacon heard at
@@ -983,3 +987,12 @@ P0-findings. The user skipped the checks that need someone at the Pager.
 
 Still open: ordinary laps in a busy place, the evil-twin run with a hostile-looking name, and the live test with
 a real drone (§10).
+
+## 22. A cheaper decoder and a frame cap of 700 (2026-10-08)
+
+Design: `2026-10-08-squachwatch-rid-decoder-speedup-design.md`. On two walks the Pager's recon heard 1,000 to 1,500
+access points per 10 minutes (about 50 at home), so a window there very likely filled its 300 frames within seconds
+(inferred). On the Pager about 70% of the decoder's 16.7 ms per ordinary beacon went to joining tcpdump's hex field
+by field. The decoder now joins each hex line's text after tcpdump's prefix and strips the blanks once per frame (a
+line of another shape takes the old field loop; tested against the old joining on every fixture, the hostile ones
+too, on mawk and BusyBox awk), and `SW_RID_MAX_FRAMES` defaults to 700.
````

- [ ] **Step 6: The whole suite**

Run: `bash test/run.sh` → last line `PASS=1666 FAIL=0`, nothing else printed but the headers and the dashes.

- [ ] **Step 7: Commit**

```bash
git add payloads/user/reconnaissance/squachwatch/payload.sh payloads/user/reconnaissance/squachwatch/lib/remoteid.sh \
  test/remoteid_test.sh test/payload_test.sh test/perf_test.sh README.md \
  docs/superpowers/specs/2026-10-01-squachwatch-remote-id-wifi-design.md
TZ=UTC git -c user.name=Ziggy -c user.email=79704039+therealziggy@users.noreply.github.com commit -F - <<'EOF'
remoteid: the frame cap's default is 700

With the cheaper joining an ordinary beacon costs about 8 ms on the Pager
(the decoder's 6.3 ms and tcpdump's 1.8 ms), so 700 frames take about 5.6 s
of CPU a lap at the cap, what 300 took before. A window in a busy place
(1,000 to 1,500 access points per 10 minutes on two walks) is heard about
2.3 times longer before the cap stops tcpdump. The default moves in
payload.sh and in the fallbacks of sw_rid_start and sw_rid_collect.

Tests: the defaults, tcpdump's -c, the capped lap at the new default, and
300 frames reading ok at both ends (the setting unset, and a setting that
is not a number). README and the Remote ID spec (§6, §7.5, §22). 1666
assertions.

Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>
EOF
git log -1 --format=%B | grep -cF 'Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>'
```

Expected: the last command prints `1`.

---

## After the tasks (the controller, not an implementer)

1. One whole-branch review (opus) of the two commits, with the design as its lens.
2. The suite as root (`unshare -r bash test/run.sh`); the whole mutation matrix on copies, with the new group `f8`
   in `.superpowers/sdd/tools/rid_mutate.py` (10 mutants from the dry run: the shape check removed, the cut one
   place late, tabs not stripped, no strip, the fast path never taken, and the cap left at 300 in each of its five
   places; each was caught); the privacy scan of `origin/main..main` (with a read-only copy of the Pager's recon
   database, deleted after).
3. With the user's OK, on the Pager: the install (staged on the same file system, `mv`, md5 of all 12 files); one
   benchmark of the old and the new decoder on 300 real beacons (CPU per beacon; the output's md5 identical); the
   new decoder's awk parity on the Pager's BusyBox awk (the fixtures and the streams, with and without a key); a
   silent launcher-faithful run. Aggregates only into P0-findings, in a docs commit.
4. Then, with the user's OK, the push.
