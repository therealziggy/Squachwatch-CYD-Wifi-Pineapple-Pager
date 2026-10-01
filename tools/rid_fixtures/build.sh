#!/usr/bin/env bash
# tools/rid_fixtures/build.sh — regenerate the committed Remote ID test fixtures (test/fixtures/rid/).
# Dev box only: it needs curl, a C compiler and tcpdump. It downloads four files of opendroneid-core-c,
# the reference Remote ID library (Apache-2.0), pinned by commit AND by sha256, so a changed download
# stops it; builds gen.c against them in a temporary folder; writes one pcap per fixture; and runs the
# real tcpdump over each to make the text the tests read. The frames only ever go to files.
# -t: no clock times in that text (they would show this box's time zone in a public repository).
# Every fixture is first written to a folder beside them and renamed into place only once all of them were
# made, so a failure (a missing tool, a download, tcpdump) leaves the committed fixtures as they were.
# (test/fixtures/rid/hostile/ is not made here: those frames are byte edits of these fixtures, documented
# in test/remoteid_test.sh, and kept as tcpdump text only.)
set -eu
missing=""
for t in curl gcc tcpdump; do command -v "$t" >/dev/null 2>&1 || missing="$missing $t"; done
if [ -n "$missing" ]; then echo "build.sh: missing:$missing (it needs curl, gcc and tcpdump)" >&2; exit 1; fi
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$(cd "$HERE/../../test/fixtures" && pwd)/rid"
SHA=6484f26545d4f012682524e2d843fab0fbdc0b34
BASE="https://raw.githubusercontent.com/opendroneid/opendroneid-core-c/$SHA/libopendroneid"
KINDS="beacon nan parrot multi unknowns equator order quiet truncated full emptyserial"
mkdir -p "$OUT"
WORK="$(mktemp -d)"; NEW="$(mktemp -d "$OUT/.build.XXXXXX")"; trap 'rm -rf "$WORK" "$NEW"' EXIT
while read -r sum f; do
  curl -fsSL "$BASE/$f" -o "$WORK/$f"
  echo "$sum  $WORK/$f" | sha256sum -c --quiet - || { echo "checksum mismatch: $f" >&2; exit 1; }
done <<'SUMS'
60b0964f5f2a0dc13833eb6a304f7bd3f64bb9c227fae168c7caba53c82927c2 opendroneid.c
a60b9b38c4fa82d7c85437dc11f57f0dea4ebf8bb4b90b3ff3c21c585ccd55f4 opendroneid.h
bae2f4e85e8e391c78f33aba33d32beef98ace7aee42881a0aee4a1a34aa442b wifi.c
44e39ca04eb004233db78e8e91f44a732203e0bf57aabbb721632040aa82ffd8 odid_wifi.h
SUMS
# warnings shown for our own gen.c; the library's sources are built quietly
gcc -O2 -w -c "$WORK/opendroneid.c" -o "$WORK/opendroneid.o" -I"$WORK"
gcc -O2 -w -c "$WORK/wifi.c" -o "$WORK/wifi.o" -I"$WORK"
gcc -O2 -Wall -c "$HERE/gen.c" -o "$WORK/gen.o" -I"$WORK"
gcc -o "$WORK/gen" "$WORK/gen.o" "$WORK/opendroneid.o" "$WORK/wifi.o" -lm
for k in $KINDS; do
  "$WORK/gen" "$k" "$NEW/$k.pcap"
done
# badlink: the beacon under another link type (LINKTYPE_ETHERNET = 1, at byte 20 of the pcap header)
cp "$NEW/beacon.pcap" "$NEW/badlink.pcap"
printf '\001' | dd of="$NEW/badlink.pcap" bs=1 seek=20 count=1 conv=notrunc 2>/dev/null
for k in $KINDS badlink; do
  # tcpdump's stderr says which file it read; it is shown only when tcpdump fails
  TZ=UTC tcpdump -r "$NEW/$k.pcap" -t -nn -xx > "$NEW/$k.txt" 2> "$WORK/tcpdump.err" \
    || { echo "tcpdump failed on $k.pcap:" >&2; cat "$WORK/tcpdump.err" >&2; exit 1; }
done
for k in $KINDS badlink; do
  mv -f "$NEW/$k.pcap" "$OUT/$k.pcap"; mv -f "$NEW/$k.txt" "$OUT/$k.txt"
done
echo "fixtures written to $OUT"
