#!/usr/bin/env bash
# tools/rid_fixtures/build.sh — regenerate the committed Remote ID test fixtures (test/fixtures/rid/).
# Dev box only: it needs curl, a C compiler and tcpdump. It downloads four files of opendroneid-core-c,
# the reference Remote ID library (Apache-2.0), pinned by commit AND by sha256, so a changed download
# stops it; builds gen.c against them in a temporary folder; writes one pcap per fixture; and runs the
# real tcpdump over each to make the text the tests read. The frames only ever go to files.
# -t: no clock times in that text (they would show this box's time zone in a public repository).
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$(cd "$HERE/../../test/fixtures" && pwd)/rid"
SHA=6484f26545d4f012682524e2d843fab0fbdc0b34
BASE="https://raw.githubusercontent.com/opendroneid/opendroneid-core-c/$SHA/libopendroneid"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
mkdir -p "$OUT"
while read -r sum f; do
  curl -fsSL "$BASE/$f" -o "$WORK/$f"
  echo "$sum  $WORK/$f" | sha256sum -c --quiet - || { echo "checksum mismatch: $f" >&2; exit 1; }
done <<'SUMS'
60b0964f5f2a0dc13833eb6a304f7bd3f64bb9c227fae168c7caba53c82927c2 opendroneid.c
a60b9b38c4fa82d7c85437dc11f57f0dea4ebf8bb4b90b3ff3c21c585ccd55f4 opendroneid.h
bae2f4e85e8e391c78f33aba33d32beef98ace7aee42881a0aee4a1a34aa442b wifi.c
44e39ca04eb004233db78e8e91f44a732203e0bf57aabbb721632040aa82ffd8 odid_wifi.h
SUMS
gcc -O2 -w -o "$WORK/gen" "$HERE/gen.c" "$WORK/opendroneid.c" "$WORK/wifi.c" -I"$WORK" -lm
for k in beacon nan parrot multi unknowns equator order quiet truncated; do
  "$WORK/gen" "$k" "$OUT/$k.pcap"
done
# badlink: the beacon under another link type (LINKTYPE_ETHERNET = 1, at byte 20 of the pcap header)
cp "$OUT/beacon.pcap" "$OUT/badlink.pcap"
printf '\001' | dd of="$OUT/badlink.pcap" bs=1 seek=20 count=1 conv=notrunc 2>/dev/null
for k in beacon nan parrot multi unknowns equator order quiet truncated badlink; do
  TZ=UTC tcpdump -r "$OUT/$k.pcap" -t -nn -xx 2>/dev/null > "$OUT/$k.txt"
done
echo "fixtures written to $OUT"
