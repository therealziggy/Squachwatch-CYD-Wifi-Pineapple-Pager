#!/usr/bin/env bash
# tools/pager_screenshot.sh OUT.png [HOST] — save what the Pager's screen shows now, the right way up.
# PC only (python3 + Pillow). Screenshots show real MACs: keep them OUT of the repository.
set -euo pipefail
OUT="${1:?usage: $0 OUT.png [HOST]}"; HOST="${2:-root@172.16.52.1}"
RAW="$(mktemp)"; trap 'rm -f "$RAW"' EXIT
ssh -o BatchMode=yes "$HOST" 'cat /dev/fb0' </dev/null > "$RAW"
python3 - "$RAW" "$OUT" <<'PY'
import sys
from PIL import Image
fb = open(sys.argv[1], 'rb').read(); W, H = 222, 480   # the panel is portrait, RGB565 little-endian
if len(fb) != W * H * 2:
    sys.exit(f'unexpected framebuffer size {len(fb)}')
im = Image.new('RGB', (H, W)); px = im.load()
for y in range(H):
    for x in range(W):
        v = fb[(y * W + x) * 2] | (fb[(y * W + x) * 2 + 1] << 8)
        px[y, W - 1 - x] = (((v >> 11) & 31) * 255 // 31, ((v >> 5) & 63) * 255 // 63, (v & 31) * 255 // 31)
im.save(sys.argv[2])
PY
echo "saved $OUT"
