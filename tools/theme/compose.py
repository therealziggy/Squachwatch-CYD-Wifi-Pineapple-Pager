#!/usr/bin/env python3
"""Build the SquachWatch theme's two pictures from SquachWatch-CYD emulator renders (PC only).

payload_bg.png (480x222)
  layout B: the sunset with the sun at x=400, darkened on the left for the text, and Squachy standing
            in front of the sun.
  layout C: a starry night sky for the text, and a sunset band with a small Squachy along the bottom.
alert_card.png (429x222): the CYD alert card, with a rainbow border, a pink strip, a dark data plate,
  and a radar with Squachy's face.
Both are saved as 256-colour palette PNGs, like the stock theme's images.
"""
import argparse
import math
import os

from PIL import Image, ImageChops, ImageDraw, ImageFont

W, H = 480, 222
BG = (8, 0, 8)                                   # CYD VAPRW4VE BG, 0x0801
PINK = (255, 45, 123)                            # PINK, 0xF96F
VPINK = (255, 113, 206)                          # VAPOR_PINK, 0xFB99
PURPLE = (173, 130, 255)                         # PURPLE, 0xAC1F
GREEN = (0, 255, 0)                              # GREEN, 0x07E0
RINGS = ((0, 48, 45), (0, 64, 60), (0, 90, 86))  # the CYD radar rings, outer to inner
STARS = [((i * 97) % 480, 24 + (i * 53) % 100) for i in range(40)]  # fixed, so renders repeat


def squachy_cutout(plain, with_sq):
    """Squachy alone (RGBA): the pixels where the render with him differs from the one without."""
    mask = ImageChops.difference(plain, with_sq).convert('L').point(lambda v: 255 if v else 0)
    box = mask.getbbox()
    if box is None:
        raise SystemExit('no Squachy found: the two renders are identical')
    cut = with_sq.crop(box).convert('RGBA')
    cut.putalpha(mask.crop(box))
    return cut


def scene_band(wide):
    """The 480x222 left part of the 800-wide scene (sun at x=400). Rows 204-221 repeat the water, which
    covers the CYD's counter row."""
    s = wide.crop((0, 0, W, H)).copy()
    s.paste(wide.crop((0, 176, W, 194)), (0, 204))
    return s


def layout_b(wide, cut):
    img = scene_band(wide).convert('RGBA')
    shade = Image.new('RGBA', (W, H), (0, 0, 0, 0))
    d = ImageDraw.Draw(shade)
    for x in range(W):  # dark behind the text on the left, fading out toward Squachy
        d.line((x, 0, x, H), fill=BG + (int(235 - 150 * max(0.0, (x - 250) / 230)),))
    img = Image.alpha_composite(img, shade)
    band = Image.new('RGBA', (W, H), (0, 0, 0, 0))
    ImageDraw.Draw(band).rectangle((0, 20, 330, H - 1), fill=BG + (120,))
    img = Image.alpha_composite(img, band)
    img.alpha_composite(cut, (405 - cut.width // 2, H - cut.height))
    return img.convert('RGB')


def layout_c(wide, cut):
    img = Image.new('RGB', (W, H))
    d = ImageDraw.Draw(img)
    for y in range(H):
        t = y / H
        d.line((0, y, W, y), fill=(int(10 + 30 * t), 0, int(15 + 45 * t)))
    for p in STARS:
        d.point(p, fill=(200, 200, 255))
    band = scene_band(wide).crop((0, 60, W, 140))
    img.paste(band, (0, H - band.height))
    small = cut.resize((cut.width // 2, cut.height // 2), Image.NEAREST)
    img.paste(small, (400 - small.width // 2, H - small.height), small)
    return img


def rainbow(t):
    """Hue t in [0, 1) -> fully saturated RGB."""
    return tuple(int(255 * max(0.0, min(1.0, abs((t * 6 + k) % 6 - 3) - 1))) for k in (0, 4, 2))


def alert_card(cut, font_path):
    cw, ch = 429, 222
    card = Image.new('RGB', (cw, ch), BG)
    d = ImageDraw.Draw(card)
    for i in range(cw):  # 2 px rainbow border (the CYD's rotating border, frozen)
        c = rainbow(i / cw)
        d.line((i, 0, i, 1), fill=c)
        d.line((cw - 1 - i, ch - 2, cw - 1 - i, ch - 1), fill=c)
    for j in range(ch):
        c = rainbow(j / ch)
        d.line((0, j, 1, j), fill=c)
        d.line((cw - 2, ch - 1 - j, cw - 1, ch - 1 - j), fill=c)
    d.rectangle((2, 2, cw - 3, 42), fill=PINK)
    d.line((2, 43, cw - 3, 43), fill=(120, 10, 60))
    d.text((14, 4), 'HEADS UP!', font=ImageFont.truetype(font_path, 32), fill=BG)
    d.rectangle((12, 54, 272, 208), fill=(4, 0, 8), outline=PURPLE)   # the data plate (screen x 40-300)
    cx, cy, r = 350, 128, 62
    for rr, col in zip((r, r * 2 // 3, r // 3), RINGS):
        d.ellipse((cx - rr, cy - rr, cx + rr, cy + rr), outline=col, width=2)
    d.line((cx - r, cy, cx + r, cy), fill=RINGS[1])
    d.line((cx, cy - r, cx, cy + r), fill=RINGS[1])
    d.line((cx, cy, cx + int(r * math.cos(-0.9)), cy + int(r * math.sin(-0.9))), fill=GREEN, width=2)
    d.ellipse((cx - r - 3, cy - r - 3, cx + r + 3, cy + r + 3), outline=VPINK, width=3)
    face = cut.crop((0, 0, cut.width, 64)).resize((cut.width * 2 // 3, 42), Image.NEAREST)
    card.paste(face, (cx - face.width // 2, cy - 21), face)
    return card


def save_256(img, path):
    q = img.convert('RGB').quantize(colors=256, method=Image.Quantize.MEDIANCUT,
                                    dither=Image.Dither.FLOYDSTEINBERG)
    q.save(path, optimize=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--layout', choices=('B', 'C'), default='B')
    ap.add_argument('--wide', required=True)
    ap.add_argument('--plain', required=True)
    ap.add_argument('--with-squachy', required=True, dest='with_sq')
    ap.add_argument('--font', required=True)
    ap.add_argument('--out', required=True)
    a = ap.parse_args()
    wide = Image.open(a.wide).convert('RGB')
    cut = squachy_cutout(Image.open(a.plain).convert('RGB'), Image.open(a.with_sq).convert('RGB'))
    os.makedirs(a.out, exist_ok=True)
    save_256(layout_b(wide, cut) if a.layout == 'B' else layout_c(wide, cut),
             os.path.join(a.out, 'payload_bg.png'))
    save_256(alert_card(cut, a.font), os.path.join(a.out, 'alert_card.png'))


if __name__ == '__main__':
    main()
