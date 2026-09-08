#!/usr/bin/env python3
"""Generate the GitHub social-preview card (1280x640) as docs/social-preview.png.

Rendered with Pillow so the wordmark, tagline, and command are pixel-crisp
(AI image generators garble text on a card that needs a legible shell command).

Usage:  python scripts/gen_social.py
"""
from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

W, H = 1280, 640
BG = (13, 17, 23)          # GitHub dark
PANEL = (22, 27, 34)
FG = (230, 237, 243)
MUTED = (139, 148, 158)
ACCENT = (63, 185, 80)     # green "valid"
WARN = (210, 153, 34)      # amber "review"
RED = (248, 81, 73)


def _font(size: int, bold: bool = False, mono: bool = False) -> ImageFont.FreeTypeFont:
    candidates = []
    if mono:
        candidates += [
            "/System/Library/Fonts/Menlo.ttc",
            "/System/Library/Fonts/SFNSMono.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf",
        ]
    else:
        candidates += [
            "/System/Library/Fonts/SFNS.ttf",
            "/System/Library/Fonts/Helvetica.ttc",
            "/System/Library/Fonts/Supplemental/Arial Bold.ttf" if bold
            else "/System/Library/Fonts/Supplemental/Arial.ttf",
            "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf" if bold
            else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        ]
    for path in candidates:
        if Path(path).exists():
            try:
                return ImageFont.truetype(path, size)
            except Exception:
                continue
    return ImageFont.load_default()


def _text(d, xy, s, font, fill, anchor="la"):
    d.text(xy, s, font=font, fill=fill, anchor=anchor)


def main() -> None:
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)

    # subtle top accent bar
    d.rectangle([0, 0, W, 8], fill=ACCENT)

    # shield glyph (simple) + wordmark
    _text(d, (80, 70), "\u25c8 Vouch", _font(84, bold=True), FG)
    _text(d, (84, 178), "the trust layer for AI agents", _font(30), MUTED)

    # tagline
    _text(d, (80, 250), "See what your AI agents can actually do.",
          _font(46, bold=True), FG)

    # terminal panel
    px0, py0, px1, py1 = 80, 340, W - 80, 500
    d.rounded_rectangle([px0, py0, px1, py1], radius=14, fill=PANEL)
    # window dots
    for i, col in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        d.ellipse([px0 + 22 + i * 26, py0 + 20, px0 + 36 + i * 26, py0 + 34], fill=col)
    mono = _font(30, mono=True)
    _text(d, (px0 + 30, py0 + 58), "$ vouch --audit", mono, FG)
    _text(d, (px0 + 30, py0 + 100),
          "53 skills \u00b7 3 locations \u00b7 4 flagged for review", mono, WARN)

    # bottom strip
    _text(d, (80, 545), "Deterministic  \u00b7  zero false alarms  \u00b7  100% precision",
          _font(28), MUTED)
    _text(d, (W - 80, 545), "pip install vouch-agent", _font(30, bold=True, mono=True),
          ACCENT, anchor="ra")

    out = Path(__file__).resolve().parent.parent / "docs" / "social-preview.png"
    out.parent.mkdir(parents=True, exist_ok=True)
    img.save(out)
    print(f"wrote {out} ({W}x{H})")


if __name__ == "__main__":
    main()
