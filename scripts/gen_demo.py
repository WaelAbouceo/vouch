#!/usr/bin/env python3
"""Generate an animated terminal demo GIF for the README — no external tools.

Runs real `vouch` commands, captures their output, and renders a typed-terminal
animation with Pillow. Regenerate with:

    python scripts/gen_demo.py

Output: docs/demo.gif
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "demo.gif"

# --- theme (GitHub dark) ----------------------------------------------------
BG = (13, 17, 23)
PROMPT = (63, 185, 80)   # green $
CMD = (240, 246, 252)    # bright white command
GRAY = (139, 148, 158)
LIGHT = (201, 209, 217)
CYAN = (57, 197, 207)
RED = (248, 81, 73)
GREEN = (63, 185, 80)
YELLOW = (210, 168, 60)
MAGENTA = (188, 140, 255)

FONT_SIZE = 15
LINE_H = 21
PAD = 22
CHAR_W = None  # set after font load

BOX_CHARS = set("╔╗╚╝║═╠╣─│")


def load_font(size: int) -> ImageFont.FreeTypeFont:
    for path in (
        "/System/Library/Fonts/Menlo.ttc",
        "/System/Library/Fonts/Monaco.ttf",
        "/System/Library/Fonts/SFNSMono.ttf",
    ):
        if os.path.exists(path):
            return ImageFont.truetype(path, size)
    return ImageFont.load_default()


def sanitize(text: str) -> str:
    return (
        text.replace("⚠", "!")
        .replace("→", "->")
        .replace("’", "'")
        .replace("—", "--")
    )


def color_for(line: str) -> tuple[int, int, int]:
    s = line
    if any(c in BOX_CHARS for c in s):
        return CYAN
    if "MALICIOUS" in s or "DO NOT LOAD" in s or "QUARANTINE" in s or "CRITICAL" in s:
        return RED
    if (
        "SUSPICIOUS" in s
        or "REVIEW" in s
        or "REQUIRED" in s
        or s.lstrip().startswith("!")
        or "MEDIUM" in s
    ):
        return YELLOW
    if "VALID" in s or "SAFE TO LOAD" in s or "TRUSTED" in s or "No security" in s:
        return GREEN
    if "HIGH" in s:
        return MAGENTA
    header_keys = (
        "CAPABILITIES",
        "FILES",
        "SECURITY",
        "Verdict:",
        "Recommendation:",
        "Caps:",
        "Skill:",
        "Engine:",
        "Summary:",
        "Source:",
    )
    if any(k in s for k in header_keys):
        return LIGHT
    return GRAY


def run(cmd: list[str]) -> str:
    res = subprocess.run(
        cmd, cwd=ROOT, capture_output=True, text=True, check=False
    )
    return sanitize(res.stdout.rstrip("\n"))


# --- terminal simulation ----------------------------------------------------

class Frame:
    __slots__ = ("lines", "duration")

    def __init__(self, lines: list[str], duration: int):
        self.lines = lines
        self.duration = duration


def build_frames() -> tuple[list[Frame], int, int]:
    segments = [
        ("vouch ./examples/benign-skill --cv --no-llm",
         "A safe skill: clean bill of health."),
        ("vouch ./examples/malicious-skill --cv --no-llm",
         "An obviously malicious skill: caught, verdict MALICIOUS."),
        ("vouch ./examples/evasive-skill --cv --no-llm",
         "The evasive one: trips ZERO rules, but the capability gate stops it."),
    ]

    frames: list[Frame] = []
    max_cols = 0
    max_rows = 0

    # Title
    title = [
        "",
        "  vouch  —  the trust layer for AI agents",
        "  vet a Skill, see what it can do, and vouch only for the safe ones",
        "",
    ]
    frames.append(Frame(title, 1400))
    max_cols = max(max_cols, max(len(x) for x in title))
    max_rows = max(max_rows, len(title))

    for cmd, caption in segments:
        output = run(cmd.split())
        out_lines = output.split("\n")

        # typing animation for the command
        step = 4
        for i in range(0, len(cmd) + 1, step):
            frames.append(Frame([f"$ {cmd[:i]}"], 45))
        # command complete
        frames.append(Frame([f"$ {cmd}"], 350))
        # output revealed
        screen = [f"$ {cmd}", ""] + out_lines + ["", f"  # {caption}"]
        frames.append(Frame(screen, 2600))

        max_cols = max(max_cols, max(len(x) for x in screen))
        max_rows = max(max_rows, len(screen))

    # Outro
    outro = [
        "",
        "  $ vouch <skill>            # verdict + risk + findings",
        "  $ vouch <skill> --cv       # the Skill CV profile card",
        "  $ vouch <agent> --agent-cv # profile a whole agent",
        "",
        "  never run a skill you can't vouch for.",
        "",
    ]
    frames.append(Frame(outro, 2600))
    max_cols = max(max_cols, max(len(x) for x in outro))
    max_rows = max(max_rows, len(outro))

    return frames, max_cols, max_rows


def render(frames: list[Frame], cols: int, rows: int) -> None:
    global CHAR_W
    font = load_font(FONT_SIZE)
    CHAR_W = font.getlength("M")
    width = int(PAD * 2 + CHAR_W * cols)
    height = int(PAD * 2 + LINE_H * rows)

    images: list[Image.Image] = []
    durations: list[int] = []
    for fr in frames:
        img = Image.new("RGB", (width, height), BG)
        d = ImageDraw.Draw(img)
        y = PAD
        for line in fr.lines:
            if line.startswith("$ "):
                d.text((PAD, y), "$", font=font, fill=PROMPT)
                d.text((PAD + CHAR_W * 2, y), line[2:], font=font, fill=CMD)
            else:
                d.text((PAD, y), line, font=font, fill=color_for(line))
            y += LINE_H
        images.append(img)
        durations.append(fr.duration)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    images[0].save(
        OUT,
        save_all=True,
        append_images=images[1:],
        duration=durations,
        loop=0,
        disposal=2,
        optimize=True,
    )
    kb = OUT.stat().st_size / 1024
    print(f"wrote {OUT} ({width}x{height}, {len(images)} frames, {kb:.0f} KB)")


def main() -> int:
    frames, cols, rows = build_frames()
    render(frames, cols, rows)
    return 0


if __name__ == "__main__":
    sys.exit(main())
