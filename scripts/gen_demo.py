#!/usr/bin/env python3
"""Generate an animated terminal demo GIF for the README — no external tools.

Runs real `vouch` commands against a curated, reproducible set of demo skills
and renders a typed-terminal animation with Pillow. Regenerate with:

    python scripts/gen_demo.py

Output: docs/demo.gif

The demo leads with the hero command, `vouch --audit` (scan every skill on this
machine), then drills into one flagged skill's CV. It is deliberately
visibility-first: Vouch shows you what your agents can do and flags the risky
ones — it is a triage layer, not a security guarantee.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "demo.gif"
VOUCH = Path(sys.executable).parent / "vouch"

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

BOX_CHARS = set("╔╗╚╝║═╠╣─│•")


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
    if "MALICIOUS" in s or "DO NOT LOAD" in s or "QUARANTINE" in s or "CRITICAL" in s:
        return RED
    if (
        "SUSPICIOUS" in s
        or "REVIEW" in s
        or "REQUIRED" in s
        or "NEEDS A LOOK" in s
        or s.lstrip().startswith("!")
        or "MEDIUM" in s
    ):
        return YELLOW
    if "VALID" in s or "SAFE TO LOAD" in s or "TRUSTED" in s or "No security" in s:
        return GREEN
    if "HIGH" in s:
        return MAGENTA
    if any(c in BOX_CHARS for c in s):
        return CYAN
    header_keys = (
        "CAPABILITIES",
        "FILES",
        "SECURITY",
        "WHAT'S ON THIS MACHINE",
        "BY LOCATION",
        "Verdict:",
        "Recommendation:",
        "Caps:",
        "Skill:",
        "Engine:",
        "Summary:",
        "Source:",
        "skill(s)",
    )
    if any(k in s for k in header_keys):
        return LIGHT
    return GRAY


def run(args: list[str], env: dict[str, str] | None = None) -> str:
    res = subprocess.run(
        [str(VOUCH), *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    return sanitize(res.stdout.rstrip("\n"))


def build_demo_home() -> Path:
    """Create a temp HOME with a curated, reproducible mix of skills.

    Mix: a few clean skills, one 'flag for review' (obfuscated wipe), and two
    genuinely malicious ones — so the audit shows all three verdict tiers.
    """
    # Use a non-symlinked parent (macOS symlinks /var and /tmp -> /private/...,
    # which would defeat the tool's ~-abbreviation of skill paths).
    home = Path(tempfile.mkdtemp(prefix="vouch-demo-", dir=str(ROOT.parent)))
    skills = home / ".claude" / "skills"
    skills.mkdir(parents=True)

    curated = [
        ROOT / "bench" / "benign" / "markdown-formatter",
        ROOT / "bench" / "benign" / "weather-client",
        ROOT / "bench" / "benign" / "db-backup",
        ROOT / "bench" / "malicious" / "obfuscated-rm",   # -> SUSPICIOUS
        ROOT / "bench" / "malicious" / "ssh-exfil",       # -> MALICIOUS
        ROOT / "examples" / "malicious-skill",            # -> MALICIOUS
    ]
    for src in curated:
        if src.exists():
            shutil.copytree(src, skills / src.name)
    return home


# --- terminal simulation ----------------------------------------------------

class Frame:
    __slots__ = ("lines", "duration")

    def __init__(self, lines: list[str], duration: int):
        self.lines = lines
        self.duration = duration


def build_frames() -> tuple[list[Frame], int, int]:
    home = build_demo_home()
    env = {**os.environ, "HOME": str(home), "NO_COLOR": "1"}

    frames: list[Frame] = []
    max_cols = 0
    max_rows = 0

    def track(lines: list[str]) -> None:
        nonlocal max_cols, max_rows
        max_cols = max(max_cols, max((len(x) for x in lines), default=0))
        max_rows = max(max_rows, len(lines))

    # Title
    title = [
        "",
        "  vouch  —  see what your AI agents can actually do",
        "  one command audits every skill on your machine and flags the risky ones",
        "",
    ]
    frames.append(Frame(title, 1600))
    track(title)

    segments = [
        (
            ["--audit", "--no-baseline"],
            "vouch --audit",
            "Every skill on this machine, classified. The risky ones float to the top.",
        ),
        (
            [str(home / ".claude" / "skills" / "ssh-exfil"), "--cv", "--no-llm"],
            "vouch ~/.claude/skills/ssh-exfil --cv",
            "Drill into one: the Skill CV shows exactly what it can do, and why it's flagged.",
        ),
    ]

    for args, shown, caption in segments:
        output = run(args, env=env)
        out_lines = output.split("\n")

        # typing animation for the command
        step = 4
        for i in range(0, len(shown) + 1, step):
            frames.append(Frame([f"$ {shown[:i]}"], 42))
        frames.append(Frame([f"$ {shown}"], 350))

        screen = [f"$ {shown}", ""] + out_lines + ["", f"  # {caption}"]
        frames.append(Frame(screen, 3000))
        track(screen)

    # Outro — honest, visibility-first
    outro = [
        "",
        "  $ vouch --audit             # scan every skill on this machine",
        "  $ vouch <skill> --cv        # the Skill CV profile card",
        "  $ vouch --audit --llm       # add an optional AI second opinion",
        "",
        "  A fast triage layer — like npm audit, but for agent skills.",
        "",
        "  pipx run --spec vouch-agent vouch --audit",
        "",
    ]
    frames.append(Frame(outro, 3200))
    track(outro)

    shutil.rmtree(home, ignore_errors=True)
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
