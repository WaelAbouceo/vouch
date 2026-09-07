"""Load a skill from a directory, a single file, or raw text into a SkillInput."""

from __future__ import annotations

import os
from pathlib import Path

from .models import SkillFile, SkillInput

# Files we bother reading as text. Everything else is recorded by name only.
_TEXT_EXTS = {
    ".md",
    ".markdown",
    ".txt",
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".sh",
    ".bash",
    ".zsh",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".cfg",
    ".ini",
    ".rb",
    ".pl",
    ".ps1",
    ".env",
}

_MAX_FILE_BYTES = 1_000_000  # skip absurdly large files (likely binary/assets)
_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}


def load_text(content: str, name: str = "inline-skill") -> SkillInput:
    """Build a SkillInput from raw skill content held in memory."""
    return SkillInput(
        name=name,
        files=[SkillFile(path="SKILL.md", content=content)],
        source="text",
    )


def load_file(path: str | os.PathLike[str]) -> SkillInput:
    """Build a SkillInput from a single file (usually a SKILL.md)."""
    p = Path(path)
    content = p.read_text(encoding="utf-8", errors="replace")
    return SkillInput(
        name=p.stem if p.name.lower() != "skill.md" else p.parent.name or p.stem,
        files=[SkillFile(path=p.name, content=content)],
        source="file",
    )


def load_directory(path: str | os.PathLike[str]) -> SkillInput:
    """Build a SkillInput from a skill directory (SKILL.md + scripts/assets)."""
    root = Path(path)
    files: list[SkillFile] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fname in filenames:
            fpath = Path(dirpath) / fname
            rel = str(fpath.relative_to(root))
            ext = fpath.suffix.lower()
            try:
                size = fpath.stat().st_size
            except OSError:
                continue
            if ext in _TEXT_EXTS and size <= _MAX_FILE_BYTES:
                content = fpath.read_text(encoding="utf-8", errors="replace")
            else:
                # Record presence of non-text / oversized files without content.
                content = f"<non-text or oversized file: {size} bytes>"
            files.append(SkillFile(path=rel, content=content))
    files.sort(key=lambda f: (not f.path.lower().endswith("skill.md"), f.path))
    return SkillInput(name=root.name, files=files, source="directory")


def load(target: str | os.PathLike[str]) -> SkillInput:
    """Auto-detect whether ``target`` is a directory or a file and load it."""
    p = Path(target)
    if p.is_dir():
        return load_directory(p)
    if p.is_file():
        return load_file(p)
    raise FileNotFoundError(f"No such skill path: {target}")
