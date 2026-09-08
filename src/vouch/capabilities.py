"""Capability inference for skills.

Separate from :mod:`vouch.cv` (which imports the engine) so the engine can also
use capability data without a circular import.

A *capability* describes what a skill *can do* (benign-or-not): network access,
shell execution, dynamic code execution, filesystem read/write, credential
access, persistence, environment access. The engine uses the **combination** of
capabilities — not just rule findings — to gate verdicts, because the dangerous
minority of skills are multi-stage chains whose individual steps look benign.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any

from .models import SkillInput


@dataclass
class Evidence:
    file: str
    line: int
    excerpt: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Capability:
    key: str
    label: str
    present: bool = False
    evidence: list[Evidence] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "label": self.label,
            "present": self.present,
            "evidence": [e.to_dict() for e in self.evidence],
        }


# key, label, pattern
_CAP_PATTERNS: list[tuple[str, str, re.Pattern[str]]] = [
    (
        "network",
        "Network access",
        re.compile(
            r"\b(curl|wget|fetch\(|requests\.(get|post|put|delete)|urllib|"
            r"http\.client|axios|http[sx]?://)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "shell",
        "Shell execution",
        re.compile(
            r"\b(subprocess\.|os\.system|os\.popen|shell=True|/bin/(ba)?sh|"
            r"\bsh\s+-c|\bbash\b|child_process|execSync|spawn\()\b",
            re.IGNORECASE,
        ),
    ),
    (
        "code_exec",
        "Dynamic code execution",
        re.compile(r"\b(eval\(|exec\(|Function\(|compile\(|importlib)\b"),
    ),
    (
        "fs_write",
        "Filesystem writes",
        re.compile(
            r"(open\([^)]*['\"][wax]\+?['\"]|write_text|\.write\(|>>?\s*[~/.\w]|"
            r"\b(rm|mv|cp|mkdir|rmdir|touch|chmod|chown)\b)",
            re.IGNORECASE,
        ),
    ),
    (
        "fs_read",
        "Filesystem reads",
        re.compile(
            r"(open\([^)]*['\"]r['\"]?|read_text|\.read\(|\b(cat|less|more|head|tail)\b)",
            re.IGNORECASE,
        ),
    ),
    (
        "credentials",
        "Credential / secret access",
        re.compile(
            r"(\.ssh/|\.aws/|\.kube/|token|secret|api[_-]?key|password|passwd|"
            r"credential|\.env\b)",
            re.IGNORECASE,
        ),
    ),
    (
        "persistence",
        "Persistence mechanisms",
        re.compile(
            r"\b(crontab|launchctl|systemd|\.bashrc|\.zshrc|\.profile|LaunchAgents|"
            r"LaunchDaemons)\b",
            re.IGNORECASE,
        ),
    ),
    (
        "env",
        "Environment variable access",
        re.compile(r"(os\.environ|process\.env|getenv|printenv|\benv\b)", re.IGNORECASE),
    ),
]

_MAX_EVIDENCE = 3


def scan_capabilities(skill: SkillInput) -> list[Capability]:
    """Return one Capability per class, marked present with up to 3 evidence hits."""
    caps = {key: Capability(key, label) for key, label, _ in _CAP_PATTERNS}
    seen: dict[str, set[tuple[str, int]]] = {key: set() for key, _, _ in _CAP_PATTERNS}
    for sf in skill.files:
        content_lines = sf.content.splitlines()
        for key, _label, pat in _CAP_PATTERNS:
            cap = caps[key]
            for m in pat.finditer(sf.content):
                cap.present = True
                line = sf.content.count("\n", 0, m.start()) + 1
                loc = (sf.path, line)
                if loc in seen[key]:
                    continue
                seen[key].add(loc)
                if len(cap.evidence) < _MAX_EVIDENCE:
                    snippet = (
                        content_lines[line - 1].strip()
                        if line <= len(content_lines)
                        else ""
                    )
                    # Don't use markdown code-fence markers as evidence — they're
                    # noise (e.g. ```bash). The capability still counts as present.
                    if snippet.startswith("```"):
                        continue
                    cap.evidence.append(Evidence(sf.path, line, snippet[:120]))
    return list(caps.values())


def present_keys(caps: list[Capability]) -> set[str]:
    return {c.key for c in caps if c.present}
