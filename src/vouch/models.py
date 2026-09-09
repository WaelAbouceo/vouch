"""Core data models for skill validation.

Pure-stdlib dataclasses so the engine has zero required dependencies.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Verdict(str, Enum):
    """Final classification for a skill."""

    VALID = "valid"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


class Severity(str, Enum):
    """Severity of an individual finding, with an associated risk weight."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def weight(self) -> int:
        return {
            Severity.INFO: 0,
            Severity.LOW: 5,
            Severity.MEDIUM: 15,
            Severity.HIGH: 35,
            Severity.CRITICAL: 60,
        }[self]

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


@dataclass
class SkillFile:
    """A single file that is part of the skill under analysis."""

    path: str
    content: str

    @property
    def is_markdown(self) -> bool:
        return self.path.lower().endswith((".md", ".markdown"))


@dataclass
class SkillInput:
    """Normalized representation of a skill regardless of how it was supplied."""

    name: str
    files: list[SkillFile] = field(default_factory=list)
    source: str = "unknown"  # "directory" | "file" | "text"

    @property
    def combined_text(self) -> str:
        return "\n".join(f.content for f in self.files)

    @property
    def skill_md(self) -> SkillFile | None:
        for f in self.files:
            if f.path.lower().endswith("skill.md"):
                return f
        for f in self.files:
            if f.is_markdown:
                return f
        return None


@dataclass
class Finding:
    """One issue detected during analysis.

    ``category`` separates genuine threats from *awareness notices* — behaviors
    that are legitimate for many skills (running an install script, using a
    secret env var, scheduling a task) but that a user should still be told
    about before letting an agent run the skill. Notices are surfaced
    prominently but do **not**, on their own, make a skill ``suspicious`` or
    ``malicious``.
    """

    rule_id: str
    title: str
    severity: Severity
    detail: str
    source: str = "static"  # "static" | "llm" | "capability"
    category: str = "threat"  # "threat" | "notice"
    file: str | None = None
    line: int | None = None
    excerpt: str | None = None

    @property
    def is_notice(self) -> bool:
        return self.category == "notice"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class Report:
    """Aggregated result of validating a skill."""

    skill_name: str
    verdict: Verdict
    risk_score: int  # 0-100
    findings: list[Finding] = field(default_factory=list)
    summary: str = ""
    engine: str = "hybrid"  # "static" | "hybrid"
    llm_used: bool = False
    # Honest reporting of what the LLM layer actually did:
    #   "off"         -> LLM not requested
    #   "used"        -> LLM ran and its judgment was merged
    #   "unavailable" -> LLM requested but no backend/key was configured
    #   "failed"      -> LLM requested and configured, but the call errored
    llm_status: str = "off"
    # When the LLM ran: how much of the skill it actually saw. Guards against the
    # "an AI reviewed this" claim being stronger than reality for big skills.
    #   {"files_seen", "files_total", "chars_seen", "chars_total", "truncated"}
    llm_coverage: dict[str, Any] | None = None
    capabilities: list[str] = field(default_factory=list)
    # True when a dangerous capability combination requires LLM or human review
    # that has not happened yet (verdict was floored, not cleared).
    review_required: bool = False
    review_reasons: list[str] = field(default_factory=list)

    @property
    def is_malicious(self) -> bool:
        return self.verdict == Verdict.MALICIOUS

    @property
    def threats(self) -> list[Finding]:
        """Findings that count toward the verdict (real security concerns)."""
        return [f for f in self.findings if f.category != "notice"]

    @property
    def notices(self) -> list[Finding]:
        """Awareness items: legitimate-but-notable behaviors to surface."""
        return [f for f in self.findings if f.category == "notice"]

    def to_dict(self) -> dict[str, Any]:
        return {
            "skill_name": self.skill_name,
            "verdict": self.verdict.value,
            "risk_score": self.risk_score,
            "engine": self.engine,
            "llm_used": self.llm_used,
            "llm_status": self.llm_status,
            "llm_coverage": self.llm_coverage,
            "capabilities": self.capabilities,
            "review_required": self.review_required,
            "review_reasons": self.review_reasons,
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
        }

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
