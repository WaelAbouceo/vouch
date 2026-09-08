"""Agent CV: a trust profile for a whole agent (all of its skills).

Where a :class:`~vouch.cv.SkillCV` profiles a single skill, an
:class:`AgentCV` aggregates *every* skill an agent has loaded into one report:
the overall verdict, the union of capabilities across skills, and a per-skill
breakdown. Think of it as "would you hire this agent?".

An "agent" here is simply a directory that contains one or more skills (each a
folder with a ``SKILL.md``). Discovery walks the tree and treats every folder
containing a ``SKILL.md`` as a distinct skill.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import loader
from .capabilities import infer_roles
from .cv import SkillCV, build_cv
from .models import Severity, Verdict

# Ordering used to pick the "worst" verdict across skills.
_VERDICT_RANK = {Verdict.VALID: 0, Verdict.SUSPICIOUS: 1, Verdict.MALICIOUS: 2}


def discover_skills(root: str | os.PathLike[str]) -> list[Path]:
    """Return the directory of every skill (folder with a SKILL.md) under root.

    If ``root`` itself is a single skill (or a file), it is returned as-is.
    """
    p = Path(root)
    if p.is_file():
        return [p]
    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(p):
        dirnames[:] = [d for d in dirnames if d not in loader._SKIP_DIRS]
        if any(f.lower() == "skill.md" for f in filenames):
            found.append(Path(dirpath))
            # Don't descend further into a skill's own subdirectories.
            dirnames[:] = []
    if not found:
        # No SKILL.md anywhere; treat the root itself as one skill.
        return [p]
    return sorted(found)


@dataclass
class SkillSummary:
    name: str
    path: str
    verdict: Verdict
    risk_score: int
    finding_count: int
    top_capabilities: list[str] = field(default_factory=list)
    roles: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "path": self.path,
            "verdict": self.verdict.value,
            "risk_score": self.risk_score,
            "finding_count": self.finding_count,
            "top_capabilities": self.top_capabilities,
            "roles": self.roles,
        }


@dataclass
class AgentCV:
    name: str
    verdict: Verdict
    risk_score: int  # max across skills
    recommendation: str
    skill_count: int
    skills: list[SkillSummary]
    capabilities: dict[str, int]  # capability label -> how many skills use it
    findings_by_severity: dict[str, int]
    roles: dict[str, int] = field(default_factory=dict)  # role name -> skill count
    skill_cvs: list[SkillCV] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "verdict": self.verdict.value,
            "risk_score": self.risk_score,
            "recommendation": self.recommendation,
            "skill_count": self.skill_count,
            "roles": self.roles,
            "capabilities": self.capabilities,
            "findings_by_severity": self.findings_by_severity,
            "skills": [s.to_dict() for s in self.skills],
        }


_RECOMMENDATION = {
    Verdict.VALID: "TRUSTED — all skills passed. Safe to run this agent.",
    Verdict.SUSPICIOUS: "REVIEW — one or more skills need a look before trusting this agent.",
    Verdict.MALICIOUS: "QUARANTINE — this agent has a malicious skill. Do not run.",
}


def build_agent_cv(
    root: str | os.PathLike[str],
    *,
    name: str | None = None,
    use_llm: bool | None = None,
    model: str | None = None,
    api_key: str | None = None,
    human_signoff: bool = False,
) -> AgentCV:
    """Build an Agent CV by profiling every skill discovered under ``root``."""
    skill_dirs = discover_skills(root)

    skill_cvs: list[SkillCV] = []
    for sd in skill_dirs:
        skill = loader.load(str(sd))
        skill_cvs.append(
            build_cv(
                skill,
                use_llm=use_llm,
                model=model,
                api_key=api_key,
                human_signoff=human_signoff,
            )
        )

    worst = Verdict.VALID
    max_risk = 0
    cap_counts: dict[str, int] = {}
    role_counts: dict[str, int] = {}
    sev_totals: dict[str, int] = {s.value: 0 for s in Severity}
    summaries: list[SkillSummary] = []

    for cv in skill_cvs:
        if _VERDICT_RANK[cv.verdict] > _VERDICT_RANK[worst]:
            worst = cv.verdict
        max_risk = max(max_risk, cv.risk_score)
        present = [c.label for c in cv.capabilities if c.present]
        for label in present:
            cap_counts[label] = cap_counts.get(label, 0) + 1
        roles = [r.name for r in infer_roles(cv.capabilities)]
        for rname in roles:
            role_counts[rname] = role_counts.get(rname, 0) + 1
        for sev, n in cv.findings_by_severity.items():
            sev_totals[sev] += n
        summaries.append(
            SkillSummary(
                name=cv.name,
                path=cv.report.skill_name,
                verdict=cv.verdict,
                risk_score=cv.risk_score,
                finding_count=len(cv.report.findings),
                top_capabilities=present[:4],
                roles=roles,
            )
        )

    # Worst skills first, then by risk.
    summaries.sort(key=lambda s: (_VERDICT_RANK[s.verdict], s.risk_score), reverse=True)

    agent_name = name or Path(root).name or "agent"
    return AgentCV(
        name=agent_name,
        verdict=worst,
        risk_score=max_risk,
        recommendation=_RECOMMENDATION[worst],
        skill_count=len(skill_cvs),
        skills=summaries,
        capabilities=dict(sorted(cap_counts.items(), key=lambda kv: -kv[1])),
        findings_by_severity=sev_totals,
        roles=dict(sorted(role_counts.items(), key=lambda kv: -kv[1])),
        skill_cvs=skill_cvs,
    )


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------

_VERDICT_BADGE = {
    Verdict.VALID: "🟢 TRUSTED",
    Verdict.SUSPICIOUS: "🟡 REVIEW",
    Verdict.MALICIOUS: "🔴 QUARANTINE",
}


def render_markdown(cv: AgentCV) -> str:
    lines: list[str] = []
    lines.append(f"# Agent CV — {cv.name}")
    lines.append("")
    lines.append(
        f"**Status:** {_VERDICT_BADGE[cv.verdict]}  ·  "
        f"**Max risk:** {cv.risk_score}/100  ·  "
        f"**Skills:** {cv.skill_count}"
    )
    lines.append("")
    lines.append(f"**Recommendation:** {cv.recommendation}")
    lines.append("")

    lines.append("## What this agent behaves as")
    if not cv.roles:
        lines.append("_No skills profiled._")
    else:
        for name, count in cv.roles.items():
            lines.append(f"- **{name}** — {count} skill(s)")
    lines.append("")

    lines.append("## Skills")
    lines.append("")
    lines.append("| Skill | Verdict | Risk | Findings | Capabilities |")
    lines.append("|---|---|---:|---:|---|")
    for s in cv.skills:
        caps = ", ".join(s.top_capabilities) or "—"
        lines.append(
            f"| {s.name} | {s.verdict.value} | {s.risk_score} | "
            f"{s.finding_count} | {caps} |"
        )
    lines.append("")

    lines.append("## Capabilities across the agent")
    if not cv.capabilities:
        lines.append("_None detected._")
    else:
        for label, count in cv.capabilities.items():
            lines.append(f"- **{label}** — used by {count} skill(s)")
    lines.append("")

    total = sum(cv.findings_by_severity.values())
    lines.append(f"## Security ({total} finding(s) total)")
    order = ["critical", "high", "medium", "low", "info"]
    badge = ", ".join(
        f"{cv.findings_by_severity[s]} {s}"
        for s in order
        if cv.findings_by_severity.get(s)
    )
    lines.append(badge or "_No findings._")
    lines.append("")
    return "\n".join(lines)


_C = {
    Verdict.VALID: "\033[32m",
    Verdict.SUSPICIOUS: "\033[33m",
    Verdict.MALICIOUS: "\033[31m",
}
_RESET = "\033[0m"
_BOLD = "\033[1m"


def render_text(cv: AgentCV, color: bool = False) -> str:
    def c(text: str, code: str) -> str:
        return f"{code}{text}{_RESET}" if color else text

    width = 62
    lines: list[str] = []
    lines.append("╔" + "═" * width + "╗")
    lines.append("║" + f" AGENT CV — {cv.name}".ljust(width)[:width] + "║")
    lines.append("╚" + "═" * width + "╝")
    badge = _VERDICT_BADGE[cv.verdict].split(" ", 1)[1]
    lines.append(
        c(f"Status: {badge}", _BOLD + _C[cv.verdict])
        + f"   Max risk: {cv.risk_score}/100   Skills: {cv.skill_count}"
    )
    lines.append(c(f"Recommendation: {cv.recommendation}", _C[cv.verdict]))
    lines.append("")

    lines.append(c("BEHAVES AS", _BOLD))
    if not cv.roles:
        lines.append("  (no skills profiled)")
    for name, count in cv.roles.items():
        lines.append(f"  • {name} — {count} skill(s)")
    lines.append("")

    lines.append(c("SKILLS", _BOLD))
    for s in cv.skills:
        mark = c(s.verdict.value.upper().ljust(10), _C[s.verdict])
        lines.append(
            f"  {mark} risk {s.risk_score:>3}  {s.finding_count:>2} finding(s)  {s.name}"
        )
        if s.roles:
            lines.append(f"             role: {', '.join(s.roles)}")
        if s.top_capabilities:
            lines.append(f"             caps: {', '.join(s.top_capabilities)}")
    lines.append("")

    lines.append(c("CAPABILITIES (agent-wide)", _BOLD))
    if not cv.capabilities:
        lines.append("  (none detected)")
    for label, count in cv.capabilities.items():
        lines.append(f"  • {label} — {count} skill(s)")
    lines.append("")

    total = sum(cv.findings_by_severity.values())
    lines.append(c(f"SECURITY ({total} total)", _BOLD))
    order = ["critical", "high", "medium", "low", "info"]
    summary = "  ".join(
        f"{cv.findings_by_severity[s]} {s}"
        for s in order
        if cv.findings_by_severity.get(s)
    )
    lines.append("  " + (summary or "(none)"))
    return "\n".join(lines)
