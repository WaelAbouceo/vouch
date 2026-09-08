"""Machine-wide skill audit: classify every skill installed on this computer.

Where :func:`~vouch.agent.build_agent_cv` profiles the skills under a single
directory, :func:`audit_machine` walks *all* the standard on-disk locations
where agent tools (Claude, Cursor, Codex, ...) install skills, classifies every
one, and rolls the whole machine up into one answer:

    "Here is every skill on this computer, what each one behaves like, and
     which ones you should look at."

It answers the question a user actually has — *what are the agents and skills on
my PC doing?* — without having to remember where each tool hides its skills.
"""

from __future__ import annotations

import os
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .agent import discover_skills
from .capabilities import infer_roles, plain_english_implications
from .cv import build_cv
from .models import Verdict

_VERDICT_RANK = {Verdict.VALID: 0, Verdict.SUSPICIOUS: 1, Verdict.MALICIOUS: 2}

# Standard on-disk locations where agent tools install skills. Both user-level
# (~) and project-level (./) are considered; only those that exist are scanned.
_USER_ROOTS = [
    "~/.claude/skills",
    "~/.cursor/skills",
    "~/.cursor/skills-cursor",
    "~/.agents/skills",
    "~/.codex/skills",
    "~/.config/agents/skills",
]
_PROJECT_ROOTS = [
    "./.claude/skills",
    "./.cursor/skills",
    "./.agents/skills",
    "./skills",
]


def known_skill_roots(
    extra: list[str] | None = None, *, include_project: bool = True
) -> list[Path]:
    """Return the skill-install directories that exist on this machine."""
    candidates = list(_USER_ROOTS)
    if include_project:
        candidates += _PROJECT_ROOTS
    if extra:
        candidates += list(extra)

    roots: list[Path] = []
    seen: set[Path] = set()
    for c in candidates:
        p = Path(os.path.expanduser(c))
        try:
            p = p.resolve()
        except OSError:
            continue
        if p in seen:
            continue
        seen.add(p)
        if p.is_dir():
            roots.append(p)
    return roots


@dataclass
class AuditEntry:
    root: str  # the skill root this came from
    name: str
    path: str
    verdict: Verdict
    risk_score: int
    review_required: bool
    roles: list[str]
    headline: str  # the single most important "what this means" line

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "name": self.name,
            "path": self.path,
            "verdict": self.verdict.value,
            "risk_score": self.risk_score,
            "review_required": self.review_required,
            "roles": self.roles,
            "headline": self.headline,
        }


@dataclass
class MachineAudit:
    roots: list[str]
    entries: list[AuditEntry] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.entries)

    @property
    def verdict_counts(self) -> dict[str, int]:
        c = Counter(e.verdict.value for e in self.entries)
        return {v.value: c.get(v.value, 0) for v in Verdict}

    @property
    def role_counts(self) -> dict[str, int]:
        c: Counter[str] = Counter()
        for e in self.entries:
            c.update(e.roles)
        return dict(c.most_common())

    @property
    def flagged(self) -> list[AuditEntry]:
        return [e for e in self.entries if e.verdict != Verdict.VALID]

    def to_dict(self) -> dict[str, Any]:
        return {
            "roots": self.roots,
            "total": self.total,
            "verdict_counts": self.verdict_counts,
            "role_counts": self.role_counts,
            "entries": [e.to_dict() for e in self.entries],
        }


def audit_machine(
    roots: list[str] | None = None,
    *,
    use_llm: bool | None = None,
    model: str | None = None,
    api_key: str | None = None,
    human_signoff: bool = False,
) -> MachineAudit:
    """Discover and classify every skill under ``roots`` (or the machine's)."""
    root_paths = (
        [Path(os.path.expanduser(r)) for r in roots]
        if roots
        else known_skill_roots()
    )

    entries: list[AuditEntry] = []
    for rp in root_paths:
        if not rp.is_dir():
            continue
        for sd in discover_skills(rp):
            cv = build_cv(
                str(sd),
                use_llm=use_llm,
                model=model,
                api_key=api_key,
                human_signoff=human_signoff,
            )
            impls = plain_english_implications(cv.capabilities)
            headline = impls[0][1] if impls else ""
            entries.append(
                AuditEntry(
                    root=str(rp),
                    name=cv.name,
                    path=str(sd),
                    verdict=cv.verdict,
                    risk_score=cv.risk_score,
                    review_required=cv.report.review_required,
                    roles=[r.name for r in infer_roles(cv.capabilities)],
                    headline=headline,
                )
            )

    entries.sort(
        key=lambda e: (_VERDICT_RANK[e.verdict], e.risk_score), reverse=True
    )
    return MachineAudit(roots=[str(r) for r in root_paths], entries=entries)


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------

_C = {
    Verdict.VALID: "\033[32m",
    Verdict.SUSPICIOUS: "\033[33m",
    Verdict.MALICIOUS: "\033[31m",
}
_RESET = "\033[0m"
_BOLD = "\033[1m"


def _worst(audit: MachineAudit) -> Verdict:
    worst = Verdict.VALID
    for e in audit.entries:
        if _VERDICT_RANK[e.verdict] > _VERDICT_RANK[worst]:
            worst = e.verdict
    return worst


def render_text(audit: MachineAudit, color: bool = False) -> str:
    def c(text: str, code: str) -> str:
        return f"{code}{text}{_RESET}" if color else text

    width = 62
    lines: list[str] = []
    lines.append("╔" + "═" * width + "╗")
    lines.append("║" + " MACHINE SKILL AUDIT".ljust(width)[:width] + "║")
    lines.append("╚" + "═" * width + "╝")

    if audit.total == 0:
        lines.append("No skills found in any known location.")
        lines.append("Looked in: " + (", ".join(audit.roots) or "(none existed)"))
        return "\n".join(lines)

    vc = audit.verdict_counts
    lines.append(
        f"{audit.total} skill(s) across {len(audit.roots)} location(s):  "
        + c(f"{vc['valid']} valid", _C[Verdict.VALID])
        + "  "
        + c(f"{vc['suspicious']} suspicious", _C[Verdict.SUSPICIOUS])
        + "  "
        + c(f"{vc['malicious']} malicious", _C[Verdict.MALICIOUS])
    )
    lines.append("")

    # What needs a look
    flagged = audit.flagged
    lines.append(c("NEEDS A LOOK", _BOLD))
    if not flagged:
        lines.append("  Nothing — every skill on this machine looks clean.")
    for e in flagged:
        mark = c(e.verdict.value.upper().ljust(10), _C[e.verdict])
        roles = ", ".join(e.roles) or "—"
        lines.append(f"  {mark} {e.name}  ({roles})")
        if e.headline:
            lines.append(f"             {e.headline}")
    lines.append("")

    # What's on this machine (role rollup)
    lines.append(c("WHAT'S ON THIS MACHINE", _BOLD))
    for role, n in audit.role_counts.items():
        lines.append(f"  • {role} — {n} skill(s)")
    lines.append("")

    # Where they live
    lines.append(c("BY LOCATION", _BOLD))
    for root in audit.roots:
        here = [e for e in audit.entries if e.root == root]
        if not here:
            continue
        worst = max((e.verdict for e in here), key=lambda v: _VERDICT_RANK[v])
        tag = c(worst.value.upper(), _C[worst])
        lines.append(f"  {len(here):>2} skill(s)  [{tag}]  {root}")
    return "\n".join(lines)


def render_markdown(audit: MachineAudit) -> str:
    lines: list[str] = []
    lines.append("# Machine Skill Audit")
    lines.append("")
    if audit.total == 0:
        lines.append("_No skills found in any known location._")
        return "\n".join(lines)
    vc = audit.verdict_counts
    lines.append(
        f"**{audit.total} skills** across **{len(audit.roots)} locations** — "
        f"{vc['valid']} valid · {vc['suspicious']} suspicious · "
        f"{vc['malicious']} malicious"
    )
    lines.append("")

    lines.append("## Needs a look")
    lines.append("")
    flagged = audit.flagged
    if not flagged:
        lines.append("_Nothing — every skill on this machine looks clean._")
    else:
        lines.append("| Skill | Verdict | Roles | What this means |")
        lines.append("|---|---|---|---|")
        for e in flagged:
            roles = ", ".join(e.roles) or "—"
            lines.append(
                f"| {e.name} | {e.verdict.value} | {roles} | {e.headline} |"
            )
    lines.append("")

    lines.append("## What's on this machine")
    lines.append("")
    for role, n in audit.role_counts.items():
        lines.append(f"- **{role}** — {n} skill(s)")
    lines.append("")
    return "\n".join(lines)
