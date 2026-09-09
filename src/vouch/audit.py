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

import hashlib
import json
import os
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import loader
from .agent import discover_skills
from .capabilities import infer_roles, plain_english_implications
from .cv import build_cv
from .models import SkillInput, Verdict

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
    """Return the skill-install directories that exist on this machine.

    Non-standard setups (e.g. a container that mounts skills at ``/mnt/skills``)
    can add locations via the ``VOUCH_SKILL_ROOTS`` environment variable, a list
    of paths separated by the OS path separator (``:`` on Unix, ``;`` on Windows)
    or commas.
    """
    candidates = list(_USER_ROOTS)
    if include_project:
        candidates += _PROJECT_ROOTS
    env_roots = os.environ.get("VOUCH_SKILL_ROOTS", "")
    if env_roots:
        for chunk in env_roots.replace(",", os.pathsep).split(os.pathsep):
            chunk = chunk.strip()
            if chunk:
                candidates.append(chunk)
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
    fingerprint: str = ""  # content hash, to detect a skill being updated

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
            "fingerprint": self.fingerprint,
        }


def _fingerprint(skill: SkillInput) -> str:
    """A stable short hash of a skill's file contents (detects updates)."""
    h = hashlib.sha256()
    for f in sorted(skill.files, key=lambda f: f.path):
        h.update(f.path.encode("utf-8", "replace"))
        h.update(b"\0")
        h.update(f.content.encode("utf-8", "replace"))
        h.update(b"\0")
    return h.hexdigest()[:16]


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
    progress: Callable[[int, int, str], None] | None = None,
) -> MachineAudit:
    """Discover and classify every skill under ``roots`` (or the machine's).

    ``progress`` is called as ``progress(index, total, name)`` before each skill
    is classified — useful for a status line during slow (LLM-enabled) runs.
    """
    root_paths = (
        [Path(os.path.expanduser(r)) for r in roots]
        if roots
        else known_skill_roots()
    )

    # Gather every skill first so we know the total up front (for progress).
    targets: list[tuple[Path, Path]] = []
    for rp in root_paths:
        if not rp.is_dir():
            continue
        for sd in discover_skills(rp):
            targets.append((rp, sd))

    entries: list[AuditEntry] = []
    total = len(targets)
    for i, (rp, sd) in enumerate(targets, start=1):
        if progress is not None:
            progress(i, total, sd.name)
        skill = loader.load(str(sd))
        cv = build_cv(
            skill,
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
                fingerprint=_fingerprint(skill),
            )
        )

    entries.sort(
        key=lambda e: (_VERDICT_RANK[e.verdict], e.risk_score), reverse=True
    )
    return MachineAudit(roots=[str(r) for r in root_paths], entries=entries)


# ---------------------------------------------------------------------------
# Baseline + diff ("what changed since last audit")
# ---------------------------------------------------------------------------

BASELINE_VERSION = 1


def default_baseline_path() -> Path:
    """Where the audit baseline is stored (``$VOUCH_HOME`` or ``~/.vouch``)."""
    home = os.environ.get("VOUCH_HOME") or os.path.join(os.path.expanduser("~"), ".vouch")
    return Path(home) / "audit-baseline.json"


def save_baseline(audit: MachineAudit, path: str | os.PathLike[str]) -> None:
    """Persist the current audit as the baseline for future comparisons."""
    p = Path(path)
    data = {
        "version": BASELINE_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "roots": audit.roots,
        "entries": {
            e.path: {
                "name": e.name,
                "verdict": e.verdict.value,
                "risk_score": e.risk_score,
                "review_required": e.review_required,
                "roles": sorted(e.roles),
                "fingerprint": e.fingerprint,
            }
            for e in audit.entries
        },
    }
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2), encoding="utf-8")


def load_baseline(path: str | os.PathLike[str]) -> dict[str, Any] | None:
    """Load a saved baseline, or ``None`` if it does not exist / is unreadable."""
    p = Path(path)
    if not p.is_file():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


@dataclass
class SkillChange:
    name: str
    path: str
    before_verdict: str
    after_verdict: str
    risk_before: int
    risk_after: int
    added_roles: list[str]
    removed_roles: list[str]
    content_changed: bool

    @property
    def verdict_changed(self) -> bool:
        return self.before_verdict != self.after_verdict

    @property
    def is_newly_risky(self) -> bool:
        """True if this change moves the skill in a more dangerous direction."""
        worse_verdict = (
            _VERDICT_RANK.get(Verdict(self.after_verdict), 0)
            > _VERDICT_RANK.get(Verdict(self.before_verdict), 0)
        )
        gained_danger = any(
            r in {"Data Courier", "Remote Code Runner", "Resident Installer"}
            for r in self.added_roles
        )
        return worse_verdict or gained_danger

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "path": self.path,
            "before_verdict": self.before_verdict,
            "after_verdict": self.after_verdict,
            "risk_before": self.risk_before,
            "risk_after": self.risk_after,
            "added_roles": self.added_roles,
            "removed_roles": self.removed_roles,
            "content_changed": self.content_changed,
            "newly_risky": self.is_newly_risky,
        }


@dataclass
class AuditDiff:
    new: list[AuditEntry] = field(default_factory=list)
    removed: list[dict[str, Any]] = field(default_factory=list)
    changed: list[SkillChange] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(self.new or self.removed or self.changed)

    @property
    def newly_risky(self) -> list[SkillChange]:
        return [c for c in self.changed if c.is_newly_risky]

    def to_dict(self) -> dict[str, Any]:
        return {
            "new": [e.to_dict() for e in self.new],
            "removed": self.removed,
            "changed": [c.to_dict() for c in self.changed],
        }


def diff_audit(current: MachineAudit, baseline: dict[str, Any]) -> AuditDiff:
    """Compare a current audit against a saved baseline dict."""
    base_entries: dict[str, Any] = baseline.get("entries", {}) or {}
    diff = AuditDiff()
    seen: set[str] = set()

    for e in current.entries:
        seen.add(e.path)
        b = base_entries.get(e.path)
        if b is None:
            diff.new.append(e)
            continue
        before_roles = set(b.get("roles", []))
        after_roles = set(e.roles)
        added = sorted(after_roles - before_roles)
        removed = sorted(before_roles - after_roles)
        content_changed = bool(b.get("fingerprint")) and b["fingerprint"] != e.fingerprint
        verdict_changed = b.get("verdict") != e.verdict.value
        if added or removed or content_changed or verdict_changed:
            diff.changed.append(
                SkillChange(
                    name=e.name,
                    path=e.path,
                    before_verdict=b.get("verdict", "unknown"),
                    after_verdict=e.verdict.value,
                    risk_before=int(b.get("risk_score", 0)),
                    risk_after=e.risk_score,
                    added_roles=added,
                    removed_roles=removed,
                    content_changed=content_changed,
                )
            )

    for path, b in base_entries.items():
        if path not in seen:
            diff.removed.append({"path": path, **b})

    # Most alarming first.
    diff.changed.sort(key=lambda c: (c.is_newly_risky, c.risk_after), reverse=True)
    return diff


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
_DIM = "\033[2m"


def _worst(audit: MachineAudit) -> Verdict:
    worst = Verdict.VALID
    for e in audit.entries:
        if _VERDICT_RANK[e.verdict] > _VERDICT_RANK[worst]:
            worst = e.verdict
    return worst


def _short_path(p: str) -> str:
    """Abbreviate the user's home dir to ``~`` for compact, readable output."""
    if not p:
        return p
    home = os.path.expanduser("~")
    if p == home:
        return "~"
    if p.startswith(home + os.sep):
        return "~" + p[len(home):]
    return p


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
        if e.path:
            lines.append(c(f"             {_short_path(e.path)}", _DIM))
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


def render_diff_text(diff: AuditDiff, color: bool = False, first_run: bool = False) -> str:
    def c(text: str, code: str) -> str:
        return f"{code}{text}{_RESET}" if color else text

    lines: list[str] = []
    lines.append(c("CHANGED SINCE LAST AUDIT", _BOLD))
    if first_run:
        lines.append("  First audit — baseline saved. Re-run later to see what changed.")
        return "\n".join(lines)
    if not diff.has_changes:
        lines.append("  Nothing changed since your last audit.")
        return "\n".join(lines)

    for e in diff.new:
        roles = ", ".join(e.roles) or "—"
        verdict = e.verdict.value.upper()
        lines.append(c(f"  + NEW  {verdict:10} {e.name}  ({roles})", _C[e.verdict]))
        if e.path:
            lines.append(c(f"             {_short_path(e.path)}", _DIM))
        if e.headline:
            lines.append(f"             {e.headline}")

    for ch in diff.changed:
        code = _C[Verdict.MALICIOUS] if ch.is_newly_risky else _C[Verdict.SUSPICIOUS]
        flag = "⚠ MORE RISKY" if ch.is_newly_risky else "changed"
        lines.append(c(f"  ~ {flag:11} {ch.name}", code))
        if ch.verdict_changed:
            lines.append(
                f"             verdict {ch.before_verdict} → {ch.after_verdict}"
            )
        if ch.added_roles:
            lines.append(f"             gained: {', '.join(ch.added_roles)}")
        if ch.removed_roles:
            lines.append(f"             dropped: {', '.join(ch.removed_roles)}")
        if ch.content_changed and not (ch.added_roles or ch.verdict_changed):
            lines.append("             contents changed (same capabilities)")

    for b in diff.removed:
        lines.append(f"  - REMOVED  {b.get('name', b.get('path'))}")

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
        lines.append("| Skill | Path | Verdict | Roles | What this means |")
        lines.append("|---|---|---|---|---|")
        for e in flagged:
            roles = ", ".join(e.roles) or "—"
            path = f"`{_short_path(e.path)}`" if e.path else "—"
            lines.append(
                f"| {e.name} | {path} | {e.verdict.value} | {roles} | {e.headline} |"
            )
    lines.append("")

    lines.append("## What's on this machine")
    lines.append("")
    for role, n in audit.role_counts.items():
        lines.append(f"- **{role}** — {n} skill(s)")
    lines.append("")
    return "\n".join(lines)
