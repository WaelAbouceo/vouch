"""Skill CV: a one-page profile ("résumé") for a skill.

A CV combines four things into a single card:

1. **Identity**  - name + description parsed from ``SKILL.md`` frontmatter.
2. **Capabilities** - what the skill *can do* (network, shell, filesystem,
   credentials, persistence, dynamic code), inferred from its content.
3. **Inventory** - the files that make up the skill.
4. **Security** - the validation verdict, risk score, and findings.

Use :func:`build_cv` to produce a :class:`SkillCV`, then render it with
``cv.render_markdown()`` / ``cv.render_text()`` or serialize with ``cv.to_dict()``.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any

from . import loader
from .engine import validate_skill
from .models import Report, Severity, SkillInput, Verdict


# ---------------------------------------------------------------------------
# Frontmatter
# ---------------------------------------------------------------------------

_FM_RE = re.compile(r"^\ufeff?---\s*\n(.*?)\n---\s*\n", re.DOTALL)


def parse_frontmatter(text: str) -> dict[str, str]:
    """Very small YAML-frontmatter reader (flat ``key: value`` pairs only)."""
    m = _FM_RE.match(text)
    if not m:
        return {}
    out: dict[str, str] = {}
    for line in m.group(1).splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if ":" not in line:
            continue
        key, _, val = line.partition(":")
        val = val.strip().strip("'\"")
        # collapse simple folded values / trailing markers
        out[key.strip().lower()] = val
    return out


# ---------------------------------------------------------------------------
# Capability inference (benign-or-not; describes what the skill *can* do)
# ---------------------------------------------------------------------------


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
            r"\bsh\s+-c|\bbash\s+-c|child_process|execSync|spawn\()\b",
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
                    continue  # one piece of evidence per line per capability
                seen[key].add(loc)
                if len(cap.evidence) < _MAX_EVIDENCE:
                    snippet = content_lines[line - 1].strip() if line <= len(content_lines) else ""
                    cap.evidence.append(Evidence(sf.path, line, snippet[:120]))
    return list(caps.values())


# ---------------------------------------------------------------------------
# The CV
# ---------------------------------------------------------------------------


@dataclass
class SkillCV:
    name: str
    description: str
    source: str
    verdict: Verdict
    risk_score: int
    summary: str
    recommendation: str
    capabilities: list[Capability]
    files: list[tuple[str, int]]  # (path, line_count)
    findings_by_severity: dict[str, int]
    report: Report

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "source": self.source,
            "verdict": self.verdict.value,
            "risk_score": self.risk_score,
            "summary": self.summary,
            "recommendation": self.recommendation,
            "capabilities": [c.to_dict() for c in self.capabilities if c.present],
            "files": [{"path": p, "lines": n} for p, n in self.files],
            "findings_by_severity": self.findings_by_severity,
            "findings": [f.to_dict() for f in self.report.findings],
        }


_RECOMMENDATION = {
    Verdict.VALID: "SAFE TO LOAD — no security concerns detected.",
    Verdict.SUSPICIOUS: "REVIEW BEFORE LOADING — potential concerns found.",
    Verdict.MALICIOUS: "DO NOT LOAD — malicious behavior detected.",
}


def build_cv(
    target: str | SkillInput,
    *,
    use_llm: bool | None = None,
    model: str | None = None,
    api_key: str | None = None,
) -> SkillCV:
    """Build a Skill CV from a path or an already-loaded :class:`SkillInput`."""
    skill = target if isinstance(target, SkillInput) else loader.load(target)

    report = validate_skill(skill, use_llm=use_llm, model=model, api_key=api_key)

    fm: dict[str, str] = {}
    md = skill.skill_md
    if md is not None:
        fm = parse_frontmatter(md.content)

    name = fm.get("name") or skill.name
    description = fm.get("description") or "(no description provided)"

    files = [(f.path, f.content.count("\n") + 1) for f in skill.files]

    by_sev: dict[str, int] = {s.value: 0 for s in Severity}
    for f in report.findings:
        by_sev[f.severity.value] += 1

    return SkillCV(
        name=name,
        description=description,
        source=skill.source,
        verdict=report.verdict,
        risk_score=report.risk_score,
        summary=report.summary,
        recommendation=_RECOMMENDATION[report.verdict],
        capabilities=scan_capabilities(skill),
        files=files,
        findings_by_severity=by_sev,
        report=report,
    )


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------

_VERDICT_BADGE = {
    Verdict.VALID: "🟢 VALID",
    Verdict.SUSPICIOUS: "🟡 SUSPICIOUS",
    Verdict.MALICIOUS: "🔴 MALICIOUS",
}


def render_markdown(cv: SkillCV) -> str:
    lines: list[str] = []
    lines.append(f"# Skill CV — {cv.name}")
    lines.append("")
    lines.append(f"> {cv.description}")
    lines.append("")
    lines.append(f"**Verdict:** {_VERDICT_BADGE[cv.verdict]}  ·  "
                 f"**Risk score:** {cv.risk_score}/100  ·  "
                 f"**Source:** {cv.source}  ·  "
                 f"**Engine:** {cv.report.engine}")
    lines.append("")
    lines.append(f"**Recommendation:** {cv.recommendation}")
    lines.append("")

    # Capabilities
    lines.append("## Capabilities")
    present = [c for c in cv.capabilities if c.present]
    if not present:
        lines.append("_None detected — the skill appears to be instructions-only._")
    else:
        for c in present:
            lines.append(f"- **{c.label}**")
            for e in c.evidence:
                lines.append(f"  - `{e.file}:{e.line}` — `{e.excerpt}`")
    lines.append("")

    # Inventory
    lines.append("## Files")
    for path, n in cv.files:
        lines.append(f"- `{path}` ({n} lines)")
    lines.append("")

    # Security
    lines.append("## Security findings")
    total = sum(cv.findings_by_severity.values())
    if total == 0:
        lines.append("_No findings._")
    else:
        order = ["critical", "high", "medium", "low", "info"]
        badge = ", ".join(
            f"{cv.findings_by_severity[s]} {s}"
            for s in order
            if cv.findings_by_severity.get(s)
        )
        lines.append(f"**{total} finding(s):** {badge}")
        lines.append("")
        ordered = sorted(
            cv.report.findings, key=lambda f: f.severity.weight, reverse=True
        )
        for f in ordered:
            loc = f" ({f.file}:{f.line})" if f.file else ""
            lines.append(f"- **[{f.severity.value.upper()}]** {f.rule_id}: {f.title}{loc}")
    lines.append("")
    return "\n".join(lines)


_C = {
    Verdict.VALID: "\033[32m",
    Verdict.SUSPICIOUS: "\033[33m",
    Verdict.MALICIOUS: "\033[31m",
}
_RESET = "\033[0m"
_BOLD = "\033[1m"


def render_text(cv: SkillCV, color: bool = False) -> str:
    def c(text: str, code: str) -> str:
        return f"{code}{text}{_RESET}" if color else text

    width = 62
    lines: list[str] = []
    lines.append("╔" + "═" * width + "╗")
    title = f" SKILL CV — {cv.name}"
    lines.append("║" + title.ljust(width)[:width] + "║")
    lines.append("╠" + "═" * width + "╣")
    lines.append("╚" + "═" * width + "╝")
    lines.append(cv.description)
    lines.append("")
    badge = _VERDICT_BADGE[cv.verdict].split(" ", 1)[1]
    lines.append(
        c(f"Verdict: {badge}", _BOLD + _C[cv.verdict])
        + f"   Risk: {cv.risk_score}/100   Source: {cv.source}   Engine: {cv.report.engine}"
    )
    lines.append(c(f"Recommendation: {cv.recommendation}", _C[cv.verdict]))
    lines.append("")

    lines.append(c("CAPABILITIES", _BOLD))
    present = [x for x in cv.capabilities if x.present]
    if not present:
        lines.append("  (none detected — instructions-only)")
    for cap in present:
        lines.append(f"  • {cap.label}")
        for e in cap.evidence:
            lines.append(f"      {e.file}:{e.line}  {e.excerpt}")
    lines.append("")

    lines.append(c("FILES", _BOLD))
    for path, n in cv.files:
        lines.append(f"  • {path} ({n} lines)")
    lines.append("")

    lines.append(c("SECURITY FINDINGS", _BOLD))
    total = sum(cv.findings_by_severity.values())
    if total == 0:
        lines.append("  (none)")
    else:
        order = ["critical", "high", "medium", "low", "info"]
        summary = "  ".join(
            f"{cv.findings_by_severity[s]} {s}"
            for s in order
            if cv.findings_by_severity.get(s)
        )
        lines.append(f"  {total} total:  {summary}")
        ordered = sorted(
            cv.report.findings, key=lambda f: f.severity.weight, reverse=True
        )
        for f in ordered:
            loc = f" ({f.file}:{f.line})" if f.file else ""
            lines.append(f"  [{f.severity.value.upper():8}] {f.rule_id}: {f.title}{loc}")
    return "\n".join(lines)
