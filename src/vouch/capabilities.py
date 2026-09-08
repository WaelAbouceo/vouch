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
    strength: str = "strong"  # "strong" (code/script) | "weak" (prose/docs)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Capability:
    key: str
    label: str
    present: bool = False
    # ``strong`` is True when the capability appears in executable context
    # (a fenced code block, or a script file) rather than only in prose. Danger
    # tiers and the capability gate rely on strong evidence, so a skill that
    # merely *documents* ``curl`` or ``API_KEY`` is not treated as behavioural.
    strong: bool = False
    evidence: list[Evidence] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "key": self.key,
            "label": self.label,
            "present": self.present,
            "strong": self.strong,
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
            r"("
            r"\.ssh/|\.aws/|\.kube/|\.env\b|"
            r"\bapi[_-]?keys?\b|\bsecret[_-]?keys?\b|\baccess[_-]?keys?\b|"
            r"\bprivate[_-]?keys?\b|"
            r"\bpassword\b|\bpasswd\b|\bcredentials?\b|\bsecrets?\b|"
            # secret-ish token phrases only — NOT the bare word "token(s)", which
            # collides with UI/design "tokens" (theme tokens, stroke tokens, ...).
            r"\b(?:auth|access|api|bearer|refresh|session|id)[_-]?tokens?\b|"
            r"\b\w+_tokens?\b"          # GITHUB_TOKEN, HF_TOKEN, ...
            r")",
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

# Files treated as prose (fenced code blocks are the only "executable" context).
# Everything else (scripts: .py/.sh/.js/...) is treated as executable throughout.
_PROSE_EXTS = {".md", ".markdown", ".mdx", ".rst", ".txt"}


# Line prefixes that indicate a comment — example URLs/paths inside comments are
# documentation, not behaviour, so they must not count as strong evidence.
_COMMENT_PREFIXES = ("*", "//", "/*", "*/", "#", "<!--", '"""', "'''", ";;")


def _is_comment_line(text: str) -> bool:
    s = text.strip()
    if not s:
        return False
    # A shebang is not a "comment" in the doc sense, but it carries no capability
    # signal either; treat everything starting with these markers as non-behaviour.
    return s.startswith(_COMMENT_PREFIXES)


def _executable_lines(content: str, path: str) -> set[int] | None:
    """Return the set of 1-based line numbers that are executable context.

    For prose files (Markdown/txt), only lines *inside* fenced code blocks count.
    For everything else (scripts), the whole file is executable, so we return
    ``None`` as a sentinel meaning "every line is strong".
    """
    name = path.rsplit("/", 1)[-1].lower()
    # TypeScript declaration files (.d.ts) are pure type declarations — they
    # contain no runtime behaviour, so nothing in them is "executable".
    if name.endswith(".d.ts"):
        return set()
    ext = ""
    if "." in name:
        ext = "." + name.rsplit(".", 1)[-1]
    if ext not in _PROSE_EXTS:
        return None  # a script: every line is executable

    code: set[int] = set()
    in_fence = False
    for i, line in enumerate(content.splitlines(), start=1):
        stripped = line.lstrip()
        if stripped.startswith("```") or stripped.startswith("~~~"):
            in_fence = not in_fence
            continue  # the fence marker line itself is not code content
        if in_fence:
            code.add(i)
    return code


def scan_capabilities(skill: SkillInput) -> list[Capability]:
    """Return one Capability per class, marked present with up to 3 evidence hits.

    Each hit is graded ``strong`` (in a fenced code block or a script file) or
    ``weak`` (mentioned only in prose/documentation). A capability is ``strong``
    if it has at least one strong hit anywhere in the skill.
    """
    caps = {key: Capability(key, label) for key, label, _ in _CAP_PATTERNS}
    seen: dict[str, set[tuple[str, int]]] = {key: set() for key, _, _ in _CAP_PATTERNS}
    # Raw text handed in directly (stdin / validate_text) is a direct check of
    # content, so treat all of it as executable. Files/dirs loaded from disk use
    # fenced-code detection so prose mentions don't count as behaviour.
    force_strong = skill.source == "text"
    for sf in skill.files:
        content_lines = sf.content.splitlines()
        exec_lines = None if force_strong else _executable_lines(sf.content, sf.path)
        for key, _label, pat in _CAP_PATTERNS:
            cap = caps[key]
            for m in pat.finditer(sf.content):
                cap.present = True
                line = sf.content.count("\n", 0, m.start()) + 1
                line_text = content_lines[line - 1] if line <= len(content_lines) else ""
                in_exec = exec_lines is None or line in exec_lines
                # A match inside a comment (e.g. an example URL in JSDoc) is
                # documentation, not behaviour — grade it weak.
                is_strong = in_exec and not _is_comment_line(line_text)
                if is_strong:
                    cap.strong = True
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
                    cap.evidence.append(
                        Evidence(
                            sf.path,
                            line,
                            snippet[:120],
                            strength="strong" if is_strong else "weak",
                        )
                    )
    return list(caps.values())


def present_keys(caps: list[Capability]) -> set[str]:
    """Capabilities mentioned anywhere (prose or code)."""
    return {c.key for c in caps if c.present}


def active_keys(caps: list[Capability]) -> set[str]:
    """Capabilities with executable (strong) evidence — actual behaviour, not docs."""
    return {c.key for c in caps if c.strong}


# Ordering of severity levels used by :func:`plain_english_implications`.
IMPLICATION_ORDER = {"danger": 0, "caution": 1, "info": 2}


def plain_english_implications(caps: list[Capability]) -> list[tuple[str, str]]:
    """Translate a capability set into plain-English "what this means for you".

    Returns a list of ``(level, sentence)`` tuples, most serious first, where
    ``level`` is one of ``"danger"``, ``"caution"`` or ``"info"``. The point is
    to state — in words a non-expert understands — what the skill can actually
    do to their machine, with special emphasis on the *combinations* that make
    exfiltration or remote code execution possible.

    Only executable (strong) evidence drives these sentences — capabilities that
    appear solely in documentation are reported separately as a mild note.
    """
    present = active_keys(caps)
    net = "network" in present
    creds = ("credentials" in present) or ("env" in present)
    shell = ("shell" in present) or ("code_exec" in present)
    fs_write = "fs_write" in present
    persistence = "persistence" in present

    dangers: list[str] = []
    cautions: list[str] = []
    infos: list[str] = []

    # --- the dangerous combinations, stated bluntly ---
    if net and creds:
        dangers.append(
            "Can read your secrets AND reach the internet — it could copy your "
            "API keys, tokens, or passwords and send them somewhere."
        )
    if net and shell:
        dangers.append(
            "Can pull code from the internet AND run it on your machine — it "
            "could execute whatever it downloads."
        )
    if persistence and (shell or fs_write):
        dangers.append(
            "Can install itself to keep running in the background, even after "
            "the task is done or you reboot."
        )

    # --- single capabilities worth stating (only if not already implied) ---
    if fs_write:
        cautions.append("Can create, change, or delete files on your machine.")
    if creds and not net:
        cautions.append(
            "Reads your API keys, tokens, or passwords (but was not seen "
            "sending them anywhere)."
        )
    if shell and not net:
        cautions.append("Runs shell commands on your machine.")
    if net and not creds and not shell:
        infos.append("Talks to the internet (can download or upload data).")

    result: list[tuple[str, str]] = (
        [("danger", s) for s in dangers]
        + [("caution", s) for s in cautions]
        + [("info", s) for s in infos]
    )
    if not result:
        doc_only = present_keys(caps) - active_keys(caps)
        if doc_only:
            result.append((
                "info",
                "Only references risky operations in its documentation — none were "
                "seen in code the skill actually runs.",
            ))
        else:
            result.append((
                "info",
                "No risky capabilities detected — appears to be instructions only.",
            ))
    return result


# Role archetypes: a plain-English "job title" for what a skill behaves like,
# derived from its capability profile. A skill can hold more than one role.
# ``level`` mirrors :func:`plain_english_implications` so callers can colour it.
@dataclass
class Role:
    name: str
    blurb: str
    level: str  # "danger" | "caution" | "info"


def infer_roles(caps: list[Capability]) -> list[Role]:
    """Group a skill's capabilities into named roles ("what it acts like").

    Ordered most-notable first. The names are deliberately memorable so they
    read like a job title on a CV (e.g. "Data Courier", "Remote Code Runner").

    Roles describe *behaviour*, so they are derived from executable (strong)
    evidence only — a skill that merely documents ``curl`` is not a "Web Client".
    """
    present = active_keys(caps)
    net = "network" in present
    creds = ("credentials" in present) or ("env" in present)
    shell = ("shell" in present) or ("code_exec" in present)
    fs_write = "fs_write" in present
    fs_read = "fs_read" in present
    persistence = "persistence" in present

    roles: list[Role] = []
    if net and creds:
        roles.append(Role(
            "Data Courier",
            "touches your secrets and can move data over the network",
            "danger",
        ))
    if net and shell:
        roles.append(Role(
            "Remote Code Runner",
            "can download code from the internet and execute it",
            "danger",
        ))
    if persistence and (shell or fs_write):
        roles.append(Role(
            "Resident Installer",
            "can set itself up to keep running after the task ends",
            "danger",
        ))
    if shell and not net:
        roles.append(Role(
            "System Operator",
            "runs shell commands on your machine",
            "caution",
        ))
    if fs_write and not shell:
        roles.append(Role(
            "File Editor",
            "creates, changes, or deletes files",
            "caution",
        ))
    if creds and not net:
        roles.append(Role(
            "Secret Reader",
            "reads API keys / tokens but was not seen sending them out",
            "caution",
        ))
    if net and not creds and not shell:
        roles.append(Role(
            "Web Client",
            "talks to the internet (downloads or uploads data)",
            "info",
        ))
    if not roles and fs_read:
        roles.append(Role(
            "File Reader",
            "reads files but takes no other risky action",
            "info",
        ))
    if not roles:
        roles.append(Role(
            "Advisor",
            "instructions only — no risky capabilities detected",
            "info",
        ))
    return roles
