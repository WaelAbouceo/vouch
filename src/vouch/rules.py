"""Static analysis rules for detecting malicious or unsafe skills.

Each rule is a regex (or callable) paired with a severity and human-readable
explanation. Rules are grouped by threat category. The engine runs every rule
against every file and aggregates the resulting :class:`Finding` objects.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Callable

from .models import Finding, Severity, SkillFile, SkillInput


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    severity: Severity
    pattern: re.Pattern[str]
    detail: str
    # Only run against files matching this predicate (default: all files).
    applies_to: Callable[[SkillFile], bool] | None = None


def _any(_f: SkillFile) -> bool:
    return True


def _code_like(f: SkillFile) -> bool:
    return f.path.lower().endswith(
        (".py", ".js", ".ts", ".sh", ".bash", ".zsh", ".rb", ".pl", ".ps1")
    )


# ---------------------------------------------------------------------------
# Rule definitions
# ---------------------------------------------------------------------------

# NOTE: patterns are compiled case-insensitive + multiline unless noted.
def _rx(pat: str, flags: int = re.IGNORECASE) -> re.Pattern[str]:
    return re.compile(pat, flags)


RULES: list[Rule] = [
    # --- Remote code execution / piping to shell -------------------------
    Rule(
        "RCE001",
        "Pipe remote content directly to a shell interpreter",
        Severity.CRITICAL,
        _rx(r"(curl|wget|fetch)\b[^\n|]*\|\s*(sudo\s+)?(ba|z|)sh\b"),
        "Downloads a remote script and executes it immediately, a classic "
        "malware installation pattern.",
    ),
    Rule(
        "RCE002",
        "Pipe remote content to an interpreter (python/perl/ruby/node)",
        Severity.CRITICAL,
        _rx(r"(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(python3?|perl|ruby|node)\b"),
        "Fetches and executes remote code through a language interpreter.",
    ),
    Rule(
        "RCE003",
        "Dynamic execution of decoded/obfuscated content",
        Severity.CRITICAL,
        _rx(r"(eval|exec)\s*\(\s*(base64\.b64decode|bytes\.fromhex|codecs\.decode|atob)"),
        "Decodes an obfuscated blob and executes it at runtime.",
    ),
    Rule(
        "RCE004",
        "Shell eval of a variable or command substitution",
        Severity.HIGH,
        _rx(r"\beval\s+[\"']?\$"),
        "Uses shell `eval` on dynamic input, enabling arbitrary command injection.",
    ),
    # --- Destructive commands -------------------------------------------
    Rule(
        "DES001",
        "Recursive force delete of a broad path",
        Severity.CRITICAL,
        _rx(r"\brm\s+-[a-z]*r[a-z]*f[a-z]*\s+(/|~|\$HOME|\*|\.)(\s|$|/)"),
        "Recursively and forcefully deletes files from a root/home/wildcard path.",
    ),
    Rule(
        "DES002",
        "Disk overwrite via dd or mkfs",
        Severity.CRITICAL,
        _rx(r"\b(dd\s+if=|mkfs\.|>\s*/dev/sd[a-z])"),
        "Writes directly to block devices, which can destroy data.",
    ),
    Rule(
        "DES003",
        "Fork bomb",
        Severity.HIGH,
        _rx(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:"),
        "Classic shell fork bomb that exhausts system resources.",
    ),
    # --- Credential / secret access & exfiltration -----------------------
    Rule(
        "EXF001",
        "Access to SSH private keys",
        Severity.HIGH,
        _rx(r"~?/?\.ssh/(id_[a-z0-9]+|identity|.*_rsa)\b"),
        "Reads SSH private keys, commonly targeted for credential theft.",
    ),
    Rule(
        "EXF002",
        "Access to cloud credential files",
        Severity.HIGH,
        _rx(r"\.(aws/credentials|config/gcloud|azure)\b|\.kube/config"),
        "Reads cloud provider credentials.",
    ),
    Rule(
        "EXF003",
        "Reads environment for secrets/tokens/keys",
        Severity.MEDIUM,
        _rx(r"(os\.environ|process\.env|printenv|env\b)[^\n]{0,40}"
            r"(secret|token|api[_-]?key|password|passwd|credential)"),
        "Harvests secrets from environment variables.",
    ),
    Rule(
        "EXF004",
        "Reads dotenv / secret files",
        Severity.MEDIUM,
        _rx(r"(cat|read|open|less|more)\b[^\n]{0,60}(\.env\b|secrets?\.(json|ya?ml|txt))"),
        "Reads local secret/dotenv files.",
    ),
    Rule(
        "EXF005",
        "Exfiltrates data to a remote host via POST",
        Severity.HIGH,
        _rx(r"(curl|wget|http[sx]?|requests\.post|fetch)\b[^\n]{0,80}"
            r"(-d\b|--data|body=|json=)[^\n]{0,80}"
            r"(env|secret|token|key|password|\$\()"),
        "Sends local/secret data to an external endpoint.",
    ),
    Rule(
        "EXF006",
        "Hardcoded external IP address with network call",
        Severity.LOW,
        _rx(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        "Contains a raw IP address; verify it is not an exfiltration endpoint.",
    ),
    # --- Persistence -----------------------------------------------------
    Rule(
        "PER001",
        "Modifies shell startup files",
        Severity.HIGH,
        _rx(r">>?\s*~?/?\.(bashrc|zshrc|bash_profile|profile|zprofile)\b"),
        "Writes to shell startup files to gain persistence.",
    ),
    Rule(
        "PER002",
        "Installs a cron job or scheduled task",
        Severity.HIGH,
        _rx(r"\b(crontab\s+-|/etc/cron|launchctl\s+load|schtasks\s+/create)\b"),
        "Creates a scheduled task for persistence.",
    ),
    Rule(
        "PER003",
        "Writes to system launch/service directories",
        Severity.HIGH,
        _rx(r"/(Library/LaunchDaemons|Library/LaunchAgents|etc/systemd/system)/"),
        "Installs a background service/daemon.",
    ),
    # --- Obfuscation -----------------------------------------------------
    Rule(
        "OBF001",
        "Large base64 blob",
        Severity.MEDIUM,
        _rx(r"[A-Za-z0-9+/]{120,}={0,2}"),
        "Contains a long base64-encoded payload that may hide code or data.",
    ),
    Rule(
        "OBF002",
        "Long hex-encoded string",
        Severity.LOW,
        _rx(r"(0x)?[0-9a-fA-F]{80,}"),
        "Contains a long hex string that may hide an obfuscated payload.",
    ),
    Rule(
        "OBF003",
        "Base64 decode piped to shell",
        Severity.CRITICAL,
        _rx(r"base64\s+(-d|--decode)\b[^\n|]*\|\s*(ba|z|)sh\b"),
        "Decodes a base64 payload and pipes it straight to a shell.",
    ),
    # --- Prompt injection targeting the reading agent --------------------
    Rule(
        "INJ001",
        "Instruction to ignore/override prior instructions",
        Severity.HIGH,
        _rx(r"ignore\s+(all\s+)?(the\s+)?(previous|prior|above|preceding|earlier)\s+"
            r"(instructions?|rules?|prompts?|context)"),
        "Attempts to override the agent's existing instructions (prompt injection).",
    ),
    Rule(
        "INJ002",
        "Instruction to disregard safety/system rules",
        Severity.HIGH,
        _rx(r"(disregard|bypass|ignore|override)\b[^\n]{0,40}"
            r"(safety|guardrails?|system\s+prompt|policies|restrictions?)"),
        "Attempts to disable the agent's safety guardrails.",
    ),
    Rule(
        "INJ003",
        "Attempts to exfiltrate the system prompt",
        Severity.MEDIUM,
        _rx(r"(reveal|print|repeat|output|show|leak)\b[^\n]{0,30}"
            r"(system\s+prompt|your\s+instructions|initial\s+prompt)"),
        "Tries to make the agent leak its system prompt/instructions.",
    ),
    Rule(
        "INJ004",
        "Do-not-tell / stay-silent instruction",
        Severity.MEDIUM,
        _rx(r"(do\s*not|don'?t|never)\b[^\n]{0,30}"
            r"(tell|inform|notify|mention|alert|warn)\b[^\n]{0,20}(the\s+)?(user|human)"),
        "Instructs the agent to hide its actions from the user.",
    ),
    Rule(
        "INJ005",
        "Escalation / silent auto-approval instruction",
        Severity.MEDIUM,
        _rx(r"(auto[-\s]?approve|without\s+(asking|confirmation|permission)|"
            r"skip\s+(the\s+)?confirmation)"),
        "Tries to make the agent act without user confirmation.",
    ),
    # --- Network / reverse shells ----------------------------------------
    Rule(
        "NET001",
        "Reverse shell via netcat/bash",
        Severity.CRITICAL,
        _rx(r"(nc|ncat|netcat)\b[^\n]{0,40}(-e|/bin/(ba)?sh)|"
            r"/dev/tcp/\d|bash\s+-i\s+>&"),
        "Opens a reverse shell to a remote host.",
    ),
    Rule(
        "NET002",
        "Crypto miner reference",
        Severity.HIGH,
        _rx(r"\b(xmrig|minerd|stratum\+tcp|cryptonight|coinhive)\b"),
        "References cryptocurrency mining software.",
    ),
    # --- Privilege / permission changes ----------------------------------
    Rule(
        "PRV001",
        "chmod 777 / world-writable or setuid",
        Severity.MEDIUM,
        _rx(r"chmod\s+([0-7]?7{3}|[+]s|u\+s)\b"),
        "Sets overly-permissive or setuid permissions.",
    ),
    Rule(
        "PRV002",
        "Disables TLS/host verification",
        Severity.MEDIUM,
        _rx(r"(curl\s+[^\n]*(-k|--insecure)|verify\s*=\s*False|"
            r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*0|rejectUnauthorized\s*:\s*false)"),
        "Disables TLS certificate verification, enabling MITM.",
    ),
]


# ---------------------------------------------------------------------------
# Hidden-unicode heuristic (not a simple regex)
# ---------------------------------------------------------------------------

_HIDDEN_CATEGORIES = {"Cf"}  # format chars: zero-width space, joiners, bidi, etc.
_HIDDEN_ALLOWED = {"\ufeff"}  # BOM at start is common/benign; still low-signal


def _scan_hidden_unicode(sf: SkillFile) -> list[Finding]:
    findings: list[Finding] = []
    for lineno, line in enumerate(sf.content.splitlines(), start=1):
        hidden = [
            ch
            for ch in line
            if unicodedata.category(ch) in _HIDDEN_CATEGORIES and ch not in _HIDDEN_ALLOWED
        ]
        if hidden:
            names = ", ".join(sorted({unicodedata.name(c, f"U+{ord(c):04X}") for c in hidden}))
            findings.append(
                Finding(
                    rule_id="OBF004",
                    title="Hidden/zero-width unicode characters",
                    severity=Severity.HIGH,
                    detail=(
                        "Line contains invisible unicode control characters "
                        f"({names}) that may hide instructions from human review."
                    ),
                    source="static",
                    file=sf.path,
                    line=lineno,
                    excerpt=line.strip()[:120] or None,
                )
            )
    return findings


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def _line_of(content: str, index: int) -> int:
    return content.count("\n", 0, index) + 1


def run_rules(skill: SkillInput) -> list[Finding]:
    """Run all static rules over every file in the skill."""
    findings: list[Finding] = []
    for sf in skill.files:
        applicable = [
            r
            for r in RULES
            if (r.applies_to or _any)(sf)
        ]
        for rule in applicable:
            for m in rule.pattern.finditer(sf.content):
                excerpt = m.group(0)
                # Trim very long matches (e.g. base64 blobs) for readability.
                if len(excerpt) > 120:
                    excerpt = excerpt[:117] + "..."
                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        title=rule.title,
                        severity=rule.severity,
                        detail=rule.detail,
                        source="static",
                        file=sf.path,
                        line=_line_of(sf.content, m.start()),
                        excerpt=excerpt,
                    )
                )
        findings.extend(_scan_hidden_unicode(sf))
    return _dedupe(findings)


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """Collapse identical (rule, file, line) findings; cap noisy rules per file."""
    seen: set[tuple[str, str | None, int | None]] = set()
    per_rule_file: dict[tuple[str, str | None], int] = {}
    out: list[Finding] = []
    for f in findings:
        key = (f.rule_id, f.file, f.line)
        if key in seen:
            continue
        seen.add(key)
        cap_key = (f.rule_id, f.file)
        count = per_rule_file.get(cap_key, 0)
        if count >= 10:  # avoid flooding on repetitive matches (e.g. IPs)
            continue
        per_rule_file[cap_key] = count + 1
        out.append(f)
    return out
