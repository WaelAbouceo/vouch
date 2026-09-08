"""Static analysis rules for detecting malicious or unsafe skills.

Each rule is a regex (or callable) paired with a severity and human-readable
explanation. Rules are grouped by threat category. The engine runs every rule
against every file and aggregates the resulting :class:`Finding` objects.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass

from .capabilities import _executable_lines, _is_comment_line
from .models import Finding, Severity, SkillFile, SkillInput

# Command/execution-style threat rules mean "this code *runs* something
# dangerous". They are only genuine threats in executable context (a fenced code
# block or a script file). When the same string appears in prose — e.g. a
# security tool quoting an attack as a detection pattern, or documentation
# showing what NOT to do — it is downgraded to an awareness notice rather than
# forcing a "malicious" verdict. Prompt-injection rules (INJ*) are deliberately
# excluded: they are attacks addressed to the reading agent and are malicious
# precisely as prose, so they always count regardless of context.
_EXEC_CONTEXT_RULES = frozenset({
    "RCE003", "RCE004", "RCE005",
    "DES001", "DES002", "DES003",
    "EXF001", "EXF005", "EXF007",
    "OBF003", "OBF005",
    "NET001",
})


@dataclass(frozen=True)
class Rule:
    rule_id: str
    title: str
    severity: Severity
    pattern: re.Pattern[str]
    detail: str
    # Only run against files matching this predicate (default: all files).
    applies_to: Callable[[SkillFile], bool] | None = None
    # "threat" counts toward the verdict; "notice" is surfaced for awareness
    # only (legitimate-but-notable behavior) and never escalates a verdict.
    category: str = "threat"


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
        "Runs a remote script fetched over the network (curl | sh)",
        Severity.MEDIUM,
        _rx(r"(curl|wget|fetch)\b[^\n|]*\|\s*(sudo\s+)?(ba|z|)sh\b"),
        "Fetches remote content and pipes it straight into a shell. This is the "
        "standard install-script pattern (e.g. rustup, Bun) and is often "
        "legitimate — but it executes code you have not seen. Verify the URL and "
        "the publisher you are trusting before letting an agent run it.",
        category="notice",
    ),
    Rule(
        "RCE002",
        "Runs remote content through an interpreter (python/perl/ruby/node)",
        Severity.MEDIUM,
        _rx(r"(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(python3?|perl|ruby|node)\b"),
        "Fetches remote content and pipes it into a language interpreter. Common "
        "for installers, but it runs unseen code — verify the source.",
        category="notice",
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
    Rule(
        "RCE005",
        "Makes a downloaded/temp file executable or runs one",
        Severity.HIGH,
        _rx(r"(chmod\s+[+0-7]*x[^\n]*\s+[^\n]*(/tmp/|/var/tmp/|/dev/shm/)|"
            r"^\s*(sudo\s+)?(\./)?(/tmp/|/var/tmp/|/dev/shm/)\S+\s*$)"),
        "Marks a file in a temp directory as executable or runs one directly. "
        "Combined with a download this is the classic 'dropper' pattern: fetch an "
        "untrusted binary to /tmp and execute it.",
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
        "Accesses cloud / cluster credential files",
        Severity.MEDIUM,
        _rx(r"\.(aws/credentials|config/gcloud|azure)\b|\.kube/config"),
        "References cloud/cluster credential files. Legitimate for deployment and "
        "infra skills, but confirm the credentials are only used locally and not "
        "sent anywhere.",
        category="notice",
    ),
    Rule(
        "EXF003",
        "Uses secret / token environment variables",
        Severity.LOW,
        _rx(r"(os\.environ|process\.env|printenv|env\b)[^\n]{0,40}"
            r"(secret|token|api[_-]?key|password|passwd|credential)"),
        "Reads secrets from environment variables. This is normal for any skill "
        "that calls an authenticated API — surfaced so you know which secrets it "
        "touches. Actual exfiltration (secret + outbound send) is flagged "
        "separately as EXF005 / the capability gate.",
        category="notice",
    ),
    Rule(
        "EXF004",
        "Reads dotenv / secret files",
        Severity.LOW,
        _rx(r"(cat|read|open|less|more)\b[^\n]{0,60}(\.env\b|secrets?\.(json|ya?ml|txt))"),
        "Reads local secret/dotenv files. Common for configuration; confirm the "
        "contents are not forwarded externally.",
        category="notice",
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
        "EXF007",
        "Pipes environment/secrets into a network sender",
        Severity.CRITICAL,
        _rx(r"\b(env|printenv|cat\s+[^\n|]*(\.ssh|\.env|id_[a-z0-9]+|secret|token|"
            r"credential)[^\n|]*)\b[^\n]*\|\s*[^\n]*\b(curl|wget|nc|ncat|netcat)\b"),
        "Reads environment variables or secret files and pipes them straight into "
        "a network tool — a direct, unambiguous data-exfiltration pattern.",
    ),
    Rule(
        "EXF006",
        "Hardcoded public IP address",
        Severity.LOW,
        _rx(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        "Contains a raw public IP address; verify it is not an exfiltration "
        "endpoint. (Private/loopback ranges are ignored.)",
        category="notice",
    ),
    # --- Persistence -----------------------------------------------------
    Rule(
        "PER001",
        "Modifies shell startup files",
        Severity.MEDIUM,
        _rx(r">>?\s*~?/?\.(bashrc|zshrc|bash_profile|profile|zprofile)\b"),
        "Writes to shell startup files. Often used by installers to add a tool to "
        "PATH, but it also persists across sessions — confirm what is written.",
        category="notice",
    ),
    Rule(
        "PER002",
        "Installs a cron job or scheduled task",
        Severity.MEDIUM,
        _rx(r"\b(crontab\s+-|/etc/cron|launchctl\s+load|schtasks\s+/create)\b"),
        "Creates a scheduled task. Legitimate for pollers/schedulers, but it lets "
        "the skill run again later without you — confirm what it schedules.",
        category="notice",
    ),
    Rule(
        "PER003",
        "Writes to system launch/service directories",
        Severity.MEDIUM,
        _rx(r"/(Library/LaunchDaemons|Library/LaunchAgents|etc/systemd/system)/"),
        "Installs a background service/daemon that runs persistently — confirm "
        "this is expected.",
        category="notice",
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
    Rule(
        "OBF005",
        "Command assembled from variable fragments",
        Severity.HIGH,
        # Two or more shell variable expansions concatenated with no separator
        # ($A$B, ${A}${B}) at a *command position* (line start, or after ; & |
        # ` or $( ). This is the classic trick for hiding a command such as
        # `rm -rf` from a scanner by splitting it across variables. Requiring a
        # command-position prefix avoids matching ordinary string concatenation
        # like path="$dir$file" or echo "$a$b".
        _rx(r"(?:^|[\n;&|`]|\$\()[ \t]*(?:\$\{?\w+\}?){2,}"),
        "Builds a command by gluing shell variables together (e.g. $A$B) — a "
        "well-known way to hide a dangerous command like `rm -rf` from scanners.",
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
        # The negation must attach directly to the tell-verb (no clause break like
        # a dash/comma/period in between), otherwise benign guidance such as
        # "do not produce a canvas — tell the user what's missing" trips it.
        _rx(r"\b(do\s*not|don'?t|never|avoid)\b[^\n\-—.,;:]{0,15}"
            r"(tell|inform|notify|mention|alert|warn|reveal|disclose)\b"
            r"[^\n\-—.,;:]{0,15}(the\s+)?(user|human|owner)"),
        "Instructs the agent to hide its actions from the user.",
    ),
    Rule(
        "INJ005",
        "Escalation / silent auto-approval instruction",
        Severity.MEDIUM,
        # Note: bare "without permission"/"without asking" were removed — they
        # fired on benign guidance ("without asking the user to spell the name").
        # The negation must attach to a confirmation/approval object.
        _rx(r"(auto[-\s]?approve|"
            r"without\s+(confirmation|consent|approval)|"
            r"without\s+asking\s+(for\s+)?(permission|confirmation|approval|"
            r"consent|first)|"
            r"skip\s+(the\s+)?confirmation|bypass\s+confirmation)"),
        "Tries to make the agent act without user confirmation.",
    ),
    # --- Network / reverse shells ----------------------------------------
    Rule(
        "NET001",
        "Reverse shell via netcat/bash",
        Severity.CRITICAL,
        _rx(r"\b(nc|ncat|netcat)\s+[^\n]{0,40}(-e\b|/bin/(ba)?sh)|"
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
        Severity.LOW,
        _rx(r"chmod\s+([0-7]?7{3}|[+]s|u\+s)\b"),
        "Sets overly-permissive or setuid permissions — often sloppy rather than "
        "malicious, but worth tightening.",
        category="notice",
    ),
    Rule(
        "PRV002",
        "Disables TLS/host verification",
        Severity.LOW,
        _rx(r"(curl\s+[^\n]*(-k|--insecure)|verify\s*=\s*False|"
            r"NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*0|rejectUnauthorized\s*:\s*false)"),
        "Disables TLS certificate verification, which enables MITM. Common in "
        "dev/test snippets but risky if shipped — verify it is intentional.",
        category="notice",
    ),
]


# ---------------------------------------------------------------------------
# Hidden-unicode heuristic (not a simple regex)
# ---------------------------------------------------------------------------

_HIDDEN_CATEGORIES = {"Cf"}  # format chars: zero-width space, joiners, bidi, etc.
_HIDDEN_ALLOWED = {"\ufeff"}  # BOM at start is common/benign; still low-signal


def _is_emoji_char(ch: str | None) -> bool:
    """True if ``ch`` is an emoji / pictographic that legitimately uses ZWJ."""
    if not ch:
        return False
    o = ord(ch)
    return (
        0x1F000 <= o <= 0x1FAFF  # pictographs, emoji, symbols
        or 0x2600 <= o <= 0x27BF  # misc symbols + dingbats
        or o in (0xFE0F, 0x2764)  # variation selector-16, heart
        or 0x1F1E6 <= o <= 0x1F1FF  # regional indicators (flags)
    )


def _scan_hidden_unicode(sf: SkillFile) -> list[Finding]:
    findings: list[Finding] = []
    for lineno, line in enumerate(sf.content.splitlines(), start=1):
        hidden = []
        for i, ch in enumerate(line):
            if unicodedata.category(ch) not in _HIDDEN_CATEGORIES:
                continue
            if ch in _HIDDEN_ALLOWED:
                continue
            # A zero-width joiner between two emoji is a normal emoji sequence
            # (e.g. 👩‍💻), not a hidden-text attack — skip it.
            if ch == "\u200d":
                prev = line[i - 1] if i > 0 else None
                nxt = line[i + 1] if i + 1 < len(line) else None
                if _is_emoji_char(prev) or _is_emoji_char(nxt):
                    continue
            hidden.append(ch)
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


def _is_private_ip(text: str) -> bool:
    """True for private / loopback / link-local / reserved IPv4 addresses."""
    import ipaddress
    import re as _re

    m = _re.search(r"(?:\d{1,3}\.){3}\d{1,3}", text)
    if not m:
        return False
    try:
        ip = ipaddress.ip_address(m.group(0))
    except ValueError:
        return True  # not a valid IP → not a real endpoint
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_unspecified
        or ip.is_multicast
    )


def run_rules(skill: SkillInput) -> list[Finding]:
    """Run all static rules over every file in the skill."""
    findings: list[Finding] = []
    # Raw text handed in directly (stdin / validate_text) is a direct check of
    # content, so every line counts as executable. Files/dirs loaded from disk
    # use fenced-code detection so prose mentions of a command are not treated as
    # the command actually running (see ``_EXEC_CONTEXT_RULES``).
    force_strong = skill.source == "text"
    for sf in skill.files:
        content_lines = sf.content.splitlines()
        exec_lines = None if force_strong else _executable_lines(sf.content, sf.path)
        applicable = [
            r
            for r in RULES
            if (r.applies_to or _any)(sf)
        ]
        for rule in applicable:
            for m in rule.pattern.finditer(sf.content):
                excerpt = m.group(0)
                # EXF006: ignore private / loopback / reserved IPs — they are not
                # exfiltration endpoints and produce heavy false positives.
                if rule.rule_id == "EXF006" and _is_private_ip(excerpt):
                    continue
                line = _line_of(sf.content, m.start())
                category = rule.category
                # Context grading: an execution-style rule that matches only in
                # prose/comment (not a fenced block or script) is downgraded to a
                # notice so quoted/documented commands don't force "malicious".
                if category == "threat" and rule.rule_id in _EXEC_CONTEXT_RULES:
                    line_text = content_lines[line - 1] if line <= len(content_lines) else ""
                    in_exec = exec_lines is None or line in exec_lines
                    if not in_exec or _is_comment_line(line_text):
                        category = "notice"
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
                        category=category,
                        file=sf.path,
                        line=line,
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
