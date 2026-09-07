"""Command-line interface: ``validate-skill``.

Examples
--------
    validate-skill ./my-skill/                 # validate a skill directory
    validate-skill ./SKILL.md                  # validate a single file
    echo "..." | validate-skill -              # validate raw text from stdin
    validate-skill ./my-skill/ --json          # machine-readable output
    validate-skill ./my-skill/ --no-llm        # static analysis only
"""

from __future__ import annotations

import argparse
import sys

from . import loader
from .engine import validate_skill
from .models import Report, Severity, Verdict

_EXIT = {Verdict.VALID: 0, Verdict.SUSPICIOUS: 1, Verdict.MALICIOUS: 2}

_COLOR = {
    Verdict.VALID: "\033[32m",       # green
    Verdict.SUSPICIOUS: "\033[33m",  # yellow
    Verdict.MALICIOUS: "\033[31m",   # red
}
_SEV_COLOR = {
    Severity.INFO: "\033[90m",
    Severity.LOW: "\033[36m",
    Severity.MEDIUM: "\033[33m",
    Severity.HIGH: "\033[35m",
    Severity.CRITICAL: "\033[31m",
}
_RESET = "\033[0m"


def _c(text: str, color: str, enabled: bool) -> str:
    return f"{color}{text}{_RESET}" if enabled else text


def _render(report: Report, color: bool) -> str:
    lines: list[str] = []
    v = report.verdict
    lines.append(
        _c(f"Verdict: {v.value.upper()}", _COLOR[v], color)
        + f"  (risk score {report.risk_score}/100)"
    )
    lines.append(f"Skill:   {report.skill_name}")
    lines.append(f"Engine:  {report.engine} (llm_used={report.llm_used})")
    lines.append(f"Summary: {report.summary}")
    if report.findings:
        lines.append("")
        lines.append(f"Findings ({len(report.findings)}):")
        ordered = sorted(
            report.findings, key=lambda f: f.severity.weight, reverse=True
        )
        for f in ordered:
            loc = ""
            if f.file:
                loc = f" [{f.file}" + (f":{f.line}" if f.line else "") + "]"
            tag = _c(f.severity.value.upper().ljust(8), _SEV_COLOR[f.severity], color)
            lines.append(f"  {tag} {f.rule_id}: {f.title}{loc}")
            lines.append(f"           {f.detail}")
            if f.excerpt:
                lines.append(f"           > {f.excerpt}")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="validate-skill",
        description="Classify an agent Skill as valid, suspicious, or malicious.",
    )
    p.add_argument(
        "target",
        help="Path to a skill directory or file, or '-' to read raw text from stdin.",
    )
    p.add_argument("--json", action="store_true", help="Emit JSON instead of text.")
    p.add_argument(
        "--cv",
        action="store_true",
        help="Render a Skill CV (profile card) instead of the plain report.",
    )
    p.add_argument(
        "--markdown",
        action="store_true",
        help="With --cv, render the CV as Markdown instead of a terminal card.",
    )
    p.add_argument(
        "--no-llm",
        action="store_true",
        help="Disable the LLM auditor (static analysis only).",
    )
    p.add_argument("--llm", action="store_true", help="Force-enable the LLM auditor.")
    p.add_argument("--model", default=None, help="Override the LLM model id.")
    p.add_argument(
        "--no-color", action="store_true", help="Disable ANSI colors in text output."
    )
    p.add_argument(
        "--fail-on",
        choices=["suspicious", "malicious", "never"],
        default="malicious",
        help="Verdict level that yields a non-zero exit code (default: malicious).",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    use_llm: bool | None = None
    if args.no_llm:
        use_llm = False
    elif args.llm:
        use_llm = True

    if args.target == "-":
        skill = loader.load_text(sys.stdin.read(), name="stdin-skill")
    else:
        try:
            skill = loader.load(args.target)
        except FileNotFoundError as e:
            print(f"error: {e}", file=sys.stderr)
            return 3

    color = sys.stdout.isatty() and not args.no_color

    if args.cv:
        from . import cv as cv_mod

        skill_cv = cv_mod.build_cv(skill, use_llm=use_llm, model=args.model)
        report = skill_cv.report
        if args.json:
            import json as _json

            print(_json.dumps(skill_cv.to_dict(), indent=2))
        elif args.markdown:
            print(cv_mod.render_markdown(skill_cv))
        else:
            print(cv_mod.render_text(skill_cv, color=color))
    else:
        report = validate_skill(skill, use_llm=use_llm, model=args.model)
        if args.json:
            print(report.to_json())
        else:
            print(_render(report, color))

    if args.fail_on == "never":
        return 0
    if args.fail_on == "suspicious":
        return 0 if report.verdict == Verdict.VALID else _EXIT[report.verdict]
    # fail-on malicious
    return 2 if report.verdict == Verdict.MALICIOUS else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
