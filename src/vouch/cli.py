"""Command-line interface: ``vouch``.

Examples
--------
    vouch ./my-skill/                 # vet a skill directory
    vouch ./SKILL.md                  # vet a single file
    echo "..." | vouch -              # vet raw text from stdin
    vouch ./my-skill/ --cv            # render a Skill CV
    vouch ./my-agent/ --agent-cv      # render an Agent CV
    vouch ./my-skill/ --json          # machine-readable output
    vouch ./my-skill/ --no-llm        # static analysis only
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
    if report.capabilities:
        lines.append(f"Caps:    {', '.join(report.capabilities)}")
    lines.append(f"Summary: {report.summary}")
    if report.review_required:
        warn = "⚠ REVIEW REQUIRED (capability gate): run with --llm or --sign-off"
        lines.append(_c(warn, "\033[33m", color))
        for reason in report.review_reasons:
            lines.append(f"         - {reason}")
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
        prog="vouch",
        description="Vet an agent Skill (or agent) and vouch for it: "
        "classify as valid, suspicious, or malicious.",
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
        "--agent-cv",
        action="store_true",
        help="Treat the target as an agent (a tree of skills) and render an "
        "aggregate Agent CV.",
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
    p.add_argument(
        "--sign-off",
        action="store_true",
        help="Human sign-off: lift the capability review gate (allow a 'valid' "
        "verdict despite a dangerous capability combination).",
    )
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

    color = sys.stdout.isatty() and not args.no_color

    # Agent CV: aggregate every skill under the target directory.
    if args.agent_cv:
        from . import agent as agent_mod

        if args.target == "-":
            print("error: --agent-cv requires a directory, not stdin.", file=sys.stderr)
            return 3
        agent_cv = agent_mod.build_agent_cv(
            args.target,
            use_llm=use_llm,
            model=args.model,
            human_signoff=args.sign_off,
        )
        if args.json:
            import json as _json

            print(_json.dumps(agent_cv.to_dict(), indent=2))
        elif args.markdown:
            print(agent_mod.render_markdown(agent_cv))
        else:
            print(agent_mod.render_text(agent_cv, color=color))
        verdict = agent_cv.verdict
        if args.fail_on == "never":
            return 0
        if args.fail_on == "suspicious":
            return 0 if verdict == Verdict.VALID else _EXIT[verdict]
        return 2 if verdict == Verdict.MALICIOUS else 0

    if args.target == "-":
        skill = loader.load_text(sys.stdin.read(), name="stdin-skill")
    else:
        try:
            skill = loader.load(args.target)
        except FileNotFoundError as e:
            print(f"error: {e}", file=sys.stderr)
            return 3

    if args.cv:
        from . import cv as cv_mod

        skill_cv = cv_mod.build_cv(
            skill, use_llm=use_llm, model=args.model, human_signoff=args.sign_off
        )
        report = skill_cv.report
        if args.json:
            import json as _json

            print(_json.dumps(skill_cv.to_dict(), indent=2))
        elif args.markdown:
            print(cv_mod.render_markdown(skill_cv))
        else:
            print(cv_mod.render_text(skill_cv, color=color))
    else:
        report = validate_skill(
            skill, use_llm=use_llm, model=args.model, human_signoff=args.sign_off
        )
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
