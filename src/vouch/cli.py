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
import os
import sys

from . import __version__, loader
from .engine import validate_skill
from .models import Report, Severity, Verdict

# Env vars that indicate an LLM backend is configured (for the --audit hint).
# Ordered generic-OpenAI-compatible first, matching backend auto-detection.
_LLM_KEY_ENVS_HINT = (
    "OPENAI_API_KEY",
    "VOUCH_LLM_API_KEY",
    "CURSOR_API_KEY",
    "SEG_API_KEY",
    "SOVEREIGNEG_API_KEY",
)

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


def _exit_for(verdict: Verdict, fail_on: str | None) -> int:
    """Map a verdict to an exit code. ``None`` fail_on behaves like 'malicious'."""
    fo = fail_on or "malicious"
    if fo == "never":
        return 0
    if fo == "suspicious":
        return 0 if verdict == Verdict.VALID else _EXIT[verdict]
    return 2 if verdict == Verdict.MALICIOUS else 0


def _fail_on_notice(verdict: Verdict, review_required: bool, fail_on: str | None) -> None:
    """Tell the user when a review-worthy result silently passed CI by default.

    Only nudges when the user is on the default (didn't pass --fail-on), so it
    never nags someone who explicitly chose a policy.
    """
    if fail_on is not None:
        return
    if verdict == Verdict.SUSPICIOUS or review_required:
        print(
            "note: this result is SUSPICIOUS / flagged for review, but the run "
            "exited 0 because --fail-on defaults to 'malicious'. Pass "
            "--fail-on suspicious to block review items in CI.",
            file=sys.stderr,
        )


def _warn_llm(report: Report) -> None:
    """Print an honest stderr warning if a requested AI review didn't fully run."""
    if report.llm_status == "unavailable":
        print(
            "warning: --llm was requested but no AI backend ran (no API key or "
            "provider unreachable); showing static-only results. Set "
            "OPENAI_API_KEY (any OpenAI-compatible endpoint, incl. a local "
            "Ollama), CURSOR_API_KEY, or SEG_API_KEY to enable it.",
            file=sys.stderr,
        )
    elif report.llm_status == "failed":
        print(
            "warning: --llm was requested but the AI backend call failed; "
            "showing static-only results.",
            file=sys.stderr,
        )
    elif report.llm_status == "used" and report.llm_coverage:
        cov = report.llm_coverage
        if cov.get("truncated"):
            print(
                f"note: the AI reviewed only {cov.get('files_seen', 0)}/"
                f"{cov.get('files_total', 0)} file(s) — the skill exceeded the "
                "prompt budget, so its review is partial.",
                file=sys.stderr,
            )


def _render(report: Report, color: bool) -> str:
    lines: list[str] = []
    v = report.verdict
    lines.append(
        _c(f"Verdict: {v.value.upper()}", _COLOR[v], color)
        + f"  (risk score {report.risk_score}/100)"
    )
    lines.append(f"Skill:   {report.skill_name}")
    lines.append(f"Engine:  {report.engine} (llm_used={report.llm_used})")
    # Be honest about what the AI layer actually did.
    if report.llm_status == "unavailable":
        lines.append(_c(
            "⚠ AI review was requested but NO backend ran (no API key / provider "
            "unreachable) — results below are static-only.",
            "\033[33m", color,
        ))
    elif report.llm_status == "failed":
        lines.append(_c(
            "⚠ AI review was requested but the backend call FAILED — results below "
            "are static-only.",
            "\033[33m", color,
        ))
    elif report.llm_status == "used" and report.llm_coverage:
        cov = report.llm_coverage
        if cov.get("truncated"):
            seen, total = cov.get("files_seen", 0), cov.get("files_total", 0)
            lines.append(_c(
                f"⚠ AI saw only {seen}/{total} file(s) — the skill was too large to "
                "show in full, so the AI review is partial.",
                "\033[33m", color,
            ))
    if report.capabilities:
        lines.append(f"Caps:    {', '.join(report.capabilities)}")
    lines.append(f"Summary: {report.summary}")
    if report.review_required:
        warn = "⚠ REVIEW REQUIRED (capability gate): run with --llm or --sign-off"
        lines.append(_c(warn, "\033[33m", color))
        for reason in report.review_reasons:
            lines.append(f"         - {reason}")
    threats = report.threats
    if threats:
        lines.append("")
        lines.append(f"Threats ({len(threats)}):")
        for f in sorted(threats, key=lambda f: f.severity.weight, reverse=True):
            loc = ""
            if f.file:
                loc = f" [{f.file}" + (f":{f.line}" if f.line else "") + "]"
            tag = _c(f.severity.value.upper().ljust(8), _SEV_COLOR[f.severity], color)
            lines.append(f"  {tag} {f.rule_id}: {f.title}{loc}")
            lines.append(f"           {f.detail}")
            if f.excerpt:
                lines.append(f"           > {f.excerpt}")

    notices = report.notices
    if notices:
        lines.append("")
        heads_up = "Heads up — legitimate but worth knowing:"
        lines.append(_c(heads_up, "\033[36m", color))
        for f in sorted(notices, key=lambda f: f.severity.weight, reverse=True):
            loc = ""
            if f.file:
                loc = f" [{f.file}" + (f":{f.line}" if f.line else "") + "]"
            lines.append(f"  • {f.rule_id}: {f.title}{loc}")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vouch",
        description="Vet an agent Skill (or agent) and vouch for it: "
        "classify as valid, suspicious, or malicious.",
    )
    p.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    p.add_argument(
        "target",
        nargs="?",
        default=None,
        help="Path to a skill directory or file, or '-' to read raw text from stdin. "
        "Optional with --audit (defaults to all skill locations on this machine).",
    )
    p.add_argument(
        "--audit",
        action="store_true",
        help="Audit every skill installed on this machine (or under the given "
        "path/paths): classify what each one does and flag the risky ones.",
    )
    p.add_argument(
        "--baseline",
        default=None,
        metavar="PATH",
        help="With --audit: baseline file to compare against and update "
        "(default: ~/.vouch/audit-baseline.json). Enables 'what changed'.",
    )
    p.add_argument(
        "--no-baseline",
        action="store_true",
        help="With --audit: do a one-off scan without reading or writing a baseline.",
    )
    p.add_argument(
        "--reset-baseline",
        action="store_true",
        help="With --audit: forget any saved baseline and start fresh (greenfield) "
        "— this scan becomes the new baseline.",
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
    p.add_argument(
        "--llm",
        action="store_true",
        help="Force-enable the AI auditor. NOTE: this sends the skill's contents "
        "to the configured LLM provider. Static analysis stays fully local.",
    )
    p.add_argument(
        "--sign-off",
        action="store_true",
        help="Human sign-off: lift the capability review gate (allow a 'valid' "
        "verdict despite a dangerous capability combination).",
    )
    p.add_argument("--model", default=None, help="Override the LLM model id.")
    p.add_argument(
        "--provider",
        choices=["auto", "openai", "cursor", "seg"],
        default=None,
        help="LLM backend to use (default: auto-detect). 'openai' is the generic "
        "OpenAI-compatible client — set OPENAI_API_KEY and (optionally) "
        "OPENAI_BASE_URL to use OpenAI, OpenRouter, Groq, a local Ollama, etc. "
        "'seg' = SovereignEG (set SEG_API_KEY).",
    )
    p.add_argument(
        "--no-color", action="store_true", help="Disable ANSI colors in text output."
    )
    p.add_argument(
        "--fail-on",
        choices=["suspicious", "malicious", "never"],
        default=None,
        help="Verdict level that yields a non-zero exit code (default: malicious). "
        "NOTE: with the default, 'suspicious'/review findings (capability gate, "
        "prose exfil, LLM concerns) do NOT fail the build — use --fail-on "
        "suspicious to block those in CI.",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    use_llm: bool | None = None
    if args.no_llm:
        use_llm = False
    elif args.llm:
        use_llm = True

    # Provider selection is read from the environment by the LLM layer, so
    # setting it here applies uniformly across validate / CV / audit paths.
    if args.provider:
        os.environ["VOUCH_LLM_PROVIDER"] = args.provider

    color = sys.stdout.isatty() and not args.no_color

    # Machine audit: discover and classify every skill on this computer.
    if args.audit:
        from . import audit as audit_mod

        roots = None
        if args.target and args.target != "-":
            roots = [args.target]

        # A machine audit can span dozens of skills, so we do NOT auto-fire the
        # LLM just because a key is configured — that would silently make N slow
        # network calls. The LLM runs only when explicitly requested with --llm.
        audit_use_llm = bool(args.llm)

        # Fail loudly (not silently) if --llm was asked for but nothing can run it.
        if audit_use_llm:
            from . import llm as _llm

            if not _llm.is_available():
                print(
                    "warning: --llm was requested but no AI backend is configured "
                    "or reachable; auditing with static analysis only. Set "
                    "OPENAI_API_KEY (any OpenAI-compatible endpoint, incl. a "
                    "local Ollama), CURSOR_API_KEY, or SEG_API_KEY to enable it.",
                    file=sys.stderr,
                )
                audit_use_llm = False

        progress = None
        if audit_use_llm:
            def progress(i: int, total: int, name: str) -> None:
                print(
                    f"\r  auditing {i}/{total}: {name[:38]:38}",
                    end="", file=sys.stderr, flush=True,
                )
                if i == total:
                    print("\r" + " " * 60 + "\r", end="", file=sys.stderr, flush=True)

        machine = audit_mod.audit_machine(
            roots,
            use_llm=audit_use_llm,
            model=args.model,
            human_signoff=args.sign_off,
            progress=progress,
        )

        # Baseline diff: "what changed since last audit".
        diff = None
        first_run = False
        baseline_path = None
        if not args.no_baseline:
            from pathlib import Path as _Path

            baseline_path = (
                _Path(args.baseline) if args.baseline
                else audit_mod.default_baseline_path()
            )
            # Greenfield: forget the old baseline so this run starts clean and
            # becomes the new baseline.
            if args.reset_baseline and baseline_path.exists():
                baseline_path.unlink()
                print(
                    f"Reset: cleared baseline at {baseline_path}",
                    file=sys.stderr,
                )
            base = audit_mod.load_baseline(baseline_path)
            if base is None:
                first_run = True
            else:
                diff = audit_mod.diff_audit(machine, base)

        if args.json:
            import json as _json

            out = machine.to_dict()
            if diff is not None:
                out["diff"] = diff.to_dict()
            print(_json.dumps(out, indent=2))
        elif args.markdown:
            print(audit_mod.render_markdown(machine))
        else:
            print(audit_mod.render_text(machine, color=color))
            if not args.no_baseline:
                print()
                print(
                    audit_mod.render_diff_text(
                        diff or audit_mod.AuditDiff(), color=color, first_run=first_run
                    )
                )
            # Nudge toward the deeper (LLM) pass when it's available but unused.
            if not audit_use_llm and any(
                os.environ.get(k) for k in _LLM_KEY_ENVS_HINT
            ):
                print(
                    "\nTip: add --llm to also run the AI auditor "
                    "(clears false 'review' flags, catches evasive threats).",
                    file=sys.stderr,
                )

        # Update the baseline for next time.
        if not args.no_baseline and baseline_path is not None:
            audit_mod.save_baseline(machine, baseline_path)

        worst = audit_mod._worst(machine)
        worst_review = any(e.review_required for e in machine.flagged)
        _fail_on_notice(worst, worst_review, args.fail_on)
        return _exit_for(worst, args.fail_on)

    # Agent CV: aggregate every skill under the target directory.
    if args.agent_cv:
        from . import agent as agent_mod

        if args.target is None or args.target == "-":
            print("error: --agent-cv requires a directory path.", file=sys.stderr)
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
        _fail_on_notice(verdict, False, args.fail_on)
        return _exit_for(verdict, args.fail_on)

    if args.target is None:
        print(
            "error: a target is required (or use --audit to scan this machine).",
            file=sys.stderr,
        )
        return 3
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

    # Warn on stderr (so JSON/markdown/CV output stays clean) whenever the AI
    # layer was asked for but didn't fully do its job — never let the tool imply
    # "an AI reviewed this" when it didn't.
    _warn_llm(report)
    _fail_on_notice(report.verdict, report.review_required, args.fail_on)
    return _exit_for(report.verdict, args.fail_on)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
