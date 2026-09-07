"""Hybrid engine: combine static rules and optional LLM judgment into a verdict."""

from __future__ import annotations

import os

from . import loader
from .models import Finding, Report, Severity, SkillInput, Verdict
from .rules import run_rules

# Score thresholds mapping the aggregate risk score to a verdict.
SUSPICIOUS_THRESHOLD = 20
MALICIOUS_THRESHOLD = 55


class Engine:
    """Configurable validator.

    Parameters
    ----------
    use_llm:
        If ``True`` (default) and the Cursor SDK + ``CURSOR_API_KEY`` are
        available, an LLM audit is layered on top of static analysis. If the
        LLM is unavailable this silently degrades to static-only.
    model:
        Optional model id override for the LLM auditor.
    api_key:
        Optional API key override (otherwise ``CURSOR_API_KEY`` is used).
    """

    def __init__(
        self,
        *,
        use_llm: bool = True,
        model: str | None = None,
        api_key: str | None = None,
    ) -> None:
        self.use_llm = use_llm
        self.model = model
        self.api_key = api_key

    # -- scoring ---------------------------------------------------------
    @staticmethod
    def _score(findings: list[Finding]) -> int:
        """Aggregate findings into a 0-100 risk score.

        A single CRITICAL finding is enough to reach the malicious band; lower
        severities accumulate with diminishing returns to avoid death-by-a-
        thousand-lints on large but benign skills.
        """
        if not findings:
            return 0
        total = 0.0
        # Sort so the highest-severity findings get full weight; extras decay.
        ordered = sorted(findings, key=lambda f: f.severity.weight, reverse=True)
        for i, f in enumerate(ordered):
            decay = 1.0 if i < 3 else 0.5 if i < 8 else 0.25
            total += f.severity.weight * decay
        return int(min(100, round(total)))

    @staticmethod
    def _verdict(score: int, findings: list[Finding]) -> Verdict:
        has_critical = any(f.severity == Severity.CRITICAL for f in findings)
        if has_critical or score >= MALICIOUS_THRESHOLD:
            return Verdict.MALICIOUS
        if score >= SUSPICIOUS_THRESHOLD:
            return Verdict.SUSPICIOUS
        return Verdict.VALID

    @staticmethod
    def _summarize(verdict: Verdict, findings: list[Finding], llm_used: bool) -> str:
        n = len(findings)
        crit = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in findings if f.severity == Severity.HIGH)
        engine = "static + LLM" if llm_used else "static"
        if verdict == Verdict.VALID and n == 0:
            return f"No security concerns detected ({engine} analysis). Skill looks valid."
        parts = [
            f"{verdict.value.upper()} — {n} finding(s) via {engine} analysis"
        ]
        if crit:
            parts.append(f"{crit} critical")
        if high:
            parts.append(f"{high} high")
        return ", ".join(parts) + "."

    # -- main entrypoint -------------------------------------------------
    def validate(self, skill: SkillInput) -> Report:
        findings = run_rules(skill)
        llm_used = False
        engine_name = "static"
        summary_override = ""

        want_llm = self.use_llm
        if want_llm:
            from . import llm  # imported lazily to keep base install light

            llm_result = llm.analyze_with_llm(
                skill, model=self.model, api_key=self.api_key
            )
            if llm_result is not None:
                llm_used = True
                engine_name = "hybrid"
                findings = findings + llm_result.findings
                summary_override = llm_result.summary

        score = self._score(findings)
        verdict = self._verdict(score, findings)

        # If the LLM strongly asserts malicious, respect it even if static missed.
        if llm_used:
            verdict = self._reconcile_with_llm(verdict, score, skill)

        summary = self._summarize(verdict, findings, llm_used)
        if summary_override:
            summary = f"{summary} LLM: {summary_override}"

        return Report(
            skill_name=skill.name,
            verdict=verdict,
            risk_score=score,
            findings=findings,
            summary=summary,
            engine=engine_name,
            llm_used=llm_used,
        )

    def _reconcile_with_llm(
        self, verdict: Verdict, score: int, skill: SkillInput
    ) -> Verdict:
        # Placeholder hook: currently the LLM findings already feed scoring.
        # Kept separate so callers can tune escalation policy later.
        return verdict


# ---------------------------------------------------------------------------
# Convenience functions (public API)
# ---------------------------------------------------------------------------


def _engine(use_llm: bool | None, model: str | None, api_key: str | None) -> Engine:
    if use_llm is None:
        # Auto: enable LLM only if plausibly configured.
        use_llm = bool(api_key or os.environ.get("CURSOR_API_KEY"))
    return Engine(use_llm=use_llm, model=model, api_key=api_key)


def validate_skill(
    skill: SkillInput,
    *,
    use_llm: bool | None = None,
    model: str | None = None,
    api_key: str | None = None,
) -> Report:
    """Validate an already-loaded :class:`SkillInput`."""
    return _engine(use_llm, model, api_key).validate(skill)


def validate_path(
    path: str,
    *,
    use_llm: bool | None = None,
    model: str | None = None,
    api_key: str | None = None,
) -> Report:
    """Load a skill directory or file from ``path`` and validate it."""
    return validate_skill(
        loader.load(path), use_llm=use_llm, model=model, api_key=api_key
    )


def validate_text(
    content: str,
    *,
    name: str = "inline-skill",
    use_llm: bool | None = None,
    model: str | None = None,
    api_key: str | None = None,
) -> Report:
    """Validate raw skill ``content`` supplied in memory."""
    return validate_skill(
        loader.load_text(content, name=name),
        use_llm=use_llm,
        model=model,
        api_key=api_key,
    )
