"""Hybrid engine: combine static rules, capability gating, and optional LLM
judgment into a verdict.

Beyond finding-based scoring, the engine gates verdicts on **capability
composition**. The dangerous minority of skills are deliberately evasive
multi-stage chains whose individual steps look benign, so a clean rule sweep is
not sufficient evidence of safety. When a skill exhibits a dangerous capability
combination (e.g. network + credential access, or network + shell execution), it
cannot be returned as ``valid`` from a static-only pass: it is floored to
``suspicious`` with ``review_required=True``. That floor lifts only if the LLM
auditor actually ran, or a human explicitly signs off.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from . import loader
from .capabilities import present_keys, scan_capabilities
from .models import Finding, Report, Severity, SkillInput, Verdict
from .rules import run_rules

# Score thresholds mapping the aggregate risk score to a verdict.
SUSPICIOUS_THRESHOLD = 20
MALICIOUS_THRESHOLD = 55


@dataclass(frozen=True)
class CapabilityCombo:
    """A capability combination that warrants review before a 'valid' verdict."""

    rule_id: str
    caps: frozenset[str]
    severity: Severity
    title: str
    detail: str


# Ordered most-specific first. These encode the capability profiles that
# confirmed-malicious-skill research repeatedly flags as the real attack surface.
CAPABILITY_COMBOS: list[CapabilityCombo] = [
    CapabilityCombo(
        "CAP-CHAIN",
        frozenset({"network", "credentials", "shell"}),
        Severity.HIGH,
        "Full attack-chain capability profile",
        "Network access + credential/secret access + shell execution together are "
        "the canonical capability profile of confirmed-malicious skills. Even if "
        "each step looks benign in isolation, the combination is the attack "
        "surface. Requires LLM or human review before it can be trusted.",
    ),
    CapabilityCombo(
        "CAP-EXFIL",
        frozenset({"network", "credentials"}),
        Severity.MEDIUM,
        "Data-exfiltration capability surface",
        "The skill can both access credentials/secrets and make network calls — "
        "the classic data-exfiltration combination. Static rules cannot prove the "
        "two are unconnected, so this needs LLM or human review.",
    ),
    CapabilityCombo(
        "CAP-RCE",
        frozenset({"network", "shell"}),
        Severity.MEDIUM,
        "Remote-code-execution capability surface",
        "The skill can fetch remote content and execute shell commands. That is "
        "sufficient to stage and run remote code, so it needs LLM or human review.",
    ),
    CapabilityCombo(
        "CAP-RCE-DYN",
        frozenset({"network", "code_exec"}),
        Severity.MEDIUM,
        "Remote dynamic-execution capability surface",
        "The skill can fetch remote content and dynamically execute code "
        "(eval/exec/compile). Needs LLM or human review.",
    ),
]


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
    human_signoff:
        If ``True``, a human has reviewed the skill; this lifts the capability
        review gate (allowing a ``valid`` verdict despite a dangerous combo).
    """

    def __init__(
        self,
        *,
        use_llm: bool = True,
        model: str | None = None,
        api_key: str | None = None,
        human_signoff: bool = False,
    ) -> None:
        self.use_llm = use_llm
        self.model = model
        self.api_key = api_key
        self.human_signoff = human_signoff

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
    def _match_combos(cap_keys: set[str]) -> list[CapabilityCombo]:
        """Return the maximal dangerous combos present (subsets suppressed)."""
        matched = [c for c in CAPABILITY_COMBOS if c.caps <= cap_keys]
        maximal: list[CapabilityCombo] = []
        for c in matched:
            if not any(c is not o and c.caps < o.caps for o in matched):
                maximal.append(c)
        return maximal

    @staticmethod
    def _summarize(
        verdict: Verdict,
        findings: list[Finding],
        llm_used: bool,
        review_required: bool,
    ) -> str:
        n = len(findings)
        crit = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in findings if f.severity == Severity.HIGH)
        engine = "static + LLM" if llm_used else "static"
        if review_required:
            base = (
                f"{verdict.value.upper()} — verdict floored: a dangerous capability "
                f"combination requires LLM or human review before this skill can be "
                f"trusted ({engine} analysis only)."
            )
        elif verdict == Verdict.VALID and n == 0:
            return f"No security concerns detected ({engine} analysis). Skill looks valid."
        else:
            parts = [f"{verdict.value.upper()} — {n} finding(s) via {engine} analysis"]
            if crit:
                parts.append(f"{crit} critical")
            if high:
                parts.append(f"{high} high")
            base = ", ".join(parts) + "."
        return base

    # -- main entrypoint -------------------------------------------------
    def validate(self, skill: SkillInput) -> Report:
        findings = run_rules(skill)
        llm_used = False
        engine_name = "static"
        summary_override = ""

        # Capability composition analysis.
        caps = scan_capabilities(skill)
        cap_keys = present_keys(caps)
        cap_labels = [c.label for c in caps if c.present]
        combos = self._match_combos(cap_keys)
        for combo in combos:
            findings.append(
                Finding(
                    rule_id=combo.rule_id,
                    title=combo.title,
                    severity=combo.severity,
                    detail=combo.detail,
                    source="capability",
                )
            )

        if self.use_llm:
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

        # -- capability gate -------------------------------------------
        # A dangerous capability combination cannot yield a clean 'valid' from a
        # static-only pass. The gate lifts if the LLM actually ran or a human
        # signed off. It never downgrades a malicious verdict.
        review_required = False
        review_reasons: list[str] = []
        if combos and verdict != Verdict.MALICIOUS:
            cleared = llm_used or self.human_signoff
            review_reasons = [f"{c.title} ({', '.join(sorted(c.caps))})" for c in combos]
            if not cleared:
                review_required = True
                if verdict == Verdict.VALID:
                    verdict = Verdict.SUSPICIOUS

        summary = self._summarize(verdict, findings, llm_used, review_required)
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
            capabilities=cap_labels,
            review_required=review_required,
            review_reasons=review_reasons,
        )


# ---------------------------------------------------------------------------
# Convenience functions (public API)
# ---------------------------------------------------------------------------


def _engine(
    use_llm: bool | None,
    model: str | None,
    api_key: str | None,
    human_signoff: bool,
) -> Engine:
    if use_llm is None:
        # Auto: enable LLM only if plausibly configured.
        use_llm = bool(api_key or os.environ.get("CURSOR_API_KEY"))
    return Engine(
        use_llm=use_llm, model=model, api_key=api_key, human_signoff=human_signoff
    )


def validate_skill(
    skill: SkillInput,
    *,
    use_llm: bool | None = None,
    model: str | None = None,
    api_key: str | None = None,
    human_signoff: bool = False,
) -> Report:
    """Validate an already-loaded :class:`SkillInput`."""
    return _engine(use_llm, model, api_key, human_signoff).validate(skill)


def validate_path(
    path: str,
    *,
    use_llm: bool | None = None,
    model: str | None = None,
    api_key: str | None = None,
    human_signoff: bool = False,
) -> Report:
    """Load a skill directory or file from ``path`` and validate it."""
    return validate_skill(
        loader.load(path),
        use_llm=use_llm,
        model=model,
        api_key=api_key,
        human_signoff=human_signoff,
    )


def validate_text(
    content: str,
    *,
    name: str = "inline-skill",
    use_llm: bool | None = None,
    model: str | None = None,
    api_key: str | None = None,
    human_signoff: bool = False,
) -> Report:
    """Validate raw skill ``content`` supplied in memory."""
    return validate_skill(
        loader.load_text(content, name=name),
        use_llm=use_llm,
        model=model,
        api_key=api_key,
        human_signoff=human_signoff,
    )
