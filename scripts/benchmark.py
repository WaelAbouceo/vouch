#!/usr/bin/env python3
"""Measure Vouch's detection quality on a labeled benchmark.

We can't claim "accurate" without a number. This runs Vouch over a labeled set
of skills (``bench/benign/*`` and ``bench/malicious/*``) and reports precision
and recall under two definitions of a positive:

  A. "flagged for review" — verdict != valid (the triage question a user asks).
  B. "classified malicious" — verdict == malicious (the strong claim).

It prints the confusion matrix for each, and — most importantly — lists the
false negatives (missed malicious skills) and false positives (benign skills
flagged), because those are what actually matter.

Usage:
  python scripts/benchmark.py                 # static engine only
  python scripts/benchmark.py --llm           # hybrid (needs CURSOR_API_KEY)
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path

from vouch import loader
from vouch.engine import validate_skill

ROOT = Path(__file__).resolve().parent.parent
BENCH = ROOT / "bench"


@dataclass
class Result:
    name: str
    label: str  # "benign" | "malicious"
    verdict: str
    risk: int
    rules: list[str]


def _load_labeled() -> list[tuple[str, Path]]:
    items: list[tuple[str, Path]] = []
    for label in ("benign", "malicious"):
        base = BENCH / label
        if not base.is_dir():
            continue
        for d in sorted(base.iterdir()):
            if d.is_dir() and (d / "SKILL.md").exists():
                items.append((label, d))
    return items


def _confusion(results: list[Result], is_positive) -> tuple[int, int, int, int]:
    tp = fp = fn = tn = 0
    for r in results:
        pred = is_positive(r)
        actual = r.label == "malicious"
        if pred and actual:
            tp += 1
        elif pred and not actual:
            fp += 1
        elif not pred and actual:
            fn += 1
        else:
            tn += 1
    return tp, fp, fn, tn


def _metrics(tp: int, fp: int, fn: int, tn: int) -> tuple[float, float, float, float]:
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if (precision + recall)
        else 0.0
    )
    accuracy = (tp + tn) / (tp + fp + fn + tn) if results_total(tp, fp, fn, tn) else 0.0
    return precision, recall, f1, accuracy


def results_total(*xs: int) -> int:
    return sum(xs)


def _report_mode(title: str, results: list[Result], is_positive) -> None:
    tp, fp, fn, tn = _confusion(results, is_positive)
    p, r, f1, acc = _metrics(tp, fp, fn, tn)
    print(f"\n{title}")
    print(f"  precision {p:.0%}   recall {r:.0%}   F1 {f1:.2f}   accuracy {acc:.0%}")
    print(f"  confusion: TP={tp}  FP={fp}  FN={fn}  TN={tn}")


def main() -> int:
    ap = argparse.ArgumentParser(description="Benchmark Vouch detection quality.")
    ap.add_argument("--llm", action="store_true", help="Enable the LLM auditor (hybrid).")
    ap.add_argument("--model", default=None)
    ap.add_argument(
        "--provider",
        choices=["auto", "seg", "cursor", "openai"],
        default=None,
        help="LLM backend (default: auto-detect). 'seg' = SovereignEG.",
    )
    args = ap.parse_args()

    labeled = _load_labeled()
    if not labeled:
        print("No fixtures found under bench/.", file=sys.stderr)
        return 1

    engine = "hybrid (static + LLM)" if args.llm else "static only"
    results: list[Result] = []
    for label, d in labeled:
        skill = loader.load(str(d))
        rep = validate_skill(
            skill, use_llm=args.llm, model=args.model, provider=args.provider
        )
        results.append(
            Result(
                name=d.name,
                label=label,
                verdict=rep.verdict.value,
                risk=rep.risk_score,
                rules=sorted({f.rule_id for f in rep.findings if f.category != "notice"}),
            )
        )

    n_ben = sum(1 for r in results if r.label == "benign")
    n_mal = sum(1 for r in results if r.label == "malicious")
    print("=" * 64)
    print(f"VOUCH BENCHMARK — {len(results)} skills "
          f"({n_ben} benign, {n_mal} malicious) — engine: {engine}")

    _report_mode(
        'Mode A — "flagged for review" (positive = verdict != valid)',
        results,
        lambda r: r.verdict != "valid",
    )
    _report_mode(
        'Mode B — "classified malicious" (positive = verdict == malicious)',
        results,
        lambda r: r.verdict == "malicious",
    )

    # The lists that actually matter.
    missed = [r for r in results if r.label == "malicious" and r.verdict == "valid"]
    print(f"\nMISSED malicious — returned VALID ({len(missed)}):")
    for r in missed or []:
        print(f"  ✗ {r.name}")
    if not missed:
        print("  (none)")

    false_alarms = [r for r in results if r.label == "benign" and r.verdict == "malicious"]
    print(f"\nFALSE 'malicious' on benign ({len(false_alarms)}):")
    for r in false_alarms or []:
        print(f"  ! {r.name}  (rules: {', '.join(r.rules) or '—'})")
    if not false_alarms:
        print("  (none)")

    # Full table.
    print("\nPer-skill:")
    for r in sorted(results, key=lambda r: (r.label, r.name)):
        flag = "" if (
            (r.label == "malicious" and r.verdict != "valid")
            or (r.label == "benign" and r.verdict == "valid")
        ) else "  <-- check"
        print(f"  [{r.label:9}] {r.verdict:10} risk {r.risk:>3}  {r.name}{flag}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
