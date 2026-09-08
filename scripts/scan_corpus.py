#!/usr/bin/env python3
"""Scan public agent Skills at scale and aggregate the results.

This is the harness behind Vouch's "we scanned N public agent Skills" data.
It is deliberately *read-only*: it fetches `SKILL.md` text via the GitHub API
and runs Vouch's **static** analysis on it. It never clones, builds, or
executes anything.

Pipeline:
  1. discover — GitHub code search for `SKILL.md` files (several keyword
     queries, deduped by repo+path). Respects the code-search rate limit.
  2. fetch    — download each file's text via `gh api ... /contents/...`
     (cached on disk so re-runs are cheap).
  3. scan     — run `vouch.validate_text` (static only) on each file.
  4. aggregate— verdict distribution, capability-gate rate, top capabilities,
     top rules, and the list of flagged skills.

Usage:
  python scripts/scan_corpus.py --limit-per-query 60 --max 400
  python scripts/scan_corpus.py --report-only        # re-aggregate cache

Outputs:
  data/corpus_results.json   full machine-readable results
  data/corpus_summary.md     human-readable summary with the headline stat

Requires: an authenticated `gh` CLI (`gh auth status`).
"""

from __future__ import annotations

import argparse
import base64
import json
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

from vouch import validate_skill
from vouch.models import SkillFile, SkillInput

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
CACHE = DATA / "corpus_cache"

# Keyword queries paired with the SKILL.md filename qualifier. GitHub code
# search requires a term alongside the qualifier, and each query returns at most
# ~1000 results, so varying the term is how we get past that cap and dedup a
# broad, less-biased corpus.
QUERIES = [
    # frontmatter / structure terms
    "description", "name", "usage", "instructions", "tools", "examples",
    "workflow", "steps", "when to use", "overview", "prerequisites", "output",
    "input", "notes", "configuration", "arguments", "parameters", "context",
    # domain / behavior terms
    "agent", "claude", "mcp", "api", "python", "typescript", "bash", "install",
    "git", "database", "file", "search", "image", "test", "deploy", "browser",
    "http", "json", "markdown", "prompt", "review", "code", "data", "server",
    # capability-ish terms (surface higher-signal skills too)
    "curl", "token", "secret", "env", "shell", "network", "credentials",
]


def headline_finding(rep) -> str:
    """The finding that best explains the verdict: the most severe *threat*
    (what actually drove suspicious/malicious), not merely the first finding —
    which is often a low-priority awareness notice like a curl|sh install line.
    Falls back to the top notice only when there are no threats."""
    pool = rep.threats or rep.findings
    if not pool:
        return ""
    top = max(pool, key=lambda f: f.severity.weight)
    return f"{top.rule_id}: {top.title}"


def scan_md(text: str, name: str):
    """Validate SKILL.md text as a *markdown file* (source='file'), so the
    prose-vs-code evidence grading applies — matching how the tool treats a real
    skill on disk. Using validate_text() here would force every capability to
    'strong' and inflate the capability-gate rate."""
    skill = SkillInput(
        name=name,
        files=[SkillFile(path="SKILL.md", content=text)],
        source="file",
    )
    return validate_skill(skill, use_llm=False)


def sh(args: list[str]) -> str:
    res = subprocess.run(args, capture_output=True, text=True, check=False)
    if res.returncode != 0:
        raise RuntimeError(f"{' '.join(args)}\n{res.stderr.strip()}")
    return res.stdout


def discover(limit_per_query: int, pause: float) -> list[dict]:
    """Return deduped [{repo, path}] from code search across QUERIES."""
    seen: dict[tuple[str, str], dict] = {}
    for i, term in enumerate(QUERIES):
        try:
            out = sh(
                [
                    "gh", "search", "code", term,
                    "--filename=SKILL.md",
                    f"--limit={limit_per_query}",
                    "--json", "repository,path",
                ]
            )
        except RuntimeError as e:
            print(f"  ! query {term!r} failed: {e}", file=sys.stderr)
            time.sleep(pause)
            continue
        rows = json.loads(out)
        added = 0
        for r in rows:
            repo = r["repository"]["nameWithOwner"]
            path = r["path"]
            key = (repo, path)
            if key not in seen:
                seen[key] = {"repo": repo, "path": path}
                added += 1
        print(f"  [{i + 1}/{len(QUERIES)}] {term!r}: +{added} new "
              f"(total {len(seen)})")
        if i < len(QUERIES) - 1:
            time.sleep(pause)  # respect code-search rate limit (~10/min)
    return list(seen.values())


def _cache_path(repo: str, path: str) -> Path:
    safe = f"{repo}__{path}".replace("/", "_")
    return CACHE / f"{safe}"


def fetch(repo: str, path: str) -> str | None:
    """Fetch file text via the contents API, with an on-disk cache."""
    cp = _cache_path(repo, path)
    if cp.exists():
        return cp.read_text(encoding="utf-8", errors="replace")
    try:
        out = sh(["gh", "api", f"repos/{repo}/contents/{path}",
                  "--jq", ".content"])
    except RuntimeError:
        return None
    try:
        text = base64.b64decode(out).decode("utf-8", errors="replace")
    except Exception:
        return None
    cp.parent.mkdir(parents=True, exist_ok=True)
    cp.write_text(text, encoding="utf-8")
    return text


def aggregate(records: list[dict]) -> dict:
    verdicts = Counter(r["verdict"] for r in records)
    gated = sum(1 for r in records if r["review_required"])
    caps = Counter()
    rules = Counter()
    for r in records:
        for c in r["capabilities"]:
            caps[c] += 1
        for rule in r["rules"]:
            rules[rule] += 1
    flagged = sorted(
        (r for r in records if r["verdict"] != "valid"),
        key=lambda r: (-r["risk_score"]),
    )
    n = len(records)
    return {
        "scanned": n,
        "verdicts": dict(verdicts),
        "pct_not_clean": round(100 * (n - verdicts.get("valid", 0)) / n, 1)
        if n else 0,
        "review_required": gated,
        "pct_review_required": round(100 * gated / n, 1) if n else 0,
        "top_capabilities": caps.most_common(12),
        "top_rules": rules.most_common(15),
        "flagged": flagged,
    }


def scan_all(candidates: list[dict]) -> list[dict]:
    records: list[dict] = []
    total = len(candidates)
    for i, c in enumerate(candidates):
        text = fetch(c["repo"], c["path"])
        if not text or not text.strip():
            continue
        rep = scan_md(text, name=c["repo"])
        records.append(
            {
                "repo": c["repo"],
                "path": c["path"],
                "verdict": rep.verdict.value,
                "risk_score": rep.risk_score,
                "review_required": rep.review_required,
                "capabilities": rep.capabilities,
                "rules": sorted({f.rule_id for f in rep.findings}),
                "top_finding": headline_finding(rep),
            }
        )
        if (i + 1) % 25 == 0 or i + 1 == total:
            print(f"  scanned {i + 1}/{total}")
    return records


def write_summary(agg: dict) -> None:
    v = agg["verdicts"]
    lines = [
        "# We scanned public agent Skills with Vouch",
        "",
        f"**{agg['scanned']} public `SKILL.md` files scanned** "
        "(static analysis only).",
        "",
        f"- **{agg['pct_not_clean']}%** were *not* a clean `valid` "
        f"({v.get('suspicious', 0)} suspicious, {v.get('malicious', 0)} "
        "malicious).",
        f"- **{agg['pct_review_required']}%** tripped the capability gate "
        f"(dangerous capability combination requiring review): "
        f"{agg['review_required']} skills.",
        "",
        "## Verdicts",
        "",
        "| valid | suspicious | malicious |",
        "|---:|---:|---:|",
        f"| {v.get('valid', 0)} | {v.get('suspicious', 0)} | "
        f"{v.get('malicious', 0)} |",
        "",
        "## Most common capabilities",
        "",
        "| capability | skills |",
        "|---|---:|",
    ]
    for cap, cnt in agg["top_capabilities"]:
        lines.append(f"| {cap} | {cnt} |")
    lines += ["", "## Most frequently triggered rules", "",
              "| rule | hits |", "|---|---:|"]
    for rule, cnt in agg["top_rules"]:
        lines.append(f"| {rule} | {cnt} |")
    lines += ["", f"## Flagged skills ({len(agg['flagged'])})", "",
              "| repo | verdict | risk | top finding |",
              "|---|---|---:|---|"]
    for r in agg["flagged"][:50]:
        lines.append(
            f"| {r['repo']} | {r['verdict']} | {r['risk_score']} | "
            f"{r['top_finding']} |"
        )
    (DATA / "corpus_summary.md").write_text("\n".join(lines) + "\n",
                                            encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser(description="Scan public agent Skills.")
    ap.add_argument("--limit-per-query", type=int, default=50)
    ap.add_argument("--max", type=int, default=400,
                    help="cap total unique candidates")
    ap.add_argument("--pause", type=float, default=7.0,
                    help="seconds between code-search queries")
    ap.add_argument("--report-only", action="store_true",
                    help="skip discovery/fetch; re-scan whatever is cached")
    args = ap.parse_args()

    DATA.mkdir(parents=True, exist_ok=True)

    if args.report_only:
        cached = list(CACHE.glob("*"))
        print(f"report-only: {len(cached)} cached files")
        candidates = []
        for cp in cached:
            # reconstruct repo/path best-effort from filename
            candidates.append({"repo": cp.name, "path": cp.name})
        records = []
        for cp in cached:
            text = cp.read_text(encoding="utf-8", errors="replace")
            if not text.strip():
                continue
            rep = scan_md(text, name=cp.name)
            records.append({
                "repo": cp.name, "path": "SKILL.md",
                "verdict": rep.verdict.value, "risk_score": rep.risk_score,
                "review_required": rep.review_required,
                "capabilities": rep.capabilities,
                "rules": sorted({f.rule_id for f in rep.findings}),
                "top_finding": headline_finding(rep),
            })
    else:
        print("Discovering public SKILL.md files ...")
        candidates = discover(args.limit_per_query, args.pause)
        if len(candidates) > args.max:
            candidates = candidates[: args.max]
        print(f"Fetching + scanning {len(candidates)} candidates ...")
        records = scan_all(candidates)

    agg = aggregate(records)
    (DATA / "corpus_results.json").write_text(
        json.dumps({"summary": {k: v for k, v in agg.items()
                                if k != "flagged"},
                    "records": records}, indent=2),
        encoding="utf-8",
    )
    write_summary(agg)

    print("\n" + "=" * 60)
    print(f"SCANNED: {agg['scanned']} public SKILL.md files")
    print(f"  valid={agg['verdicts'].get('valid', 0)}  "
          f"suspicious={agg['verdicts'].get('suspicious', 0)}  "
          f"malicious={agg['verdicts'].get('malicious', 0)}")
    print(f"  not-clean: {agg['pct_not_clean']}%   "
          f"capability-gate: {agg['pct_review_required']}%")
    print(f"  top caps: {agg['top_capabilities'][:5]}")
    print(f"Wrote {DATA / 'corpus_results.json'} and "
          f"{DATA / 'corpus_summary.md'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
