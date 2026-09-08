# Vouch benchmark

A small **labeled** corpus for measuring detection quality honestly. We can't
call Vouch "accurate" without a number, so this reports precision/recall on
skills whose ground truth we know.

## Layout

```
bench/
  benign/<name>/SKILL.md      # 11 skills that are safe (some powerful-but-legit)
  malicious/<name>/SKILL.md   # 11 skills that are genuinely harmful
```

The benign set deliberately includes the hard cases: a powerful-but-legitimate
`video-maker` (shell + network + API key), a `db-backup` that touches the
environment, an `sdk-docs` that only *mentions* `curl`/tokens in prose, and a
defensive `prompt-linter` that **quotes attack strings as detection patterns**.

The malicious set spans obvious to evasive: `rm -rf /`, reverse shell, SSH/env
exfiltration, dotfile persistence — plus obfuscated (`base64 | bash`,
variable-assembled `rm`), a staged dropper (download → `chmod +x /tmp` → run),
typosquat + `exec()` of remote code, prompt-injection exfiltration, and an
**auditor-injection** skill that tries to talk the reviewer into a "safe" verdict.

## Run it

```bash
PYTHONPATH=src python scripts/benchmark.py          # static engine
PYTHONPATH=src python scripts/benchmark.py --llm    # hybrid (needs CURSOR_API_KEY)
```

It reports two definitions of a "positive":

- **Mode A — flagged for review** (`verdict != valid`): the triage question a
  user actually asks — "should I look at this before trusting it?"
- **Mode B — classified malicious** (`verdict == malicious`): the strong claim.

## Honest results (22 skills)

**Static engine only:**

| Mode | Precision | Recall | F1 | Notes |
|------|-----------|--------|----|-------|
| A — flagged for review | 91% | 91% | 0.91 | 1 miss, 1 false alarm |
| B — classified malicious | 100% | 64% | 0.78 | 0 false accusations; some evasive threats land as "suspicious" |

**Hybrid (static + LLM)** — measured live on [SovereignEG](https://sovereigneg.com)
with `gpt-4o-mini` (`--llm --provider seg`):

| Mode | Precision | Recall | F1 | Notes |
|------|-----------|--------|----|-------|
| A — flagged for review | 85% | **100%** | 0.92 | nothing dangerous slips through as "valid"; 2 powerful-benign skills flagged for review |
| B — classified malicious | **100%** | 64% | 0.78 | identical to static — "malicious" is deterministic-only |

**Why "malicious" recall isn't higher (and why that's correct).** We deliberately
**do not let the LLM declare a skill "malicious" on its own.** LLM judgments are
non-deterministic: on real first-party skills we saw the same skill flip between
`valid`, `suspicious`, and `malicious` across identical runs. So the LLM is used
as a **recall booster for the *review queue***, not a malware oracle:

- It raises evasive misses (`obfuscated-rm`, `staged-dropper`, `typosquat-fetch`)
  to **suspicious / review** — Mode A recall becomes **100%** (nothing dangerous
  is left as a clean "valid").
- **"Malicious" stays reserved for deterministic static detections** — so that
  verdict is reproducible and trustworthy (100% precision, 0 false accusations),
  never a coin-flip from a weak model.

If you want the LLM's opinion to carry more weight, use a stronger model via
`SEG_MODEL` — but the *malicious* verdict remains rule-driven by design.

**What this means, plainly:**

- **Zero false "malicious" verdicts** — Vouch does not brand a benign skill as
  malware. The defensive `prompt-linter` correctly resolves to *suspicious /
  review*, not *malicious*.
- **It flags what matters** — every dangerous capability combination (network +
  secrets, network + shell, persistence, dropper) is surfaced for review.
- **Static's one blind spot here:** `obfuscated-rm`, which assembles `rm -rf`
  from single-character shell variables. Regex will always lose this arms race —
  this is exactly the evasive case the **LLM auditor** exists for. The hybrid
  numbers (run with `--llm` + a provider key) are the ones to beat; the LLM
  verdict can escalate this miss to `malicious` (see `tests/test_llm.py`).

The honest headline is unchanged: **Vouch is a transparency + triage layer.** A
clean verdict means "nothing our checks caught," not "proven safe."
