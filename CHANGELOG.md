# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### CI
- New `install-slim` job: builds the wheel and installs it **from scratch with
  all extras in a fresh `python:3.12-slim` container**, then verifies imports
  (incl. `mcp`/`PyJWT`), `pip check`, and that the CLI/HTTP/MCP entrypoints
  construct. Catches real install-time failures that a post-hoc `pip check`
  can't.

## [0.8.1] - 2026-09-09

### Security
- **`/validate/path` can now be scoped to a directory.** `VOUCH_ALLOW_PATH=1`
  alone made the HTTP endpoint an arbitrary-file-read (it would happily analyze
  `/etc/passwd` or `/etc/shadow`). Set **`VOUCH_PATH_ROOT=/path/to/skills`** to
  restrict reads to a subtree; requests outside it — including `..` traversal and
  symlink escapes (checked via `realpath` + `commonpath`) — return `403`. If path
  reads are enabled without a root, `vouch-api` now logs a startup warning. The
  README documents this as "same trust level as shell access."

### Docs
- Install guidance: the optional extras (`[mcp]`/`[api]`/`[all]`) can fail to
  install into a **system** Debian/Ubuntu Python even past PEP-668, because the
  `mcp` SDK needs a newer `PyJWT` than the apt-managed one and pip won't override
  a distro-owned package. Documented that extras must go in a **venv or pipx**
  (verified: fresh venv resolves PyJWT 2.x, `pip check` clean).

## [0.8.0] - 2026-09-09

### Fixed
- **The AI layer no longer fails silently.** If you pass `--llm` but no backend
  is configured or the call errors, Vouch now prints a **warning** and reports
  `llm_status` = `unavailable`/`failed` instead of quietly returning static-only
  results dressed up as an AI review. `--audit --llm` warns up front too.
- **Partial AI reviews are now disclosed.** Big skills used to exceed the prompt
  budget so the model saw only the first few files — yet the tool still implied a
  full review. The report now shows exactly how much the AI saw
  ("AI saw only 4/51 files…") and exposes `llm_coverage` in `--json`.
- **The risky file is no longer the one that gets truncated.** The prompt now
  orders files risky-first (scripts/executables before prose docs) and caps each
  file so one large file can't starve the rest — so a payload script late in a
  big skill still reaches the auditor.

### Added
- `Report.llm_status` (`off`/`used`/`unavailable`/`failed`) and
  `Report.llm_coverage` (`files_seen`/`files_total`/`chars_*`/`truncated`), both
  in `--json`.

### Changed
- **Privacy transparency.** `--llm` help and the README now state plainly that
  enabling the AI layer **sends the skill's contents to the chosen provider**
  (static analysis stays 100% local). Docs lead with OpenAI-compatible endpoints
  (incl. a **fully local Ollama**) rather than framing a single hosted startup as
  the default.

## [0.7.4] - 2026-09-09

### Fixed
- **HTTP API was broken (`vouch[api]`).** `from __future__ import annotations`
  combined with request models defined inside `create_app()` made FastAPI/pydantic
  unable to resolve the endpoint annotations at runtime — every request raised
  `PydanticUndefinedAnnotation`. Removed the future-import so the models resolve.
  The bug went unnoticed because the module had **0% test coverage**.
- `vouch.api` no longer advertises a hard-coded stale `version="0.3.0"`; it now
  reports the real package `__version__`.
- **MCP server was broken (`vouch[mcp]`).** The `mcp` SDK released 2.x, which
  renamed `FastMCP` → `MCPServer` and moved the import path, so `pip install
  "vouch[mcp]"` pulled an incompatible SDK and `vouch-mcp` failed to start.
  Pinned the extra to `mcp>=1.2.0,<2` to match the v1 code (verified `vouch[all]`
  still installs cleanly via `pip check`). Migration to the 2.x API is tracked
  in the roadmap.

### Added
- Real smoke tests for both optional delivery forms: `tests/test_api.py`
  (FastAPI endpoints via `TestClient`, incl. the `/validate/path` FS guard) and
  `tests/test_mcp_server.py` (MCP server builds and registers its tools). The
  `dev` extra now installs `fastapi`/`httpx`/`mcp` so CI actually exercises both
  entry points instead of silently skipping them. API coverage 0% → 96%.

## [0.7.3] - 2026-09-09

### Changed
- **Positioning + discoverability.** Aligned the package's headline everywhere to
  "**security scanner for AI-agent skills**" (dropping the stale "trust layer /
  CVs" framing as the lead). Rewrote the PyPI `description`, refreshed `keywords`
  (search terms like `security-scanner`, `malware-detection`,
  `secret-exfiltration`, `supply-chain-security`, `claude`, `cursor`, `mcp`),
  updated the GitHub repo description, and expanded GitHub topics. No code or API
  changes — the Skill CV / Agent CV features remain, just no longer the pitch.

### Added
- `vouch --audit --reset-baseline` — **greenfield mode**: forget any saved
  baseline and start fresh, so the current scan becomes the new baseline
  (reports "First audit" again). Complements `--no-baseline` (a one-off scan
  that neither reads nor writes a baseline).

### Fixed
- `vouch --audit` now prints each flagged skill's **on-disk path** in the
  human-readable reports (default text and `--markdown`), not just in `--json`.
  Previously the report showed only the skill's frontmatter `name:`, which can
  differ from its folder (e.g. a skill named `key-sync` living in `ssh-exfil/`),
  making a flagged skill effectively unfindable without dropping into `--json`.
  The text report adds a dimmed `~`-abbreviated path line under each entry (also
  for `+ NEW` diff entries); the markdown report gains a **Path** column.

### Added
- `EXF009` rule (**threat**, HIGH) — the *blatant* prose-exfiltration case:
  a send/exfil verb + a secret + an **explicit `http(s)://` destination** in one
  instruction (e.g. "send the `api_key` to `https://…`"). Unlike the `EXF008`
  notice, this **drives the verdict to `suspicious`**, so CI gating
  (`--fail-on suspicious`) now actually stops prose-based exfiltration in
  automated pipelines. Like the `INJ*` rules it fires in prose (a SKILL.md
  instruction *is* behavior). High precision: **0.1% of the 1,141-skill corpus**
  (1 hit — a private key sent to an RPC URL, itself a legitimate review case).

### Changed
- README "Known limitations" now describes exfiltration detection in tiers:
  blatant explicit-URL prose is caught (`suspicious`, CI-gating works), while
  softer/ambiguous phrasing remains a heads-up notice and LLM territory.
- **Quickstart** now leads with `pipx run --spec vouch-agent` (zero-install) and
  documents the fix for Debian/Ubuntu's PEP-668 `externally-managed-environment`
  error (`pipx`, venv, or `--user`), the first thing many new users hit.

## [0.6.0] - 2026-09-09

### Added
- `EXF008` rule (notice) — surfaces **prose instructions that describe sending a
  secret/credential** (a send/exfil verb next to `api_key`/`token`/…). Catches
  natural-language exfiltration that carries no literal code for the command
  rules to match. It is a *heads-up notice*, never a verdict driver: statically
  we can't tell a legitimate authenticated call from exfiltration (the
  destination decides), so it's flagged for a human/LLM to judge (~4% of the
  1,141-skill corpus). The README "Known limitations" now documents this
  prose-instruction gap explicitly.
- `OBF005` rule — catches commands assembled from concatenated shell variables
  at a command position (`$A$B`), the classic trick for hiding a command like
  `rm -rf` from scanners. Closes a known static blind spot (`obfuscated-rm` now
  resolves to *suspicious / review*) with **zero hits across the 1,141-skill
  corpus** (no new false positives).
- **OpenSSF Scorecard** workflow + README badge — supply-chain trust signal.
- README **"Known limitations"** section — blunt about what static analysis
  can't catch (deep obfuscation, semantic intent, defensive-tool false
  positives, runtime behavior).
- `docs/scan-findings.md` — anonymized, review-framed write-up of the
  1,141-skill scan for launch posts.

### Fixed
- Three provider-detection tests assumed the optional `openai` package was
  installed; they now skip cleanly when it isn't, so a fresh clone (base + `dev`
  deps) runs **green** in CI (93 passed, 3 skipped) instead of red.

### Changed
- README/bench benchmark stats corrected and qualified: static "flag for review"
  is now **~92% precision / 100% recall** on the **22-skill** set (obfuscated-rm
  no longer a miss), with an explicit "small, directional — growing the corpus"
  caveat and a roadmap link. "Malicious" stays **100% precision**.

## [0.5.1] - 2026-09-08

### Fixed
- **GitHub Action install** — `action.yml` installed a non-existent `vouch`
  package (the distribution is `vouch-agent`); it now installs `vouch-agent`
  from PyPI, so the CI Action actually works.

### Added
- `vouch --version` — prints the installed version.
- `py.typed` marker is now shipped, so downstream type checkers see Vouch's
  type hints (matches the `Typing :: Typed` classifier).

### Changed
- Real author metadata on PyPI; pre-commit `rev` example bumped to `v0.5.0`;
  Action `use-llm` doc no longer implies Cursor-only.

## [0.5.0] - 2026-09-08

### Added
- **Labeled benchmark** (`bench/` + `scripts/benchmark.py`) — 22 ground-truth
  skills (11 benign incl. powerful-but-legit and a defensive tool; 11 malicious
  incl. obfuscated, staged-dropper, and auditor-injection cases). Reports
  precision/recall for "flagged for review" and "classified malicious", and
  lists misses/false-alarms. Supports `--llm` for the hybrid comparison. This
  replaces "trust us" with measured numbers.
- `RCE005` — detects the dropper pattern (marking a `/tmp` file executable or
  running one directly), catching download-then-execute chains static missed.
- **Provider-agnostic LLM auditor** — the LLM layer now supports any
  OpenAI-compatible endpoint (OpenAI, OpenRouter, Together, local Ollama via
  `OPENAI_BASE_URL`) in addition to the Cursor SDK. Auto-detects across
  `CURSOR_API_KEY` / `OPENAI_API_KEY` / `VOUCH_LLM_API_KEY`; choose a backend
  with `--provider` (CLI) or `VOUCH_LLM_PROVIDER`. A `responder` injection hook
  makes the hybrid pipeline fully testable offline.
- **SovereignEG backend** — first-class support for [SovereignEG](https://sovereigneg.com),
  an OpenAI-compatible, Egypt-hosted inference platform. Set `SEG_API_KEY` and use
  `--provider seg`; calls the OpenAI-compatible `/v1` endpoint (default base
  `https://sovereigneg.com`, model `gpt-4o-mini`, both overridable via
  `SEG_BASE_URL` / `SEG_MODEL`), with the `sovereigneg` SDK as a fallback. Takes
  priority in auto-detect. **Verified live**: on SovereignEG (`gpt-4o-mini`) the
  hybrid engine reaches **100% flag-for-review recall** (no dangerous skill left
  as a clean "valid") while "malicious" stays deterministic (100% precision).
- **Machine-wide audit** (`vouch --audit`) — auto-discovers every skill
  installed for Claude, Cursor, Codex, and friends, classifies each, names what
  it behaves like (roles), and reports which need a look. Saves a baseline and,
  on later runs, shows **what changed since last audit** (new / removed / newly
  risky skills). `--json` for dashboards; pass a path to scan a single folder.
- **Evidence-graded capabilities + plain-English profiles** — capabilities are
  inferred from *executable* context (fenced code / scripts, not prose), each
  skill gets a plain-English "what this means for you" and a role (Data Courier,
  Remote Code Runner, File Editor, Advisor, …).

### Changed
- **`--audit` UX** — the LLM is now opt-in for audits (`--llm`, not
  auto-enabled), a progress indicator prints during LLM runs, and a hint appears
  when an LLM key is configured but `--llm` wasn't used, so `vouch --audit` never
  looks like it hung.
- **README reframed value-first** — leads with `vouch --audit` (the flagship),
  demotes secondary surfaces (HTTP API, MCP) and multi-provider LLM setup into
  collapsible sections.
- **Context-graded threats** — command/execution rules (`RCE003-005`, `DES*`,
  `EXF001/005/007`, `OBF003`, `NET001`) now only count as *threats* when they
  appear in executable context (a fenced code block or a script). The same
  string quoted in prose — e.g. a security tool listing an attack as a detection
  pattern — is downgraded to an awareness notice. Prompt-injection rules (`INJ*`)
  are exempt and always count, since they are attacks precisely as prose. This
  removes the defensive-tool false positive: static now scores **100% precision
  / 0 false "malicious"** on the benchmark.
- **LLM is advisory, not authoritative** — the LLM auditor can raise a skill to
  **"suspicious / review"** (catching evasive threats static misses) but can
  **never brand a skill "malicious" on its own**. LLM verdicts are
  non-deterministic (we observed the same real skill flip between valid /
  suspicious / malicious across identical runs), so the strongest verdict is
  reserved for deterministic static detections — keeping "malicious"
  reproducible and false-accusation-free. LLM findings are excluded from the
  risk score; capability combinations drive the review **gate**, not the score,
  and a clean LLM pass or human sign-off lifts the gate.
- `EXF007` raised to **critical** — piping environment/secret files straight
  into a network sender is unambiguous exfiltration (improves benchmark
  malicious-recall from 55% → 64%).

## [0.4.0] - 2026-09-08

### Added
- **Awareness notices** — a new finding category (`threat` vs `notice`).
  Legitimate-but-notable behaviors (running an install script, using a secret
  env var, scheduling a task, touching cloud-credential files) are now surfaced
  loudly in a dedicated "Heads up" section of the CV / report, but **never**
  make a Skill `suspicious` or `malicious` on their own. Verdicts are driven by
  genuine threats and the capability gate.
- `scripts/scan_corpus.py` — reproducible harness to scan public `SKILL.md`
  files at scale and aggregate results.
- `EXF007` — detects piping environment variables / secret files straight into
  a network sender (a real data-exfiltration pattern).

### Changed
- Reclassified as awareness notices (no longer verdict-driving threats):
  `RCE001`/`RCE002` (curl|sh install scripts), `EXF002`/`EXF003`/`EXF004`
  (credential/secret file & env-var use), `EXF006` (hardcoded IP),
  `PER001`/`PER002`/`PER003` (persistence), `PRV001` (permissions),
  `PRV002` (disabled TLS verification).

### Fixed
- `EXF006` no longer flags private / loopback / reserved IP addresses.
- `OBF004` no longer flags the zero-width joiner inside emoji (e.g. 👩‍💻).
- `NET001` no longer false-matches `nc` inside words like `sync --extra`.
- `INJ005` no longer fires on negated guidance ("don't do X without permission").

## [0.3.1] - 2026-09-08

### Fixed
- The package-level `render_text()` and `render_markdown()` now dispatch on the
  CV type, so they render an **`AgentCV`** as well as a `SkillCV`. Previously
  `from vouch import render_text; render_text(agent_cv)` raised
  `AttributeError`.

## [0.3.0] - 2026-09-08

### Added
- Packaging for PyPI under the distribution name `vouch-agent` (the import
  package and CLI remain `vouch`). Automated publish via GitHub Actions using
  PyPI Trusted Publishing (OIDC) — see `.github/workflows/release.yml`.
- PyPI classifiers and project URLs.

### Added
- **Capability-composition gate** — verdicts are now weighted by capability
  class, not just findings. A Skill exhibiting a dangerous combination
  (e.g. network + credentials, or network + shell) can no longer land on a
  clean `valid` from a static-only scan; it is floored to `suspicious` with
  `review_required=true` until an LLM pass or human `--sign-off` clears it.
- New `capabilities.py` module (extracted to break the `cv` ↔ `engine` cycle).
- `--sign-off` CLI flag to record explicit human review.
- **Agent CV** — aggregate trust profile that rolls up every Skill an agent
  loads (`--agent-cv`).
- Animated demo GIF in the README, generated by `scripts/gen_demo.py`
  (self-contained, no external recorder required).
- `examples/evasive-skill` fixture demonstrating the capability gate.

### Changed
- Project renamed from `skill-validator` to **Vouch** (package, CLI, entry
  points, environment variables, and docs). CLI is now `vouch`; API and MCP
  entry points are `vouch-api` and `vouch-mcp`.
- Capability evidence no longer surfaces markdown code-fence markers as noise.
- Deterministic linting: pinned an explicit Ruff rule set in `pyproject.toml`.

### Removed
- All backward-compatibility shims and aliases for the old `skill-validator`
  name.

## [0.2.0] - 2026-09-07

### Added
- Skill CV profile card (`--cv`).
- HTTP API (FastAPI) and MCP server delivery forms.

## [0.1.0] - 2026-09-07

### Added
- Initial release: hybrid static + LLM validation engine, CLI, and rule set.

[Unreleased]: https://github.com/WaelAbouceo/vouch/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/WaelAbouceo/vouch/releases/tag/v0.4.0
[0.3.1]: https://github.com/WaelAbouceo/vouch/releases/tag/v0.3.1
[0.3.0]: https://github.com/WaelAbouceo/vouch/releases/tag/v0.3.0
[0.2.0]: https://github.com/WaelAbouceo/vouch/releases/tag/v0.2.0
[0.1.0]: https://github.com/WaelAbouceo/vouch/releases/tag/v0.1.0
