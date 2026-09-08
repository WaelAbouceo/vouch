# Roadmap

**Positioning:** the antivirus / linter for agent Skills — scan any skill before
your agent runs it.

Traction strategy: sharp positioning → zero-friction distribution → a
data-driven "wow" moment → deep integrations → community & credibility.

## Phase 1 — Trivially adoptable  _(in progress)_
- [ ] Publish to PyPI — deferred. NOTE: the name `vouch` is already taken on
      PyPI, so pick a distribution name when publishing (e.g. `vouch-agents` or
      `agent-vouch`); the `import vouch` name can stay the same.
- [x] GitHub Action to scan skills in CI (`action.yml`)
- [x] pre-commit hook (`.pre-commit-hooks.yaml`)
- [x] CI workflow (tests + self-scan on every push/PR)
- [x] README: animated demo GIF of the CV catching a malicious skill
      (`docs/demo.gif`, regenerate with `python scripts/gen_demo.py`)
- [x] README badges (PyPI, CI, license)

## Phase 2 — The wow moment (launch)
- [ ] Scan every public skill we can find (`SKILL.md` across GitHub, awesome-*
      lists, MCP registries) and publish "We scanned N public agent skills…"
- [ ] Public leaderboard / registry of scanned skills with verdicts
- [ ] Launch post (HN / r/programming / X) built around the data

## Phase 3 — Integrations where users already are
- [ ] List the MCP server in MCP registries / `awesome-mcp`
- [ ] Cursor hook / rule that auto-scans a skill before it loads
- [ ] VS Code / Cursor extension: inline CV card when viewing a `SKILL.md`

## Phase 4 — Credibility & community
- [ ] Curated, versioned rule DB with a CHANGELOG and named rules
- [ ] Benchmark repo of labeled benign/malicious skills (detection quality)
- [ ] `CONTRIBUTING.md` + "contribute a rule" guide (low-friction first PRs)
- [ ] Security-advisory format for malicious skills we discover

## Explicitly deprioritized (for now)
- Heavy LLM features, a large web platform, broad "agent security platform" scope.
  The wedge is one sharp tool that's everywhere and backed by real data.
