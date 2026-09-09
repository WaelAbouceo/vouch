# Roadmap

**Positioning:** the antivirus / linter for agent Skills — scan any skill before
your agent runs it.

Traction strategy: sharp positioning → zero-friction distribution → a
data-driven "wow" moment → deep integrations → community & credibility.

## Phase 1 — Trivially adoptable  _(in progress)_
- [x] Publish to PyPI as `vouch-agent` (the name `vouch` was taken; `import
      vouch` and the `vouch` CLI are unchanged). Automated on tag via
      `.github/workflows/release.yml` using PyPI Trusted Publishing (OIDC).
- [x] GitHub Action to scan skills in CI (`action.yml`)
- [x] pre-commit hook (`.pre-commit-hooks.yaml`)
- [x] CI workflow (tests + self-scan on every push/PR)
- [x] README: animated demo GIF of the CV catching a malicious skill
      (`docs/demo.gif`, regenerate with `python scripts/gen_demo.py`)
- [x] README badges (CI, Python, license, status)

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
- [ ] Migrate the MCP server to the `mcp` 2.x API (`FastMCP` → `MCPServer`) and
      unpin `mcp<2` in the `mcp`/`all` extras.
- [ ] Curated, versioned rule DB with a CHANGELOG and named rules
- [ ] **Grow the labeled benchmark to 100+ real-world samples** (draw from public
      malicious-skill / malware corpora) so precision/recall numbers are
      defensible under scrutiny. Current set is 22 hand-built skills (`bench/`).
- [ ] `CONTRIBUTING.md` + "contribute a rule" guide (low-friction first PRs)
- [ ] Security-advisory format for malicious skills we discover

## Explicitly deprioritized (for now)
- Heavy LLM features, a large web platform, broad "agent security platform" scope.
  The wedge is one sharp tool that's everywhere and backed by real data.
