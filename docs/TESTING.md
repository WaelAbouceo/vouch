# Testing Vouch (for teammates & early testers)

Thanks for kicking the tires. This page is the one link to test from — it takes
about 10 minutes. **Please be blunt in your feedback**; false-alarm reports and
"it missed X" reports are the most valuable thing you can give us.

## 1. Install

```bash
pipx run --spec vouch-agent vouch --audit      # zero-install, one-shot
# or
pip install vouch-agent && vouch --audit       # persistent install
```

> On stock **Debian/Ubuntu**, system `pip` blocks global installs
> (`externally-managed-environment`). Use `pipx`, a `venv`, or
> `pip install --break-system-packages vouch-agent`.

## 2. The flagship: audit your machine

```bash
vouch --audit                     # scan every skill installed for your agents
vouch --audit --reset-baseline    # greenfield: this scan becomes the baseline
vouch --audit --json              # machine-readable
```

It scans known skill folders (`~/.claude/skills`, `~/.cursor/skills`, …), tells
you in plain English what each skill can do, and flags the ones worth a look.

## 3. Scan a single skill

```bash
vouch ./path/to/skill            # plain report
vouch ./path/to/skill --cv       # a "CV" profile card
vouch ./path/to/skill --json     # structured output
```

## 4. Optional AI second opinion

Enabling `--llm` **sends the skill's contents** to your chosen provider (static
analysis stays 100% local). Point it at a provider you already trust — or run it
fully local so nothing leaves your machine:

```bash
# Any OpenAI-compatible endpoint (OpenAI, OpenRouter, Groq, vLLM…)
export OPENAI_API_KEY="sk-..."
# …or fully local with Ollama:
export OPENAI_API_KEY="ollama" OPENAI_BASE_URL="http://localhost:11434/v1" OPENAI_MODEL="llama3.1"

vouch --audit --llm
```

## 5. Set expectations honestly

- A `valid` verdict means *"no obvious literal red flag"* — **not** "safe."
  Treat Vouch as a **triage filter**, not a security boundary.
- Static analysis reliably catches blunt malware (curl-pipe-to-sh, `rm -rf ~`,
  credential exfil, `shutil.rmtree(home)`, list-arg `rm -rf /`). It can be
  defeated by **one variable of indirection** or **paraphrased prose** — that's
  what `--llm` helps with. See the README's **Known limitations**.
- In CI, the default (`--fail-on malicious`) does **not** block "suspicious"/
  review items. Pass `--fail-on suspicious` to fail the build on those (Vouch
  prints a note reminding you).

## What to report

Open an issue (templates provided) with:

- **False alarm?** The skill snippet + the finding it produced. → *"Report a
  false alarm"* / use the rule template.
- **Missed something?** A skill that should have been flagged but wasn't. → *"Report
  a malicious skill Vouch missed"*.
- **Crash / install problem?** OS, Python version, and the full command + output.
- **UX confusion?** Anything in the report that was unclear or misleading.

Repo: <https://github.com/WaelAbouceo/vouch> · PyPI:
<https://pypi.org/project/vouch-agent/>
