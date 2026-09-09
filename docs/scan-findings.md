# I scanned 1,141 public AI-agent skills. Here's what showed up.

AI agents (Claude, Cursor, Codex, and friends) load **skills** — packages of
instructions (`SKILL.md`) plus scripts the agent reads and may execute. They
come from many authors, they pile up fast, and almost nobody audits what they
can do before letting an agent run them.

So I built a deterministic scanner ([Vouch](https://github.com/WaelAbouceo/vouch))
and pointed it at **1,141 public `SKILL.md` files** on GitHub. Static analysis
only — it never clones, builds, or runs anything, just reads the files. The scan
is reproducible (`scripts/scan_corpus.py`), and the same input always produces
the same verdict.

## The headline

- **Roughly 1 in 12 skills (8.6%) weren't a clean pass.** 88 were flagged
  *"review this first,"* and 10 tripped hard danger rules.
- **1 in 14 skills (7.1%, 81 of them) request a dangerous *capability
  combination*** — e.g. the ability to read secrets **and** reach the network,
  the classic "copy your keys and send them somewhere" shape.

| verdict | count | share |
|---|---:|---:|
| valid | 1,043 | 91.4% |
| suspicious (review) | 88 | 7.7% |
| malicious (hard rule hit) | 10 | 0.9% |

## The real story isn't malware — it's quiet power

The scary part isn't a pile of viruses. It's how much access ordinary skills
casually request, buried in a Markdown file you were never going to read:

| capability | skills (of 1,141) |
|---|---:|
| Filesystem writes | 785 |
| Shell execution | 720 |
| Filesystem reads | 467 |
| Credential / secret access | 448 |
| Environment variable access | 294 |
| Network access | 254 |
| Persistence mechanisms | 33 |

Most of these are perfectly innocent. But you can't tell which ones aren't
**without looking** — and that's exactly the point.

## Why I'm not publishing a "malware list"

I deliberately won't name-and-shame specific repos as "malware," for a reason
that matters:

- **Static rules flag for review; humans (or an LLM) confirm.** A "malicious"
  verdict here means *"matched an unambiguous danger rule,"* not *"proven
  evil."*
- **Several scary-looking hits were defensive tools.** A prompt-shield or an
  agent-guard that **quotes** `rm -rf /` or `ignore all previous instructions`
  as the very attacks it detects will trip a scanner. Branding those as malware
  would be false and unfair.

Being blunt about that is the whole game for a security tool. Vouch is a
**transparency + triage layer**, not a verdict machine. (Its
[known limitations](https://github.com/WaelAbouceo/vouch#known-limitations-read-this-before-you-rely-on-it)
are documented up front.)

## Check your own machine in 10 seconds

The interesting question isn't the public corpus — it's *your* environment. One
command audits every skill installed for your agents, tells you in plain English
what each can do, and flags the ones worth a look:

```bash
pipx run --spec vouch-agent vouch --audit
# or: pip install vouch-agent && vouch --audit
```

No signup, no telemetry, zero dependencies for the static core. It reads your
skill folders and prints a report. You'll probably be surprised what's in there.

---

*Repo: <https://github.com/WaelAbouceo/vouch> · Reproduce the scan:
`python scripts/scan_corpus.py` · Numbers current as of the latest green-field
run on the shipped engine.*
