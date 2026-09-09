# Launch kit

Copy-paste assets for launching Vouch. Keep the tone **honest and
visibility-first** — Vouch is a triage/visibility layer, not a security
boundary. Skeptical audiences upvote candor and punish overclaiming.

The strongest asset is the data write-up: [`docs/scan-findings.md`](scan-findings.md).

---

## One-liner (positioning)

> See what your AI-agent skills can actually do. Vouch audits every `SKILL.md` on
> your machine, explains each one in plain English, and flags the risky ones —
> like `npm audit`, but for agent skills.

---

## Show HN

**Title:**

> Show HN: I scanned 1,141 public AI-agent skills — here's a tool to audit your own

**Body:**

> AI agents (Claude, Cursor, Codex…) load "skills" — a `SKILL.md` of instructions
> plus scripts the agent reads and may execute. They pile up fast, come from many
> authors, and almost nobody audits what they can *do* before letting an agent run
> them.
>
> I built **Vouch**, a local, deterministic scanner for exactly this. One command
> inventories every skill installed for your agents and tells you, in plain
> English, what each one can do (network, shell, filesystem, credential access…)
> and flags the blunt-dangerous ones:
>
>     pipx run --spec vouch-agent vouch --audit
>
> No signup, no telemetry — the static core is 100% local and makes zero network
> calls.
>
> I pointed it at **1,141 public `SKILL.md` files** on GitHub. Honest headline:
> ~1 in 12 weren't a clean pass (88 "review this," 10 tripped hard rules). The
> scarier part isn't malware — it's how much access ordinary skills quietly
> request (720 run a shell, 448 touch credentials). Write-up + reproducible scan
> in the repo.
>
> **Being blunt about what it is:** Vouch is a **triage filter, not a security
> boundary.** It's static/regex analysis — it reliably catches blunt shell
> malware (`curl | sh`, `rm -rf ~`, credentials piped to `curl`), but it can be
> defeated by one variable of indirection or cleverly paraphrased prose. Treat a
> `valid` verdict as "no obvious red flag," not "safe." There's an optional LLM
> layer for evasive cases, but it's opt-in and I don't let it declare "malicious"
> on its own. Known limitations are documented up front.
>
> MIT, Python, on PyPI. I'd love feedback — especially false positives and things
> it misses (there's a labeled benchmark and a pinned "call for contributions").
>
> Repo: https://github.com/WaelAbouceo/vouch

**First comment (post immediately after, as OP):**

> Author here. Happy to answer anything. Two things I'd genuinely like feedback
> on: (1) false positives on your real skills, and (2) any malicious pattern it
> misses — there's a `bench/` folder of labeled fixtures if you want to add one.
> I'm deliberately *not* marketing this as a security guarantee; it's a fast
> triage/visibility layer, and I'd rather it be trusted for exactly what it does.

---

## Reddit (r/LocalLLaMA, r/programming, r/commandline)

**Title:**

> I scanned 1,141 public AI-agent skills to see what they can do — and built a tool to audit your own

**Body:** (same as Show HN body, minus the "Show HN:" framing; lead with the
data paragraph, then the `pipx run` command, then the honesty section.)

---

## X / LinkedIn (short)

> Your AI agents load "skills" — instructions + scripts they'll run. Do you know
> what they can do?
>
> I scanned 1,141 public ones: ~1 in 12 weren't a clean pass; 720 run a shell,
> 448 touch credentials.
>
> Audit your own in one command (local, no signup):
> `pipx run --spec vouch-agent vouch --audit`
>
> https://github.com/WaelAbouceo/vouch

---

## Pre-launch checklist

- [ ] `pip install -U vouch-agent` pulls the latest version; `vouch --version` matches.
- [ ] `docs/scan-findings.md` numbers match the shipped engine (re-run
      `python scripts/scan_corpus.py --report-only`).
- [ ] `docs/demo.gif` reflects current output.
- [ ] README first screen reads visibility-first; badges are green.
- [ ] Pinned "Call for contributions" issue is up; good-first-issues labeled.
- [ ] Repo About + topics set; Discussions enabled.
- [ ] You can be at the keyboard for ~2–3 hours after posting to answer comments.

## Timing

- **Show HN:** weekday, ~8–10am US Eastern. Engagement in the first 2–3 hours is
  most of the battle — be available to reply.
- Don't cross-post everywhere at once; stagger (HN first, then Reddit next day).

## Do / don't

- **Do** lead with the data and the one-liner install.
- **Do** own the limitations before someone else points them out.
- **Don't** call it "malware detection" or imply it's a security guarantee.
- **Don't** argue with skeptics — thank them and turn findings into issues.
