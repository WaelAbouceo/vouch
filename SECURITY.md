# Security Policy

Vouch is a tool for vetting the safety of AI-agent Skills, so we take the
security of the tool itself seriously.

## Supported versions

Vouch is pre-1.0 (alpha). Security fixes land on `main` and in the latest
tagged release. Please track the most recent tag.

## Reporting a vulnerability

**Please do not open a public issue for security vulnerabilities.**

Instead, report privately via GitHub's
[private vulnerability reporting](https://github.com/WaelAbouceo/vouch/security/advisories/new)
(Security tab → *Report a vulnerability*).

Please include:

- a description of the issue and its impact,
- steps to reproduce (a minimal Skill or command line is ideal),
- the Vouch version / commit and your OS + Python version.

We aim to acknowledge reports within 72 hours and to provide a remediation
timeline after triage.

## Scope

In scope:

- **Detection bypasses** — a malicious Skill that Vouch reports as `valid`,
  or that evades the capability gate.
- **False sense of safety** — logic errors in the engine, gate, or CV that
  could lead a user to trust an unsafe Skill.
- Code execution or injection **in Vouch itself** while it analyzes a Skill
  (Vouch must analyze untrusted input *without* executing it).

Out of scope:

- Findings that require the user to intentionally run a Skill after Vouch has
  already flagged it.
- The behavior of the optional LLM auditor's third-party model.

## A note on verdicts

A `valid` verdict means "nothing suspicious found by the static rules, the
capability gate, and (optionally) one LLM pass." It is a filter, not a
guarantee. See the capability-gate section of the README for details.
