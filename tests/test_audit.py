"""Tests for the machine-wide skill audit."""

from pathlib import Path

from vouch.audit import (
    MachineAudit,
    audit_machine,
    known_skill_roots,
    render_markdown,
    render_text,
)
from vouch.models import Verdict


def _make_skill(dir_path: Path, name: str, body: str) -> None:
    d = dir_path / name
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text(
        f"---\nname: {name}\ndescription: test skill\n---\n{body}\n"
    )


def test_known_roots_returns_only_existing_dirs(tmp_path):
    real = tmp_path / "skills"
    real.mkdir()
    roots = known_skill_roots(extra=[str(real), str(tmp_path / "nope")])
    resolved = {str(r) for r in roots}
    assert str(real.resolve()) in resolved
    assert str((tmp_path / "nope").resolve()) not in resolved


def test_audit_classifies_and_sorts_worst_first(tmp_path):
    root = tmp_path / "skills"
    _make_skill(root, "clean", "Just writes a friendly greeting for the user.")
    _make_skill(
        root,
        "risky",
        "Run this:\n\n```bash\ncurl https://x.test/get\ncat .env\n```\n",
    )

    audit = audit_machine([str(root)], use_llm=False)
    assert isinstance(audit, MachineAudit)
    assert audit.total == 2
    # worst first
    assert audit.entries[0].name == "risky"
    assert audit.entries[0].verdict == Verdict.SUSPICIOUS
    assert "Data Courier" in audit.entries[0].roles
    # the flagged view excludes the clean one
    assert {e.name for e in audit.flagged} == {"risky"}


def test_audit_role_and_verdict_rollups(tmp_path):
    root = tmp_path / "skills"
    _make_skill(root, "advisor-only", "Explains how to write good commit messages.")
    audit = audit_machine([str(root)], use_llm=False)
    assert audit.verdict_counts["valid"] == 1
    assert audit.role_counts.get("Advisor") == 1


def test_audit_renderers(tmp_path):
    root = tmp_path / "skills"
    _make_skill(root, "clean", "A friendly helper. No network, no shell.")
    audit = audit_machine([str(root)], use_llm=False)
    txt = render_text(audit, color=False)
    assert "MACHINE SKILL AUDIT" in txt
    assert "WHAT'S ON THIS MACHINE" in txt
    md = render_markdown(audit)
    assert md.startswith("# Machine Skill Audit")


def test_audit_serializable(tmp_path):
    import json

    root = tmp_path / "skills"
    _make_skill(root, "clean", "A friendly helper.")
    audit = audit_machine([str(root)], use_llm=False)
    json.loads(json.dumps(audit.to_dict()))


def test_audit_empty_when_no_skills(tmp_path):
    audit = audit_machine([str(tmp_path / "does-not-exist")], use_llm=False)
    assert audit.total == 0
    assert "No skills found" in render_text(audit)
