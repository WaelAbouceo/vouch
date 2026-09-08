"""Tests for the Agent CV (aggregate profile across an agent's skills)."""

from pathlib import Path

from vouch import build_agent_cv, discover_skills
from vouch.agent import render_markdown, render_text
from vouch.models import Verdict

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
AGENT = EXAMPLES / "example-agent"


def test_discover_finds_all_skills():
    dirs = discover_skills(str(AGENT))
    names = {d.name for d in dirs}
    assert names == {"note-taker", "env-installer"}


def test_agent_cv_aggregates_and_quarantines():
    cv = build_agent_cv(str(AGENT), use_llm=False)
    assert cv.skill_count == 2
    # worst-of: one malicious skill quarantines the whole agent
    assert cv.verdict == Verdict.MALICIOUS
    assert "QUARANTINE" in cv.recommendation
    # per-skill breakdown present, worst first
    assert cv.skills[0].verdict == Verdict.MALICIOUS
    # capabilities are unioned across skills
    assert any("Network" in label for label in cv.capabilities)


def test_agent_cv_all_valid_is_trusted():
    # An agent whose only skill is the benign example should be trusted.
    cv = build_agent_cv(str(EXAMPLES / "benign-skill"), use_llm=False)
    assert cv.verdict == Verdict.VALID
    assert "TRUSTED" in cv.recommendation
    assert cv.skill_count == 1


def test_agent_renderers():
    cv = build_agent_cv(str(AGENT), use_llm=False)
    md = render_markdown(cv)
    assert md.startswith("# Agent CV")
    assert "| Skill |" in md
    txt = render_text(cv, color=False)
    assert "AGENT CV" in txt
    assert "SKILLS" in txt


def test_agent_cv_serializable():
    import json

    cv = build_agent_cv(str(AGENT), use_llm=False)
    json.loads(json.dumps(cv.to_dict()))


def test_agent_cv_groups_skills_by_role():
    cv = build_agent_cv(str(AGENT), use_llm=False)
    # roles are aggregated across skills and surfaced in the render
    assert cv.roles
    assert all(count >= 1 for count in cv.roles.values())
    md = render_markdown(cv)
    assert "What this agent behaves as" in md
    txt = render_text(cv, color=False)
    assert "BEHAVES AS" in txt


def test_toplevel_renderers_dispatch_on_cv_type():
    """The package-level render_text/render_markdown must handle BOTH
    SkillCV and AgentCV (regression: they previously only handled SkillCV)."""
    import vouch
    from vouch import build_cv, render_markdown, render_text

    skill_cv = build_cv(str(EXAMPLES / "benign-skill"), use_llm=False)
    agent_cv = build_agent_cv(str(AGENT), use_llm=False)

    assert isinstance(skill_cv, vouch.SkillCV)
    assert isinstance(agent_cv, vouch.AgentCV)

    assert "SKILL CV" in render_text(skill_cv)
    assert "AGENT CV" in render_text(agent_cv)
    assert render_markdown(skill_cv).startswith("# Skill CV")
    assert render_markdown(agent_cv).startswith("# Agent CV")
