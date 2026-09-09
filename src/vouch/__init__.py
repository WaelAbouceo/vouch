"""vouch: vet agent Skills and agents, and vouch for the safe ones.

Public API
----------
    from vouch import validate_skill, validate_path, validate_text
    from vouch import build_cv, build_agent_cv

Each validator returns a :class:`~vouch.models.Report` with a ``verdict`` of
``"valid"``, ``"suspicious"`` or ``"malicious"``.
"""

from functools import singledispatch

from . import agent as _agent
from . import cv as _cv
from .agent import AgentCV, build_agent_cv, discover_skills
from .cv import SkillCV, build_cv
from .engine import Engine, validate_path, validate_skill, validate_text
from .models import Finding, Report, Severity, SkillInput, Verdict


@singledispatch
def render_text(cv, color: bool = False) -> str:
    """Render a ``SkillCV`` or ``AgentCV`` as a plain-text card."""
    raise TypeError(f"render_text() does not support {type(cv).__name__!r}")


@singledispatch
def render_markdown(cv) -> str:
    """Render a ``SkillCV`` or ``AgentCV`` as Markdown."""
    raise TypeError(f"render_markdown() does not support {type(cv).__name__!r}")


render_text.register(SkillCV, _cv.render_text)
render_text.register(AgentCV, _agent.render_text)
render_markdown.register(SkillCV, _cv.render_markdown)
render_markdown.register(AgentCV, _agent.render_markdown)

__all__ = [
    "AgentCV",
    "Engine",
    "Finding",
    "Report",
    "Severity",
    "SkillCV",
    "SkillInput",
    "Verdict",
    "build_agent_cv",
    "build_cv",
    "discover_skills",
    "render_markdown",
    "render_text",
    "validate_path",
    "validate_skill",
    "validate_text",
]

__version__ = "0.9.2"
