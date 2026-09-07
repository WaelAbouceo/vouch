"""vouch: vet agent Skills and agents, and vouch for the safe ones.

Public API
----------
    from vouch import validate_skill, validate_path, validate_text
    from vouch import build_cv, build_agent_cv

Each validator returns a :class:`~vouch.models.Report` with a ``verdict`` of
``"valid"``, ``"suspicious"`` or ``"malicious"``.

The previous import path ``skill_validator`` still works via a deprecated shim.
"""

from .agent import AgentCV, build_agent_cv, discover_skills
from .cv import SkillCV, build_cv, render_markdown, render_text
from .engine import Engine, validate_path, validate_skill, validate_text
from .models import Finding, Report, Severity, SkillInput, Verdict

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

__version__ = "0.3.0"
