"""skill_validator: classify agent Skills as valid or malicious.

Public API
----------
    from skill_validator import validate_skill, validate_path, validate_text

Each returns a :class:`~skill_validator.models.Report` with a ``verdict`` of
``"valid"``, ``"suspicious"`` or ``"malicious"``.
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

__version__ = "0.2.0"
