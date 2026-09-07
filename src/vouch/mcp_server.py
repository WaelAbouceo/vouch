"""MCP server exposing skill validation as a tool for AI agents.

Run with::

    vouch-mcp                      # stdio transport (default)

Requires the ``mcp`` extra::

    pip install "vouch[mcp]"

Tools exposed
-------------
- ``validate_skill_text``: validate raw skill content passed inline.
- ``validate_skill_path``: validate a skill directory/file on the local FS.
"""

from __future__ import annotations

import json

from . import loader
from .engine import validate_skill


def _report_payload(report) -> str:
    return json.dumps(report.to_dict(), indent=2)


def build_server():
    """Construct and return the FastMCP server instance."""
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception as e:  # pragma: no cover - import guard
        raise SystemExit(
            "The 'mcp' package is required. Install with: pip install "
            '"vouch[mcp]"'
        ) from e

    mcp = FastMCP("vouch")

    @mcp.tool()
    def validate_skill_text(
        content: str,
        name: str = "inline-skill",
        use_llm: bool = False,
    ) -> str:
        """Validate raw Skill content and classify it as valid/suspicious/malicious.

        Args:
            content: The full text of the skill (e.g. a SKILL.md body).
            name: Optional name for the skill (used in the report).
            use_llm: Whether to additionally run the LLM auditor (needs API key).

        Returns:
            A JSON report string with verdict, risk_score, and findings.
        """
        skill = loader.load_text(content, name=name)
        report = validate_skill(skill, use_llm=use_llm)
        return _report_payload(report)

    @mcp.tool()
    def validate_skill_path(path: str, use_llm: bool = False) -> str:
        """Validate a Skill directory or file on the local filesystem.

        Args:
            path: Path to a skill directory (containing SKILL.md) or a single file.
            use_llm: Whether to additionally run the LLM auditor (needs API key).

        Returns:
            A JSON report string with verdict, risk_score, and findings.
        """
        skill = loader.load(path)
        report = validate_skill(skill, use_llm=use_llm)
        return _report_payload(report)

    @mcp.tool()
    def skill_cv(
        path: str = "",
        content: str = "",
        name: str = "inline-skill",
        use_llm: bool = False,
        as_markdown: bool = True,
    ) -> str:
        """Produce a Skill CV: a profile of a skill's identity, capabilities,
        file inventory, and security verdict.

        Provide exactly one of ``path`` (a local skill dir/file) or ``content``
        (raw skill text). Returns Markdown when ``as_markdown`` is true,
        otherwise a JSON object.
        """
        from . import cv as cv_mod

        if path:
            skill = loader.load(path)
        else:
            skill = loader.load_text(content, name=name)
        skill_cv = cv_mod.build_cv(skill, use_llm=use_llm)
        if as_markdown:
            return cv_mod.render_markdown(skill_cv)
        return json.dumps(skill_cv.to_dict(), indent=2)

    return mcp


def main() -> None:
    server = build_server()
    server.run()  # defaults to stdio transport


if __name__ == "__main__":  # pragma: no cover
    main()
