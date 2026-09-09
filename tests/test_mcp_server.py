"""Smoke tests for the optional MCP server (`vouch.mcp_server`).

Skips cleanly if the `mcp` extra isn't installed. Verifies the server builds
and its tools return well-formed reports.
"""
import json

import pytest

pytest.importorskip("mcp")

from vouch.mcp_server import build_server  # noqa: E402


def test_server_builds_and_registers_tools():
    import asyncio

    server = build_server()
    assert server is not None
    # Tool registration is async in FastMCP; assert the expected tools exist.
    tools = asyncio.new_event_loop().run_until_complete(server.list_tools())
    names = {t.name for t in tools}
    assert {"validate_skill_text", "validate_skill_path", "skill_cv"} <= names


def test_validate_skill_text_report_shape():
    # Exercise the same code path the tool uses, independent of transport.
    from vouch import loader
    from vouch.engine import validate_skill

    skill = loader.load_text("Formats markdown.", name="x")
    payload = json.dumps(validate_skill(skill, use_llm=False).to_dict())
    data = json.loads(payload)
    assert data["verdict"] == "valid"
