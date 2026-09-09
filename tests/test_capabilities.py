"""Regression tests for capability-detection false positives/negatives.

These pin the exact cases a reviewer reopened: a URL in a LICENSE file must not
count as "network access", and `re.compile(...)` must not count as "dynamic code
execution" — while real network APIs and bare builtins still register.
"""
from vouch.capabilities import scan_capabilities
from vouch.models import SkillFile, SkillInput


def _active(files):
    s = SkillInput(
        name="t",
        files=[SkillFile(path=p, content=c) for p, c in files],
        source="directory",
    )
    return {c.label for c in scan_capabilities(s) if c.strong}


# --- network: a bare URL string is not network access ----------------------

def test_license_url_is_not_network():
    assert "Network access" not in _active(
        [("LICENSE.txt", "Terms: https://www.anthropic.com/legal/terms")]
    )


def test_xml_namespace_url_is_not_network():
    assert "Network access" not in _active(
        [("theme.xml", '<a xmlns="http://schemas.openxmlformats.org/drawingml"/>')]
    )


def test_real_network_apis_still_detected():
    for path, code in (
        ("run.py", "import requests\nrequests.get('http://x')\n"),
        ("run.sh", "curl http://x -o out\n"),
        ("run.py", "import httpx\nhttpx.get('http://x')\n"),
        ("run.js", "http.get('http://x')\n"),
    ):
        assert "Network access" in _active([(path, code)]), code


def test_download_verb_next_to_url_is_network():
    # Prose intent: "download ... from https://..." (as raw text = executable).
    s = SkillInput(
        name="t",
        files=[SkillFile(path="SKILL.md", content="Download the helper from https://x.test/s")],
        source="text",
    )
    assert "Network access" in {c.label for c in scan_capabilities(s) if c.strong}


# --- code_exec: method calls like re.compile are not dynamic exec ----------

def test_re_compile_is_not_code_exec():
    assert "Dynamic code execution" not in _active(
        [("add_slide.py", "import re\nPAT = re.compile(r'\\d+')\n")]
    )


def test_pandas_method_eval_is_not_code_exec():
    assert "Dynamic code execution" not in _active([("run.py", "df.eval('a + b')\n")])


def test_bare_builtins_still_code_exec():
    for code in ("eval(user_input)\n", "compile(src, '<s>', 'exec')\n", "exec(payload)\n"):
        assert "Dynamic code execution" in _active([("run.py", code)]), code
