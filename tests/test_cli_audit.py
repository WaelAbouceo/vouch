"""CLI-level tests for `vouch --audit` baseline behaviour."""
from pathlib import Path

from vouch.cli import main


def _make_skill(root: Path, name: str, body: str) -> None:
    d = root / name
    d.mkdir(parents=True)
    (d / "SKILL.md").write_text(f"---\nname: {name}\n---\n{body}\n")


def test_reset_baseline_starts_greenfield(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("VOUCH_HOME", str(tmp_path / "vhome"))
    skills = tmp_path / "skills"
    _make_skill(skills, "clean", "A friendly helper. No network, no shell.")

    base = tmp_path / "vhome" / "audit-baseline.json"

    # First run: creates the baseline, reports first audit.
    main(["--audit", str(skills), "--no-llm", "--no-color", "--fail-on", "never"])
    assert base.exists()
    out = capsys.readouterr().out
    assert "First audit" in out

    # Second run: baseline exists, nothing changed.
    main(["--audit", str(skills), "--no-llm", "--no-color", "--fail-on", "never"])
    out = capsys.readouterr().out
    assert "Nothing changed" in out

    # Greenfield: --reset-baseline clears history and reports a first audit again.
    main([
        "--audit", str(skills), "--no-llm", "--no-color",
        "--fail-on", "never", "--reset-baseline",
    ])
    captured = capsys.readouterr()
    assert "cleared baseline" in captured.err.lower()
    assert "First audit" in captured.out
    assert base.exists()  # a fresh baseline was written


def test_reset_baseline_noop_when_none_exists(tmp_path, monkeypatch, capsys):
    # Resetting with no prior baseline should not error; it just starts fresh.
    monkeypatch.setenv("VOUCH_HOME", str(tmp_path / "vhome"))
    skills = tmp_path / "skills"
    _make_skill(skills, "clean", "A friendly helper.")

    rc = main([
        "--audit", str(skills), "--no-llm", "--no-color",
        "--fail-on", "never", "--reset-baseline",
    ])
    assert rc == 0
    out = capsys.readouterr().out
    assert "First audit" in out
