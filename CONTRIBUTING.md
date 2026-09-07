# Contributing

Thanks for helping make agent Skills safer! The easiest and most valuable way to
contribute is **adding a detection rule**.

## Dev setup

```bash
pip install -e ".[dev]"
pytest -q
ruff check .
```

## Add a detection rule

Rules live in [`src/vouch/rules.py`](src/vouch/rules.py).
Each rule is a `Rule(...)` with a stable ID, a title, a `Severity`, a compiled
regex, and a human-readable `detail`.

1. Pick a category prefix and next number (e.g. `EXF007`). Categories:
   `RCE` (remote code exec), `DES` (destructive), `EXF` (exfiltration),
   `PER` (persistence), `OBF` (obfuscation), `INJ` (prompt injection),
   `NET` (network/reverse-shell), `PRV` (privilege/permission).
2. Add the `Rule(...)` to the `RULES` list.
3. Add a test in [`tests/test_rules.py`](tests/test_rules.py) proving it fires
   on a malicious sample **and** does not fire on a benign one.
4. Run `pytest -q` and `ruff check .`.

Keep patterns tight to avoid false positives — the benign example
(`examples/benign-skill`) must always stay `valid`.

## Reporting a malicious skill in the wild

Open an issue using the "Malicious skill report" template. Redact any secrets.
