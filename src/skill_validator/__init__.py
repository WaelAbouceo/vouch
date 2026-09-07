"""Deprecated compatibility shim.

``skill_validator`` was renamed to :mod:`vouch`. This module re-exports the new
package so existing imports keep working::

    from skill_validator import validate_path   # still works (deprecated)

Please migrate to ``import vouch`` / ``from vouch import ...``.
"""

from __future__ import annotations

import importlib
import sys
import warnings

import vouch as _vouch
from vouch import *  # noqa: F401,F403  (re-export public API)
from vouch import __all__ as __all__  # noqa: PLC0414

warnings.warn(
    "`skill_validator` has been renamed to `vouch`; update your imports "
    "(`import vouch`). The old name will be removed in a future release.",
    DeprecationWarning,
    stacklevel=2,
)

# Make `import skill_validator.<sub>` resolve to the corresponding vouch module.
_SUBMODULES = [
    "agent",
    "api",
    "cli",
    "cv",
    "engine",
    "llm",
    "loader",
    "mcp_server",
    "models",
    "rules",
]
for _name in _SUBMODULES:
    try:
        sys.modules[f"{__name__}.{_name}"] = importlib.import_module(f"vouch.{_name}")
    except Exception:  # pragma: no cover - optional deps (api/mcp) may be absent
        pass

__version__ = _vouch.__version__
