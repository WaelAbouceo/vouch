"""HTTP API for skill validation (FastAPI).

Run with::

    vouch-api                           # uvicorn on 0.0.0.0:8000
    # or
    uvicorn vouch.api:app --reload

Requires the ``api`` extra::

    pip install "vouch[api]"

Endpoints
---------
- ``GET  /health``           -> liveness probe
- ``POST /validate/text``    -> body: {content, name?, use_llm?}
- ``POST /validate/path``    -> body: {path, use_llm?}  (local FS access)
"""

import os
import sys

from . import __version__


def _is_within(path: str, root: str) -> bool:
    """True iff ``path`` resolves to a location inside ``root`` (symlink-safe).

    Uses realpath on both sides so ``..`` traversal and symlink escapes can't
    slip a request outside the configured root.
    """
    root_real = os.path.realpath(root)
    path_real = os.path.realpath(path)
    try:
        return os.path.commonpath([root_real, path_real]) == root_real
    except ValueError:
        # Different drives / mixed absolute-relative — treat as outside.
        return False


def create_app():
    try:
        from fastapi import FastAPI, HTTPException
        from pydantic import BaseModel, Field
    except Exception as e:  # pragma: no cover - import guard
        raise SystemExit(
            "The HTTP API needs extra dependencies. Install with: "
            'pip install "vouch-agent[api]"'
        ) from e

    from . import loader
    from .engine import validate_skill

    app = FastAPI(
        title="Vouch",
        version=__version__,
        description="Security scanner for AI-agent skills: classify as valid, "
        "suspicious, or malicious.",
    )

    class TextRequest(BaseModel):
        content: str = Field(..., description="Raw skill content (e.g. SKILL.md body).")
        name: str = Field("inline-skill", description="Optional skill name.")
        use_llm: bool | None = Field(
            None, description="Enable LLM auditor. Default: auto (if API key set)."
        )
        model: str | None = Field(None, description="Optional LLM model id override.")

    class PathRequest(BaseModel):
        path: str = Field(..., description="Local path to a skill dir or file.")
        use_llm: bool | None = Field(None, description="Enable LLM auditor.")
        model: str | None = Field(None, description="Optional LLM model id override.")

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    @app.post("/validate/text")
    def validate_text_endpoint(req: TextRequest) -> dict:
        skill = loader.load_text(req.content, name=req.name)
        report = validate_skill(skill, use_llm=req.use_llm, model=req.model)
        return report.to_dict()

    @app.post("/cv/text")
    def cv_text_endpoint(req: TextRequest) -> dict:
        from . import cv as cv_mod

        skill = loader.load_text(req.content, name=req.name)
        skill_cv = cv_mod.build_cv(skill, use_llm=req.use_llm, model=req.model)
        payload = skill_cv.to_dict()
        payload["markdown"] = cv_mod.render_markdown(skill_cv)
        return payload

    @app.post("/validate/path")
    def validate_path_endpoint(req: PathRequest) -> dict:
        # Guard: local-path validation is disabled unless explicitly allowed,
        # since it exposes the host filesystem to callers.
        if os.environ.get("VOUCH_ALLOW_PATH") != "1":
            raise HTTPException(
                status_code=403,
                detail="Path validation disabled. Set VOUCH_ALLOW_PATH=1 "
                "to enable local filesystem access.",
            )
        # Optional (recommended for any shared/networked deployment): scope reads
        # to a single directory subtree. Without this, /validate/path is an
        # arbitrary-file-read endpoint at the same trust level as shell access.
        root = os.environ.get("VOUCH_PATH_ROOT")
        if root and not _is_within(req.path, root):
            raise HTTPException(
                status_code=403,
                detail=f"Path is outside the allowed root ({root}). "
                "Set VOUCH_PATH_ROOT to widen the scope.",
            )
        try:
            skill = loader.load(req.path)
        except FileNotFoundError as e:
            raise HTTPException(status_code=404, detail=str(e)) from e
        report = validate_skill(skill, use_llm=req.use_llm, model=req.model)
        return report.to_dict()

    # Loud warning if path reads are enabled without scoping — this is an
    # arbitrary-file-read endpoint otherwise.
    if os.environ.get("VOUCH_ALLOW_PATH") == "1" and not os.environ.get(
        "VOUCH_PATH_ROOT"
    ):
        print(
            "vouch-api WARNING: VOUCH_ALLOW_PATH=1 without VOUCH_PATH_ROOT — "
            "/validate/path can read ANY file the server process can (e.g. "
            "/etc/passwd). Set VOUCH_PATH_ROOT=/path/to/skills to scope it, or "
            "only enable this on a trusted, non-networked host.",
            file=sys.stderr,
        )

    return app


# Module-level app for `uvicorn vouch.api:app`.
try:  # pragma: no cover - only succeeds when FastAPI is installed
    app = create_app()
except SystemExit:
    app = None  # type: ignore[assignment]


def run() -> None:  # pragma: no cover - thin runner
    # Fail with a clean, actionable message (like vouch-mcp) instead of a raw
    # traceback when the optional server deps aren't installed.
    try:
        import uvicorn
    except Exception as e:
        raise SystemExit(
            "The HTTP API needs extra dependencies. Install with: "
            'pip install "vouch-agent[api]"'
        ) from e
    if app is None:
        raise SystemExit(
            "The HTTP API needs extra dependencies. Install with: "
            'pip install "vouch-agent[api]"'
        )
    host = os.environ.get("VOUCH_HOST", "0.0.0.0")
    port = int(os.environ.get("VOUCH_PORT", "8000"))
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":  # pragma: no cover
    run()
