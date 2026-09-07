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

from __future__ import annotations

import os


def create_app():
    try:
        from fastapi import FastAPI, HTTPException
        from pydantic import BaseModel, Field
    except Exception as e:  # pragma: no cover - import guard
        raise SystemExit(
            "FastAPI is required. Install with: pip install "
            '"vouch[api]"'
        ) from e

    from . import loader
    from .engine import validate_skill

    app = FastAPI(
        title="Vouch",
        version="0.3.0",
        description="Vet agent Skills; classify as valid, suspicious, or malicious.",
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
        try:
            skill = loader.load(req.path)
        except FileNotFoundError as e:
            raise HTTPException(status_code=404, detail=str(e)) from e
        report = validate_skill(skill, use_llm=req.use_llm, model=req.model)
        return report.to_dict()

    return app


# Module-level app for `uvicorn vouch.api:app`.
try:  # pragma: no cover - only succeeds when FastAPI is installed
    app = create_app()
except SystemExit:
    app = None  # type: ignore[assignment]


def run() -> None:  # pragma: no cover - thin runner
    import uvicorn

    host = os.environ.get("VOUCH_HOST", "0.0.0.0")
    port = int(os.environ.get("VOUCH_PORT", "8000"))
    uvicorn.run("vouch.api:app", host=host, port=port)


if __name__ == "__main__":  # pragma: no cover
    run()
