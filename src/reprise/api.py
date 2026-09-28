"""Local read-only replay API.

This API deliberately accepts sanitized fixture bytes, not cluster credentials or
filesystem paths. It is a development/replay surface and is not an authenticated
production service yet.
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from . import __version__
from .contracts import validate_evidence_package
from .fixture import FixtureError, load_fixture_bytes
from .report import build_evidence_package

MAX_REQUEST_BYTES = 1_000_000

app = FastAPI(
    title="REPRISE replay API",
    version=__version__,
    description="Read-only analysis of bounded metadata-only Kubernetes incident fixtures.",
)


@app.middleware("http")
async def response_safety_headers(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            if int(content_length) > MAX_REQUEST_BYTES:
                return JSONResponse(
                    status_code=413,
                    content={"detail": "request body exceeds the replay limit"},
                )
        except ValueError:
            return JSONResponse(status_code=400, content={"detail": "invalid content-length header"})

    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-REPRISE-Mode"] = "read-only-replay"
    return response


@app.get("/health")
async def health() -> dict[str, str]:
    return {
        "status": "ok",
        "version": __version__,
        "mode": "read-only-replay",
        "authentication": "not-configured-local-only",
    }


@app.get("/v1/capabilities")
async def capabilities() -> dict[str, object]:
    return {
        "mode": "read-only-replay",
        "mutation_endpoints": [],
        "accepted_input": "bounded metadata-only JSON fixture",
        "supported_outputs": ["evidence-package", "markdown-compatible JSON structure"],
        "live_kubernetes": False,
    }


@app.post("/v1/replay")
async def replay(request: Request):
    content_type = request.headers.get("content-type", "")
    if not content_type.lower().startswith("application/json"):
        return JSONResponse(
            status_code=415,
            content={"detail": "replay requests must use application/json"},
        )
    payload = await request.body()
    if len(payload) > MAX_REQUEST_BYTES:
        return JSONResponse(status_code=413, content={"detail": "request body exceeds the replay limit"})
    try:
        fixture = load_fixture_bytes(payload, max_bytes=MAX_REQUEST_BYTES)
        package = build_evidence_package(fixture)
        validate_evidence_package(package)
    except (FixtureError, ValueError) as exc:
        return JSONResponse(status_code=422, content={"detail": str(exc)})
    return JSONResponse(content=package)
