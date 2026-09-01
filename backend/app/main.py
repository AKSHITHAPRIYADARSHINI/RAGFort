"""Phase 1 health-only API; security-sensitive endpoints are intentionally not implemented."""

from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI(title="RAGFort API", version="0.1.0", docs_url=None, redoc_url=None, openapi_url=None)


@app.middleware("http")
async def request_identifier(request: Request, call_next):
    """Assign an opaque server request ID without trusting a client-provided value."""
    request.state.request_id = f"req_{uuid4().hex}"
    response = await call_next(request)
    response.headers["X-Request-ID"] = request.state.request_id
    return response


@app.get("/health/live")
async def liveness(request: Request) -> JSONResponse:
    """Public process-only liveness; deliberately exposes no dependency information."""
    return JSONResponse(
        {"success": True, "data": {"status": "live"}, "request_id": request.state.request_id}
    )


@app.get("/health/ready")
async def readiness(request: Request) -> JSONResponse:
    """Phase 1 readiness for the health-only foundation.

    Production deployment must restrict this endpoint at the gateway and replace the
    constant with verified, fail-closed checks for critical dependencies.
    """
    return JSONResponse(
        {"success": True, "data": {"status": "ready"}, "request_id": request.state.request_id}
    )


@app.exception_handler(Exception)
async def safe_unhandled_error(request: Request, _: Exception) -> JSONResponse:
    """Do not disclose stack traces or internals in a public API response."""
    return JSONResponse(
        status_code=500,
        content={
            "success": False,
            "error": {"code": "INTERNAL_ERROR", "message": "An unexpected error occurred."},
            "request_id": getattr(request.state, "request_id", f"req_{uuid4().hex}"),
        },
    )
