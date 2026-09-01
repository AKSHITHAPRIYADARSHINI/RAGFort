"""Phase 1 health-only API; security-sensitive endpoints are intentionally not implemented."""

from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from backend.app.core.dependencies import get_query_service, get_settings
from backend.app.rag.embeddings import EmbeddingUnavailableError
from backend.app.rag.generation import GenerationUnavailableError
from backend.app.rag.retrieval import RetrievalUnavailableError

app = FastAPI(title="RAGFort API", version="0.1.0", docs_url=None, redoc_url=None, openapi_url=None)


class QueryBody(BaseModel):
    query: str


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
        {
            "success": True,
            "data": {"status": "foundation-ready", "phase": 1},
            "request_id": request.state.request_id,
        }
    )


@app.post("/api/v1/query")
async def query(body: QueryBody, request: Request) -> JSONResponse:
    """Execute Phase 2 baseline RAG over only the controlled development corpus."""
    question = body.query.strip()
    max_chars = get_settings().rag_query_max_chars
    if not question or len(question) > max_chars:
        return JSONResponse(
            status_code=400,
            content={
                "success": False,
                "error": {"code": "INVALID_QUERY", "message": "Provide a valid question."},
                "request_id": request.state.request_id,
            },
        )
    try:
        outcome = get_query_service().query(question)
    except EmbeddingUnavailableError:
        return _rag_unavailable("RAG_EMBEDDING_UNAVAILABLE", request)
    except RetrievalUnavailableError:
        return _rag_unavailable("RAG_RETRIEVAL_UNAVAILABLE", request)
    except GenerationUnavailableError:
        return _rag_unavailable("RAG_GENERATION_UNAVAILABLE", request)
    data = {
        "answer": outcome.answer,
        "answer_status": outcome.answer_status,
        "sources": [citation.__dict__ for citation in outcome.sources],
    }
    if outcome.trace is not None:
        data["trace"] = outcome.trace
    return JSONResponse({"success": True, "data": data, "request_id": request.state.request_id})


def _rag_unavailable(code: str, request: Request) -> JSONResponse:
    return JSONResponse(
        status_code=503,
        content={
            "success": False,
            "error": {"code": code, "message": "The knowledge base is unavailable right now."},
            "request_id": request.state.request_id,
        },
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
