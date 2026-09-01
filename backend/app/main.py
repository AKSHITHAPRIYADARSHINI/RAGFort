"""Phase 1 health-only API; security-sensitive endpoints are intentionally not implemented."""

from uuid import uuid4

from fastapi import FastAPI, File, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from backend.app.core.dependencies import get_document_service, get_query_service, get_settings
from backend.app.documents.models import DocumentError
from backend.app.rag.embeddings import EmbeddingUnavailableError
from backend.app.rag.generation import GenerationUnavailableError
from backend.app.rag.retrieval import RetrievalUnavailableError

app = FastAPI(title="RAGFort API", version="0.1.0", docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=False,
    allow_methods=["POST", "GET", "DELETE"],
    allow_headers=["Content-Type"],
)


class QueryBody(BaseModel):
    query: str


def _document_error(error: DocumentError, request: Request, status_code: int = 400) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "success": False,
            "error": {"code": error.code, "message": error.message},
            "request_id": request.state.request_id,
        },
    )


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


@app.post("/api/v1/documents")
async def upload_document(request: Request, file: UploadFile = File(...)) -> JSONResponse:
    try:
        result = get_document_service().upload(
            file.filename or "", file.content_type, await file.read()
        )
    except DocumentError as error:
        return _document_error(error, request)
    return JSONResponse({"success": True, "data": result, "request_id": request.state.request_id})


@app.get("/api/v1/documents")
async def list_documents(request: Request) -> JSONResponse:
    try:
        result = get_document_service().list_documents()
    except Exception:
        return _document_error(DocumentError(), request, 503)
    return JSONResponse(
        {"success": True, "data": {"documents": result}, "request_id": request.state.request_id}
    )


@app.get("/api/v1/documents/{document_id}")
async def document_detail(document_id: str, request: Request) -> JSONResponse:
    try:
        result = get_document_service().get_document(document_id)
    except DocumentError as error:
        return _document_error(error, request, 404 if error.code == "DOCUMENT_NOT_FOUND" else 400)
    return JSONResponse({"success": True, "data": result, "request_id": request.state.request_id})


@app.get("/api/v1/documents/{document_id}/security")
async def document_security(document_id: str, request: Request) -> JSONResponse:
    try:
        result = get_document_service().get_document(document_id, include_findings=True)
    except DocumentError as error:
        return _document_error(error, request, 404 if error.code == "DOCUMENT_NOT_FOUND" else 400)
    return JSONResponse({"success": True, "data": result, "request_id": request.state.request_id})


@app.post("/api/v1/documents/{document_id}/approve")
async def approve_document(document_id: str, request: Request) -> JSONResponse:
    try:
        result = get_document_service().approve(document_id)
    except DocumentError as error:
        return _document_error(error, request)
    return JSONResponse({"success": True, "data": result, "request_id": request.state.request_id})


@app.post("/api/v1/documents/{document_id}/quarantine")
async def quarantine_document(document_id: str, request: Request) -> JSONResponse:
    try:
        result = get_document_service().quarantine(document_id)
    except DocumentError as error:
        return _document_error(error, request, 404 if error.code == "DOCUMENT_NOT_FOUND" else 400)
    return JSONResponse({"success": True, "data": result, "request_id": request.state.request_id})


@app.delete("/api/v1/documents/{document_id}")
async def delete_document(document_id: str, request: Request) -> JSONResponse:
    try:
        result = get_document_service().delete(document_id)
    except DocumentError as error:
        return _document_error(error, request, 404 if error.code == "DOCUMENT_NOT_FOUND" else 400)
    return JSONResponse({"success": True, "data": result, "request_id": request.state.request_id})


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
