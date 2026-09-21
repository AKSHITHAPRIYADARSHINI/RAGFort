"""RAGFort Phase 4 API: authenticated, pre-filtered RAG retrieval."""

import base64
import hashlib
from secrets import token_urlsafe
from urllib.parse import urlencode
from urllib.request import Request as UrlRequest
from urllib.request import urlopen
from uuid import uuid4

from fastapi import Cookie, Depends, FastAPI, File, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, ConfigDict

from backend.app.auth.dependencies import AuthenticationError, AuthenticationUnavailableError
from backend.app.auth.models import RequestContext
from backend.app.auth.policy import (
    AuthorizationDeniedError,
    AuthorizationService,
    ResourceAttributes,
)
from backend.app.auth.session import local_oidc_sessions
from backend.app.core.dependencies import (
    get_document_service,
    get_query_service,
    get_request_context_dependency,
    get_settings,
    require_request_context,
)
from backend.app.documents.models import DocumentAccessAssignment, DocumentError
from backend.app.rag.embeddings import EmbeddingUnavailableError
from backend.app.rag.generation import GenerationUnavailableError
from backend.app.rag.retrieval import RetrievalScope, RetrievalUnavailableError

app = FastAPI(title="RAGFort API", version="0.1.0", docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:3001",
        "http://127.0.0.1:3001",
    ],
    allow_credentials=True,
    allow_methods=["POST", "GET", "DELETE"],
    allow_headers=["Content-Type"],
)


def _pkce_challenge(verifier: str) -> str:
    return (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )


@app.get("/api/v1/auth/login")
async def login() -> RedirectResponse:
    settings = get_settings()
    if not all((settings.oidc_authorization_url, settings.oidc_redirect_uri)):
        raise AuthenticationUnavailableError()
    verifier = token_urlsafe(48)
    state = local_oidc_sessions.begin(verifier)
    parameters = {
        "client_id": settings.oidc_client_id,
        "redirect_uri": settings.oidc_redirect_uri,
        "response_type": "code",
        "scope": "openid",
        "state": state,
        "code_challenge": _pkce_challenge(verifier),
        "code_challenge_method": "S256",
    }
    return RedirectResponse(
        f"{settings.oidc_authorization_url}?{urlencode(parameters)}", status_code=302
    )


@app.get("/api/v1/auth/callback")
async def oidc_callback(code: str, state: str) -> RedirectResponse:
    settings = get_settings()
    pending = local_oidc_sessions.consume(state)
    if pending is None or not settings.oidc_token_url:
        raise AuthenticationError()
    body = urlencode(
        {
            "grant_type": "authorization_code",
            "client_id": settings.oidc_client_id,
            "code": code,
            "redirect_uri": settings.oidc_redirect_uri,
            "code_verifier": pending.verifier,
        }
    ).encode()
    try:
        with urlopen(
            UrlRequest(
                settings.oidc_token_url,
                data=body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            ),
            timeout=10,
        ) as response:  # noqa: S310
            import json

            token_data = json.loads(response.read().decode())
    except Exception as error:
        raise AuthenticationError() from error
    token = token_data.get("access_token")
    expires_in = token_data.get("expires_in")
    if not isinstance(token, str) or not isinstance(expires_in, int):
        raise AuthenticationError()
    context = get_request_context_dependency()(f"Bearer {token}")
    session_id = local_oidc_sessions.create(token, expires_in, context.authorization_epoch)
    response = RedirectResponse(settings.frontend_url, status_code=302)
    response.set_cookie(
        "ragfort_session",
        session_id,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=expires_in,
        path="/",
    )
    return response


@app.post("/api/v1/auth/logout")
async def logout(ragfort_session: str | None = Cookie(default=None)) -> JSONResponse:
    local_oidc_sessions.revoke(ragfort_session)
    response = JSONResponse({"success": True, "data": {"signed_out": True}})
    response.delete_cookie("ragfort_session", path="/")
    return response


class QueryBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
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


def _auth_error(error: RuntimeError, request: Request) -> JSONResponse:
    if isinstance(error, AuthenticationUnavailableError):
        status, code, message = 503, error.code, error.message
    elif isinstance(error, AuthenticationError):
        status, code, message = 401, error.code, error.message
    else:
        status, code, message = (
            403,
            "ACCESS_DENIED",
            "You do not have permission to access this resource.",
        )
    return JSONResponse(
        status_code=status,
        content={
            "success": False,
            "error": {"code": code, "message": message},
            "request_id": request.state.request_id,
        },
    )


@app.exception_handler(AuthenticationError)
@app.exception_handler(AuthenticationUnavailableError)
@app.exception_handler(AuthorizationDeniedError)
async def auth_exception(request: Request, error: RuntimeError) -> JSONResponse:
    return _auth_error(error, request)


def _scope(context: RequestContext) -> RetrievalScope:
    AuthorizationService().require("query", context)
    return RetrievalScope(
        tenant_id=context.tenant_id,
        user_id=context.user_id,
        allowed_classifications=tuple(
            sorted(AuthorizationService().allowed_classifications(context))
        ),
        role_ids=tuple(sorted(context.roles)),
    )


def _upload_access_assignment(context: RequestContext) -> DocumentAccessAssignment:
    """Derive reviewable access state from the canonical principal only.

    Contributors can submit documents but cannot review them. Every new
    tenant-scoped document consequently includes the tenant's privileged review
    roles in its server-owned ACL, so a contributor submission cannot become
    permanently unreviewable.
    """
    return DocumentAccessAssignment(
        tenant_id=context.tenant_id,
        allowed_role_ids=tuple(sorted(context.roles | {"reviewer", "admin"})),
        department=context.attribute_map.get("department"),
    )


def _document_resource(document: dict) -> ResourceAttributes:
    """Build policy input only from persisted server output.

    Phase 4 deliberately treats missing tenant/classification/lifecycle metadata as
    an authorization failure.  This keeps legacy Phase 3 records inaccessible
    until the controlled metadata migration has completed.
    """
    tenant_id = document.get("tenant_id")
    classification = document.get("classification")
    lifecycle_status = document.get("status")
    allowed_roles = document.get("_allowed_role_ids")
    metadata = (tenant_id, classification, lifecycle_status)
    if not all(isinstance(value, str) and value for value in metadata):
        raise AuthorizationDeniedError()
    if not isinstance(allowed_roles, list) or not allowed_roles or not all(
        isinstance(role, str) and role for role in allowed_roles
    ):
        raise AuthorizationDeniedError()
    return ResourceAttributes(
        tenant_id=tenant_id,
        classification=classification,
        lifecycle_status=lifecycle_status,
        allowed_role_ids=tuple(allowed_roles),
    )


def _public_document(document: dict) -> dict:
    """Keep server-owned ACL inputs out of ordinary document API responses."""
    return {key: value for key, value in document.items() if not key.startswith("_")}


def _require_document_access(action: str, context: RequestContext, document: dict) -> None:
    """Enforce RBAC plus document attributes without trusting route parameters."""
    AuthorizationService().require(action, context, _document_resource(document))


def _load_authorized_document(
    document_id: str, action: str, context: RequestContext, include_findings: bool = False
) -> dict:
    """Load a record only after action RBAC succeeds, then apply tenant/ABAC checks.

    The route never returns a record before this check.  A cross-tenant caller
    therefore receives the same generic denial as another forbidden action.
    """
    AuthorizationService().require(action, context)
    document = get_document_service().get_document(document_id, include_findings=include_findings)
    _require_document_access(action, context, document)
    return document


@app.get("/api/v1/me")
async def me(
    request: Request, context: RequestContext = Depends(require_request_context)
) -> JSONResponse:
    return JSONResponse(
        {
            "success": True,
            "data": {
                "display_name": context.principal.display_name or "RAGFort user",
                "tenant_id": context.tenant_id,
                "roles": sorted(context.roles),
            },
            "request_id": request.state.request_id,
        }
    )


@app.post("/api/v1/query")
async def query(
    body: QueryBody, request: Request, context: RequestContext = Depends(require_request_context)
) -> JSONResponse:
    """Authenticate and authorize before embedding, retrieval, context, or generation."""
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
        outcome = get_query_service().query(question, scope=_scope(context))
    except (AuthenticationError, AuthenticationUnavailableError, AuthorizationDeniedError) as error:
        return _auth_error(error, request)
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
async def upload_document(
    request: Request,
    file: UploadFile = File(...),
    context: RequestContext = Depends(require_request_context),
) -> JSONResponse:
    try:
        AuthorizationService().require("document:upload", context)
        raw_bytes = await file.read(1_000_001)
        result = get_document_service().upload(
            file.filename or "",
            file.content_type,
            raw_bytes,
            access=_upload_access_assignment(context),
        )
    except DocumentError as error:
        return _document_error(error, request)
    return JSONResponse(
        {"success": True, "data": _public_document(result), "request_id": request.state.request_id}
    )


@app.post("/api/v1/documents/{document_id}/scan")
async def rescan_document(
    document_id: str,
    request: Request,
    context: RequestContext = Depends(require_request_context),
) -> JSONResponse:
    try:
        _load_authorized_document(document_id, "document:scan", context)
        result = get_document_service().rescan(document_id)
    except DocumentError as error:
        return _document_error(error, request, 404 if error.code == "DOCUMENT_NOT_FOUND" else 400)
    return JSONResponse(
        {"success": True, "data": _public_document(result), "request_id": request.state.request_id}
    )


@app.get("/api/v1/documents")
async def list_documents(
    request: Request, context: RequestContext = Depends(require_request_context)
) -> JSONResponse:
    try:
        AuthorizationService().require("document:read", context)
        result = get_document_service().list_documents()
    except AuthorizationDeniedError:
        raise
    except Exception:
        return _document_error(DocumentError(), request, 503)
    # Listing is a metadata API, so filter its visible rows before serialization.
    # This is separate from RAG retrieval, whose Qdrant filter is built pre-search.
    visible: list[dict] = []
    for document in result:
        try:
            _require_document_access("document:read", context, document)
        except AuthorizationDeniedError:
            continue
        visible.append(_public_document(document))
    return JSONResponse(
        {"success": True, "data": {"documents": visible}, "request_id": request.state.request_id}
    )


@app.get("/api/v1/documents/{document_id}")
async def document_detail(
    document_id: str,
    request: Request,
    context: RequestContext = Depends(require_request_context),
) -> JSONResponse:
    try:
        result = _load_authorized_document(document_id, "document:read", context)
    except DocumentError as error:
        return _document_error(error, request, 404 if error.code == "DOCUMENT_NOT_FOUND" else 400)
    return JSONResponse(
        {"success": True, "data": _public_document(result), "request_id": request.state.request_id}
    )


@app.get("/api/v1/documents/{document_id}/security")
async def document_security(
    document_id: str,
    request: Request,
    context: RequestContext = Depends(require_request_context),
) -> JSONResponse:
    try:
        result = _load_authorized_document(
            document_id, "document:review", context, include_findings=True
        )
    except DocumentError as error:
        return _document_error(error, request, 404 if error.code == "DOCUMENT_NOT_FOUND" else 400)
    return JSONResponse(
        {"success": True, "data": _public_document(result), "request_id": request.state.request_id}
    )


@app.post("/api/v1/documents/{document_id}/approve")
async def approve_document(
    document_id: str,
    request: Request,
    context: RequestContext = Depends(require_request_context),
) -> JSONResponse:
    try:
        _load_authorized_document(document_id, "document:review", context)
        result = get_document_service().approve(document_id)
    except DocumentError as error:
        return _document_error(error, request)
    return JSONResponse(
        {"success": True, "data": _public_document(result), "request_id": request.state.request_id}
    )


@app.post("/api/v1/documents/{document_id}/quarantine")
async def quarantine_document(
    document_id: str,
    request: Request,
    context: RequestContext = Depends(require_request_context),
) -> JSONResponse:
    try:
        _load_authorized_document(document_id, "document:review", context)
        result = get_document_service().quarantine(document_id)
    except DocumentError as error:
        return _document_error(error, request, 404 if error.code == "DOCUMENT_NOT_FOUND" else 400)
    return JSONResponse(
        {"success": True, "data": _public_document(result), "request_id": request.state.request_id}
    )


@app.delete("/api/v1/documents/{document_id}")
async def delete_document(
    document_id: str,
    request: Request,
    context: RequestContext = Depends(require_request_context),
) -> JSONResponse:
    try:
        _load_authorized_document(document_id, "document:delete", context)
        result = get_document_service().delete(document_id)
    except DocumentError as error:
        return _document_error(error, request, 404 if error.code == "DOCUMENT_NOT_FOUND" else 400)
    return JSONResponse(
        {"success": True, "data": _public_document(result), "request_id": request.state.request_id}
    )


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
