import json
from collections.abc import Callable
from functools import lru_cache

from fastapi import Cookie, Header
from qdrant_client import QdrantClient
from sqlalchemy import select

from backend.app.auth.dependencies import (
    StaleAuthorizationError,
    build_request_context_dependency,
    extract_bearer_token,
)
from backend.app.auth.oidc import OidcConfiguration, PyJwtOidcValidator
from backend.app.auth.resolver import SqlAlchemyRequestContextResolver
from backend.app.auth.session import local_oidc_sessions
from backend.app.core.config import Settings
from backend.app.documents.ingestion import DocumentService
from backend.app.documents.persistence import (
    DocumentRecord,
    DocumentVersionRecord,
    make_session_factory,
)
from backend.app.rag.citations import CitationFormatter
from backend.app.rag.context import ContextBuilder
from backend.app.rag.embeddings import HashEmbeddingService
from backend.app.rag.generation import ExtractiveGenerationService
from backend.app.rag.retrieval import QdrantRetriever, RetrievalScope
from backend.app.rag.service import QueryService
from backend.app.security.analyzer import InputSecurityAnalyzer
from backend.app.security.audit import SecurityEventSink, SqlAlchemySecurityEventSink
from backend.app.security.context_guard import ContextSecurityGuard
from backend.app.security.policy import DeterministicSecurityPolicy


@lru_cache
def get_settings() -> Settings:
    return Settings()


def _canonical_role_ids(value: str) -> frozenset[str] | None:
    """Parse the persisted role ACL using its authorization semantics.

    Role ACL order is not significant.  Malformed or empty persisted ACLs are
    deliberately ineligible rather than being interpreted permissively.
    """
    try:
        roles = json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    if not isinstance(roles, list) or not roles:
        return None
    if any(not isinstance(role, str) or not role.strip() for role in roles):
        return None
    return frozenset(roles)


def make_authoritative_version_validator(
    session_factory: Callable,
) -> Callable[[list[str], RetrievalScope], set[str]]:
    """Return the batched PostgreSQL admission check for Qdrant candidates.

    Qdrant is a derived index: its payload narrows the candidate set only.
    This validator is the final lifecycle and authorization authority.
    """

    def authoritative_version_ids(version_ids: list[str], scope: RetrievalScope) -> set[str]:
        if not version_ids:
            return set()
        with session_factory() as session:
            rows = session.execute(
                select(DocumentVersionRecord, DocumentRecord)
                .join(DocumentRecord, DocumentVersionRecord.document_id == DocumentRecord.id)
                .where(DocumentVersionRecord.id.in_(version_ids))
            ).all()
        eligible: set[str] = set()
        for version, document in rows:
            document_roles = _canonical_role_ids(document.allowed_role_ids_json)
            version_roles = _canonical_role_ids(version.allowed_role_ids_json)
            if (
                document.current_version_id == version.id
                and version.current_version
                and document.status == "INDEXED"
                and version.status == "INDEXED"
                and version.index_state == "INDEXED"
                and document.tenant_id == scope.tenant_id
                and version.tenant_id == scope.tenant_id
                # A version is an immutable snapshot of the document access
                # boundary.  Compare ACL meaning, not JSON serialization.
                and version.classification == document.classification
                and version.classification in scope.allowed_classifications
                and version.department == document.department
                and version.authorization_metadata_version
                == document.authorization_metadata_version
                and document_roles is not None
                and document_roles == version_roles
                and bool(set(scope.role_ids).intersection(document_roles))
            ):
                eligible.add(version.id)
        return eligible

    return authoritative_version_ids


def get_query_service() -> QueryService:
    settings = get_settings()

    return QueryService(
        embeddings=HashEmbeddingService(),
        retriever=QdrantRetriever(
            QdrantClient(url=settings.qdrant_url),
            settings.qdrant_collection,
            make_authoritative_version_validator(get_document_session_factory()),
        ),
        context_builder=ContextBuilder(
            max_chunks=settings.rag_top_k, max_context_tokens=settings.rag_max_context_tokens
        ),
        generator=ExtractiveGenerationService(),
        citations=CitationFormatter(),
        top_k=settings.rag_top_k,
        min_score=settings.rag_min_retrieval_score,
        dev_trace=settings.ragfort_dev_trace,
        context_guard=ContextSecurityGuard(),
    )


@lru_cache
def get_input_security_analyzer() -> InputSecurityAnalyzer:
    return InputSecurityAnalyzer()


@lru_cache
def get_security_policy() -> DeterministicSecurityPolicy:
    return DeterministicSecurityPolicy()


@lru_cache
def get_security_event_sink() -> SecurityEventSink:
    return SqlAlchemySecurityEventSink(get_document_session_factory())


@lru_cache
def get_document_session_factory():
    return make_session_factory(get_settings().database_url)


def get_document_service() -> DocumentService:
    settings = get_settings()
    return DocumentService(
        get_document_session_factory(),
        HashEmbeddingService(),
        QdrantRetriever(QdrantClient(url=settings.qdrant_url), settings.qdrant_collection),
    )


@lru_cache
def get_request_context_dependency():
    """Build the only application path from a bearer token to trusted context."""
    settings = get_settings()
    configuration = OidcConfiguration(
        issuer=settings.oidc_issuer,
        audience=settings.oidc_audience,
        jwks_url=settings.oidc_jwks_url,
        algorithms=settings.oidc_algorithms,
        tenant_claim=settings.oidc_tenant_claim,
        authorization_epoch_claim=settings.oidc_authorization_epoch_claim,
    )
    return build_request_context_dependency(
        PyJwtOidcValidator(configuration),
        SqlAlchemyRequestContextResolver(get_document_session_factory()),
    )


def require_request_context(
    authorization: str | None = Header(default=None),
    ragfort_session: str | None = Cookie(default=None),
):
    """Late-bound dependency so unset local OIDC config fails safely per request."""
    # Check the caller supplied a credential before touching provider configuration.
    token = (
        extract_bearer_token(authorization)
        if authorization
        else local_oidc_sessions.token(ragfort_session)
    )
    if token is None:
        extract_bearer_token(None)
    context = get_request_context_dependency()(f"Bearer {token}")
    if not authorization:
        session_epoch = local_oidc_sessions.epoch(ragfort_session)
        if session_epoch != context.authorization_epoch:
            local_oidc_sessions.revoke(ragfort_session)
            raise StaleAuthorizationError()
    return context
