from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Protocol
from uuid import NAMESPACE_URL, uuid5

from qdrant_client import QdrantClient, models

from backend.app.rag.models import DocumentChunk, RetrievalResult

PHASE4_SECURITY_METADATA_VERSION = "phase4-v1"
REQUIRED_PHASE4_PAYLOAD_FIELDS = frozenset(
    {
        "tenant_id",
        "classification",
        "approval_status",
        "index_state",
        "document_status",
        "current_version",
        "security_metadata_version",
    }
)


class RetrievalUnavailableError(RuntimeError):
    pass


@dataclass(frozen=True)
class RetrievalScope:
    """A policy-owned scope for a single retrieval decision.

    This contract deliberately contains only values derived by a trusted policy
    service. It is not an HTTP request model and must never be populated from
    client-supplied tenant, role, or classification values.
    """

    tenant_id: str
    user_id: str
    allowed_classifications: tuple[str, ...]
    role_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.tenant_id or not self.user_id or not self.allowed_classifications:
            raise ValueError("A retrieval scope requires tenant, user, and classification values.")


class Retriever(Protocol):
    def search(
        self, query_vector: list[float], top_k: int, scope: RetrievalScope | None = None
    ) -> list[RetrievalResult]: ...


class QdrantRetriever:
    """Qdrant adapter. Callers may pass only trusted, server-derived filters."""

    def __init__(self, client: QdrantClient, collection: str) -> None:
        self.client = client
        self.collection = collection

    @staticmethod
    def _equality_filter(filters: Mapping[str, Any] | None) -> models.Filter | None:
        if not filters:
            return None
        return models.Filter(
            must=[
                models.FieldCondition(key=key, match=models.MatchValue(value=value))
                for key, value in filters.items()
            ]
        )

    @staticmethod
    def _scope_filter(scope: RetrievalScope) -> models.Filter:
        """Build the mandatory Phase 4 pre-retrieval filter.

        Qdrant only receives a scope produced on the server. The same checks
        are repeated on returned payloads because Qdrant is a derived index,
        not the authorization authority.
        """
        # At least one explicit, server-owned ACL must match.  Tenant equality
        # alone is deliberately insufficient: a point without an ACL is a
        # legacy/incomplete point and therefore cannot become queryable.
        audience_conditions: list[models.FieldCondition] = [
            models.FieldCondition(
                key="allowed_user_ids", match=models.MatchValue(value=scope.user_id)
            ),
        ]
        if scope.role_ids:
            audience_conditions.append(
                models.FieldCondition(
                    key="allowed_role_ids", match=models.MatchAny(any=list(scope.role_ids))
                )
            )
        return models.Filter(
            must=[
                models.FieldCondition(
                    key="tenant_id", match=models.MatchValue(value=scope.tenant_id)
                ),
                models.FieldCondition(
                    key="approval_status", match=models.MatchValue(value="approved")
                ),
                models.FieldCondition(
                    key="index_state", match=models.MatchValue(value="INDEXED")
                ),
                models.FieldCondition(
                    key="document_status", match=models.MatchValue(value="INDEXED")
                ),
                models.FieldCondition(
                    key="current_version", match=models.MatchValue(value=True)
                ),
                models.FieldCondition(
                    key="security_metadata_version",
                    match=models.MatchValue(value=PHASE4_SECURITY_METADATA_VERSION),
                ),
                models.FieldCondition(
                    key="classification",
                    match=models.MatchAny(any=list(scope.allowed_classifications)),
                ),
            ],
            min_should=models.MinShould(conditions=audience_conditions, min_count=1),
        )

    @staticmethod
    def _matches_scope(payload: Mapping[str, Any], scope: RetrievalScope) -> bool:
        """Fail closed for legacy, incomplete, or inconsistent index payloads."""
        if not REQUIRED_PHASE4_PAYLOAD_FIELDS.issubset(payload):
            return False
        if (
            payload.get("tenant_id") != scope.tenant_id
            or payload.get("approval_status") != "approved"
            or payload.get("index_state") != "INDEXED"
            or payload.get("document_status") != "INDEXED"
            or payload.get("current_version") is not True
            or payload.get("security_metadata_version") != PHASE4_SECURITY_METADATA_VERSION
            or payload.get("classification") not in scope.allowed_classifications
        ):
            return False
        allowed_users = payload.get("allowed_user_ids", [])
        if isinstance(allowed_users, list) and scope.user_id in allowed_users:
            return True
        allowed_roles = payload.get("allowed_role_ids", [])
        return (
            isinstance(allowed_roles, list)
            and bool(set(scope.role_ids).intersection(str(role) for role in allowed_roles))
        )

    def search(
        self, query_vector: list[float], top_k: int, scope: RetrievalScope | None = None
    ) -> list[RetrievalResult]:
        try:
            response = self.client.query_points(
                collection_name=self.collection,
                query=query_vector,
                limit=top_k,
                query_filter=self._scope_filter(scope) if scope is not None else None,
                with_payload=True,
            )
        except Exception as error:  # backend boundary maps provider exceptions safely
            raise RetrievalUnavailableError("Retrieval service is unavailable.") from error
        results: list[RetrievalResult] = []
        for point in response.points:
            payload = point.payload or {}
            required = {"chunk_id", "document_id", "text", "title", "source"}
            if not required.issubset(payload):
                continue
            if scope is not None and not self._matches_scope(payload, scope):
                continue
            metadata = {
                key: value
                for key, value in payload.items()
                if key not in {"chunk_id", "document_id", "text"}
            }
            results.append(
                RetrievalResult(
                    chunk_id=str(payload["chunk_id"]),
                    document_id=str(payload["document_id"]),
                    text=str(payload["text"]),
                    score=float(point.score),
                    metadata=metadata,
                )
            )
        return results

    def upsert(self, chunks: list[DocumentChunk], vectors: list[list[float]]) -> None:
        points = []
        for chunk, vector in zip(chunks, vectors, strict=True):
            payload = {
                "chunk_id": chunk.chunk_id,
                "document_id": chunk.document_id,
                "chunk_index": chunk.chunk_index,
                "text": chunk.text,
                **chunk.metadata,
            }
            points.append(
                models.PointStruct(
                    id=str(uuid5(NAMESPACE_URL, chunk.chunk_id)), vector=vector, payload=payload
                )
            )
        try:
            self.client.upsert(collection_name=self.collection, points=points, wait=True)
        except Exception as error:
            raise RetrievalUnavailableError("Retrieval service is unavailable.") from error

    def delete_by_filter(self, filters: Mapping[str, Any]) -> None:
        try:
            self.client.delete(
                collection_name=self.collection,
                points_selector=models.FilterSelector(filter=self._equality_filter(filters)),
                wait=True,
            )
        except Exception as error:
            raise RetrievalUnavailableError("Retrieval service is unavailable.") from error

    def ensure_collection(self, dimension: int, reset: bool = False) -> None:
        try:
            exists = self.client.collection_exists(self.collection)
            if reset and exists:
                self.client.delete_collection(self.collection)
                exists = False
            if not exists:
                self.client.create_collection(
                    collection_name=self.collection,
                    vectors_config=models.VectorParams(
                        size=dimension, distance=models.Distance.COSINE
                    ),
                )
        except Exception as error:
            raise RetrievalUnavailableError("Retrieval service is unavailable.") from error
