from collections.abc import Mapping
from typing import Any, Protocol

from qdrant_client import QdrantClient, models

from backend.app.rag.models import DocumentChunk, RetrievalResult


class RetrievalUnavailableError(RuntimeError):
    pass


class Retriever(Protocol):
    def search(
        self, query_vector: list[float], top_k: int, filters: Mapping[str, Any] | None = None
    ) -> list[RetrievalResult]: ...


class QdrantRetriever:
    """Qdrant adapter. Callers may pass only trusted, server-derived filters."""

    def __init__(self, client: QdrantClient, collection: str) -> None:
        self.client = client
        self.collection = collection

    @staticmethod
    def _filter(filters: Mapping[str, Any] | None) -> models.Filter | None:
        if not filters:
            return None
        return models.Filter(
            must=[
                models.FieldCondition(key=key, match=models.MatchValue(value=value))
                for key, value in filters.items()
            ]
        )

    def search(
        self, query_vector: list[float], top_k: int, filters: Mapping[str, Any] | None = None
    ) -> list[RetrievalResult]:
        try:
            response = self.client.query_points(
                collection_name=self.collection,
                query=query_vector,
                limit=top_k,
                query_filter=self._filter(filters),
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
                    id=chunk.chunk_id.removeprefix("chunk_"), vector=vector, payload=payload
                )
            )
        try:
            self.client.upsert(collection_name=self.collection, points=points, wait=True)
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
