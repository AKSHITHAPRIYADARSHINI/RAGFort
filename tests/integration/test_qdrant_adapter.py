from qdrant_client import QdrantClient

from backend.app.rag.chunking import DocumentChunker
from backend.app.rag.embeddings import HashEmbeddingService
from backend.app.rag.models import Document
from backend.app.rag.retrieval import QdrantRetriever, RetrievalScope


def test_qdrant_adapter_indexes_and_filters_deterministically() -> None:
    embedding = HashEmbeddingService()
    retriever = QdrantRetriever(QdrantClient(path=":memory:"), "test_rag")
    chunks = DocumentChunker().chunk(
        Document("doc_remote", "Remote Work", "fixture", "1", "Remote work allows three days.")
    )
    retriever.ensure_collection(embedding.dimension)
    retriever.upsert(chunks, embedding.embed_documents([chunk.text for chunk in chunks]))

    results = retriever.search(embedding.embed_query("remote work days"), 5)

    assert len(results) == 1
    assert results[0].chunk_id == chunks[0].chunk_id


def test_scoped_search_denies_legacy_and_cross_tenant_payloads() -> None:
    embedding = HashEmbeddingService()
    retriever = QdrantRetriever(QdrantClient(path=":memory:"), "test_scoped_rag")
    chunks = [
        DocumentChunker().chunk(
            Document("doc_legacy", "Legacy", "fixture", "1", "Remote work allows one day.")
        )[0],
        DocumentChunker().chunk(
            Document("doc_other", "Other Tenant", "fixture", "1", "Remote work allows two days.")
        )[0],
        DocumentChunker().chunk(
            Document("doc_allowed", "Allowed", "fixture", "1", "Remote work allows three days.")
        )[0],
    ]
    secured = [
        chunks[0],
        chunks[1].__class__(
            chunks[1].chunk_id,
            chunks[1].document_id,
            chunks[1].chunk_index,
            chunks[1].text,
            {
                **chunks[1].metadata,
                "tenant_id": "tenant_other",
                "approval_status": "approved",
                "index_state": "INDEXED",
                "current_version": True,
                "classification": "INTERNAL",
                "visibility": "tenant",
            },
        ),
        chunks[2].__class__(
            chunks[2].chunk_id,
            chunks[2].document_id,
            chunks[2].chunk_index,
            chunks[2].text,
            {
                **chunks[2].metadata,
                "tenant_id": "tenant_a",
                "approval_status": "approved",
                "index_state": "INDEXED",
                "current_version": True,
                "classification": "INTERNAL",
                "allowed_role_ids": ["employee"],
            },
        ),
    ]
    retriever.ensure_collection(embedding.dimension)
    retriever.upsert(secured, embedding.embed_documents([chunk.text for chunk in secured]))

    results = retriever.search(
        embedding.embed_query("remote work days"),
        5,
        RetrievalScope("tenant_a", "user_a", ("PUBLIC", "INTERNAL"), ("employee",)),
    )

    assert [result.document_id for result in results] == ["doc_allowed"]
