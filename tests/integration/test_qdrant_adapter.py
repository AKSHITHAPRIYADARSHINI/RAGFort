from qdrant_client import QdrantClient

from backend.app.rag.chunking import DocumentChunker
from backend.app.rag.embeddings import HashEmbeddingService
from backend.app.rag.models import Document
from backend.app.rag.retrieval import QdrantRetriever


def test_qdrant_adapter_indexes_and_filters_deterministically() -> None:
    embedding = HashEmbeddingService()
    retriever = QdrantRetriever(QdrantClient(path=":memory:"), "test_rag")
    chunks = DocumentChunker().chunk(
        Document("doc_remote", "Remote Work", "fixture", "1", "Remote work allows three days.")
    )
    retriever.ensure_collection(embedding.dimension)
    retriever.upsert(chunks, embedding.embed_documents([chunk.text for chunk in chunks]))

    results = retriever.search(
        embedding.embed_query("remote work days"), 5, {"document_id": "doc_remote"}
    )

    assert len(results) == 1
    assert results[0].chunk_id == chunks[0].chunk_id
