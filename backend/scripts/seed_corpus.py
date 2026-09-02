import argparse
import json
from pathlib import Path

from qdrant_client import QdrantClient

from backend.app.core.config import Settings
from backend.app.rag.chunking import DocumentChunker
from backend.app.rag.embeddings import HashEmbeddingService
from backend.app.rag.models import Document, DocumentChunk
from backend.app.rag.retrieval import PHASE4_SECURITY_METADATA_VERSION, QdrantRetriever

DEFAULT_PHASE4_ACCESS = {
    "tenant_id": "tenant_acme",
    "classification": "INTERNAL",
    "allowed_role_ids": ["viewer", "contributor", "reviewer", "admin"],
    "allowed_user_ids": [],
    "approval_status": "approved",
    "index_state": "INDEXED",
    "document_status": "INDEXED",
    "current_version": True,
    "security_metadata_version": PHASE4_SECURITY_METADATA_VERSION,
    "security_scan_status": "PASSED",
}


def _document_from_record(record: dict[str, object]) -> Document:
    return Document(
        document_id=str(record["document_id"]),
        title=str(record["title"]),
        source=str(record["source"]),
        version=str(record["version"]),
        content=str(record["content"]),
        section=str(record.get("section", "")),
    )


def _secure_chunks(chunker: DocumentChunker, record: dict[str, object]) -> list[DocumentChunk]:
    """Attach only controlled development fixture metadata before indexing.

    This is a reproducible development corpus, not the Phase 4 production
    reindexer.  Production document metadata is populated from PostgreSQL by
    the document lifecycle service.  Every point still carries the complete
    Phase 4 payload so a reset corpus cannot silently restore legacy vectors.
    """
    metadata = {**DEFAULT_PHASE4_ACCESS, **dict(record.get("access", {}))}
    metadata["version_id"] = f"{record['document_id']}:{record['version']}"
    return [
        DocumentChunk(
            chunk_id=chunk.chunk_id,
            document_id=chunk.document_id,
            chunk_index=chunk.chunk_index,
            text=chunk.text,
            metadata={**chunk.metadata, **metadata},
        )
        for chunk in chunker.chunk(_document_from_record(record))
    ]


def load_seed_chunks() -> tuple[list[dict[str, object]], list[DocumentChunk]]:
    """Load the baseline corpus plus isolated Phase 4 tenant test fixtures."""
    repository_root = Path(__file__).resolve().parents[2]
    corpus_directory = repository_root / "evaluation" / "corpus"
    baseline = json.loads((corpus_directory / "documents.json").read_text(encoding="utf-8"))
    phase4 = json.loads(
        (corpus_directory / "phase4-security-documents.json").read_text(encoding="utf-8")
    )
    records = [*baseline, *phase4]
    chunker = DocumentChunker()
    return records, [chunk for record in records for chunk in _secure_chunks(chunker, record)]


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed the Phase 2 development corpus into Qdrant.")
    parser.add_argument(
        "--reset", action="store_true", help="Explicitly recreate the configured collection."
    )
    args = parser.parse_args()
    settings = Settings()
    records, chunks = load_seed_chunks()
    embeddings = HashEmbeddingService()
    retriever = QdrantRetriever(QdrantClient(url=settings.qdrant_url), settings.qdrant_collection)
    retriever.ensure_collection(embeddings.dimension, reset=args.reset)
    retriever.upsert(chunks, embeddings.embed_documents([chunk.text for chunk in chunks]))
    message = f"Seeded {len(records)} documents and {len(chunks)} chunks"
    print(f"{message} into {settings.qdrant_collection}.")


if __name__ == "__main__":
    main()
