import argparse
import json
from pathlib import Path

from qdrant_client import QdrantClient

from backend.app.core.config import Settings
from backend.app.rag.chunking import DocumentChunker
from backend.app.rag.embeddings import HashEmbeddingService
from backend.app.rag.models import Document
from backend.app.rag.retrieval import QdrantRetriever


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed the Phase 2 development corpus into Qdrant.")
    parser.add_argument(
        "--reset", action="store_true", help="Explicitly recreate the configured collection."
    )
    args = parser.parse_args()
    settings = Settings()
    records = json.loads(Path("evaluation/corpus/documents.json").read_text(encoding="utf-8"))
    documents = [Document(**record) for record in records]
    chunker = DocumentChunker()
    chunks = [chunk for document in documents for chunk in chunker.chunk(document)]
    embeddings = HashEmbeddingService()
    retriever = QdrantRetriever(QdrantClient(url=settings.qdrant_url), settings.qdrant_collection)
    retriever.ensure_collection(embeddings.dimension, reset=args.reset)
    retriever.upsert(chunks, embeddings.embed_documents([chunk.text for chunk in chunks]))
    message = f"Seeded {len(documents)} documents and {len(chunks)} chunks"
    print(f"{message} into {settings.qdrant_collection}.")


if __name__ == "__main__":
    main()
