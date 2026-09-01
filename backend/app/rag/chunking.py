import hashlib
import re

from backend.app.rag.models import Document, DocumentChunk


def normalize_text(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


class DocumentChunker:
    """Deterministic character chunker; later phases may add secure-ingestion metadata."""

    def __init__(self, chunk_size_chars: int = 1600, overlap_chars: int = 300) -> None:
        if chunk_size_chars <= 0 or overlap_chars < 0 or overlap_chars >= chunk_size_chars:
            raise ValueError("Chunk size must be positive and overlap smaller than chunk size.")
        self.chunk_size_chars = chunk_size_chars
        self.overlap_chars = overlap_chars

    def chunk(self, document: Document) -> list[DocumentChunk]:
        text = normalize_text(document.content)
        chunks: list[DocumentChunk] = []
        start = 0
        while start < len(text):
            end = min(len(text), start + self.chunk_size_chars)
            if end < len(text):
                boundary = text.rfind(". ", start, end)
                if boundary > start:
                    end = boundary + 1
            content = text[start:end].strip()
            if content:
                index = len(chunks)
                digest = hashlib.sha256(
                    f"{document.document_id}:{document.version}:{index}".encode()
                ).hexdigest()[:24]
                chunks.append(
                    DocumentChunk(
                        chunk_id=f"chunk_{digest}",
                        document_id=document.document_id,
                        chunk_index=index,
                        text=content,
                        metadata={
                            "title": document.title,
                            "source": document.source,
                            "section": document.section,
                            "version": document.version,
                        },
                    )
                )
            if end >= len(text):
                break
            start = end - self.overlap_chars
        return chunks
