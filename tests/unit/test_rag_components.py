from backend.app.rag.chunking import DocumentChunker
from backend.app.rag.citations import CitationFormatter
from backend.app.rag.context import ContextBuilder
from backend.app.rag.models import Document, RetrievalResult


def test_chunk_ids_are_stable_and_metadata_is_preserved() -> None:
    document = Document(
        "doc_remote", "Remote Work", "fixture", "1", "A policy sentence. " * 20, "Policy"
    )
    chunker = DocumentChunker(chunk_size_chars=80, overlap_chars=10)

    first = chunker.chunk(document)
    second = chunker.chunk(document)

    assert [chunk.chunk_id for chunk in first] == [chunk.chunk_id for chunk in second]
    assert first[0].metadata["title"] == "Remote Work"


def test_context_keeps_complete_chunks_and_citations_derive_from_it() -> None:
    results = [
        RetrievalResult(
            "chunk_a",
            "doc_a",
            "A" * 100,
            0.9,
            {"title": "Policy A", "source": "fixture", "section": "One"},
        ),
        RetrievalResult(
            "chunk_b", "doc_b", "B" * 100, 0.8, {"title": "Policy B", "source": "fixture"}
        ),
    ]
    context = ContextBuilder(max_chunks=5, max_context_tokens=40).build(results)

    assert [chunk.chunk_id for chunk in context.chunks] == ["chunk_a"]
    citations = CitationFormatter().format(context)
    assert citations[0].chunk_id == "chunk_a"
    assert citations[0].document_id == "doc_a"
