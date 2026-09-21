"""Phase 4 negative retrieval checks using Qdrant's in-memory engine.

These tests exercise the provider filter itself.  They are intentionally not
post-retrieval Python authorization tests: every forbidden point must be
excluded by the Qdrant query filter before it can become a retrieval result or
an application citation.
"""

import json
from pathlib import Path

from qdrant_client import QdrantClient

from backend.app.rag.chunking import DocumentChunker
from backend.app.rag.citations import CitationFormatter
from backend.app.rag.context import ContextBuilder
from backend.app.rag.embeddings import HashEmbeddingService
from backend.app.rag.generation import ExtractiveGenerationService
from backend.app.rag.models import Document, DocumentChunk
from backend.app.rag.retrieval import (
    PHASE4_SECURITY_METADATA_VERSION,
    QdrantRetriever,
    RetrievalScope,
)
from backend.app.rag.service import QueryService
from backend.scripts.seed_corpus import DEFAULT_PHASE4_ACCESS


def _records() -> list[dict[str, object]]:
    path = Path("evaluation/corpus/phase4-security-documents.json")
    return json.loads(path.read_text(encoding="utf-8"))


def _chunk(record: dict[str, object], **overrides: object) -> DocumentChunk:
    document = Document(
        document_id=str(record["document_id"]),
        title=str(record["title"]),
        source=str(record["source"]),
        version=str(record["version"]),
        content=str(record["content"]),
        section=str(record.get("section", "")),
    )
    chunk = DocumentChunker().chunk(document)[0]
    access = {**DEFAULT_PHASE4_ACCESS, **dict(record.get("access", {})), **overrides}
    access["version_id"] = f"{document.document_id}:{document.version}"
    return DocumentChunk(
        chunk.chunk_id,
        chunk.document_id,
        chunk.chunk_index,
        chunk.text,
        {**chunk.metadata, **access},
    )


def _service(retriever: QdrantRetriever) -> QueryService:
    return QueryService(
        HashEmbeddingService(),
        retriever,
        ContextBuilder(),
        ExtractiveGenerationService(),
        CitationFormatter(),
        top_k=5,
        min_score=0.1,
    )


def _seed(
    chunks: list[DocumentChunk], authoritative_version_ids=None
) -> tuple[HashEmbeddingService, QdrantRetriever]:
    embeddings = HashEmbeddingService()
    retriever = QdrantRetriever(
        QdrantClient(path=":memory:"), "phase4_secure_retrieval", authoritative_version_ids
    )
    retriever.ensure_collection(embeddings.dimension)
    retriever.upsert(chunks, embeddings.embed_documents([chunk.text for chunk in chunks]))
    return embeddings, retriever


def test_missing_phase4_payload_metadata_is_nonqueryable_and_uncitable() -> None:
    legacy = DocumentChunker().chunk(
        Document(
            "doc_legacy_only",
            "Legacy Point",
            "legacy-fixture",
            "1",
            "Legacy-only marker LEGACY-MIST-204 must never be queryable in Phase 4.",
        )
    )[0]
    embeddings, retriever = _seed([legacy])
    scope = RetrievalScope("tenant_acme", "acme_employee", ("INTERNAL",), ("viewer",))

    results = retriever.search(embeddings.embed_query("LEGACY-MIST-204"), 5, scope)
    outcome = _service(retriever).query("What is LEGACY-MIST-204?", scope)

    assert results == []
    assert outcome.answer_status == "insufficient_context"
    assert outcome.sources == ()


def test_cross_tenant_marker_never_becomes_a_chunk_or_citation() -> None:
    chunks = [_chunk(record) for record in _records()]
    embeddings, retriever = _seed(chunks)
    acme_scope = RetrievalScope("tenant_acme", "acme_employee", ("PUBLIC", "INTERNAL"), ("viewer",))

    results = retriever.search(embeddings.embed_query("COBALT-RIVER-942"), 5, acme_scope)
    outcome = _service(retriever).query("What is COBALT-RIVER-942?", acme_scope)

    assert "doc_globex_marker" not in {item.document_id for item in results}
    assert all(source.document_id != "doc_globex_marker" for source in outcome.sources)
    assert outcome.answer_status == "insufficient_context"


def test_hr_cannot_retrieve_finance_but_finance_reader_can() -> None:
    chunks = [_chunk(record) for record in _records()]
    embeddings, retriever = _seed(chunks)
    hr_scope = RetrievalScope(
        "tenant_acme", "acme_hr", ("PUBLIC", "INTERNAL", "CONFIDENTIAL"), ("hr_reader",)
    )
    finance_scope = RetrievalScope(
        "tenant_acme", "acme_finance", ("PUBLIC", "INTERNAL", "CONFIDENTIAL"), ("finance_reader",)
    )

    hr_results = retriever.search(embeddings.embed_query("FINANCE-ORCHID-815"), 5, hr_scope)
    finance_outcome = _service(retriever).query("What is FINANCE-ORCHID-815?", finance_scope)
    hr_outcome = _service(retriever).query("What is FINANCE-ORCHID-815?", hr_scope)

    assert "doc_acme_finance" not in {item.document_id for item in hr_results}
    assert all(source.document_id != "doc_acme_finance" for source in hr_outcome.sources)
    assert hr_outcome.answer_status == "insufficient_context"
    assert finance_outcome.answer_status == "grounded"
    assert [source.document_id for source in finance_outcome.sources] == ["doc_acme_finance"]


def test_classification_and_unsafe_lifecycle_states_are_excluded_before_results() -> None:
    records = _records()
    restricted = next(
        record for record in records if record["document_id"] == "doc_acme_restricted"
    )
    finance = next(record for record in records if record["document_id"] == "doc_acme_finance")
    quarantined = _chunk(
        finance,
        document_status="QUARANTINED",
        index_state="QUARANTINED",
        approval_status="quarantined",
    )
    deleted = _chunk(
        finance,
        document_status="DELETED",
        index_state="DELETED",
        approval_status="deleted",
    )
    embeddings, retriever = _seed([_chunk(restricted), quarantined, deleted])
    admin_without_restricted = RetrievalScope(
        "tenant_acme",
        "acme_admin",
        ("PUBLIC", "INTERNAL", "CONFIDENTIAL"),
        ("admin", "finance_reader"),
    )
    privileged = RetrievalScope(
        "tenant_acme",
        "acme_admin",
        ("PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"),
        ("admin", "finance_reader", "restricted_reader"),
    )

    classification_results = retriever.search(
        embeddings.embed_query("RESTRICTED-CEDAR-619"), 5, admin_without_restricted
    )
    lifecycle_results = retriever.search(
        embeddings.embed_query("FINANCE-ORCHID-815"), 5, privileged
    )

    assert classification_results == []
    assert "doc_acme_finance" not in {item.document_id for item in lifecycle_results}
    assert PHASE4_SECURITY_METADATA_VERSION == "phase4-v1"


def test_authoritative_lifecycle_revalidation_excludes_stale_quarantined_and_deleted_vectors() -> (
    None
):
    finance = next(record for record in _records() if record["document_id"] == "doc_acme_finance")
    indexed = _chunk(finance)
    stale_quarantined = DocumentChunk(
        "stale-quarantined",
        indexed.document_id,
        1,
        indexed.text,
        {**indexed.metadata, "version_id": "doc_acme_finance:stale-quarantined"},
    )
    stale_deleted = DocumentChunk(
        "stale-deleted",
        indexed.document_id,
        2,
        indexed.text,
        {**indexed.metadata, "version_id": "doc_acme_finance:stale-deleted"},
    )
    allowed = {str(indexed.metadata["version_id"])}
    embeddings, retriever = _seed(
        [indexed, stale_quarantined, stale_deleted], lambda _ids, _scope: allowed
    )
    scope = RetrievalScope(
        "tenant_acme", "acme_finance", ("PUBLIC", "INTERNAL", "CONFIDENTIAL"), ("finance_reader",)
    )

    results = retriever.search(embeddings.embed_query("FINANCE-ORCHID-815"), 5, scope)
    outcome = _service(retriever).query("What is FINANCE-ORCHID-815?", scope)

    assert [result.metadata["version_id"] for result in results] == [indexed.metadata["version_id"]]
    assert [source.chunk_id for source in outcome.sources] == [indexed.chunk_id]
