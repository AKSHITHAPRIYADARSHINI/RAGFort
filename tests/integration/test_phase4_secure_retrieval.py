"""Phase 4 negative retrieval checks using Qdrant's in-memory engine.

These tests exercise the provider filter itself.  They are intentionally not
post-retrieval Python authorization tests: every forbidden point must be
excluded by the Qdrant query filter before it can become a retrieval result or
an application citation.
"""

import json
from pathlib import Path

import pytest
from qdrant_client import QdrantClient

from backend.app.core.dependencies import make_authoritative_version_validator
from backend.app.documents.ingestion import DocumentService
from backend.app.documents.models import DocumentAccessAssignment, DocumentStatus
from backend.app.documents.persistence import (
    DocumentRecord,
    DocumentVersionRecord,
    make_session_factory,
)
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
    RetrievalUnavailableError,
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


def _real_lifecycle_services(tmp_path: Path):
    """Create the real persistence, indexing, and secured retrieval path."""
    factory = make_session_factory(f"sqlite:///{tmp_path / 'stale-vector.db'}")
    embeddings = HashEmbeddingService()
    client = QdrantClient(path=":memory:")
    collection = "phase4_stale_vector_lifecycle"
    index = QdrantRetriever(client, collection)
    documents = DocumentService(factory, embeddings, index)
    secured_retriever = QdrantRetriever(
        client, collection, make_authoritative_version_validator(factory)
    )
    return (
        factory,
        embeddings,
        client,
        index,
        documents,
        _service(secured_retriever),
        secured_retriever,
    )


def _indexed_document(documents: DocumentService, marker: str) -> dict:
    uploaded = documents.upload(
        f"{marker}.txt",
        "text/plain",
        f"The controlled lifecycle marker is {marker}.".encode(),
        access=DocumentAccessAssignment("tenant_acme", ("finance_reader",), "finance"),
    )
    return documents.approve(uploaded["document_id"])


def _scope() -> RetrievalScope:
    return RetrievalScope(
        "tenant_acme", "acme_finance", ("PUBLIC", "INTERNAL", "CONFIDENTIAL"), ("finance_reader",)
    )


@pytest.mark.parametrize(
    ("operation", "expected_status", "marker"),
    [
        ("quarantine", DocumentStatus.QUARANTINED, "STALE-QUARANTINE-ZEPHYR-92841"),
        # The established lifecycle records a failed index deletion as
        # DELETION_PENDING, which is an authoritative non-retrievable state.
        ("delete", DocumentStatus.DELETION_PENDING, "STALE-DELETE-BASIL-51729"),
    ],
)
def test_real_lifecycle_revalidation_rejects_qdrant_vectors_left_after_delete_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
    expected_status: str,
    marker: str,
) -> None:
    factory, embeddings, _client, index, documents, query, secured_retriever = (
        _real_lifecycle_services(tmp_path)
    )
    subject = _indexed_document(documents, marker)
    positive = _indexed_document(documents, "CURRENT-LANTERN-64173")
    scope = _scope()

    assert query.query(f"What is {marker}?", scope).answer_status == "grounded"

    def failed_qdrant_delete(_filters) -> None:
        raise RetrievalUnavailableError("fault-injected Qdrant deletion failure")

    monkeypatch.setattr(index, "delete_by_filter", failed_qdrant_delete)
    getattr(documents, operation)(subject["document_id"])
    with factory() as session:
        document = session.get(DocumentRecord, subject["document_id"])
        version = session.get(DocumentVersionRecord, subject["version_id"])
        assert document.status == expected_status
        assert version.status == expected_status

    # The unmodified Qdrant point still looks indexed and remains a candidate
    # if queried directly; only the secured path may admit final results.
    raw_candidates = index.search(embeddings.embed_query(marker), 5)
    assert subject["version_id"] in {item.metadata["version_id"] for item in raw_candidates}

    outcome = query.query(f"What is {marker}?", scope)
    assert outcome.answer_status == "insufficient_context"
    assert outcome.answer is None
    assert outcome.sources == ()
    secured_candidates = secured_retriever.search(embeddings.embed_query(marker), 5, scope)
    assert subject["version_id"] not in {
        item.metadata["version_id"] for item in secured_candidates
    }

    # Positive control: authoritative revalidation still admits an eligible,
    # current, same-tenant document through the same secured query path.
    allowed = query.query("What is CURRENT-LANTERN-64173?", scope)
    assert allowed.answer_status == "grounded"
    assert [source.document_id for source in allowed.sources] == [positive["document_id"]]


def test_authoritative_validation_unavailable_fails_closed_after_qdrant_candidates(
    tmp_path: Path,
) -> None:
    _factory, embeddings, client, _index, documents, _query, _retriever = _real_lifecycle_services(
        tmp_path
    )
    subject = _indexed_document(documents, "POSTGRES-VALIDATION-OUTAGE-92841")

    def unavailable_session_factory():
        raise RuntimeError("PostgreSQL unavailable")

    retriever = QdrantRetriever(
        client,
        "phase4_stale_vector_lifecycle",
        make_authoritative_version_validator(unavailable_session_factory),
    )
    query = _service(retriever)
    with pytest.raises(RetrievalUnavailableError, match="Authoritative lifecycle validation"):
        query.query("What is POSTGRES-VALIDATION-OUTAGE-92841?", _scope())

    # Establish that Qdrant did have the candidate; the failure is solely the
    # authoritative decision boundary, which must never produce an answer.
    assert subject["version_id"] in {
        item.metadata["version_id"]
        for item in QdrantRetriever(client, "phase4_stale_vector_lifecycle").search(
            embeddings.embed_query("POSTGRES-VALIDATION-OUTAGE-92841"), 5
        )
    }
