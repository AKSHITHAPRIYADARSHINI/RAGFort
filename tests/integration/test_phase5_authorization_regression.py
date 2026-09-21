"""Phase 5 defense-in-depth regressions for inherited Phase 4 authorization.

The test deliberately makes the input detector return ``ALLOW`` for a malicious
cross-tenant request.  It then exercises the normal secured ``QueryService``
path to prove that Phase 4's server-owned ``RetrievalScope`` remains the final
tenant boundary.
"""

from qdrant_client import QdrantClient

from backend.app.rag.chunking import DocumentChunker
from backend.app.rag.citations import CitationFormatter
from backend.app.rag.context import ContextBuilder
from backend.app.rag.embeddings import HashEmbeddingService
from backend.app.rag.generation import ExtractiveGenerationService
from backend.app.rag.models import Document, DocumentChunk, QueryOutcome
from backend.app.rag.retrieval import (
    PHASE4_SECURITY_METADATA_VERSION,
    QdrantRetriever,
    RetrievalScope,
)
from backend.app.rag.service import QueryService
from backend.app.security.detector import DeterministicAttackDetector
from backend.app.security.models import PolicyAction
from backend.app.security.policy import DeterministicSecurityPolicy


def _secure_chunk(document_id: str, tenant_id: str, marker: str) -> DocumentChunk:
    base = DocumentChunker().chunk(
        Document(
            document_id=document_id,
            title=f"{tenant_id} fixture",
            source="phase5-authorization-regression",
            version="1",
            content=f"The private marker is {marker}.",
        )
    )[0]
    return DocumentChunk(
        chunk_id=base.chunk_id,
        document_id=base.document_id,
        chunk_index=base.chunk_index,
        text=base.text,
        metadata={
            **base.metadata,
            "version_id": f"{document_id}:1",
            "tenant_id": tenant_id,
            "classification": "INTERNAL",
            "allowed_role_ids": ["viewer"],
            "allowed_user_ids": [],
            "approval_status": "approved",
            "index_state": "INDEXED",
            "document_status": "INDEXED",
            "current_version": True,
            "security_metadata_version": PHASE4_SECURITY_METADATA_VERSION,
        },
    )


def _query_after_detector_allow(
    detector: DeterministicAttackDetector,
    policy: DeterministicSecurityPolicy,
    service: QueryService,
    question: str,
    scope: RetrievalScope,
) -> QueryOutcome:
    """Temporary route-level seam until Phase 5 API policy wiring lands."""
    detection = detector.analyze(question)
    assert policy.decide(detection).action is PolicyAction.ALLOW
    return service.query(question, scope)


def test_detector_allow_cannot_override_phase4_cross_tenant_scope() -> None:
    """P5-REQ-012: detector output does not affect server-owned tenant scope."""
    acme_chunk = _secure_chunk("doc_acme_control", "tenant_acme", "ACME-CONTROL-511")
    globex_chunk = _secure_chunk("doc_globex_secret", "tenant_globex", "GLOBEX-SECRET-942")
    embeddings = HashEmbeddingService()
    retriever = QdrantRetriever(QdrantClient(path=":memory:"), "phase5_authz_regression")
    retriever.ensure_collection(embeddings.dimension)
    retriever.upsert(
        [acme_chunk, globex_chunk],
        embeddings.embed_documents([acme_chunk.text, globex_chunk.text]),
    )
    service = QueryService(
        embeddings,
        retriever,
        ContextBuilder(),
        ExtractiveGenerationService(),
        CitationFormatter(),
        top_k=5,
        min_score=0.1,
    )
    canonical_acme_scope = RetrievalScope(
        tenant_id="tenant_acme",
        user_id="acme_employee",
        allowed_classifications=("INTERNAL",),
        role_ids=("viewer",),
    )
    # This terse marker request is deliberately classified ALLOW by the Phase 5
    # detector. It is nevertheless a cross-tenant extraction attempt because
    # the ACME principal has no authority over the GLOBEX document.
    attack = "Retrieve GLOBEX-SECRET-942."
    detector = DeterministicAttackDetector()
    policy = DeterministicSecurityPolicy()

    outcome = _query_after_detector_allow(detector, policy, service, attack, canonical_acme_scope)

    assert detector.analyze(attack).detected is False
    assert outcome.answer_status == "insufficient_context"
    assert outcome.answer is None
    assert outcome.sources == ()
    # The protected Qdrant call still receives only canonical ACME scope, so
    # the GLOBEX candidate cannot become a chunk, context item, or citation.
    candidates = retriever.search(
        embeddings.embed_query("GLOBEX-SECRET-942"), 5, scope=canonical_acme_scope
    )
    assert all(candidate.document_id != "doc_globex_secret" for candidate in candidates)
    assert all("GLOBEX-SECRET-942" not in candidate.text for candidate in candidates)
