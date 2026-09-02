import pytest

from backend.app.rag.citations import CitationFormatter
from backend.app.rag.context import ContextBuilder
from backend.app.rag.embeddings import HashEmbeddingService
from backend.app.rag.generation import ExtractiveGenerationService
from backend.app.rag.retrieval import RetrievalScope, RetrievalUnavailableError
from backend.app.rag.service import QueryService


class EmptyRetriever:
    def search(self, *_args, **_kwargs):
        return []


class FailingRetriever:
    def search(self, *_args, **_kwargs):
        raise RetrievalUnavailableError("unavailable")


class UnrelatedRetriever:
    def search(self, *_args, **_kwargs):
        from backend.app.rag.models import RetrievalResult

        return [
            RetrievalResult(
                "chunk_unrelated",
                "doc_unrelated",
                "Vacation days require approval.",
                0.99,
                {"title": "Vacation", "source": "fixture"},
            )
        ]


def build_service(retriever):
    return QueryService(
        HashEmbeddingService(),
        retriever,
        ContextBuilder(),
        ExtractiveGenerationService(),
        CitationFormatter(),
        top_k=5,
        min_score=0.1,
    )


def test_empty_retrieval_returns_insufficient_context_without_generation() -> None:
    result = build_service(EmptyRetriever()).query("What is unknown?")

    assert result.answer_status == "insufficient_context"
    assert result.sources == ()


def test_retrieval_failure_propagates_without_fallback() -> None:
    with pytest.raises(RetrievalUnavailableError):
        build_service(FailingRetriever()).query("What is unknown?")


def test_unrelated_retrieval_does_not_claim_grounded_evidence() -> None:
    result = build_service(UnrelatedRetriever()).query("What is the company stock price?")

    assert result.answer_status == "insufficient_context"


def test_query_forwards_only_the_trusted_scope_to_retrieval() -> None:
    class ScopeCapturingRetriever:
        received_scope = None

        def search(self, _vector, _top_k, scope=None):
            self.received_scope = scope
            return []

    retriever = ScopeCapturingRetriever()
    scope = RetrievalScope("tenant_a", "user_a", ("INTERNAL",), ("employee",))

    result = build_service(retriever).query("What is unknown?", scope)

    assert result.answer_status == "insufficient_context"
    assert retriever.received_scope == scope
