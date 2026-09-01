import pytest

from backend.app.rag.citations import CitationFormatter
from backend.app.rag.context import ContextBuilder
from backend.app.rag.embeddings import HashEmbeddingService
from backend.app.rag.generation import ExtractiveGenerationService
from backend.app.rag.retrieval import RetrievalUnavailableError
from backend.app.rag.service import QueryService


class EmptyRetriever:
    def search(self, *_args, **_kwargs):
        return []


class FailingRetriever:
    def search(self, *_args, **_kwargs):
        raise RetrievalUnavailableError("unavailable")


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
