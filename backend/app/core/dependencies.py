from functools import lru_cache

from qdrant_client import QdrantClient

from backend.app.core.config import Settings
from backend.app.rag.citations import CitationFormatter
from backend.app.rag.context import ContextBuilder
from backend.app.rag.embeddings import HashEmbeddingService
from backend.app.rag.generation import ExtractiveGenerationService
from backend.app.rag.retrieval import QdrantRetriever
from backend.app.rag.service import QueryService


@lru_cache
def get_settings() -> Settings:
    return Settings()


def get_query_service() -> QueryService:
    settings = get_settings()
    return QueryService(
        embeddings=HashEmbeddingService(),
        retriever=QdrantRetriever(
            QdrantClient(url=settings.qdrant_url), settings.qdrant_collection
        ),
        context_builder=ContextBuilder(
            max_chunks=settings.rag_top_k, max_context_tokens=settings.rag_max_context_tokens
        ),
        generator=ExtractiveGenerationService(),
        citations=CitationFormatter(),
        top_k=settings.rag_top_k,
        min_score=settings.rag_min_retrieval_score,
        dev_trace=settings.ragfort_dev_trace,
    )
