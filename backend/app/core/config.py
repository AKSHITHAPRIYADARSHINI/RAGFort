import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    database_url: str = os.getenv("DATABASE_URL", "sqlite:///./ragfort-documents.db")
    qdrant_url: str = os.getenv("QDRANT_URL", "http://localhost:6333")
    qdrant_collection: str = os.getenv("QDRANT_COLLECTION", "ragfort_phase2")
    embedding_model: str = os.getenv("EMBEDDING_MODEL", "hash-embedding-v1")
    rag_top_k: int = int(os.getenv("RAG_TOP_K", "5"))
    rag_max_context_tokens: int = int(os.getenv("RAG_MAX_CONTEXT_TOKENS", "1800"))
    rag_min_retrieval_score: float = float(os.getenv("RAG_MIN_RETRIEVAL_SCORE", "0.12"))
    rag_query_max_chars: int = int(os.getenv("RAG_QUERY_MAX_CHARS", "2000"))
    ragfort_dev_trace: bool = os.getenv("RAGFORT_DEV_TRACE", "false").lower() == "true"
