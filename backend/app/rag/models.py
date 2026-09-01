from dataclasses import dataclass, field
from typing import Any, Literal


@dataclass(frozen=True)
class Document:
    document_id: str
    title: str
    source: str
    version: str
    content: str
    section: str = ""


@dataclass(frozen=True)
class DocumentChunk:
    chunk_id: str
    document_id: str
    chunk_index: int
    text: str
    metadata: dict[str, Any]


@dataclass(frozen=True)
class RetrievalResult:
    chunk_id: str
    document_id: str
    text: str
    score: float
    metadata: dict[str, Any]


@dataclass(frozen=True)
class ContextPackage:
    chunks: tuple[RetrievalResult, ...]
    context_text: str
    estimated_tokens: int


@dataclass(frozen=True)
class GenerationResult:
    answer: str
    provider: str
    model: str
    duration_ms: float


@dataclass(frozen=True)
class SourceCitation:
    document_id: str
    chunk_id: str
    title: str
    source: str
    section: str | None = None


@dataclass(frozen=True)
class QueryOutcome:
    answer: str | None
    answer_status: Literal["grounded", "insufficient_context"]
    sources: tuple[SourceCitation, ...] = field(default_factory=tuple)
    trace: dict[str, Any] | None = None
