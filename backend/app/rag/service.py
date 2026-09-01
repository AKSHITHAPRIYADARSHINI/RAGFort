import re
import time

from backend.app.rag.citations import CitationFormatter
from backend.app.rag.context import ContextBuilder
from backend.app.rag.embeddings import EmbeddingService, EmbeddingUnavailableError
from backend.app.rag.generation import GenerationService, GenerationUnavailableError
from backend.app.rag.models import QueryOutcome
from backend.app.rag.retrieval import Retriever


class QueryService:
    def __init__(
        self,
        embeddings: EmbeddingService,
        retriever: Retriever,
        context_builder: ContextBuilder,
        generator: GenerationService,
        citations: CitationFormatter,
        top_k: int,
        min_score: float,
        dev_trace: bool = False,
    ) -> None:
        self.embeddings = embeddings
        self.retriever = retriever
        self.context_builder = context_builder
        self.generator = generator
        self.citations = citations
        self.top_k = top_k
        self.min_score = min_score
        self.dev_trace = dev_trace

    def query(self, question: str) -> QueryOutcome:
        trace: dict[str, object] = {}
        try:
            started = time.perf_counter()
            vector = self.embeddings.embed_query(question)
            trace["embedding_duration_ms"] = round((time.perf_counter() - started) * 1000, 2)
        except Exception as error:
            raise EmbeddingUnavailableError("Embedding service is unavailable.") from error
        started = time.perf_counter()
        results = self.retriever.search(vector, self.top_k, filters=None)
        trace["retrieval_duration_ms"] = round((time.perf_counter() - started) * 1000, 2)
        stop_words = {"a", "an", "are", "can", "company", "how", "is", "of", "the", "what"}
        evidence_terms = set(re.findall(r"[a-z0-9]+", question.lower())) - stop_words
        usable = [
            result
            for result in results
            if result.score >= self.min_score
            and evidence_terms & set(re.findall(r"[a-z0-9]+", result.text.lower()))
        ]
        if not usable:
            return QueryOutcome(
                answer=None,
                answer_status="insufficient_context",
                trace={**trace, "retrieved_chunks": 0} if self.dev_trace else None,
            )
        started = time.perf_counter()
        context = self.context_builder.build(usable)
        trace["context_duration_ms"] = round((time.perf_counter() - started) * 1000, 2)
        if not context.chunks:
            return QueryOutcome(answer=None, answer_status="insufficient_context")
        try:
            generation = self.generator.generate(question=question, context=context)
        except Exception as error:
            raise GenerationUnavailableError("Generation service is unavailable.") from error
        trace.update(
            {
                "generation_duration_ms": round(generation.duration_ms, 2),
                "retrieved_chunks": len(context.chunks),
                "context_estimated_tokens": context.estimated_tokens,
                "provider": generation.provider,
            }
        )
        return QueryOutcome(
            answer=generation.answer,
            answer_status="grounded",
            sources=self.citations.format(context),
            trace=trace if self.dev_trace else None,
        )
