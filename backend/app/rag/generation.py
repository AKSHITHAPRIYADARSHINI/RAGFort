import re
import time
from typing import Protocol

from backend.app.rag.models import ContextPackage, GenerationResult

GROUNDING_INSTRUCTION = (
    "Answer using only the supplied retrieved context. If it is insufficient, say so. "
    "Do not invent sources."
)


class GenerationUnavailableError(RuntimeError):
    pass


class GenerationService(Protocol):
    def generate(self, *, question: str, context: ContextPackage) -> GenerationResult: ...


class ExtractiveGenerationService:
    """Local development provider that only returns a sentence from retrieved evidence."""

    provider = "extractive-development"
    model = "sentence-selector-v1"

    def generate(self, *, question: str, context: ContextPackage) -> GenerationResult:
        started = time.perf_counter()
        question_terms = set(re.findall(r"[a-z0-9]+", question.lower()))
        candidates = [
            sentence.strip()
            for chunk in context.chunks
            for sentence in re.split(r"(?<=[.!?])\s+", chunk.text)
            if sentence.strip()
        ]
        insufficient = (
            "I couldn't find enough information in the available documents to answer that reliably."
        )
        answer = max(
            candidates,
            key=lambda sentence: len(
                question_terms & set(re.findall(r"[a-z0-9]+", sentence.lower()))
            ),
            default=insufficient,
        )
        return GenerationResult(
            answer, self.provider, self.model, (time.perf_counter() - started) * 1000
        )
