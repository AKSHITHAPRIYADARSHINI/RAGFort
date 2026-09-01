import hashlib
import math
import re
from typing import Protocol


class EmbeddingUnavailableError(RuntimeError):
    pass


class EmbeddingService(Protocol):
    dimension: int

    def embed_documents(self, texts: list[str]) -> list[list[float]]: ...

    def embed_query(self, text: str) -> list[float]: ...


class HashEmbeddingService:
    """Deterministic token embedding for CI and the synthetic development corpus.

    This is deliberately an adapter, not a claim of production embedding quality.
    """

    def __init__(self, dimension: int = 256) -> None:
        self.dimension = dimension

    def _embed(self, text: str) -> list[float]:
        vector = [0.0] * self.dimension
        stop_words = {"a", "an", "are", "can", "company", "how", "is", "of", "the", "what"}
        for token in re.findall(r"[a-z0-9]+", text.lower()):
            if token in stop_words:
                continue
            index = int(hashlib.sha256(token.encode()).hexdigest(), 16) % self.dimension
            vector[index] += 1.0
        norm = math.sqrt(sum(value * value for value in vector))
        return [value / norm for value in vector] if norm else vector

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return [self._embed(text) for text in texts]

    def embed_query(self, text: str) -> list[float]:
        return self._embed(text)
