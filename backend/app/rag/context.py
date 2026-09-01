from backend.app.rag.models import ContextPackage, RetrievalResult


class ContextBuilder:
    def __init__(self, max_chunks: int = 5, max_context_tokens: int = 1800) -> None:
        self.max_chunks = max_chunks
        self.max_context_tokens = max_context_tokens

    def build(self, results: list[RetrievalResult]) -> ContextPackage:
        selected: list[RetrievalResult] = []
        parts: list[str] = []
        used_chars = 0
        max_chars = self.max_context_tokens * 4
        for result in results[: self.max_chunks]:
            chunk_text = (
                f"[SOURCE chunk_id={result.chunk_id} document_id={result.document_id}]\n"
                f"{result.text}\n[END SOURCE]"
            )
            if used_chars + len(chunk_text) > max_chars:
                break
            selected.append(result)
            parts.append(chunk_text)
            used_chars += len(chunk_text)
        return ContextPackage(tuple(selected), "\n\n".join(parts), (used_chars + 3) // 4)
