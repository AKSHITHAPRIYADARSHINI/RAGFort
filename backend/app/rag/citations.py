from backend.app.rag.models import ContextPackage, SourceCitation


class CitationFormatter:
    def format(self, context: ContextPackage) -> tuple[SourceCitation, ...]:
        citations: list[SourceCitation] = []
        seen: set[str] = set()
        for chunk in context.chunks:
            if chunk.chunk_id in seen:
                continue
            seen.add(chunk.chunk_id)
            citations.append(
                SourceCitation(
                    document_id=chunk.document_id,
                    chunk_id=chunk.chunk_id,
                    title=str(chunk.metadata["title"]),
                    source=str(chunk.metadata["source"]),
                    section=str(chunk.metadata.get("section") or "") or None,
                )
            )
        return tuple(citations)
