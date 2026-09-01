import json
import statistics
import time
from pathlib import Path

from backend.app.rag.chunking import DocumentChunker
from backend.app.rag.embeddings import HashEmbeddingService
from backend.app.rag.models import Document


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, round((len(ordered) - 1) * fraction))]


def main() -> None:
    corpus = json.loads(Path("evaluation/corpus/documents.json").read_text())
    questions = json.loads(Path("evaluation/questions/questions.json").read_text())
    chunks = [chunk for doc in corpus for chunk in DocumentChunker().chunk(Document(**doc))]
    embedder = HashEmbeddingService()
    vectors = embedder.embed_documents([chunk.text for chunk in chunks])
    runs = {}
    for k in (3, 5, 8):
        precisions, recalls, hits, reciprocal, latencies = [], [], [], [], []
        for item in questions:
            started = time.perf_counter()
            query = embedder.embed_query(item["question"])
            scored = sorted(
                (
                    (sum(a * b for a, b in zip(query, vector)), chunk)
                    for vector, chunk in zip(vectors, chunks)
                ),
                reverse=True,
                key=lambda pair: pair[0],
            )[:k]
            latencies.append((time.perf_counter() - started) * 1000)
            expected = set(item["expected_documents"])
            relevant = [
                index for index, (_, chunk) in enumerate(scored, 1) if chunk.document_id in expected
            ]
            if expected:
                precisions.append(len(relevant) / k)
                recalls.append(len(relevant) / len(expected))
                hits.append(1 if relevant else 0)
                reciprocal.append(1 / relevant[0] if relevant else 0)
        runs[str(k)] = {
            "precision_at_k": sum(precisions) / len(precisions),
            "recall_at_k": sum(recalls) / len(recalls),
            "hit_rate_at_k": sum(hits) / len(hits),
            "mrr": sum(reciprocal) / len(reciprocal),
            "retrieval_latency_ms": {
                "average": statistics.mean(latencies),
                "p50": percentile(latencies, 0.5),
                "p95": percentile(latencies, 0.95),
            },
        }
    result = {
        "corpus_documents": len(corpus),
        "chunk_count": len(chunks),
        "average_chunk_chars": statistics.mean(len(chunk.text) for chunk in chunks),
        "embedding_model": "hash-embedding-v1",
        "vector_dimension": embedder.dimension,
        "similarity_metric": "cosine/dot-product on normalized vectors",
        "runs": runs,
        "limitations": (
            "Deterministic development embedding; Docker Qdrant benchmark awaits Docker Desktop."
        ),
    }
    target = Path("evaluation/results/phase2-retrieval.json")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
