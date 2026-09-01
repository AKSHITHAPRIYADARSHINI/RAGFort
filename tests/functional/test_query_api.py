from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.rag.models import QueryOutcome, SourceCitation

client = TestClient(app)


class GroundedService:
    def query(self, _question):
        return QueryOutcome(
            answer="Employees may work remotely up to three days per week with manager approval.",
            answer_status="grounded",
            sources=(
                SourceCitation(
                    "doc_remote_work", "chunk_remote", "Remote Work Policy", "fixture"
                ),
            ),
        )


def test_query_api_returns_retrieval_derived_sources(monkeypatch) -> None:
    monkeypatch.setattr("backend.app.main.get_query_service", lambda: GroundedService())

    response = client.post("/api/v1/query", json={"query": "What is the remote work policy?"})

    assert response.status_code == 200
    body = response.json()
    assert body["request_id"].startswith("req_")
    assert body["data"]["answer_status"] == "grounded"
    assert body["data"]["sources"][0]["document_id"] == "doc_remote_work"


def test_query_api_rejects_empty_query() -> None:
    response = client.post("/api/v1/query", json={"query": "  "})

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "INVALID_QUERY"
