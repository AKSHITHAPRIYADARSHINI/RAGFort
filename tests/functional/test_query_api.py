from fastapi.testclient import TestClient

from backend.app.auth.models import Principal, RequestContext
from backend.app.core.dependencies import require_request_context
from backend.app.main import app
from backend.app.rag.models import QueryOutcome, SourceCitation

client = TestClient(app)


class GroundedService:
    def query(self, _question, scope=None):
        assert scope is not None
        return QueryOutcome(
            answer="Employees may work remotely up to three days per week with manager approval.",
            answer_status="grounded",
            sources=(
                SourceCitation("doc_remote_work", "chunk_remote", "Remote Work Policy", "fixture"),
            ),
        )


def _context() -> RequestContext:
    return RequestContext(
        principal=Principal(subject="query-test", issuer="https://issuer.example.test"),
        user_id="usr_query_test",
        tenant_id="tenant_acme",
        roles=frozenset({"viewer"}),
    )


def test_query_api_returns_retrieval_derived_sources(monkeypatch) -> None:
    monkeypatch.setattr("backend.app.main.get_query_service", lambda: GroundedService())
    app.dependency_overrides[require_request_context] = _context
    try:
        response = client.post("/api/v1/query", json={"query": "What is the remote work policy?"})

        assert response.status_code == 200
        body = response.json()
        assert body["request_id"].startswith("req_")
        assert body["data"]["answer_status"] == "grounded"
        assert body["data"]["sources"][0]["document_id"] == "doc_remote_work"
    finally:
        app.dependency_overrides.clear()


def test_query_api_rejects_empty_query() -> None:
    app.dependency_overrides[require_request_context] = _context
    try:
        response = client.post("/api/v1/query", json={"query": "  "})

        assert response.status_code == 400
        assert response.json()["error"]["code"] == "INVALID_QUERY"
    finally:
        app.dependency_overrides.clear()


def test_query_api_denies_missing_identity_before_rag_service(monkeypatch) -> None:
    called = False

    def service():
        nonlocal called
        called = True
        return GroundedService()

    monkeypatch.setattr("backend.app.main.get_query_service", service)
    response = client.post("/api/v1/query", json={"query": "What is the remote work policy?"})

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHENTICATED"
    assert not called
