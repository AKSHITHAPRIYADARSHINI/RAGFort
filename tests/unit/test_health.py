from fastapi.testclient import TestClient

from backend.app.main import app

client = TestClient(app)


def test_liveness_uses_safe_envelope_and_request_id() -> None:
    response = client.get("/health/live")

    assert response.status_code == 200
    assert response.json()["success"] is True
    assert response.json()["data"] == {"status": "live"}
    assert response.json()["request_id"].startswith("req_")
    assert response.headers["X-Request-ID"] == response.json()["request_id"]


def test_foundation_readiness_exposes_no_dependency_topology() -> None:
    response = client.get("/health/ready")

    assert response.status_code == 200
    assert response.json()["data"] == {"status": "foundation-ready", "phase": 1}
    rendered = response.text.lower()
    assert "postgres" not in rendered
    assert "qdrant" not in rendered
    assert "llm" not in rendered
