from fastapi.testclient import TestClient

from backend.app.auth.models import Principal, RequestContext
from backend.app.core.dependencies import require_request_context
from backend.app.main import app


def _context() -> RequestContext:
    return RequestContext(
        principal=Principal(
            subject="acme_employee",
            issuer="https://issuer.example.test",
            display_name="ACME Employee",
        ),
        user_id="usr_acme_employee",
        tenant_id="tenant_acme",
        roles=frozenset({"viewer"}),
        attributes=(("department", "Operations"),),
        authorization_epoch=1,
    )


def test_me_returns_only_safe_server_derived_session_summary() -> None:
    app.dependency_overrides[require_request_context] = _context
    try:
        response = TestClient(app).get("/api/v1/me")

        assert response.status_code == 200
        assert response.json()["data"] == {
            "display_name": "ACME Employee",
            "tenant_id": "tenant_acme",
            "roles": ["viewer"],
        }
        serialized = str(response.json()).lower()
        assert "authorization" not in serialized
        assert "token" not in serialized
        assert "epoch" not in serialized
    finally:
        app.dependency_overrides.clear()


def test_me_requires_authentication() -> None:
    response = TestClient(app).get("/api/v1/me")

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHENTICATED"
