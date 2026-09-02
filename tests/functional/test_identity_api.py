from fastapi.testclient import TestClient

from backend.app.auth.dependencies import StaleAuthorizationError
from backend.app.auth.models import Principal, RequestContext
from backend.app.auth.persistence import (
    MembershipRoleRecord,
    RoleRecord,
    TenantMembershipRecord,
    TenantRecord,
    UserRecord,
)
from backend.app.auth.resolver import SqlAlchemyRequestContextResolver
from backend.app.core.dependencies import require_request_context
from backend.app.documents.persistence import make_session_factory
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


def _resolver_with_identity(tmp_path, *, active: bool = True):
    factory = make_session_factory(f"sqlite:///{tmp_path / 'identity-api.db'}")
    with factory.begin() as session:
        session.add_all(
            [
                TenantRecord(id="tenant_acme", name="ACME"),
                UserRecord(
                    id="usr_acme",
                    issuer="https://issuer.example.test",
                    subject="acme_employee",
                    active=active,
                    authorization_epoch=2,
                ),
                RoleRecord(id="viewer", name="viewer"),
                TenantMembershipRecord(
                    id="membership_acme",
                    user_id="usr_acme",
                    tenant_id="tenant_acme",
                    authorization_epoch=2,
                ),
                MembershipRoleRecord(membership_id="membership_acme", role_id="viewer"),
            ]
        )
    return SqlAlchemyRequestContextResolver(factory)


def test_me_maps_stale_authorization_to_safe_reauthentication(tmp_path) -> None:
    resolver = _resolver_with_identity(tmp_path)
    stale_principal = Principal(
        subject="acme_employee",
        issuer="https://issuer.example.test",
        tenant_hint="tenant_acme",
        authorization_epoch_hint=1,
    )
    app.dependency_overrides[require_request_context] = lambda: resolver.resolve(stale_principal)
    try:
        response = TestClient(app).get("/api/v1/me")

        assert response.status_code == 401
        assert response.json()["error"]["code"] == StaleAuthorizationError.code
    finally:
        app.dependency_overrides.clear()


def test_me_denies_disabled_canonical_account(tmp_path) -> None:
    resolver = _resolver_with_identity(tmp_path, active=False)
    principal = Principal(
        subject="acme_employee", issuer="https://issuer.example.test", tenant_hint="tenant_acme"
    )
    app.dependency_overrides[require_request_context] = lambda: resolver.resolve(principal)
    try:
        response = TestClient(app).get("/api/v1/me")

        assert response.status_code == 403
        assert response.json()["error"]["code"] == "ACCESS_DENIED"
    finally:
        app.dependency_overrides.clear()
