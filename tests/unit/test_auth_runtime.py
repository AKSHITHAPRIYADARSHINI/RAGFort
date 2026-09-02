from types import SimpleNamespace

import pytest

from backend.app.auth.dependencies import AuthenticationError, AuthenticationUnavailableError
from backend.app.auth.models import Principal
from backend.app.auth.oidc import OidcConfiguration, PyJwtOidcValidator
from backend.app.auth.persistence import (
    MembershipRoleRecord,
    RoleRecord,
    TenantMembershipRecord,
    TenantRecord,
    UserRecord,
)
from backend.app.auth.policy import AuthorizationDeniedError
from backend.app.auth.resolver import SqlAlchemyRequestContextResolver
from backend.app.documents.persistence import make_session_factory


class FakeJwks:
    def __init__(self, key: object = "key", error: Exception | None = None) -> None:
        self.key = key
        self.error = error

    def get_signing_key_from_jwt(self, _token: str):
        if self.error:
            raise self.error
        return SimpleNamespace(key=self.key)


def config() -> OidcConfiguration:
    return OidcConfiguration(
        issuer="https://issuer.example.test", audience="ragfort-api", jwks_url="https://issuer/jwks"
    )


def test_validator_fails_closed_when_jwks_is_unavailable() -> None:
    with pytest.raises(AuthenticationUnavailableError):
        PyJwtOidcValidator(config(), FakeJwks(error=OSError())).validate("signed.token")


def test_validator_maps_invalid_signature_or_claims_to_unauthenticated(monkeypatch) -> None:
    validator = PyJwtOidcValidator(config(), FakeJwks())

    def invalid_decode(*_args, **_kwargs):
        from jwt.exceptions import InvalidTokenError

        raise InvalidTokenError()

    monkeypatch.setattr("backend.app.auth.oidc.jwt.decode", invalid_decode)
    with pytest.raises(AuthenticationError):
        validator.validate("bad.token")


def test_validator_maps_only_validated_claims_to_principal(monkeypatch) -> None:
    validator = PyJwtOidcValidator(config(), FakeJwks())
    monkeypatch.setattr(
        "backend.app.auth.oidc.jwt.decode",
        lambda *_args, **_kwargs: {
            "sub": "external-user",
            "name": "Ada",
            "tenant_id": "tenant_a",
            "auth_time": 123,
        },
    )

    principal = validator.validate("valid.token")

    assert principal.subject == "external-user"
    assert principal.tenant_hint == "tenant_a"


def seed_identity(factory, second_membership: bool = False) -> None:
    with factory.begin() as session:
        session.add_all(
            [
                TenantRecord(id="tenant_a", name="Tenant A"),
                TenantRecord(id="tenant_b", name="Tenant B"),
                UserRecord(
                    id="user_a",
                    issuer="https://issuer.example.test",
                    subject="external-user",
                    authorization_epoch=3,
                ),
                RoleRecord(id="role_viewer", name="viewer"),
                TenantMembershipRecord(
                    id="member_a",
                    user_id="user_a",
                    tenant_id="tenant_a",
                    authorization_epoch=5,
                ),
                MembershipRoleRecord(membership_id="member_a", role_id="role_viewer"),
            ]
        )
        if second_membership:
            session.add(
                TenantMembershipRecord(id="member_b", user_id="user_a", tenant_id="tenant_b")
            )


def test_resolver_uses_database_roles_tenant_and_highest_authorization_epoch(tmp_path) -> None:
    factory = make_session_factory(f"sqlite:///{tmp_path / 'identity.db'}")
    seed_identity(factory)

    result = SqlAlchemyRequestContextResolver(factory).resolve(
        Principal("external-user", "https://issuer.example.test", tenant_hint="tenant_a")
    )

    assert result.tenant_id == "tenant_a"
    assert result.roles == frozenset({"viewer"})
    assert result.authorization_epoch == 5


def test_resolver_denies_ambiguous_or_unmapped_membership(tmp_path) -> None:
    factory = make_session_factory(f"sqlite:///{tmp_path / 'identity.db'}")
    seed_identity(factory, second_membership=True)
    resolver = SqlAlchemyRequestContextResolver(factory)

    with pytest.raises(AuthorizationDeniedError):
        resolver.resolve(Principal("external-user", "https://issuer.example.test"))
    with pytest.raises(AuthorizationDeniedError):
        resolver.resolve(
            Principal("external-user", "https://issuer.example.test", tenant_hint="tenant_x")
        )
