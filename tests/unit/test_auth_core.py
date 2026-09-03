import pytest

from backend.app.auth.dependencies import AuthenticationError, extract_bearer_token
from backend.app.auth.models import Principal, RequestContext
from backend.app.auth.policy import AuthorizationService, ResourceAttributes


def context(*roles: str, tenant: str = "tenant_a") -> RequestContext:
    return RequestContext(
        principal=Principal(subject="user-1", issuer="https://issuer.example.test"),
        user_id="usr_1",
        tenant_id=tenant,
        roles=frozenset(roles),
        authorization_epoch=2,
    )


@pytest.mark.parametrize("header", [None, "", "Basic abc", "Bearer", "Bearer a b"])
def test_bearer_header_parser_rejects_ambiguous_or_missing_credentials(header: str | None) -> None:
    with pytest.raises(AuthenticationError):
        extract_bearer_token(header)


def test_bearer_header_parser_accepts_only_a_single_bearer_value() -> None:
    assert extract_bearer_token("Bearer signed.jwt.value") == "signed.jwt.value"


def test_policy_builds_server_owned_scope_for_authorized_query() -> None:
    decision = AuthorizationService().require("query", context("viewer"))

    assert decision.retrieval_scope is not None
    assert decision.retrieval_scope.tenant_id == "tenant_a"
    assert decision.retrieval_scope.as_filters()["approval_status"] == "approved"
    assert set(decision.retrieval_scope.as_filters()["classification"]) == {"INTERNAL", "PUBLIC"}


def test_cross_tenant_resource_is_denied_even_to_an_authorized_role() -> None:
    decision = AuthorizationService().decide(
        "document:read",
        context("admin"),
        ResourceAttributes(tenant_id="tenant_b", classification="RESTRICTED"),
    )

    assert not decision.allowed
    assert decision.reason == "TENANT_MISMATCH"


def test_classification_and_lifecycle_are_enforced_deterministically() -> None:
    policy = AuthorizationService()
    restricted = policy.decide(
        "document:read",
        context("viewer"),
        ResourceAttributes(tenant_id="tenant_a", classification="RESTRICTED"),
    )
    unapproved = policy.decide(
        "document:read",
        context("admin"),
        ResourceAttributes(
            tenant_id="tenant_a",
            lifecycle_status="REVIEW_REQUIRED",
            allowed_role_ids=("admin",),
        ),
    )

    assert restricted.reason == "CLASSIFICATION_DENIED"
    assert unapproved.reason == "LIFECYCLE_DENIED"


def test_document_acl_denies_roles_not_in_server_owned_assignment() -> None:
    decision = AuthorizationService().decide(
        "document:read",
        context("viewer"),
        ResourceAttributes(
            tenant_id="tenant_a",
            allowed_role_ids=("reviewer",),
        ),
    )

    assert not decision.allowed
    assert decision.reason == "ROLE_ACL_DENIED"
