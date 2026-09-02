"""Deterministic RBAC plus ABAC policy primitives for secure retrieval."""

from collections.abc import Mapping
from dataclasses import dataclass

from backend.app.auth.models import RequestContext


class AuthorizationDeniedError(RuntimeError):
    code = "ACCESS_DENIED"
    message = "You do not have permission to access this resource."


@dataclass(frozen=True)
class ResourceAttributes:
    tenant_id: str
    classification: str = "INTERNAL"
    lifecycle_status: str = "INDEXED"


@dataclass(frozen=True)
class RetrievalScope:
    """Filters created by policy, not accepted from clients.

    The Qdrant adapter will translate these values to its provider filter shape;
    it must revalidate returned payload metadata before context construction.
    """

    tenant_id: str
    allowed_classifications: frozenset[str]
    approval_status: str = "approved"
    index_state: str = "indexed"

    def as_filters(self) -> Mapping[str, object]:
        return {
            "tenant_id": self.tenant_id,
            "approval_status": self.approval_status,
            "index_state": self.index_state,
            "classification": tuple(sorted(self.allowed_classifications)),
        }


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    action: str
    reason: str
    retrieval_scope: RetrievalScope | None = None


class AuthorizationService:
    """Small deterministic policy core; never delegates decisions to an LLM."""

    _ROLE_PERMISSIONS: Mapping[str, frozenset[str]] = {
        "viewer": frozenset({"query", "document:read"}),
        "contributor": frozenset({"query", "document:read", "document:upload"}),
        "reviewer": frozenset(
            {"query", "document:read", "document:upload", "document:scan", "document:review"}
        ),
        "admin": frozenset(
            {
                "query",
                "document:read",
                "document:upload",
                "document:scan",
                "document:review",
                "document:delete",
            }
        ),
    }
    _ROLE_CLASSIFICATIONS: Mapping[str, frozenset[str]] = {
        "viewer": frozenset({"PUBLIC", "INTERNAL"}),
        "contributor": frozenset({"PUBLIC", "INTERNAL"}),
        "reviewer": frozenset({"PUBLIC", "INTERNAL", "CONFIDENTIAL"}),
        "admin": frozenset({"PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"}),
    }

    def decide(
        self,
        action: str,
        context: RequestContext,
        resource: ResourceAttributes | None = None,
    ) -> PolicyDecision:
        permissions = frozenset().union(
            *(self._ROLE_PERMISSIONS.get(role, frozenset()) for role in context.roles)
        )
        if action not in permissions:
            return PolicyDecision(False, action, "ROLE_PERMISSION_DENIED")
        if resource is not None:
            if resource.tenant_id != context.tenant_id:
                return PolicyDecision(False, action, "TENANT_MISMATCH")
            classifications = self.allowed_classifications(context)
            if resource.classification not in classifications:
                return PolicyDecision(False, action, "CLASSIFICATION_DENIED")
            if resource.lifecycle_status not in {"APPROVED", "INDEXED"}:
                return PolicyDecision(False, action, "LIFECYCLE_DENIED")
        scope = self.retrieval_scope(context) if action == "query" else None
        return PolicyDecision(True, action, "ALLOWED", scope)

    def require(
        self,
        action: str,
        context: RequestContext,
        resource: ResourceAttributes | None = None,
    ) -> PolicyDecision:
        decision = self.decide(action, context, resource)
        if not decision.allowed:
            raise AuthorizationDeniedError()
        return decision

    def allowed_classifications(self, context: RequestContext) -> frozenset[str]:
        return frozenset().union(
            *(self._ROLE_CLASSIFICATIONS.get(role, frozenset()) for role in context.roles)
        )

    def retrieval_scope(self, context: RequestContext) -> RetrievalScope:
        return RetrievalScope(context.tenant_id, self.allowed_classifications(context))
