"""Trusted identity models created only after token validation and lookup."""

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Principal:
    """Provider-neutral, cryptographically verified external identity."""

    subject: str
    issuer: str
    authenticated_at: int | None = None
    display_name: str | None = None

    def __post_init__(self) -> None:
        if not self.subject.strip() or not self.issuer.strip():
            raise ValueError("principal subject and issuer are required")


@dataclass(frozen=True)
class RequestContext:
    """Canonical, server-derived authorization input.

    `tenant_id`, roles, and authorization epoch are resolved from trusted
    server state. They are never accepted from a query body or browser header.
    """

    principal: Principal
    user_id: str
    tenant_id: str
    roles: frozenset[str] = field(default_factory=frozenset)
    attributes: tuple[tuple[str, str], ...] = ()
    authorization_epoch: int = 0
    policy_version: str = "phase-4"

    def __post_init__(self) -> None:
        if not self.user_id.strip() or not self.tenant_id.strip():
            raise ValueError("request context requires canonical user and tenant IDs")
        if self.authorization_epoch < 0:
            raise ValueError("authorization epoch cannot be negative")

    @property
    def attribute_map(self) -> dict[str, str]:
        return dict(self.attributes)
