"""Canonical server-side principal to authorization-context resolution."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.auth.dependencies import StaleAuthorizationError
from backend.app.auth.models import Principal, RequestContext
from backend.app.auth.persistence import (
    MembershipRoleRecord,
    RoleRecord,
    TenantMembershipRecord,
    UserRecord,
    active_memberships,
)
from backend.app.auth.policy import AuthorizationDeniedError


class SqlAlchemyRequestContextResolver:
    """Looks up current membership and roles; token claims never grant roles directly."""

    def __init__(self, session_factory, policy_version: str = "phase-4") -> None:
        self.session_factory = session_factory
        self.policy_version = policy_version

    def resolve(self, principal: Principal) -> RequestContext:
        with self.session_factory() as session:
            user = session.scalar(
                select(UserRecord).where(
                    UserRecord.issuer == principal.issuer,
                    UserRecord.subject == principal.subject,
                    UserRecord.active.is_(True),
                )
            )
            if user is None:
                raise AuthorizationDeniedError()
            membership = self._membership(session, user, principal.tenant_hint)
            roles = frozenset(
                session.scalars(
                    select(RoleRecord.name)
                    .join(MembershipRoleRecord, MembershipRoleRecord.role_id == RoleRecord.id)
                    .where(MembershipRoleRecord.membership_id == membership.id)
                )
            )
            authorization_epoch = max(user.authorization_epoch, membership.authorization_epoch)
            if (
                principal.authorization_epoch_hint is not None
                and principal.authorization_epoch_hint != authorization_epoch
            ):
                raise StaleAuthorizationError()
            attributes = (("department", user.department),) if user.department else ()
            return RequestContext(
                principal=principal,
                user_id=user.id,
                tenant_id=membership.tenant_id,
                roles=roles,
                attributes=attributes,
                authorization_epoch=authorization_epoch,
                policy_version=self.policy_version,
            )

    @staticmethod
    def _membership(
        session: Session, user: UserRecord, tenant_hint: str | None
    ) -> TenantMembershipRecord:
        memberships = active_memberships(session, user)
        if tenant_hint is not None:
            memberships = [item for item in memberships if item.tenant_id == tenant_hint]
        if len(memberships) != 1:
            raise AuthorizationDeniedError()
        return memberships[0]
