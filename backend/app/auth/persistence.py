"""SQLAlchemy identity authority used by Phase 4 request-context resolution."""

from datetime import datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Engine,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
    select,
)
from sqlalchemy.orm import Mapped, Session, mapped_column

from backend.app.documents.persistence import Base


class TenantRecord(Base):
    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), unique=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class UserRecord(Base):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("issuer", "subject", name="uq_users_issuer_subject"),)

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    issuer: Mapped[str] = mapped_column(String(512), index=True)
    subject: Mapped[str] = mapped_column(String(512), index=True)
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    authorization_epoch: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class RoleRecord(Base):
    __tablename__ = "roles"

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(80), unique=True, index=True)


class TenantMembershipRecord(Base):
    __tablename__ = "tenant_memberships"
    __table_args__ = (UniqueConstraint("user_id", "tenant_id", name="uq_membership_user_tenant"),)

    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    tenant_id: Mapped[str] = mapped_column(ForeignKey("tenants.id"), index=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    authorization_epoch: Mapped[int] = mapped_column(Integer, default=0)


class MembershipRoleRecord(Base):
    __tablename__ = "membership_roles"
    __table_args__ = (UniqueConstraint("membership_id", "role_id", name="uq_membership_role"),)

    membership_id: Mapped[str] = mapped_column(
        ForeignKey("tenant_memberships.id"), primary_key=True
    )
    role_id: Mapped[str] = mapped_column(ForeignKey("roles.id"), primary_key=True)


def bootstrap_identity_schema(engine: Engine) -> None:
    """Create missing development tables without drop/recreate operations.

    Production uses migrations generated from this same metadata. This helper
    is intentionally additive and is not a migration replacement.
    """
    Base.metadata.create_all(engine)


def active_memberships(session: Session, user: UserRecord) -> list[TenantMembershipRecord]:
    return list(
        session.scalars(
            select(TenantMembershipRecord)
            .join(TenantRecord, TenantMembershipRecord.tenant_id == TenantRecord.id)
            .where(
                TenantMembershipRecord.user_id == user.id,
                TenantMembershipRecord.active.is_(True),
                TenantRecord.active.is_(True),
            )
        )
    )
