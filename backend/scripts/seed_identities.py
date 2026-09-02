"""Idempotently seed only synthetic local Phase 4 identities.

This script contains no credentials, tokens, or signing keys.  The local OIDC
provider maps these fixed subjects to the database records below; PostgreSQL
remains authoritative for tenant membership, roles, account state, and epochs.
"""

from backend.app.auth.persistence import (
    MembershipRoleRecord,
    RoleRecord,
    TenantMembershipRecord,
    TenantRecord,
    UserRecord,
    bootstrap_identity_schema,
)
from backend.app.core.dependencies import get_document_session_factory

ISSUER = "http://localhost:8080/realms/ragfort"

ROLES = ("viewer", "contributor", "reviewer", "admin", "finance_reader", "hr_reader")

IDENTITIES = (
    ("acme_employee", "ACME Employee", "tenant_acme", "Operations", ("viewer",)),
    (
        "acme_finance_reader",
        "ACME Finance Reader",
        "tenant_acme",
        "Finance",
        ("viewer", "finance_reader", "reviewer"),
    ),
    (
        "acme_hr_reader",
        "ACME HR Reader",
        "tenant_acme",
        "Human Resources",
        ("viewer", "hr_reader", "reviewer"),
    ),
    (
        "acme_knowledge_manager",
        "ACME Knowledge Manager",
        "tenant_acme",
        "Knowledge",
        ("reviewer",),
    ),
    (
        "acme_security_analyst",
        "ACME Security Analyst",
        "tenant_acme",
        "Security",
        ("reviewer",),
    ),
    ("globex_employee", "GLOBEX Employee", "tenant_globex", "Operations", ("viewer",)),
    (
        "globex_knowledge_manager",
        "GLOBEX Knowledge Manager",
        "tenant_globex",
        "Knowledge",
        ("reviewer",),
    ),
)


def main() -> None:
    factory = get_document_session_factory()
    bootstrap_identity_schema(factory.kw["bind"])
    with factory.begin() as session:
        for tenant_id, name in (("tenant_acme", "ACME"), ("tenant_globex", "GLOBEX")):
            if session.get(TenantRecord, tenant_id) is None:
                session.add(TenantRecord(id=tenant_id, name=name))
        session.flush()
        for role in ROLES:
            if session.get(RoleRecord, role) is None:
                session.add(RoleRecord(id=role, name=role))
        session.flush()
        for subject, display_name, tenant_id, department, roles in IDENTITIES:
            user = session.query(UserRecord).filter_by(issuer=ISSUER, subject=subject).one_or_none()
            if user is None:
                user = UserRecord(
                    id=f"usr_{subject}", issuer=ISSUER, subject=subject,
                    display_name=display_name, department=department, active=True,
                    authorization_epoch=1,
                )
                session.add(user)
                session.flush()
            membership_id = f"membership_{subject}"
            membership = session.get(TenantMembershipRecord, membership_id)
            if membership is None:
                membership = TenantMembershipRecord(
                    id=membership_id, user_id=user.id, tenant_id=tenant_id,
                    active=True, authorization_epoch=1,
                )
                session.add(membership)
                session.flush()
            for role in roles:
                key = {"membership_id": membership.id, "role_id": role}
                if session.get(MembershipRoleRecord, key) is None:
                    session.add(MembershipRoleRecord(membership_id=membership.id, role_id=role))
    print(f"Seeded {len(IDENTITIES)} synthetic Phase 4 identities.")


if __name__ == "__main__":
    main()
