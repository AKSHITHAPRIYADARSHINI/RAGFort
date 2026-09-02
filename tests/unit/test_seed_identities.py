from backend.app.auth.persistence import (
    MembershipRoleRecord,
    TenantMembershipRecord,
    TenantRecord,
    UserRecord,
)
from backend.app.documents.persistence import make_session_factory
from backend.scripts import seed_identities


def test_synthetic_identity_seed_is_idempotent_and_authoritative(tmp_path) -> None:
    factory = make_session_factory(f"sqlite:///{tmp_path / 'identity.db'}")
    database_url = f"sqlite:///{tmp_path / 'identity.db'}"
    subjects = {
        identity.key: identity.key for identity in seed_identities.SYNTHETIC_IDENTITIES
    }

    seed_identities.persist_application_identities(
        subjects, "https://issuer.example/realms/ragfort", database_url
    )
    seed_identities.persist_application_identities(
        subjects, "https://issuer.example/realms/ragfort", database_url
    )

    with factory() as session:
        assert {tenant.id for tenant in session.query(TenantRecord)} == {
            "tenant_acme",
            "tenant_globex",
        }
        finance = session.query(UserRecord).filter_by(subject="acme_finance_reader").one()
        assert finance.department == "finance"
        assert finance.authorization_epoch == 0
        membership = session.query(TenantMembershipRecord).filter_by(user_id=finance.id).one()
        assert membership.tenant_id == "tenant_acme"
        assigned_roles = session.query(MembershipRoleRecord).filter_by(membership_id=membership.id)
        assert assigned_roles.count() >= 2
