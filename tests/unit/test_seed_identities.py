from backend.app.auth.persistence import (
    MembershipRoleRecord,
    TenantMembershipRecord,
    TenantRecord,
    UserRecord,
)
from backend.app.documents.persistence import make_session_factory
from backend.scripts import seed_identities


def test_synthetic_identity_seed_is_idempotent_and_authoritative(monkeypatch, tmp_path) -> None:
    factory = make_session_factory(f"sqlite:///{tmp_path / 'identity.db'}")
    monkeypatch.setattr(seed_identities, "get_document_session_factory", lambda: factory)

    seed_identities.main()
    seed_identities.main()

    with factory() as session:
        assert {tenant.id for tenant in session.query(TenantRecord)} == {
            "tenant_acme",
            "tenant_globex",
        }
        finance = session.query(UserRecord).filter_by(subject="acme_finance_reader").one()
        assert finance.department == "Finance"
        assert finance.authorization_epoch == 1
        membership = session.query(TenantMembershipRecord).filter_by(user_id=finance.id).one()
        assert membership.tenant_id == "tenant_acme"
        assigned_roles = session.query(MembershipRoleRecord).filter_by(membership_id=membership.id)
        assert assigned_roles.count() >= 2
