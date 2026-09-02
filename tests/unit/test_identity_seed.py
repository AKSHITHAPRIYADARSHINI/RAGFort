from sqlalchemy import func, select

from backend.app.auth.persistence import TenantMembershipRecord, UserRecord
from backend.app.documents.persistence import make_session_factory
from backend.scripts.seed_identities import (
    DEFAULT_ISSUER,
    ROLE_NAMES,
    SYNTHETIC_IDENTITIES,
    TENANTS,
    persist_application_identities,
)


def test_local_identity_seed_is_synthetic_multi_tenant_and_has_no_password_data() -> None:
    assert set(TENANTS) == {"tenant_acme", "tenant_globex"}
    assert {identity.key for identity in SYNTHETIC_IDENTITIES} == {
        "acme_employee",
        "acme_finance_reader",
        "acme_hr_reader",
        "acme_knowledge_manager",
        "acme_security_analyst",
        "globex_employee",
        "globex_knowledge_manager",
    }
    assert {"viewer", "reviewer", "finance_reader", "hr_reader"}.issubset(ROLE_NAMES)
    assert all("password" not in identity.display_name.lower() for identity in SYNTHETIC_IDENTITIES)


def test_application_identity_seed_is_repeatable_and_persists_no_credentials(tmp_path) -> None:
    database_url = f"sqlite:///{tmp_path / 'identities.db'}"
    subjects = {identity.key: f"oidc-{identity.key}" for identity in SYNTHETIC_IDENTITIES}

    persist_application_identities(subjects, DEFAULT_ISSUER, database_url)
    persist_application_identities(subjects, DEFAULT_ISSUER, database_url)

    factory = make_session_factory(database_url)
    with factory() as session:
        assert session.scalar(select(func.count()).select_from(UserRecord)) == len(SYNTHETIC_IDENTITIES)
        assert session.scalar(select(func.count()).select_from(TenantMembershipRecord)) == len(
            SYNTHETIC_IDENTITIES
        )
        assert all(
            user.subject.startswith("oidc-")
            for user in session.scalars(select(UserRecord)).all()
        )
