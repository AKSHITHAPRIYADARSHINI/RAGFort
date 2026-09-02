from backend.scripts.seed_identities import ROLE_NAMES, SYNTHETIC_IDENTITIES, TENANTS


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
