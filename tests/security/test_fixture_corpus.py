"""Contract checks for the version-controlled, synthetic Phase 5 corpus."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

FIXTURE_DIR = Path(__file__).parent / "fixtures"
REQUIRED_FIELDS = {
    "test_id",
    "attack_family",
    "payload",
    "expected_categories",
    "expected_action",
    "expected_retrieval",
    "expected_event",
}
OPTIONAL_FIELDS = {"context_payload", "expected_context_action", "notes"}
CATEGORIES = {
    "PROMPT_INJECTION",
    "INDIRECT_PROMPT_INJECTION",
    "SYSTEM_PROMPT_EXTRACTION",
    "DATA_EXFILTRATION",
    "CROSS_TENANT_EXFILTRATION",
    "ROLE_MANIPULATION",
    "IDENTITY_MANIPULATION",
    "INSTRUCTION_OVERRIDE",
    "CONTEXT_MANIPULATION",
    "RETRIEVAL_MANIPULATION",
    "ENCODED_PAYLOAD",
    "TOOL_ABUSE",
    "SUSPICIOUS_CONTROL_LANGUAGE",
}
ACTIONS = {"ALLOW", "ALLOW_AND_LOG", "BLOCK"}
CONTEXT_ACTIONS = {"ALLOW", "ALLOW_WITH_SECURITY_EVENT", "DROP_CHUNK", "BLOCK_REQUEST"}


def load_corpus(name: str) -> list[dict[str, object]]:
    """Load one checked-in corpus without depending on production security code."""
    with (FIXTURE_DIR / name).open(encoding="utf-8") as fixture_file:
        corpus = json.load(fixture_file)
    assert isinstance(corpus, list)
    return corpus


@pytest.fixture(scope="module")
def attack_cases() -> list[dict[str, object]]:
    return load_corpus("attack_cases.json")


@pytest.fixture(scope="module")
def benign_cases() -> list[dict[str, object]]:
    return load_corpus("benign_cases.json")


@pytest.mark.parametrize("corpus_name", ["attack_cases.json", "benign_cases.json"])
def test_fixture_corpus_has_a_valid_security_contract(corpus_name: str) -> None:
    for case in load_corpus(corpus_name):
        assert set(case).issubset(REQUIRED_FIELDS | OPTIONAL_FIELDS)
        assert REQUIRED_FIELDS.issubset(case)
        assert isinstance(case["test_id"], str)
        assert isinstance(case["attack_family"], str)
        assert isinstance(case["payload"], str) and case["payload"].strip()
        assert isinstance(case["expected_categories"], list)
        assert set(case["expected_categories"]).issubset(CATEGORIES)
        assert case["expected_action"] in ACTIONS
        assert isinstance(case["expected_retrieval"], bool)
        assert isinstance(case["expected_event"], bool)
        if "context_payload" in case:
            assert isinstance(case["context_payload"], str) and case["context_payload"].strip()
            assert case["expected_context_action"] in CONTEXT_ACTIONS


def test_fixture_ids_are_unique_across_attack_and_benign_corpora(
    attack_cases: list[dict[str, object]], benign_cases: list[dict[str, object]]
) -> None:
    test_ids = [case["test_id"] for case in [*attack_cases, *benign_cases]]
    assert len(test_ids) == len(set(test_ids))
    assert all(str(test_id).startswith(("P5-ATT-", "P5-BEN-")) for test_id in test_ids)


def test_attack_corpus_covers_required_phase_five_attack_families(
    attack_cases: list[dict[str, object]],
) -> None:
    families = {case["attack_family"] for case in attack_cases}
    assert {
        "direct_injection",
        "prompt_extraction",
        "role_manipulation",
        "tenant_manipulation",
        "data_exfiltration",
        "cross_tenant",
        "indirect_injection",
        "retrieval_manipulation",
        "obfuscation",
        "tool_abuse",
    }.issubset(families)


def test_indirect_cases_are_explicit_context_inspection_cases(
    attack_cases: list[dict[str, object]],
) -> None:
    indirect_cases = [case for case in attack_cases if "context_payload" in case]
    assert len(indirect_cases) >= 3
    assert all(
        "INDIRECT_PROMPT_INJECTION" in case["expected_categories"] for case in indirect_cases
    )
    assert all(
        case["expected_context_action"] in {"DROP_CHUNK", "BLOCK_REQUEST"}
        for case in indirect_cases
    )


def test_benign_security_terminology_is_not_expected_to_block(
    benign_cases: list[dict[str, object]],
) -> None:
    assert len(benign_cases) >= 8
    assert all(case["expected_action"] == "ALLOW" for case in benign_cases)
    assert all(case["expected_categories"] == [] for case in benign_cases)
    assert all(case["expected_retrieval"] is True for case in benign_cases)
    assert all(case["expected_event"] is False for case in benign_cases)
