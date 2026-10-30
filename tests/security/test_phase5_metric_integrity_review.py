"""Independent negative controls for observed Phase 5 evaluation metrics."""

import pytest

from evaluation.phase5_attack_evaluation import aggregate_metrics, assert_release_gate


def observation():
    return {
        "is_attack": True, "corpus_case": True, "detected": True,
        "actual_action": "BLOCK", "malicious_presented": ["malicious"],
        "malicious_detected": ["malicious"], "admitted_chunks": [],
        "retrieved_chunks": [], "citations": [], "context": "", "response": {},
        "expected_allowed_chunk_ids": ["safe"],
        "expected_chunk_documents": {"safe": "safe-document"},
        "foreign_markers": ["GLOBEX-ORCHID-92841"],
        "expected_authorized_tenant": "tenant_acme", "passed": True,
    }


def test_foreign_content_observation_cannot_report_perfect_isolation():
    record = observation()
    record["retrieved_chunks"] = [
        {"chunk_id": "foreign", "metadata": {"tenant_id": "tenant_globex"}}
    ]
    metrics = aggregate_metrics([record])
    assert metrics["cross_tenant_leakage"] == 1
    with pytest.raises(ValueError, match="release gate failed"):
        assert_release_gate({"metrics": metrics, "records": [record]})


@pytest.mark.parametrize("surface", ["context", "response"])
def test_foreign_marker_in_generated_output_is_measured(surface):
    record = observation()
    record[surface] = "Disclosed GLOBEX-ORCHID-92841"
    assert aggregate_metrics([record])["cross_tenant_leakage"] == 1


def test_empty_denominators_are_explicitly_undefined():
    metrics = aggregate_metrics([])
    for metric in (
        "attack_detection_rate", "attack_block_rate", "false_positive_rate",
        "false_negative_rate", "indirect_injection_detection_rate",
        "malicious_context_admission_rate",
    ):
        assert metrics[metric] is None
    with pytest.raises(ValueError):
        assert_release_gate({"metrics": metrics, "records": []})


def test_detection_rates_respond_to_false_negative_and_false_positive():
    attack, benign = observation(), observation()
    attack.update(detected=False, actual_action="ALLOW", malicious_detected=[])
    benign.update(is_attack=False, malicious_presented=[], malicious_detected=[])
    metrics = aggregate_metrics([attack, benign])
    assert metrics["attack_detection_rate"] == 0.0
    assert metrics["attack_block_rate"] == 0.0
    assert metrics["false_negative_rate"] == 1.0
    assert metrics["false_positive_rate"] == 1.0
    assert metrics["indirect_injection_detection_rate"] == 0.0


def test_allowed_chunk_id_cannot_hide_foreign_document_citation():
    record = observation()
    record["citations"] = [{"chunk_id": "safe", "document_id": "foreign-document"}]
    metrics = aggregate_metrics([record])
    assert metrics["forbidden_citations"] == 1
    with pytest.raises(ValueError):
        assert_release_gate({"metrics": metrics, "records": [record]})
