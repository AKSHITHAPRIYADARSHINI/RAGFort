from copy import deepcopy

import pytest

from evaluation.phase5_attack_evaluation import (
    FOREIGN_MARKER,
    aggregate_metrics,
    assert_release_gate,
    evaluate,
)


@pytest.fixture(scope="module")
def measured_report():
    return evaluate()


def test_phase5_synthetic_attack_evaluation_meets_critical_invariants(measured_report) -> None:
    report = measured_report

    assert report["corpus"] == {"attack_cases": 15, "benign_cases": 8}
    metrics = report["metrics"]
    assert metrics["attack_detection_rate"] == 1.0
    assert metrics["false_positive_rate"] == 0.0
    assert metrics["false_negative_rate"] == 0.0
    assert metrics["indirect_injection_detection_rate"] == 1.0
    assert metrics["malicious_context_admission_rate"] == 0.0
    assert metrics["cross_tenant_leakage"] == 0
    assert metrics["forbidden_chunks"] == 0
    assert metrics["forbidden_citations"] == 0


def test_foreign_chunk_negative_control_cannot_report_zero(measured_report):
    report = deepcopy(measured_report)
    record = report["records"][-1]
    record["admitted_chunks"].append(
        {
            "chunk_id": "chunk_foreign",
            "text": FOREIGN_MARKER,
            "metadata": {"tenant_id": "tenant_globex"},
        }
    )
    report["metrics"] = aggregate_metrics(report["records"])
    assert report["metrics"]["cross_tenant_leakage"] == 1
    assert report["metrics"]["forbidden_chunks"] == 1
    with pytest.raises(ValueError, match="release gate failed"):
        assert_release_gate(report)


@pytest.mark.parametrize(
    "chunk_id",
    [
        "chunk_classification",
        "chunk_acl",
        "chunk_lifecycle",
        "chunk_version",
        "chunk_stale",
    ],
)
def test_forbidden_policy_chunk_negative_controls(measured_report, chunk_id):
    records = deepcopy(measured_report["records"])
    records[-1]["admitted_chunks"].append(
        {
            "chunk_id": chunk_id,
            "metadata": {"tenant_id": "tenant_acme"},
        }
    )
    assert aggregate_metrics(records)["forbidden_chunks"] == 1


def test_forbidden_citation_negative_control(measured_report):
    report = deepcopy(measured_report)
    report["records"][-1]["citations"].append({"chunk_id": "chunk_foreign"})
    report["metrics"] = aggregate_metrics(report["records"])
    assert report["metrics"]["forbidden_citations"] == 1
    with pytest.raises(ValueError, match="release gate failed"):
        assert_release_gate(report)


def test_malicious_context_admission_negative_control(measured_report):
    report = deepcopy(measured_report)
    record = next(r for r in report["records"] if r["malicious_presented"])
    record["admitted_chunks"].append(
        {
            "chunk_id": record["malicious_presented"][0],
            "metadata": {"tenant_id": "tenant_acme"},
        }
    )
    report["metrics"] = aggregate_metrics(report["records"])
    assert report["metrics"]["malicious_context_admission_rate"] == pytest.approx(1 / 3)
    assert report["metrics"]["forbidden_chunks"] == 1
    with pytest.raises(ValueError, match="release gate failed"):
        assert_release_gate(report)


def test_detection_metrics_use_detection_not_expectation_match(measured_report):
    records = deepcopy(measured_report["records"])
    attack = next(r for r in records if r["is_attack"])
    attack["detected"] = False
    attack["actual_action"] = "ALLOW"
    benign = next(r for r in records if not r["is_attack"] and r["corpus_case"])
    benign["detected"] = True
    metrics = aggregate_metrics(records)
    assert metrics["attack_detection_rate"] == pytest.approx(14 / 15)
    assert metrics["false_negative_rate"] == pytest.approx(1 / 15)
    assert metrics["false_positive_rate"] == pytest.approx(1 / 8)
    assert metrics["attack_block_rate"] == pytest.approx(9 / 15)


def test_zero_denominators_are_explicitly_unmeasured():
    metrics = aggregate_metrics([])
    assert all(value is None for name, value in metrics.items() if name.endswith("_rate"))


def test_executed_observations_cover_security_boundaries(measured_report):
    records = measured_report["records"]
    assert sum(len(r["malicious_presented"]) for r in records) == 3
    assert sum(len(r["malicious_dropped"]) for r in records) == 3
    assert records[-1]["actual_action"] == "ALLOW"
    assert records[-1]["retrieval_calls"] == 1
    for record in records:
        if record["actual_action"] == "BLOCK":
            assert record["retrieval_calls"] == record["generation_calls"] == 0
            assert record["admitted_chunks"] == record["citations"] == []
