from evaluation.phase5_attack_evaluation import evaluate


def test_phase5_synthetic_attack_evaluation_meets_critical_invariants() -> None:
    report = evaluate()

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
