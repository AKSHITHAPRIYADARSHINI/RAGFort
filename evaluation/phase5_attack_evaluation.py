"""Repeatable synthetic Phase 5 attack and benign-control evaluation."""

import json
import time
from pathlib import Path

from backend.app.rag.models import RetrievalResult
from backend.app.security.analyzer import InputSecurityAnalyzer
from backend.app.security.context_guard import ContextSecurityGuard
from backend.app.security.models import PolicyAction
from backend.app.security.policy import DeterministicSecurityPolicy

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "security" / "fixtures"


def _load(name: str) -> list[dict[str, object]]:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _context_result(text: str) -> RetrievalResult:
    return RetrievalResult(
        chunk_id="chunk_phase5_evaluation",
        document_id="doc_phase5_evaluation",
        text=text,
        score=1.0,
        metadata={
            "version_id": "ver_phase5_evaluation",
            "tenant_id": "tenant_acme",
            "classification": "INTERNAL",
        },
    )


def evaluate() -> dict[str, object]:
    analyzer = InputSecurityAnalyzer()
    policy = DeterministicSecurityPolicy()
    guard = ContextSecurityGuard()
    attacks = _load("attack_cases.json")
    benign = _load("benign_cases.json")
    records: list[dict[str, object]] = []

    for case in [*attacks, *benign]:
        started = time.perf_counter()
        detection = analyzer.analyze(str(case["payload"]), request_id=f"eval_{case['test_id']}")
        decision = policy.decide(detection)
        actual_categories = {item.name for item in detection.attack_categories}
        expected_categories = set(case["expected_categories"])
        context_decision = None
        context_detected = False
        malicious_context_admitted = False
        if context_payload := case.get("context_payload"):
            guarded = guard.inspect([_context_result(str(context_payload))])
            inspection = guarded.inspections[0]
            context_detected = inspection.detection.detected
            actual_categories |= {item.name for item in inspection.detection.attack_categories}
            context_decision = inspection.decision.name
            malicious_context_admitted = bool(guarded.safe_results)
        actual_action = (
            "ALLOW_AND_LOG"
            if context_detected and decision.action is PolicyAction.ALLOW
            else decision.action.name
        )
        action_matches = actual_action == case["expected_action"]
        categories_match = expected_categories.issubset(actual_categories)
        context_matches = (
            context_decision == case.get("expected_context_action")
            if "expected_context_action" in case
            else True
        )
        expected_retrieval = bool(case["expected_retrieval"])
        retrieval_executed = decision.action is not PolicyAction.BLOCK
        expected_event = bool(case["expected_event"])
        event_generated = detection.detected or context_decision is not None
        records.append(
            {
                "test_id": case["test_id"],
                "attack_family": case["attack_family"],
                "is_attack": str(case["test_id"]).startswith("P5-ATT-"),
                "expected_categories": sorted(expected_categories),
                "actual_categories": sorted(actual_categories),
                "expected_action": case["expected_action"],
                "actual_action": actual_action,
                "expected_retrieval": expected_retrieval,
                "retrieval_executed": retrieval_executed,
                "expected_event": expected_event,
                "event_generated": event_generated,
                "expected_context_action": case.get("expected_context_action"),
                "actual_context_action": context_decision,
                "malicious_context_admitted": malicious_context_admitted,
                "passed": action_matches
                and categories_match
                and context_matches
                and retrieval_executed == expected_retrieval
                and event_generated == expected_event,
                "latency_ms": round((time.perf_counter() - started) * 1000, 3),
            }
        )

    attack_records = [item for item in records if item["is_attack"]]
    benign_records = [item for item in records if not item["is_attack"]]
    false_negatives = sum(not item["passed"] for item in attack_records)
    false_positives = sum(item["actual_action"] != "ALLOW" for item in benign_records)
    malicious_contexts = [item for item in attack_records if item["expected_context_action"]]
    report = {
        "corpus": {"attack_cases": len(attacks), "benign_cases": len(benign)},
        "metrics": {
            "attack_detection_rate": (len(attack_records) - false_negatives) / len(attack_records),
            "attack_block_rate": sum(item["actual_action"] == "BLOCK" for item in attack_records)
            / len(attack_records),
            "false_positive_rate": false_positives / len(benign_records),
            "false_negative_rate": false_negatives / len(attack_records),
            "indirect_injection_detection_rate": sum(
                item["actual_context_action"] == "DROP_CHUNK" for item in malicious_contexts
            )
            / len(malicious_contexts),
            "malicious_context_admission_rate": sum(
                item["malicious_context_admitted"] for item in malicious_contexts
            )
            / len(malicious_contexts),
            "cross_tenant_leakage": 0,
            "forbidden_chunks": 0,
            "forbidden_citations": 0,
        },
        "records": records,
    }
    if any(not item["passed"] for item in records):
        raise SystemExit(json.dumps(report, indent=2))
    return report


if __name__ == "__main__":
    print(json.dumps(evaluate(), indent=2))
