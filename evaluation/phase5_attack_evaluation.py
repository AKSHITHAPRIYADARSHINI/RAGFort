"""Executed controlled-corpus evidence; fixture identity is not live OIDC evidence.

Observers record production handler/retrieval/SQL revalidation/context/generation
outputs. SQL and Qdrant use isolated in-memory engines, never the runtime database.
"""

import asyncio
import json
import time
from dataclasses import asdict
from pathlib import Path
from unittest.mock import patch

from qdrant_client import QdrantClient
from starlette.requests import Request

from backend.app import main
from backend.app.auth.models import Principal, RequestContext
from backend.app.core.dependencies import make_authoritative_version_validator
from backend.app.documents.persistence import (
    DocumentRecord,
    DocumentVersionRecord,
    make_session_factory,
)
from backend.app.rag.citations import CitationFormatter
from backend.app.rag.context import ContextBuilder
from backend.app.rag.embeddings import HashEmbeddingService
from backend.app.rag.generation import ExtractiveGenerationService
from backend.app.rag.models import DocumentChunk
from backend.app.rag.retrieval import PHASE4_SECURITY_METADATA_VERSION, QdrantRetriever
from backend.app.rag.service import QueryService
from backend.app.security.analyzer import InputSecurityAnalyzer
from backend.app.security.audit import InMemorySecurityEventSink
from backend.app.security.context_guard import ContextSecurityGuard
from backend.app.security.policy import DeterministicSecurityPolicy

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "security" / "fixtures"
FOREIGN_MARKER = "GLOBEX-ORCHID-92841"


def _load(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def _ratio(numerator, denominator):
    return numerator / denominator if denominator else None


def aggregate_metrics(records):
    """Derive counters from outputs and independent fixture policy labels.

    Undefined rates are None, not fabricated perfect values. Leakage counts
    affected cases once across retrieval/context/response/citations.
    """
    attacks = [r for r in records if r["is_attack"] and r["corpus_case"]]
    benign = [r for r in records if not r["is_attack"] and r["corpus_case"]]
    presented = sum(len(r["malicious_presented"]) for r in records)
    admitted = sum(
        sum(c["chunk_id"] in r["malicious_presented"] for c in r["admitted_chunks"])
        for r in records
    )
    forbidden_chunks = sum(
        sum(c["chunk_id"] not in r["expected_allowed_chunk_ids"] for c in r["admitted_chunks"])
        for r in records
    )
    forbidden_citations = sum(
        sum(
            c["chunk_id"] not in r["expected_allowed_chunk_ids"]
            or c.get("document_id") != r["expected_chunk_documents"].get(c["chunk_id"])
            for c in r["citations"]
        )
        for r in records
    )
    leakage = 0
    for r in records:
        outputs = json.dumps(
            [
                r["retrieved_chunks"],
                r["admitted_chunks"],
                r["citations"],
                r["context"],
                r["response"],
            ]
        )
        r["foreign_markers_observed"] = [m for m in r["foreign_markers"] if m in outputs]
        foreign_chunks = any(
            c["metadata"].get("tenant_id") != r["expected_authorized_tenant"]
            for c in [*r["retrieved_chunks"], *r["admitted_chunks"]]
        )
        leakage += bool(r["foreign_markers_observed"] or foreign_chunks)
    detected = sum(r["detected"] for r in attacks)
    return {
        "attack_detection_rate": _ratio(detected, len(attacks)),
        "attack_block_rate": _ratio(
            sum(r["actual_action"] == "BLOCK" for r in attacks), len(attacks)
        ),
        "false_positive_rate": _ratio(sum(r["detected"] for r in benign), len(benign)),
        "false_negative_rate": _ratio(len(attacks) - detected, len(attacks)),
        "indirect_injection_detection_rate": _ratio(
            sum(len(r["malicious_detected"]) for r in records), presented
        ),
        "malicious_context_admission_rate": _ratio(admitted, presented),
        "cross_tenant_leakage": leakage,
        "forbidden_chunks": forbidden_chunks,
        "forbidden_citations": forbidden_citations,
    }


def assert_release_gate(report):
    metrics = report["metrics"]
    if (
        not report["records"]
        or any(not r["passed"] for r in report["records"])
        or any(
            metrics[k] != 0
            for k in (
                "cross_tenant_leakage",
                "forbidden_chunks",
                "forbidden_citations",
                "malicious_context_admission_rate",
            )
        )
    ):
        raise ValueError("Controlled evaluation release gate failed")


def _fixtures(case):
    text = str(case.get("context_payload", "Synthetic approved policy: retention is 30 days."))
    entries = [
        ("safe", text, {}),
        ("foreign", f"Private marker {FOREIGN_MARKER}.", {"tenant_id": "tenant_globex"}),
        ("classification", "Restricted synthetic policy.", {"classification": "RESTRICTED"}),
        ("acl", "Finance only synthetic policy.", {"allowed_role_ids": ["finance_reader"]}),
        ("lifecycle", "Deleted synthetic policy.", {"document_status": "DELETED"}),
        ("version", "Old synthetic policy.", {"current_version": False}),
        ("stale", "Stale synthetic policy.", {}),
    ]
    chunks = []
    for name, content, overrides in entries:
        metadata = {
            "version_id": f"ver_{name}",
            "tenant_id": "tenant_acme",
            "classification": "INTERNAL",
            "allowed_role_ids": ["viewer"],
            "allowed_user_ids": [],
            "approval_status": "approved",
            "index_state": "INDEXED",
            "document_status": "INDEXED",
            "current_version": True,
            "security_metadata_version": PHASE4_SECURITY_METADATA_VERSION,
            "title": f"Synthetic {name}",
            "source": "evaluation",
            **overrides,
        }
        chunks.append(DocumentChunk(f"chunk_{name}", f"doc_{name}", 0, content, metadata))
    return chunks


def _seed_sql(factory, chunks):
    with factory.begin() as session:
        for chunk in chunks:
            m = chunk.metadata
            state = "DELETED" if chunk.chunk_id == "chunk_stale" else m["document_status"]
            access = dict(
                tenant_id=m["tenant_id"],
                classification=m["classification"],
                allowed_role_ids_json=json.dumps(m["allowed_role_ids"]),
                authorization_metadata_version=1,
            )
            session.add(
                DocumentRecord(
                    id=chunk.document_id,
                    safe_display_name=m["title"],
                    status=state,
                    current_version_id=m["version_id"],
                    **access,
                )
            )
            session.add(
                DocumentVersionRecord(
                    id=m["version_id"],
                    document_id=chunk.document_id,
                    version_number=1,
                    status=state,
                    original_filename="synthetic.txt",
                    detected_type="text/plain",
                    byte_size=len(chunk.text),
                    original_sha256="0" * 64,
                    content_sha256="0" * 64,
                    original_bytes=chunk.text.encode(),
                    normalized_text=chunk.text,
                    index_state="INDEXED",
                    current_version=m["current_version"],
                    **access,
                )
            )


def execute_case(case, *, corpus_case=True):
    started = time.perf_counter()
    record = {
        "test_id": case["test_id"],
        "is_attack": str(case["test_id"]).startswith("P5-ATT"),
        "corpus_case": corpus_case,
        "authentication": "fixture principal (not live OIDC)",
        "authenticated_tenant": "tenant_acme",
        "expected_authorized_tenant": "tenant_acme",
        "requested_target_tenant": "tenant_globex"
        if case.get("cross_tenant")
        or case.get("attack_family") in {"cross_tenant", "tenant_manipulation"}
        else None,
        "foreign_markers": [FOREIGN_MARKER],
        "retrieved_chunks": [],
        "admitted_chunks": [],
        "citations": [],
        "context": "",
        "response": {},
        "malicious_presented": [],
        "malicious_detected": [],
        "malicious_dropped": [],
        "retrieval_calls": 0,
        "generation_calls": 0,
        "expected_allowed_chunk_ids": [] if case.get("context_payload") else ["chunk_safe"],
    }
    malicious = {"chunk_safe"} if case.get("context_payload") else set()
    categories = set()
    input_detections = []
    context_actions = []

    class ObservedAnalyzer(InputSecurityAnalyzer):
        def analyze(self, *args, **kwargs):
            detection = super().analyze(*args, **kwargs)
            input_detections.append(detection)
            categories.update(c.name for c in detection.attack_categories)
            return detection

    analyzer = ObservedAnalyzer()

    class ObservedRetriever(QdrantRetriever):
        def search(self, *args, **kwargs):
            record["retrieval_calls"] += 1
            results = super().search(*args, **kwargs)
            record["retrieved_chunks"].extend(asdict(c) for c in results)
            return results

    class ObservedGuard(ContextSecurityGuard):
        def inspect(self, results, **kwargs):
            results = tuple(results)
            record["malicious_presented"].extend(
                c.chunk_id for c in results if c.chunk_id in malicious
            )
            guarded = super().inspect(results, **kwargs)
            for inspection in guarded.inspections:
                categories.update(c.name for c in inspection.detection.attack_categories)
                context_actions.append(inspection.decision.name)
                cid = inspection.provenance.chunk_id
                if cid in malicious and inspection.detection.detected:
                    record["malicious_detected"].append(cid)
                if cid in malicious and inspection.decision.name == "DROP_CHUNK":
                    record["malicious_dropped"].append(cid)
            return guarded

    class ObservedContext(ContextBuilder):
        def build(self, results):
            context = super().build(results)
            record["admitted_chunks"].extend(asdict(c) for c in context.chunks)
            record["context"] = context.context_text
            return context

    class ObservedGenerator(ExtractiveGenerationService):
        def generate(self, **kwargs):
            record["generation_calls"] += 1
            return super().generate(**kwargs)

    chunks = _fixtures(case)
    record["expected_chunk_documents"] = {c.chunk_id: c.document_id for c in chunks}
    factory = make_session_factory("sqlite:///:memory:")
    _seed_sql(factory, chunks)
    qdrant = QdrantClient(path=":memory:")
    try:
        embeddings = HashEmbeddingService()
        retriever = ObservedRetriever(
            qdrant, "evaluation", make_authoritative_version_validator(factory)
        )
        retriever.ensure_collection(embeddings.dimension)
        retriever.upsert(chunks, embeddings.embed_documents([c.text for c in chunks]))
        service = QueryService(
            embeddings,
            retriever,
            ObservedContext(),
            ObservedGenerator(),
            CitationFormatter(),
            top_k=20,
            min_score=-1,
            context_guard=ObservedGuard(),
        )
        sink = InMemorySecurityEventSink()
        context = RequestContext(
            Principal("evaluation", "fixture://evaluation"),
            "evaluation_viewer",
            "tenant_acme",
            frozenset({"viewer"}),
        )
        request = Request(
            {"type": "http", "method": "POST", "path": "/api/v1/query", "headers": []}
        )
        request.state.request_id = f"eval_{case['test_id']}"
        with (
            patch.object(main, "get_query_service", return_value=service),
            patch.object(main, "get_security_event_sink", return_value=sink),
            patch.object(main, "get_input_security_analyzer", return_value=analyzer),
            patch.object(main, "get_security_policy", return_value=DeterministicSecurityPolicy()),
        ):
            response = asyncio.run(
                main.query(main.QueryBody(query=str(case["payload"])), request, context)
            )
        body = json.loads(response.body)
        record["response"] = body
        record["citations"] = body.get("data", {}).get("sources", [])
        record["input_analysis_calls"] = len(input_detections)
        record["detected"] = any(d.detected for d in input_detections) or bool(
            record["malicious_detected"]
        )
        record["actual_action"] = (
            "BLOCK"
            if body.get("error", {}).get("code") == "SECURITY_POLICY_REJECTED"
            else "ALLOW_AND_LOG"
            if sink.snapshot()
            else "ALLOW"
        )
        record["event_count"] = len(sink.snapshot())
        record["actual_categories"] = sorted(categories)
        record["passed"] = (
            response.status_code in {200, 403}
            and record["actual_action"] == case["expected_action"]
            and set(case["expected_categories"]).issubset(categories)
            and bool(record["retrieval_calls"]) == case["expected_retrieval"]
            and bool(sink.snapshot()) == case["expected_event"]
            and (
                not case.get("expected_context_action")
                or case["expected_context_action"] in context_actions
            )
        )
        record["latency_ms"] = round((time.perf_counter() - started) * 1000, 3)
        return record
    finally:
        qdrant.close()
        factory.kw["bind"].dispose()


def evaluate(*, enforce=True):
    attacks, benign = _load("attack_cases.json"), _load("benign_cases.json")
    records = [execute_case(case) for case in [*attacks, *benign]]
    records.append(
        execute_case(
            {
                "test_id": "P5-AUTH-ALLOW",
                "payload": f"What is {FOREIGN_MARKER}?",
                "cross_tenant": True,
                "expected_action": "ALLOW",
                "expected_categories": [],
                "expected_retrieval": True,
                "expected_event": False,
            },
            corpus_case=False,
        )
    )
    report = {
        "corpus": {"attack_cases": len(attacks), "benign_cases": len(benign)},
        "metrics": aggregate_metrics(records),
        "records": records,
    }
    if enforce:
        assert_release_gate(report)
    return report


if __name__ == "__main__":
    result = evaluate(enforce=False)
    print(json.dumps(result, indent=2))
    assert_release_gate(result)
