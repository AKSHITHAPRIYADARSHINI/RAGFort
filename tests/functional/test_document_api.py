from fastapi.testclient import TestClient

from backend.app.auth.models import Principal, RequestContext
from backend.app.core.dependencies import require_request_context
from backend.app.documents.models import FileTooLargeError
from backend.app.main import app


class FakeDocumentService:
    def __init__(self) -> None:
        self.upload_access = None
        self.record = {
            "document_id": "doc_test",
            "version_id": "ver_test",
            "name": "policy.txt",
            "status": "INDEXED",
            "classification": "INTERNAL",
            "index_state": "NOT_INDEXED",
            "tenant_id": "tenant_acme",
            "_allowed_role_ids": ["admin"],
        }

    def upload(self, _name, _content_type, data, *, access=None):
        self.upload_access = access
        if len(data) > 5:
            raise FileTooLargeError()
        return self.record

    def list_documents(self):
        return [self.record]

    def get_document(self, _document_id, include_findings=False):
        return {**self.record, **({"findings": []} if include_findings else {})}

    def approve(self, _document_id):
        return {**self.record, "status": "INDEXED", "index_state": "INDEXED"}

    def quarantine(self, _document_id):
        return {**self.record, "status": "QUARANTINED"}

    def delete(self, _document_id):
        return {**self.record, "status": "DELETED"}

    def rescan(self, _document_id):
        return {**self.record, "findings": []}


def _context(*roles: str, tenant_id: str = "tenant_acme") -> RequestContext:
    return RequestContext(
        principal=Principal(subject="doc-test", issuer="https://issuer.example.test"),
        user_id="usr_doc_test",
        tenant_id=tenant_id,
        roles=frozenset(roles),
    )


def test_document_endpoints_use_safe_envelopes(monkeypatch) -> None:
    service = FakeDocumentService()
    monkeypatch.setattr("backend.app.main.get_document_service", lambda: service)
    app.dependency_overrides[require_request_context] = lambda: _context("admin")
    client = TestClient(app)
    try:
        listed = client.get("/api/v1/documents")
        uploaded = client.post(
            "/api/v1/documents", files={"file": ("policy.txt", b"safe", "text/plain")}
        )
        approved = client.post("/api/v1/documents/doc_test/approve")
        findings = client.get("/api/v1/documents/doc_test/security")

        assert listed.status_code == 200
        assert listed.json()["data"]["documents"][0]["document_id"] == "doc_test"
        assert uploaded.status_code == 200 and uploaded.json()["request_id"].startswith("req_")
        assert service.upload_access is not None
        assert service.upload_access.tenant_id == "tenant_acme"
        assert service.upload_access.allowed_role_ids == ("admin",)
        assert approved.json()["data"]["status"] == "INDEXED"
        assert findings.json()["data"]["findings"] == []
    finally:
        app.dependency_overrides.clear()


def test_upload_errors_do_not_leak_file_or_parser_details(monkeypatch) -> None:
    monkeypatch.setattr("backend.app.main.get_document_service", lambda: FakeDocumentService())
    app.dependency_overrides[require_request_context] = lambda: _context("admin")
    try:
        response = TestClient(app).post(
            "/api/v1/documents", files={"file": ("ignored.txt", b"too-large", "text/plain")}
        )

        assert response.status_code == 400
        assert response.json()["error"] == {
            "code": "FILE_TOO_LARGE",
            "message": "This file exceeds the allowed size.",
        }
    finally:
        app.dependency_overrides.clear()


def test_document_routes_reject_unauthenticated_requests() -> None:
    response = TestClient(app).get("/api/v1/documents")

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHENTICATED"


def test_cross_tenant_document_id_is_denied_without_leaking_document_metadata(monkeypatch) -> None:
    service = FakeDocumentService()
    service.record = {**service.record, "tenant_id": "tenant_globex", "name": "globex-plan.md"}
    monkeypatch.setattr("backend.app.main.get_document_service", lambda: service)
    app.dependency_overrides[require_request_context] = lambda: _context("admin")
    try:
        response = TestClient(app).get("/api/v1/documents/doc_globex")

        assert response.status_code == 403
        body = response.json()
        assert body["error"] == {
            "code": "ACCESS_DENIED",
            "message": "You do not have permission to access this resource.",
        }
        assert "globex" not in str(body).lower()
        assert "classification" not in str(body).lower()
    finally:
        app.dependency_overrides.clear()


def test_cross_tenant_document_mutations_are_denied_before_service_action(monkeypatch) -> None:
    service = FakeDocumentService()
    service.record = {**service.record, "tenant_id": "tenant_globex"}
    monkeypatch.setattr("backend.app.main.get_document_service", lambda: service)
    app.dependency_overrides[require_request_context] = lambda: _context("admin")
    try:
        client = TestClient(app)
        for method, path in (
            (client.post, "/api/v1/documents/doc_globex/approve"),
            (client.post, "/api/v1/documents/doc_globex/quarantine"),
            (client.delete, "/api/v1/documents/doc_globex"),
        ):
            response = method(path)
            assert response.status_code == 403
            assert response.json()["error"]["code"] == "ACCESS_DENIED"
    finally:
        app.dependency_overrides.clear()
