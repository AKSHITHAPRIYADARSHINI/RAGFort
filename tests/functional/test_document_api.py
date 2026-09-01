from fastapi.testclient import TestClient

from backend.app.documents.models import FileTooLargeError
from backend.app.main import app


class FakeDocumentService:
    def __init__(self) -> None:
        self.record = {
            "document_id": "doc_test",
            "version_id": "ver_test",
            "name": "policy.txt",
            "status": "REVIEW_REQUIRED",
            "classification": "INTERNAL",
            "index_state": "NOT_INDEXED",
        }

    def upload(self, _name, _content_type, data):
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


def test_document_endpoints_use_safe_envelopes(monkeypatch) -> None:
    service = FakeDocumentService()
    monkeypatch.setattr("backend.app.main.get_document_service", lambda: service)
    client = TestClient(app)

    listed = client.get("/api/v1/documents")
    uploaded = client.post(
        "/api/v1/documents", files={"file": ("policy.txt", b"safe", "text/plain")}
    )
    approved = client.post("/api/v1/documents/doc_test/approve")
    findings = client.get("/api/v1/documents/doc_test/security")

    assert listed.status_code == 200
    assert listed.json()["data"]["documents"][0]["document_id"] == "doc_test"
    assert uploaded.status_code == 200 and uploaded.json()["request_id"].startswith("req_")
    assert approved.json()["data"]["status"] == "INDEXED"
    assert findings.json()["data"]["findings"] == []


def test_upload_errors_do_not_leak_file_or_parser_details(monkeypatch) -> None:
    monkeypatch.setattr("backend.app.main.get_document_service", lambda: FakeDocumentService())
    response = TestClient(app).post(
        "/api/v1/documents", files={"file": ("ignored.txt", b"too-large", "text/plain")}
    )

    assert response.status_code == 400
    assert response.json()["error"] == {
        "code": "FILE_TOO_LARGE",
        "message": "This file exceeds the allowed size.",
    }
