import hashlib
import json
import re
import unicodedata
from datetime import datetime
from pathlib import PurePath
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from backend.app.documents.models import (
    Classification,
    DocumentAccessAssignment,
    DocumentError,
    DocumentNotFoundError,
    DocumentStatus,
    FileTooLargeError,
    FileValidationError,
    Finding,
    InvalidTransitionError,
    UnsupportedMediaError,
)
from backend.app.documents.persistence import DocumentRecord, DocumentVersionRecord
from backend.app.rag.chunking import DocumentChunker
from backend.app.rag.embeddings import EmbeddingService
from backend.app.rag.models import Document
from backend.app.rag.retrieval import QdrantRetriever, RetrievalUnavailableError

MAX_UPLOAD_BYTES = 1_000_000
MAX_EXTRACTED_CHARS = 200_000
_ALLOWED = {".txt": "text/plain", ".md": "text/markdown"}


def _safe_name(filename: str) -> str:
    name = PurePath(filename.replace("\\", "/")).name.strip()
    if not name or len(name) > 255:
        raise FileValidationError()
    return name


def _detected_type(name: str, data: bytes) -> str:
    extension = PurePath(name).suffix.lower()
    expected = _ALLOWED.get(extension)
    if expected is None:
        raise UnsupportedMediaError()
    if data.startswith(b"%PDF-") or b"\x00" in data[:4096]:
        raise FileValidationError()
    return expected


def _extract(name: str, detected_type: str, data: bytes) -> str:
    try:
        text = data.decode("utf-8")
    except FileValidationError:
        raise
    except Exception as error:
        raise DocumentError() from error
    if not text.strip() or len(text) > MAX_EXTRACTED_CHARS:
        raise FileValidationError()
    return text


def _normalize(text: str) -> tuple[str, bool]:
    has_hidden = bool(re.search(r"[\u200b-\u200f\u202a-\u202e\u2060\ufeff]", text))
    normalized = unicodedata.normalize("NFKC", text)
    normalized = re.sub(r"[\u200b-\u200f\u202a-\u202e\u2060\ufeff]", "", normalized)
    return re.sub(r"\s+", " ", normalized).strip(), has_hidden


def _scan(text: str, has_hidden: bool) -> list[Finding]:
    findings: list[Finding] = []
    patterns = [
        r"ignore\s+(all\s+)?previous\s+instructions",
        r"system\s*:",
        r"reveal\s+(the\s+)?system\s+prompt",
        r"you\s+are\s+now\s+the\s+system\s+administrator",
        r"when\s+(an\s+)?ai\s+reads",
    ]
    if any(re.search(pattern, text, re.IGNORECASE) for pattern in patterns):
        findings.append(
            Finding("SUSPICIOUS_INSTRUCTION", "HIGH", "Instruction-like content requires review.")
        )
    if has_hidden:
        findings.append(
            Finding("HIDDEN_UNICODE", "HIGH", "Hidden Unicode control content was detected.")
        )
    sensitive = [
        r"\b\d{3}-\d{2}-\d{4}\b",
        r"\b[A-Z0-9]{16,}\b",
        r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",
        r"\b(?:api[_-]?key|token|password)\s*[:=]",
    ]
    if any(re.search(pattern, text, re.IGNORECASE) for pattern in sensitive):
        findings.append(
            Finding("SENSITIVE_DATA", "MEDIUM", "Sensitive-data-like content requires review.")
        )
    return findings


class DocumentService:
    """Explicit Phase 3 pipeline. Browser input never controls lifecycle or index metadata."""

    def __init__(
        self,
        session_factory,
        embeddings: EmbeddingService,
        index: QdrantRetriever,
        *,
        default_access: DocumentAccessAssignment | None = None,
    ) -> None:
        self.session_factory = session_factory
        self.embeddings = embeddings
        self.index = index
        self.chunker = DocumentChunker()
        # Compatibility for the controlled Phase 3 development corpus only.
        # Runtime routes must provide an assignment derived from RequestContext.
        self.default_access = default_access or DocumentAccessAssignment(
            tenant_id="tenant_development", allowed_role_ids=("viewer",)
        )

    def upload(
        self,
        filename: str,
        declared_type: str | None,
        data: bytes,
        *,
        access: DocumentAccessAssignment | None = None,
    ) -> dict:
        del declared_type  # advisory only; signature and bytes are authoritative.
        if not data:
            raise FileValidationError()
        if len(data) > MAX_UPLOAD_BYTES:
            raise FileTooLargeError()
        safe_name = _safe_name(filename)
        detected_type = _detected_type(safe_name, data)
        extracted = _extract(safe_name, detected_type, data)
        normalized, has_hidden = _normalize(extracted)
        findings = _scan(normalized, has_hidden)
        original_hash = hashlib.sha256(data).hexdigest()
        content_hash = hashlib.sha256(normalized.encode()).hexdigest()
        assignment = access or self.default_access
        with self.session_factory.begin() as session:
            duplicate = session.scalar(
                select(DocumentVersionRecord).where(
                    DocumentVersionRecord.original_sha256 == original_hash
                )
            )
            if duplicate:
                return self._summary(session.get(DocumentRecord, duplicate.document_id), duplicate)
            document = session.scalar(
                select(DocumentRecord).where(DocumentRecord.safe_display_name == safe_name)
            )
            if document is None:
                document = DocumentRecord(
                    id=f"doc_{uuid4().hex}",
                    safe_display_name=safe_name,
                    status=DocumentStatus.REVIEW_REQUIRED,
                    classification=Classification.INTERNAL,
                    tenant_id=assignment.tenant_id,
                    allowed_role_ids_json=json.dumps(list(assignment.allowed_role_ids)),
                    department=assignment.department,
                    authorization_metadata_version=assignment.metadata_version,
                )
                session.add(document)
                version_number = 1
            else:
                version_number = (
                    session.scalar(
                        select(DocumentVersionRecord.version_number)
                        .where(DocumentVersionRecord.document_id == document.id)
                        .order_by(DocumentVersionRecord.version_number.desc())
                    )
                    or 0
                )
                version_number += 1
                # A new version belongs to the existing server-owned document
                # access boundary; client uploads cannot change it.
                assignment = self._access_assignment(document)
                prior_versions = session.scalars(
                    select(DocumentVersionRecord).where(
                        DocumentVersionRecord.document_id == document.id,
                        DocumentVersionRecord.current_version.is_(True),
                    )
                ).all()
                for prior in prior_versions:
                    prior.current_version = False
            status = (
                DocumentStatus.QUARANTINED
                if any(f.severity == "HIGH" for f in findings)
                else DocumentStatus.REVIEW_REQUIRED
            )
            version = DocumentVersionRecord(
                id=f"ver_{uuid4().hex}",
                document_id=document.id,
                version_number=version_number,
                status=status,
                original_filename=safe_name,
                detected_type=detected_type,
                byte_size=len(data),
                original_sha256=original_hash,
                content_sha256=content_hash,
                original_bytes=data,
                normalized_text=normalized,
                findings_json=json.dumps([finding.__dict__ for finding in findings]),
                index_state="NOT_INDEXED",
                tenant_id=assignment.tenant_id,
                classification=document.classification,
                allowed_role_ids_json=json.dumps(list(assignment.allowed_role_ids)),
                department=assignment.department,
                authorization_metadata_version=assignment.metadata_version,
                current_version=True,
            )
            document.status = status
            document.current_version_id = version.id
            session.add(version)
            return self._summary(document, version)

    def list_documents(self) -> list[dict]:
        with self.session_factory() as session:
            docs = session.scalars(
                select(DocumentRecord).order_by(DocumentRecord.updated_at.desc())
            ).all()
            return [
                self._summary(doc, session.get(DocumentVersionRecord, doc.current_version_id))
                for doc in docs
            ]

    def get_document(self, document_id: str, include_findings: bool = False) -> dict:
        with self.session_factory() as session:
            document, version = self._get_current(session, document_id)
            result = self._summary(document, version)
            if include_findings:
                result["findings"] = json.loads(version.findings_json)
            return result

    def approve(self, document_id: str) -> dict:
        integrity_failed = False
        with self.session_factory.begin() as session:
            document, version = self._get_current(session, document_id)
            if version.status != DocumentStatus.REVIEW_REQUIRED:
                raise InvalidTransitionError()
            if (
                hashlib.sha256(version.original_bytes).hexdigest() != version.original_sha256
                or hashlib.sha256(version.normalized_text.encode()).hexdigest()
                != version.content_sha256
            ):
                version.status = document.status = DocumentStatus.QUARANTINED
                integrity_failed = True
            else:
                version.status = document.status = DocumentStatus.APPROVED
        if integrity_failed:
            raise InvalidTransitionError()
        return self._index(document_id)

    def rescan(self, document_id: str) -> dict:
        with self.session_factory.begin() as session:
            document, version = self._get_current(session, document_id)
            if version.status in {DocumentStatus.DELETED, DocumentStatus.DELETION_PENDING}:
                raise InvalidTransitionError()
            if hashlib.sha256(version.original_bytes).hexdigest() != version.original_sha256:
                version.status = document.status = DocumentStatus.QUARANTINED
                version.index_state = "NOT_INDEXED"
                raise InvalidTransitionError()
            extracted = _extract(
                version.original_filename, version.detected_type, version.original_bytes
            )
            normalized, has_hidden = _normalize(extracted)
            if hashlib.sha256(normalized.encode()).hexdigest() != version.content_sha256:
                version.status = document.status = DocumentStatus.QUARANTINED
                version.index_state = "NOT_INDEXED"
                raise InvalidTransitionError()
            findings = _scan(normalized, has_hidden)
            version.findings_json = json.dumps([finding.__dict__ for finding in findings])
            version.status = document.status = (
                DocumentStatus.QUARANTINED
                if any(finding.severity == "HIGH" for finding in findings)
                else DocumentStatus.REVIEW_REQUIRED
            )
            version.index_state = "NOT_INDEXED"
        if document.status == DocumentStatus.QUARANTINED:
            try:
                self.index.delete_by_filter({"version_id": version.id})
            except RetrievalUnavailableError:
                pass
        return self.get_document(document_id, include_findings=True)

    def quarantine(self, document_id: str) -> dict:
        with self.session_factory.begin() as session:
            document, version = self._get_current(session, document_id)
            version.status = document.status = DocumentStatus.QUARANTINED
            version.index_state = "NOT_INDEXED"
        try:
            self.index.delete_by_filter({"version_id": version.id})
        except RetrievalUnavailableError:
            pass
        return self.get_document(document_id)

    def delete(self, document_id: str) -> dict:
        with self.session_factory.begin() as session:
            document, version = self._get_current(session, document_id)
            document.status = DocumentStatus.DELETION_PENDING
            version.status = DocumentStatus.DELETION_PENDING
        try:
            self.index.delete_by_filter({"version_id": version.id})
        except RetrievalUnavailableError:
            return self.get_document(document_id)
        with self.session_factory.begin() as session:
            document, version = self._get_current(session, document_id)
            document.status = version.status = DocumentStatus.DELETED
            version.index_state = "REMOVED"
        return self.get_document(document_id)

    def _index(self, document_id: str) -> dict:
        with self.session_factory() as session:
            document, version = self._get_current(session, document_id)
            if version.status != DocumentStatus.APPROVED:
                raise InvalidTransitionError()
            payload = self._secure_index_metadata(document, version)
            source = Document(
                document.id,
                document.safe_display_name,
                "uploaded_document",
                version.id,
                version.normalized_text,
            )
            chunks = self.chunker.chunk(source)
            chunks = [
                chunk.__class__(
                    chunk.chunk_id,
                    chunk.document_id,
                    chunk.chunk_index,
                    chunk.text,
                    {
                        **chunk.metadata,
                        **payload,
                    },
                )
                for chunk in chunks
            ]
        try:
            self.index.ensure_collection(self.embeddings.dimension)
            self.index.upsert(
                chunks, self.embeddings.embed_documents([chunk.text for chunk in chunks])
            )
        except Exception:
            with self.session_factory.begin() as session:
                document, version = self._get_current(session, document_id)
                document.status = version.status = DocumentStatus.INDEX_FAILED
                version.index_state = "FAILED"
            return self.get_document(document_id)
        with self.session_factory.begin() as session:
            document, version = self._get_current(session, document_id)
            document.status = version.status = DocumentStatus.INDEXED
            version.index_state = "INDEXED"
        return self.get_document(document_id)

    @staticmethod
    def _get_current(session: Session, document_id: str):
        document = session.get(DocumentRecord, document_id)
        if document is None or document.current_version_id is None:
            raise DocumentNotFoundError()
        version = session.get(DocumentVersionRecord, document.current_version_id)
        if version is None:
            raise DocumentNotFoundError()
        return document, version

    @staticmethod
    def _summary(document: DocumentRecord, version: DocumentVersionRecord) -> dict:
        return {
            "document_id": document.id,
            "version_id": version.id,
            "name": document.safe_display_name,
            "status": document.status,
            "classification": document.classification,
            "detected_type": version.detected_type,
            "size_bytes": version.byte_size,
            "index_state": version.index_state,
            "version": version.version_number,
            "uploaded_at": version.created_at.isoformat()
            if version.created_at
            else datetime.utcnow().isoformat(),
        }

    @staticmethod
    def _access_assignment(document: DocumentRecord) -> DocumentAccessAssignment:
        try:
            roles = tuple(str(role) for role in json.loads(document.allowed_role_ids_json))
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            raise InvalidTransitionError() from error
        try:
            return DocumentAccessAssignment(
                tenant_id=document.tenant_id or "",
                allowed_role_ids=roles,
                department=document.department,
                metadata_version=document.authorization_metadata_version,
            )
        except ValueError as error:
            raise InvalidTransitionError() from error

    def _secure_index_metadata(
        self, document: DocumentRecord, version: DocumentVersionRecord
    ) -> dict[str, object]:
        """Build the complete derived Phase 4 payload or refuse to index.

        Missing metadata never means public.  Qdrant receives this payload only
        after the authoritative document/version state passes Phase 3 integrity
        and approval checks above.
        """
        assignment = self._access_assignment(document)
        if (
            version.tenant_id != assignment.tenant_id
            or version.classification != document.classification
            or version.authorization_metadata_version != assignment.metadata_version
            or not version.current_version
        ):
            raise InvalidTransitionError()
        try:
            version_roles = tuple(str(role) for role in json.loads(version.allowed_role_ids_json))
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            raise InvalidTransitionError() from error
        if version_roles != assignment.allowed_role_ids:
            raise InvalidTransitionError()
        return {
            "version_id": version.id,
            "tenant_id": assignment.tenant_id,
            "classification": document.classification,
            "allowed_role_ids": list(assignment.allowed_role_ids),
            "department": assignment.department,
            "authorization_metadata_version": assignment.metadata_version,
            "approval_status": "approved",
            "document_status": DocumentStatus.INDEXED,
            "index_state": "INDEXED",
            "current_version": True,
            "content_sha256": version.content_sha256,
            "security_scan_status": "passed",
        }
