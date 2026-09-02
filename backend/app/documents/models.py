from dataclasses import dataclass
from enum import StrEnum


class DocumentStatus(StrEnum):
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    QUARANTINED = "QUARANTINED"
    APPROVED = "APPROVED"
    INDEXED = "INDEXED"
    INDEX_FAILED = "INDEX_FAILED"
    REJECTED = "REJECTED"
    DELETED = "DELETED"
    DELETION_PENDING = "DELETION_PENDING"


class Classification(StrEnum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"


@dataclass(frozen=True)
class DocumentAccessAssignment:
    """Server-owned Phase 4 access metadata for a document version.

    This object is intentionally a service input, not an API request model.
    Routes must build it from the canonical request context or a controlled
    administrative workflow; browser-supplied tenant or role values are never
    converted into this type.
    """

    tenant_id: str
    allowed_role_ids: tuple[str, ...]
    department: str | None = None
    metadata_version: int = 4

    def __post_init__(self) -> None:
        if not self.tenant_id.strip():
            raise ValueError("document access assignment requires a tenant")
        if not self.allowed_role_ids or any(not role.strip() for role in self.allowed_role_ids):
            raise ValueError("document access assignment requires at least one role")
        if self.metadata_version < 4:
            raise ValueError("document access metadata must use the Phase 4 schema")


@dataclass(frozen=True)
class Finding:
    category: str
    severity: str
    description: str


class DocumentError(RuntimeError):
    code = "DOCUMENT_PROCESSING_FAILED"
    message = "We couldn't process this document safely."


class FileValidationError(DocumentError):
    code = "INVALID_FILE"
    message = "This file cannot be accepted."


class FileTooLargeError(DocumentError):
    code = "FILE_TOO_LARGE"
    message = "This file exceeds the allowed size."


class UnsupportedMediaError(DocumentError):
    code = "UNSUPPORTED_MEDIA_TYPE"
    message = "Only TXT and Markdown documents are supported."


class DocumentNotFoundError(DocumentError):
    code = "DOCUMENT_NOT_FOUND"
    message = "The requested document was not found."


class InvalidTransitionError(DocumentError):
    code = "DOCUMENT_NOT_READY"
    message = "This document cannot complete that action in its current state."


class DocumentStoreUnavailableError(DocumentError):
    code = "DOCUMENT_STORE_UNAVAILABLE"
    message = "The document service is unavailable right now."
