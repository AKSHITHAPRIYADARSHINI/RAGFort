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
