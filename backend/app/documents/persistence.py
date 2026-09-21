from datetime import datetime

from sqlalchemy import DateTime, Integer, LargeBinary, String, Text, create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker


class Base(DeclarativeBase):
    pass


class DocumentRecord(Base):
    __tablename__ = "documents"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    safe_display_name: Mapped[str] = mapped_column(String(255), index=True)
    status: Mapped[str] = mapped_column(String(32), index=True)
    classification: Mapped[str] = mapped_column(String(32))
    # Phase 4 access state is authoritative in PostgreSQL.  It is copied into
    # Qdrant only as derived, query-time filtering metadata.
    tenant_id: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    allowed_role_ids_json: Mapped[str] = mapped_column(Text, default="[]")
    department: Mapped[str | None] = mapped_column(String(128), nullable=True)
    authorization_metadata_version: Mapped[int] = mapped_column(Integer, default=0)
    current_version_id: Mapped[str | None] = mapped_column(String(40), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )


class DocumentVersionRecord(Base):
    __tablename__ = "document_versions"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    document_id: Mapped[str] = mapped_column(String(40), index=True)
    version_number: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(32), index=True)
    original_filename: Mapped[str] = mapped_column(String(255))
    detected_type: Mapped[str] = mapped_column(String(32))
    byte_size: Mapped[int] = mapped_column(Integer)
    original_sha256: Mapped[str] = mapped_column(String(64), index=True)
    content_sha256: Mapped[str] = mapped_column(String(64))
    original_bytes: Mapped[bytes] = mapped_column(LargeBinary)
    normalized_text: Mapped[str] = mapped_column(Text)
    findings_json: Mapped[str] = mapped_column(Text, default="[]")
    index_state: Mapped[str] = mapped_column(String(32), default="NOT_INDEXED")
    # Snapshot access state so an old version cannot be reindexed under a
    # newer document ACL without an explicit authoritative update.
    tenant_id: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    classification: Mapped[str | None] = mapped_column(String(32), nullable=True)
    allowed_role_ids_json: Mapped[str] = mapped_column(Text, default="[]")
    department: Mapped[str | None] = mapped_column(String(128), nullable=True)
    authorization_metadata_version: Mapped[int] = mapped_column(Integer, default=0)
    current_version: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class SecurityEventRecord(Base):
    """Minimized Phase 5 audit evidence; never stores raw prompts or chunks."""

    __tablename__ = "security_events"
    event_id: Mapped[str] = mapped_column(String(40), primary_key=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime, index=True)
    request_id: Mapped[str] = mapped_column(String(64), index=True)
    detection_id: Mapped[str] = mapped_column(String(64), index=True)
    subject_id: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    tenant_id: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    categories_json: Mapped[str] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(16))
    risk_score: Mapped[int] = mapped_column(Integer)
    policy_action: Mapped[str] = mapped_column(String(24))
    detector_version: Mapped[str] = mapped_column(String(64))
    policy_version: Mapped[str] = mapped_column(String(64))
    route: Mapped[str] = mapped_column(String(128))
    outcome: Mapped[str] = mapped_column(String(32))
    indicator_codes_json: Mapped[str] = mapped_column(Text)
    safe_metadata_json: Mapped[str] = mapped_column(Text)


def make_session_factory(database_url: str):
    connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}
    engine = create_engine(database_url, future=True, connect_args=connect_args)
    Base.metadata.create_all(engine)
    _upgrade_phase4_document_access_columns(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)


def _upgrade_phase4_document_access_columns(engine) -> None:
    """Additive compatibility upgrade for Phase 3 development databases.

    This deliberately does not backfill a permissive access rule.  Existing
    points and records remain unqueryable until Phase 4 assigns metadata and
    rebuilds derived vectors.  A formal production migration can use the same
    column set without drop/recreate behaviour.
    """
    additions = {
        "documents": {
            "tenant_id": "VARCHAR(64)",
            "allowed_role_ids_json": "TEXT DEFAULT '[]'",
            "department": "VARCHAR(128)",
            "authorization_metadata_version": "INTEGER DEFAULT 0",
        },
        "document_versions": {
            "tenant_id": "VARCHAR(64)",
            "classification": "VARCHAR(32)",
            "allowed_role_ids_json": "TEXT DEFAULT '[]'",
            "department": "VARCHAR(128)",
            "authorization_metadata_version": "INTEGER DEFAULT 0",
            "current_version": "BOOLEAN DEFAULT TRUE",
        },
    }
    inspector = inspect(engine)
    with engine.begin() as connection:
        for table_name, columns in additions.items():
            if table_name not in inspector.get_table_names():
                continue
            existing = {column["name"] for column in inspector.get_columns(table_name)}
            for column_name, ddl in columns.items():
                if column_name not in existing:
                    statement = f"ALTER TABLE {table_name} ADD COLUMN {column_name} {ddl}"
                    connection.execute(text(statement))
