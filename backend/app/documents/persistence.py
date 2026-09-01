from datetime import datetime

from sqlalchemy import DateTime, Integer, LargeBinary, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker


class Base(DeclarativeBase):
    pass


class DocumentRecord(Base):
    __tablename__ = "documents"
    id: Mapped[str] = mapped_column(String(40), primary_key=True)
    safe_display_name: Mapped[str] = mapped_column(String(255), index=True)
    status: Mapped[str] = mapped_column(String(32), index=True)
    classification: Mapped[str] = mapped_column(String(32))
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
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


def make_session_factory(database_url: str):
    connect_args = {"check_same_thread": False} if database_url.startswith("sqlite") else {}
    engine = create_engine(database_url, future=True, connect_args=connect_args)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False)
