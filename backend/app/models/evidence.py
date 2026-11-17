import uuid
import enum
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    String,
    Text,
    Enum as SAEnum,
    DateTime,
    ForeignKey,
    BigInteger,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID as PGUUID

from app.database import Base


class C2PAStatus(str, enum.Enum):
    VALID = "VALID"
    INVALID = "INVALID"
    ABSENT = "ABSENT"
    ERROR = "ERROR"
    PENDING = "PENDING"


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    case_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("cases.id"), nullable=False, index=True
    )
    original_filename: Mapped[str] = mapped_column(String(500), nullable=False)
    storage_key: Mapped[str] = mapped_column(
        String(1000), unique=True, nullable=False
    )  # MinIO object key (UUID-based)
    sha256_digest: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    file_size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    mime_type: Mapped[str] = mapped_column(String(100), nullable=False)
    phash: Mapped[Optional[str]] = mapped_column(
        String(64), nullable=True, index=True
    )
    c2pa_status: Mapped[C2PAStatus] = mapped_column(
        SAEnum(C2PAStatus, name="c2pastatus"),
        nullable=False,
        default=C2PAStatus.PENDING,
    )
    c2pa_summary_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    uploaded_by: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
