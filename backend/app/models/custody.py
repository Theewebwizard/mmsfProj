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
    LargeBinary,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID as PGUUID

from app.database import Base


class EventType(str, enum.Enum):
    EVIDENCE_REGISTERED = "EVIDENCE_REGISTERED"
    CUSTODY_TRANSFER_INITIATED = "CUSTODY_TRANSFER_INITIATED"
    CUSTODY_TRANSFER_ACKNOWLEDGED = "CUSTODY_TRANSFER_ACKNOWLEDGED"
    EVIDENCE_VERIFIED = "EVIDENCE_VERIFIED"
    REPORT_EXPORTED = "REPORT_EXPORTED"


class CustodyEvent(Base):
    __tablename__ = "custody_events"

    id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    evidence_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("evidence.id"), nullable=False, index=True
    )
    actor_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("users.id"), nullable=False
    )
    event_type: Mapped[EventType] = mapped_column(
        SAEnum(EventType, name="eventtype"), nullable=False
    )
    payload_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    canonical_bytes: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True)
    signature: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )  # hex-encoded
    key_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    log_index: Mapped[Optional[int]] = mapped_column(
        BigInteger, nullable=True, index=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
