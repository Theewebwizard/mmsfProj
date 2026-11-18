import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import String, Text, DateTime, BigInteger, func
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID as PGUUID

from app.database import Base


class LogCheckpoint(Base):
    __tablename__ = "log_checkpoints"

    id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    log_id: Mapped[str] = mapped_column(String(255), nullable=False)
    tree_size: Mapped[int] = mapped_column(BigInteger, nullable=False, index=True)
    root_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    signature: Mapped[str] = mapped_column(Text, nullable=False)
    key_id: Mapped[str] = mapped_column(String(255), nullable=False)
    # The exact ISO-8601 string that was signed (part of the STH statement).
    timestamp: Mapped[str] = mapped_column(String(64), nullable=False)
    # Witness outcome: PENDING | ACKNOWLEDGED | REJECTED | UNAVAILABLE
    witness_status: Mapped[str] = mapped_column(String(32), nullable=False, default="PENDING")
    witness_key_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    witness_public_key: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    witness_timestamp_str: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    witness_alert: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    witness_ack_signature: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    witness_timestamp: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
