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
    tree_size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    root_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    signature: Mapped[str] = mapped_column(Text, nullable=False)
    key_id: Mapped[str] = mapped_column(String(255), nullable=False)
    witness_ack_signature: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    witness_timestamp: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
