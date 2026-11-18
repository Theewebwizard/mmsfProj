import uuid
from datetime import datetime

from sqlalchemy import String, DateTime, ForeignKey, BigInteger, func
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID as PGUUID

from app.database import Base


class LogEntry(Base):
    __tablename__ = "log_entries"

    index: Mapped[int] = mapped_column(
        BigInteger, primary_key=True, autoincrement=True
    )
    event_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("custody_events.id"), nullable=False
    )
    leaf_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


from sqlalchemy import event as _sa_event  # noqa: E402

from app.models.custody import _forbid  # noqa: E402

_sa_event.listen(LogEntry, "before_update", _forbid)
_sa_event.listen(LogEntry, "before_delete", _forbid)
