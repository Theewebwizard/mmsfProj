from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import BigInteger, DateTime, String, Text, Uuid, func
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from witness_service.config import settings


class Base(DeclarativeBase):
    pass


class WitnessCheckpoint(Base):
    __tablename__ = "witness_checkpoints"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    log_id: Mapped[str] = mapped_column(String(255), nullable=False)
    tree_size: Mapped[int] = mapped_column(BigInteger, nullable=False, index=True)
    root_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    log_timestamp: Mapped[str] = mapped_column(String(64), nullable=False)
    log_key_id: Mapped[str] = mapped_column(String(64), nullable=False)
    log_signature: Mapped[str] = mapped_column(Text, nullable=False)
    witness_signature: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    witness_timestamp: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, index=True)
    alert_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


engine = create_async_engine(settings.witness_db_url, future=True)
SessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def init_db(eng=None) -> None:
    async with (eng or engine).begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
