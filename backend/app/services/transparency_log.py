"""TrustChain transparency log: signed custody events, RFC 9162 Merkle log,
signed checkpoints (STHs) and witness co-signing.

Write path for a custody event (all inside one DB transaction):

    canonical_bytes = canonical_json(event statement)
    signature       = Ed25519_custody(canonical_bytes)
    leaf_hash       = SHA-256(0x00 || canonical_bytes)
    log_entries[i]  = leaf_hash        (i = next 0-based index)

Appends are serialised by an in-process asyncio lock plus, on PostgreSQL, a
transaction-scoped advisory lock, so indices are dense and gap-free.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Optional, Sequence

import httpx
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.crypto import merkle
from app.crypto.canonical import canonical_json
from app.crypto.keys import key_id_for, verify_signature
from app.crypto.statements import EVENT_TYPE, checkpoint_statement, witness_ack_statement
from app.models.checkpoint import LogCheckpoint
from app.models.custody import CustodyEvent, EventType
from app.models.log_entry import LogEntry
from app.services.crypto_context import (
    checkpoint_signer,
    custody_signer,
    pinned_witness_public_key,
)
from app.services.witness_client import witness_client

logger = logging.getLogger(__name__)

_ADVISORY_LOCK_KEY = 0x7C_9162  # arbitrary constant for pg_advisory_xact_lock
_append_lock = asyncio.Lock()
_checkpoint_lock = asyncio.Lock()


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ---------------------------------------------------------------------------
# Append
# ---------------------------------------------------------------------------


class LogWriter:
    """Handle returned by :func:`log_transaction`; appends signed events."""

    def __init__(self, db: AsyncSession) -> None:
        self.db = db
        self._next_index: Optional[int] = None
        self.appended: list[CustodyEvent] = []

    async def _allocate_index(self) -> int:
        if self._next_index is None:
            res = await self.db.execute(select(func.max(LogEntry.index)))
            current = res.scalar()
            self._next_index = 0 if current is None else int(current) + 1
        idx = self._next_index
        self._next_index += 1
        return idx

    async def _prev_event_hash(self, evidence_id: uuid.UUID) -> Optional[str]:
        res = await self.db.execute(
            select(CustodyEvent.canonical_bytes)
            .where(CustodyEvent.evidence_id == evidence_id)
            .where(CustodyEvent.log_index.is_not(None))
            .order_by(CustodyEvent.log_index.desc())
            .limit(1)
        )
        prev = res.scalar_one_or_none()
        return sha256_hex(prev) if prev else None

    async def append(
        self,
        *,
        evidence_id: uuid.UUID,
        actor_id: uuid.UUID,
        event_type: EventType,
        payload: dict[str, Any],
    ) -> CustodyEvent:
        signer = custody_signer()
        index = await self._allocate_index()
        event_id = uuid.uuid4()
        timestamp = utc_now_iso()
        statement = {
            "type": EVENT_TYPE,
            "log_id": settings.log_id,
            "event_id": str(event_id),
            "event_type": event_type.value,
            "evidence_id": str(evidence_id),
            "actor_id": str(actor_id),
            "timestamp": timestamp,
            "payload": payload,
            "prev_event_hash": await self._prev_event_hash(evidence_id),
            "key_id": signer.key_id,
        }
        canonical = canonical_json(statement)
        event = CustodyEvent(
            id=event_id,
            evidence_id=evidence_id,
            actor_id=actor_id,
            event_type=event_type,
            payload_json=canonical_json(payload).decode("utf-8"),
            canonical_bytes=canonical,
            signature=signer.sign(canonical),
            key_id=signer.key_id,
            log_index=index,
            created_at=datetime.now(timezone.utc),
        )
        self.db.add(event)
        await self.db.flush()
        self.db.add(
            LogEntry(
                index=index,
                event_id=event_id,
                leaf_hash=merkle.leaf_hash(canonical).hex(),
                created_at=datetime.now(timezone.utc),
            )
        )
        await self.db.flush()
        self.appended.append(event)
        return event


@asynccontextmanager
async def log_transaction(db: AsyncSession) -> AsyncIterator[LogWriter]:
    """Serialise log appends; commits on success, rolls back on error."""
    async with _append_lock:
        if db.bind.dialect.name == "postgresql":
            await db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": _ADVISORY_LOCK_KEY})
        writer = LogWriter(db)
        try:
            yield writer
            await db.commit()
        except BaseException:
            await db.rollback()
            raise


async def append_and_checkpoint(
    db: AsyncSession,
    *,
    evidence_id: uuid.UUID,
    actor_id: uuid.UUID,
    event_type: EventType,
    payload: dict[str, Any],
) -> CustodyEvent:
    async with log_transaction(db) as log:
        event = await log.append(
            evidence_id=evidence_id, actor_id=actor_id, event_type=event_type, payload=payload
        )
    if settings.auto_checkpoint:
        await create_checkpoint(db)
    return event


# ---------------------------------------------------------------------------
# Reading the tree
# ---------------------------------------------------------------------------


async def load_leaves(db: AsyncSession, tree_size: Optional[int] = None) -> list[bytes]:
    q = select(LogEntry.index, LogEntry.leaf_hash).order_by(LogEntry.index)
    if tree_size is not None:
        q = q.where(LogEntry.index < tree_size)
    rows = (await db.execute(q)).all()
    leaves = []
    for expected, (idx, h) in enumerate(rows):
        if idx != expected:
            raise RuntimeError(f"log is not dense: expected index {expected}, found {idx}")
        leaves.append(bytes.fromhex(h))
    if tree_size is not None and len(leaves) != tree_size:
        raise ValueError(f"tree size {tree_size} exceeds log size {len(leaves)}")
    return leaves


async def log_size(db: AsyncSession) -> int:
    res = await db.execute(select(func.count()).select_from(LogEntry))
    return int(res.scalar() or 0)


async def latest_checkpoint(
    db: AsyncSession, *, acknowledged_only: bool = False, min_size: int = 0
) -> Optional[LogCheckpoint]:
    q = select(LogCheckpoint).where(LogCheckpoint.tree_size >= min_size)
    if acknowledged_only:
        q = q.where(LogCheckpoint.witness_status == "ACKNOWLEDGED")
    q = q.order_by(LogCheckpoint.tree_size.desc(), LogCheckpoint.created_at.desc()).limit(1)
    return (await db.execute(q)).scalar_one_or_none()


async def earliest_acknowledged_checkpoint(
    db: AsyncSession, min_size: int
) -> Optional[LogCheckpoint]:
    q = (
        select(LogCheckpoint)
        .where(LogCheckpoint.tree_size >= min_size)
        .where(LogCheckpoint.witness_status == "ACKNOWLEDGED")
        .order_by(LogCheckpoint.tree_size.asc(), LogCheckpoint.created_at.asc())
        .limit(1)
    )
    return (await db.execute(q)).scalar_one_or_none()


def checkpoint_to_dict(cp: LogCheckpoint) -> dict[str, Any]:
    return {
        "id": str(cp.id),
        "log_id": cp.log_id,
        "tree_size": cp.tree_size,
        "root_hash": cp.root_hash,
        "timestamp": cp.timestamp,
        "key_id": cp.key_id,
        "signature": cp.signature,
        "witness": {
            "status": cp.witness_status,
            "key_id": cp.witness_key_id,
            "public_key": cp.witness_public_key,
            "timestamp": cp.witness_timestamp_str,
            "signature": cp.witness_ack_signature,
            "alert": cp.witness_alert,
        },
    }


# ---------------------------------------------------------------------------
# Checkpoints + witness
# ---------------------------------------------------------------------------


async def create_checkpoint(db: AsyncSession, *, submit: bool = True) -> Optional[LogCheckpoint]:
    """Sign a new STH over the current log and (optionally) get it witnessed.

    Serialised so the witness always sees monotonically growing tree sizes.
    """
    async with _checkpoint_lock:
        leaves = await load_leaves(db)
        if not leaves:
            return None
        size = len(leaves)
        root = merkle.root_hash(leaves).hex()

        existing = await latest_checkpoint(db)
        if (
            existing is not None
            and existing.tree_size == size
            and existing.root_hash == root
            and existing.witness_status == "ACKNOWLEDGED"
        ):
            return existing

        signer = checkpoint_signer()
        ts = utc_now_iso()
        stmt = checkpoint_statement(settings.log_id, size, root, ts, signer.key_id)
        cp = LogCheckpoint(
            id=uuid.uuid4(),
            log_id=settings.log_id,
            tree_size=size,
            root_hash=root,
            timestamp=ts,
            key_id=signer.key_id,
            signature=signer.sign(stmt),
            witness_status="PENDING",
            created_at=datetime.now(timezone.utc),
        )
        db.add(cp)
        await db.commit()

        if submit:
            await submit_to_witness(db, cp, leaves)
        return cp


async def submit_to_witness(
    db: AsyncSession, cp: LogCheckpoint, leaves: Sequence[bytes]
) -> LogCheckpoint:
    try:
        state = await witness_client.latest()
        prev_size = int(state.get("tree_size") or 0)
        if 0 < prev_size <= cp.tree_size:
            proof = merkle.consistency_proof(prev_size, leaves[: cp.tree_size])
        else:
            proof = []
        submission = {
            "log_id": cp.log_id,
            "tree_size": cp.tree_size,
            "root_hash": cp.root_hash,
            "timestamp": cp.timestamp,
            "key_id": cp.key_id,
            "signature": cp.signature,
            "previous_tree_size": prev_size,
            "previous_root_hash": state.get("root_hash"),
            "consistency_proof": [p.hex() for p in proof],
        }
        status_code, body = await witness_client.submit(submission)
    except (httpx.HTTPError, OSError, ValueError) as exc:
        logger.warning("witness unavailable: %s", exc)
        cp.witness_status = "UNAVAILABLE"
        cp.witness_alert = f"witness unreachable: {type(exc).__name__}"
        await db.commit()
        return cp

    if status_code == 200 and body.get("status") == "ACCEPTED":
        wpub = pinned_witness_public_key() or body.get("witness_public_key")
        wkid = body.get("witness_key_id")
        wts = body.get("witness_timestamp")
        wsig = body.get("witness_signature")
        ok = bool(wpub and wsig and wkid == key_id_for(bytes.fromhex(wpub))) and verify_signature(
            wpub,
            witness_ack_statement(cp.log_id, cp.tree_size, cp.root_hash, cp.signature, wts, wkid),
            wsig,
        )
        if ok:
            cp.witness_status = "ACKNOWLEDGED"
            cp.witness_ack_signature = wsig
            cp.witness_key_id = wkid
            cp.witness_public_key = wpub
            cp.witness_timestamp_str = wts
            cp.witness_timestamp = datetime.now(timezone.utc)
        else:
            cp.witness_status = "REJECTED"
            cp.witness_alert = "witness acknowledgement signature did not verify"
    else:
        cp.witness_status = "REJECTED"
        cp.witness_alert = str(body.get("alert_reason") or body.get("detail") or status_code)
    await db.commit()
    return cp


# ---------------------------------------------------------------------------
# Proof helpers used by API + bundle export
# ---------------------------------------------------------------------------


@dataclass
class InclusionProof:
    log_index: int
    tree_size: int
    leaf_hash: str
    root_hash: str
    proof: list[str]


async def inclusion_proof_for(
    db: AsyncSession, log_index: int, tree_size: int, leaves: Optional[list[bytes]] = None
) -> InclusionProof:
    leaves = leaves if leaves is not None else await load_leaves(db, tree_size)
    tree = leaves[:tree_size]
    proof = merkle.inclusion_proof(log_index, tree)
    return InclusionProof(
        log_index=log_index,
        tree_size=tree_size,
        leaf_hash=tree[log_index].hex(),
        root_hash=merkle.root_hash(tree).hex(),
        proof=[p.hex() for p in proof],
    )


def event_to_dict(ev: CustodyEvent) -> dict[str, Any]:
    statement = json.loads(ev.canonical_bytes.decode("utf-8")) if ev.canonical_bytes else None
    return {
        "id": str(ev.id),
        "evidence_id": str(ev.evidence_id),
        "actor_id": str(ev.actor_id),
        "event_type": ev.event_type.value if hasattr(ev.event_type, "value") else ev.event_type,
        "payload": json.loads(ev.payload_json) if ev.payload_json else None,
        "timestamp": statement.get("timestamp") if statement else None,
        "prev_event_hash": statement.get("prev_event_hash") if statement else None,
        "log_index": ev.log_index,
        "key_id": ev.key_id,
        "signature": ev.signature,
        "canonical_bytes": ev.canonical_bytes.decode("utf-8") if ev.canonical_bytes else None,
    }
