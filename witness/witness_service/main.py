"""Independent Witness microservice.

Runs in its own container with its own Ed25519 key and its own database.
It accepts Signed Tree Heads from the primary TrustChain log and counter-signs
them only if they (1) carry a valid signature from the pinned log key,
(2) do not roll the log back, and (3) are provably consistent (RFC 9162) with
the last tree head this witness accepted.  Every rejection is persisted as a
security alert.
"""

from __future__ import annotations

import asyncio
import hmac
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from functools import lru_cache
from typing import AsyncIterator, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, status
from fastapi.responses import JSONResponse
from nacl.signing import SigningKey
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from witness_service import core
from witness_service.config import load_log_public_key, load_witness_signing_key, settings
from witness_service.crypto import key_id_for, sign_ed25519, witness_ack_statement
from witness_service.db import SessionLocal, WitnessCheckpoint, init_db

_lock = asyncio.Lock()


@lru_cache(maxsize=1)
def witness_key() -> SigningKey:
    return load_witness_signing_key()


def witness_public_hex() -> str:
    return bytes(witness_key().verify_key).hex()


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    witness_key()
    yield


app = FastAPI(title="TrustChain Witness Service", version="1.0.0", lifespan=lifespan)


async def get_session() -> AsyncIterator[AsyncSession]:
    async with SessionLocal() as s:
        yield s


def require_token(x_witness_token: Optional[str] = Header(None, alias="X-Witness-Token")) -> None:
    if not x_witness_token or not hmac.compare_digest(x_witness_token, settings.witness_token):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid witness token")


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CheckpointSubmission(BaseModel):
    log_id: str
    tree_size: int = Field(ge=1)
    root_hash: str
    timestamp: str
    key_id: str
    signature: str
    consistency_proof: list[str] = []
    previous_tree_size: int = 0  # informational; the witness uses its OWN state
    previous_root_hash: Optional[str] = None


class WitnessAck(BaseModel):
    status: str
    tree_size: int
    root_hash: str
    witness_signature: Optional[str] = None
    witness_key_id: Optional[str] = None
    witness_public_key: Optional[str] = None
    witness_timestamp: Optional[str] = None
    alert_reason: Optional[str] = None
    alert_detail: Optional[str] = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _last_accepted(db: AsyncSession) -> Optional[WitnessCheckpoint]:
    q = (
        select(WitnessCheckpoint)
        .where(WitnessCheckpoint.status == core.ACCEPTED)
        .order_by(WitnessCheckpoint.tree_size.desc(), WitnessCheckpoint.created_at.desc())
        .limit(1)
    )
    return (await db.execute(q)).scalar_one_or_none()


def _row_dict(r: WitnessCheckpoint) -> dict:
    return {
        "id": str(r.id),
        "log_id": r.log_id,
        "tree_size": r.tree_size,
        "root_hash": r.root_hash,
        "log_timestamp": r.log_timestamp,
        "log_key_id": r.log_key_id,
        "log_signature": r.log_signature,
        "witness_signature": r.witness_signature,
        "witness_timestamp": r.witness_timestamp,
        "status": r.status,
        "alert_reason": r.alert_reason,
        "created_at": r.created_at.isoformat() if r.created_at else None,
    }


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.get("/witness/public-key")
async def public_key() -> dict:
    pub = witness_public_hex()
    return {"public_key": pub, "key_id": key_id_for(bytes.fromhex(pub)), "algorithm": "Ed25519"}


@app.get("/witness/latest")
async def latest(db: AsyncSession = Depends(get_session)) -> dict:
    last = await _last_accepted(db)
    if last is None:
        return {"tree_size": 0, "root_hash": None}
    return _row_dict(last)


@app.get("/witness/checkpoints")
async def list_checkpoints(limit: int = 100, db: AsyncSession = Depends(get_session)) -> list[dict]:
    q = select(WitnessCheckpoint).order_by(WitnessCheckpoint.created_at.desc()).limit(min(limit, 1000))
    return [_row_dict(r) for r in (await db.execute(q)).scalars()]


@app.get("/witness/alerts")
async def list_alerts(db: AsyncSession = Depends(get_session)) -> list[dict]:
    q = (
        select(WitnessCheckpoint)
        .where(WitnessCheckpoint.status == core.REJECTED)
        .order_by(WitnessCheckpoint.created_at.desc())
    )
    return [_row_dict(r) for r in (await db.execute(q)).scalars()]


@app.post(
    "/witness/checkpoint",
    response_model=WitnessAck,
    responses={409: {"model": WitnessAck}},
    dependencies=[Depends(require_token)],
)
async def witness_checkpoint(
    body: CheckpointSubmission, db: AsyncSession = Depends(get_session)
):
    log_pub = load_log_public_key()
    if not log_pub:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE, "primary log public key is not pinned"
        )
    log_kid = key_id_for(bytes.fromhex(log_pub))

    async with _lock:
        last = await _last_accepted(db)
        state = (
            core.WitnessState(last.tree_size, last.root_hash) if last else core.WitnessState()
        )
        decision = core.evaluate(
            core.Submission(
                log_id=body.log_id,
                tree_size=body.tree_size,
                root_hash=body.root_hash.lower(),
                timestamp=body.timestamp,
                key_id=body.key_id,
                signature=body.signature,
                consistency_proof=body.consistency_proof,
            ),
            state,
            log_pub,
            log_kid,
            settings.witness_log_id,
        )

        row = WitnessCheckpoint(
            id=uuid.uuid4(),
            log_id=body.log_id,
            tree_size=body.tree_size,
            root_hash=body.root_hash.lower(),
            log_timestamp=body.timestamp,
            log_key_id=body.key_id,
            log_signature=body.signature,
            status=decision.status,
        )
        if decision.status == core.ACCEPTED:
            sk = witness_key()
            wkid = key_id_for(bytes(sk.verify_key))
            wts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            row.witness_timestamp = wts
            row.witness_signature = sign_ed25519(
                sk,
                witness_ack_statement(
                    body.log_id, body.tree_size, row.root_hash, body.signature, wts, wkid
                ),
            )
        else:
            row.alert_reason = f"{decision.reason}: {decision.detail}"
        db.add(row)
        await db.commit()

    if decision.status == core.ACCEPTED:
        return WitnessAck(
            status=core.ACCEPTED,
            tree_size=row.tree_size,
            root_hash=row.root_hash,
            witness_signature=row.witness_signature,
            witness_key_id=key_id_for(bytes(witness_key().verify_key)),
            witness_public_key=witness_public_hex(),
            witness_timestamp=row.witness_timestamp,
        )
    ack = WitnessAck(
        status=core.REJECTED,
        tree_size=row.tree_size,
        root_hash=row.root_hash,
        alert_reason=decision.reason,
        alert_detail=decision.detail,
    )
    return JSONResponse(status_code=status.HTTP_409_CONFLICT, content=ack.model_dump())
