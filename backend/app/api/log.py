"""Transparency-log routes: checkpoints, proofs and public keys."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.crypto import merkle
from app.deps import get_current_user, get_db
from app.models.checkpoint import LogCheckpoint
from app.models.log_entry import LogEntry
from app.models.user import User
from app.services import transparency_log as tlog
from app.services.crypto_context import checkpoint_signer, custody_signer, pinned_witness_public_key

router = APIRouter()


@router.get("/public-keys")
async def public_keys(_: User = Depends(get_current_user)) -> dict[str, Any]:
    cs, ks = custody_signer(), checkpoint_signer()
    return {
        "log_id": settings.log_id,
        "custody": {"key_id": cs.key_id, "public_key": cs.public_key_hex},
        "checkpoint": {"key_id": ks.key_id, "public_key": ks.public_key_hex},
        "witness_pinned": pinned_witness_public_key(),
    }


@router.get("/stats")
async def stats(db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)) -> dict[str, Any]:
    size = await tlog.log_size(db)
    cp = await tlog.latest_checkpoint(db)
    return {
        "log_id": settings.log_id,
        "tree_size": size,
        "root_hash": merkle.root_hash(await tlog.load_leaves(db)).hex() if size else merkle.EMPTY_ROOT.hex(),
        "latest_checkpoint": tlog.checkpoint_to_dict(cp) if cp else None,
    }


@router.get("/entries")
async def entries(
    offset: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> list[dict[str, Any]]:
    rows = (
        await db.execute(select(LogEntry).order_by(LogEntry.index).offset(offset).limit(limit))
    ).scalars()
    return [{"index": r.index, "event_id": str(r.event_id), "leaf_hash": r.leaf_hash} for r in rows]


@router.get("/checkpoints")
async def list_checkpoints(
    limit: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> list[dict[str, Any]]:
    rows = (
        await db.execute(
            select(LogCheckpoint).order_by(LogCheckpoint.tree_size.desc(), LogCheckpoint.created_at.desc()).limit(limit)
        )
    ).scalars()
    return [tlog.checkpoint_to_dict(r) for r in rows]


@router.get("/checkpoints/latest")
async def latest(db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)) -> dict[str, Any]:
    cp = await tlog.latest_checkpoint(db)
    if cp is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no checkpoints yet")
    return tlog.checkpoint_to_dict(cp)


@router.post("/checkpoints", status_code=status.HTTP_201_CREATED)
async def new_checkpoint(db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)) -> dict[str, Any]:
    """Sign a fresh STH over the current log and submit it to the witness."""
    cp = await tlog.create_checkpoint(db)
    if cp is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "log is empty")
    return tlog.checkpoint_to_dict(cp)


@router.get("/proof/inclusion")
async def proof_inclusion(
    index: int = Query(..., ge=0),
    tree_size: int = Query(..., ge=1),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> dict[str, Any]:
    try:
        p = await tlog.inclusion_proof_for(db, index, tree_size)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))
    return p.__dict__


@router.get("/proof/consistency")
async def proof_consistency(
    first: int = Query(..., ge=1),
    second: int = Query(..., ge=1),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> dict[str, Any]:
    if first > second:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "first must be <= second")
    try:
        leaves = await tlog.load_leaves(db, second)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))
    return {
        "first": first,
        "second": second,
        "first_root": merkle.root_hash(leaves[:first]).hex(),
        "second_root": merkle.root_hash(leaves).hex(),
        "proof": [p.hex() for p in merkle.consistency_proof(first, leaves)],
    }
