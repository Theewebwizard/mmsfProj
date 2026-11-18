"""Evidence-centric routes addressed by evidence id alone (mounted at /evidence).

Custody workflow, full TrustChain verification, inclusion proofs, image
content streaming and offline-bundle export.
"""

from __future__ import annotations

import json
import uuid
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.evidence import IntegrityVerifyResponse, run_integrity_check
from app.deps import get_current_user, get_db, require_role
from app.models.custody import CustodyEvent, EventType
from app.models.evidence import Evidence
from app.models.user import User, UserRole
from app.services import transparency_log as tlog
from app.services.bundle import build_bundle
from app.services.verification import load_events, verify_evidence_record
from app.storage.minio_client import minio_client

router = APIRouter()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def get_evidence_or_404(db: AsyncSession, evidence_id: uuid.UUID) -> Evidence:
    ev = (await db.execute(select(Evidence).where(Evidence.id == evidence_id))).scalar_one_or_none()
    if ev is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Evidence not found")
    return ev


def custody_state(events: list[CustodyEvent]) -> dict[str, Optional[str]]:
    """Derive the current custodian and any pending transfer from the signed log."""
    custodian: Optional[str] = None
    pending_to: Optional[str] = None
    pending_event: Optional[str] = None
    for e in events:
        payload = json.loads(e.payload_json) if e.payload_json else {}
        if e.event_type == EventType.EVIDENCE_REGISTERED:
            custodian = str(e.actor_id)
        elif e.event_type == EventType.CUSTODY_TRANSFER_INITIATED:
            pending_to = payload.get("to_user_id")
            pending_event = str(e.id)
        elif e.event_type == EventType.CUSTODY_TRANSFER_ACKNOWLEDGED:
            custodian = str(e.actor_id)
            pending_to = pending_event = None
    return {"custodian_id": custodian, "pending_transfer_to": pending_to, "pending_transfer_event": pending_event}


def evidence_dict(ev: Evidence) -> dict[str, Any]:
    return {
        "id": str(ev.id),
        "case_id": str(ev.case_id),
        "original_filename": ev.original_filename,
        "storage_key": ev.storage_key,
        "sha256_digest": ev.sha256_digest,
        "file_size": ev.file_size,
        "mime_type": ev.mime_type,
        "phash": ev.phash,
        "c2pa_status": ev.c2pa_status.value if hasattr(ev.c2pa_status, "value") else ev.c2pa_status,
        "c2pa_summary": json.loads(ev.c2pa_summary_json) if ev.c2pa_summary_json else None,
        "exif": json.loads(ev.exif_json) if ev.exif_json else None,
        "uploaded_by": str(ev.uploaded_by),
        "created_at": ev.created_at.isoformat() if ev.created_at else None,
    }


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class TransferRequest(BaseModel):
    to_user_id: uuid.UUID
    reason: str = Field("", max_length=1000)


class AcknowledgeRequest(BaseModel):
    note: str = Field("", max_length=1000)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/{evidence_id}")
async def evidence_detail(
    evidence_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> dict[str, Any]:
    ev = await get_evidence_or_404(db, evidence_id)
    events = await load_events(db, ev.id)
    d = evidence_dict(ev)
    d["registration_log_index"] = events[0].log_index if events else None
    d["custody"] = custody_state(events)
    return d


@router.get("/{evidence_id}/content")
async def evidence_content(
    evidence_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> Response:
    """Stream the stored original through the API (authenticated)."""
    ev = await get_evidence_or_404(db, evidence_id)
    try:
        data = await minio_client.get_object_bytes(ev.storage_key)
    except Exception as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, f"storage error: {type(exc).__name__}")
    return Response(content=data, media_type=ev.mime_type, headers={"Cache-Control": "no-store"})


@router.get("/{evidence_id}/custody")
async def custody_timeline(
    evidence_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Chronological custody events with per-event signature + inclusion status."""
    ev = await get_evidence_or_404(db, evidence_id)
    report = await verify_evidence_record(db, ev, check_storage=False)
    events = await load_events(db, ev.id)
    return {
        "evidence_id": str(ev.id),
        "state": custody_state(events),
        "checkpoint": report.checkpoint,
        "events": report.events,
    }


@router.post("/{evidence_id}/custody/transfer", status_code=status.HTTP_201_CREATED)
async def initiate_transfer(
    evidence_id: uuid.UUID,
    body: TransferRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_role(UserRole.INVESTIGATOR)),
) -> dict[str, Any]:
    ev = await get_evidence_or_404(db, evidence_id)
    state = custody_state(await load_events(db, ev.id))
    if state["custodian_id"] != str(current_user.id):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "only the current custodian can transfer custody")
    if state["pending_transfer_to"]:
        raise HTTPException(status.HTTP_409_CONFLICT, "a transfer is already pending")
    target = (await db.execute(select(User).where(User.id == body.to_user_id))).scalar_one_or_none()
    if target is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "recipient not found")
    if target.id == current_user.id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "cannot transfer custody to yourself")
    event = await tlog.append_and_checkpoint(
        db,
        evidence_id=ev.id,
        actor_id=current_user.id,
        event_type=EventType.CUSTODY_TRANSFER_INITIATED,
        payload={
            "from_user_id": str(current_user.id),
            "to_user_id": str(target.id),
            "reason": body.reason,
        },
    )
    return tlog.event_to_dict(event)


@router.post("/{evidence_id}/custody/acknowledge", status_code=status.HTTP_201_CREATED)
async def acknowledge_transfer(
    evidence_id: uuid.UUID,
    body: AcknowledgeRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    ev = await get_evidence_or_404(db, evidence_id)
    state = custody_state(await load_events(db, ev.id))
    if state["pending_transfer_to"] != str(current_user.id):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "no pending transfer addressed to you")
    event = await tlog.append_and_checkpoint(
        db,
        evidence_id=ev.id,
        actor_id=current_user.id,
        event_type=EventType.CUSTODY_TRANSFER_ACKNOWLEDGED,
        payload={
            "transfer_event_id": state["pending_transfer_event"],
            "from_user_id": state["custodian_id"],
            "note": body.note,
        },
    )
    return tlog.event_to_dict(event)


@router.post("/{evidence_id}/verify-integrity", response_model=IntegrityVerifyResponse)
async def verify_integrity(
    evidence_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> IntegrityVerifyResponse:
    ev = await get_evidence_or_404(db, evidence_id)
    return await run_integrity_check(db, ev, current_user)


@router.post("/{evidence_id}/verify")
async def verify_record(
    evidence_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Full TrustChain verification (storage hash, signatures, Merkle, checkpoint, witness)."""
    ev = await get_evidence_or_404(db, evidence_id)
    return (await verify_evidence_record(db, ev)).to_dict()


@router.get("/{evidence_id}/proof")
async def inclusion_proofs(
    evidence_id: uuid.UUID,
    tree_size: Optional[int] = None,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
) -> dict[str, Any]:
    ev = await get_evidence_or_404(db, evidence_id)
    events = await load_events(db, ev.id)
    size = tree_size or await tlog.log_size(db)
    leaves = await tlog.load_leaves(db, size)
    proofs = []
    for e in events:
        if e.log_index is not None and e.log_index < size:
            p = await tlog.inclusion_proof_for(db, e.log_index, size, leaves)
            proofs.append({"event_id": str(e.id), "event_type": e.event_type.value, **p.__dict__})
    return {"tree_size": size, "proofs": proofs}


@router.post("/{evidence_id}/bundle")
async def export_bundle(
    evidence_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> Response:
    """Record a REPORT_EXPORTED event, then return the offline verification bundle."""
    ev = await get_evidence_or_404(db, evidence_id)
    await tlog.append_and_checkpoint(
        db,
        evidence_id=ev.id,
        actor_id=current_user.id,
        event_type=EventType.REPORT_EXPORTED,
        payload={"format": "trustchain-bundle/v1", "sha256": ev.sha256_digest},
    )
    bundle = await build_bundle(db, ev)
    return Response(
        content=json.dumps(bundle, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="trustchain-bundle-{ev.id}.json"'},
    )
