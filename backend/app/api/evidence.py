"""Evidence upload, download, and integrity-verification routes.

Mounted under /cases by the top-level API router.
"""

import asyncio
import hashlib
import json
import uuid
from datetime import datetime
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from minio.error import S3Error
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.crypto.c2pa import C2PAAdapter
from app.deps import get_current_user, get_db
from app.mediatrace.metadata import extract_exif
from app.mediatrace.phash import compute_phash
from app.models.case import Case
from app.models.custody import EventType
from app.models.evidence import C2PAStatus, Evidence
from app.services import transparency_log as tlog
from app.storage.minio_client import minio_client

router = APIRouter()

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAX_FILE_BYTES = 100 * 1024 * 1024  # 100 MB

MIME_EXTENSIONS = {
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "image/webp": ".webp",
}


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class EvidenceResponse(BaseModel):
    id: uuid.UUID
    case_id: uuid.UUID
    original_filename: str
    storage_key: str
    sha256_digest: str
    file_size: int
    mime_type: str
    phash: Optional[str] = None
    c2pa_status: Optional[str] = None
    uploaded_by: uuid.UUID
    created_at: datetime
    log_index: Optional[int] = None
    checkpoint_tree_size: Optional[int] = None
    witness_status: Optional[str] = None

    model_config = {"from_attributes": True}


class IntegrityVerifyResponse(BaseModel):
    status: str
    stored_digest: str
    computed_digest: Optional[str] = None
    log_index: Optional[int] = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _extract_user_info(current_user: Any) -> tuple[uuid.UUID, str]:
    """Extract user_id and role string from either User model or dict."""
    if isinstance(current_user, dict):
        uid = current_user.get("id")
        role = current_user.get("role")
    else:
        uid = getattr(current_user, "id", None)
        role = getattr(current_user, "role", None)

    role_str = getattr(role, "value", role) if role is not None else ""
    user_uuid = uid if isinstance(uid, uuid.UUID) else uuid.UUID(str(uid))
    return user_uuid, str(role_str)


def _require_investigator(current_user: Any) -> uuid.UUID:
    """Enforce that current_user has the INVESTIGATOR role."""
    user_id, role = _extract_user_info(current_user)
    if role != "INVESTIGATOR":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="INVESTIGATOR role required",
        )
    return user_id


def _detect_mime(header: bytes) -> Optional[str]:
    """Validate MIME type from magic bytes (JPEG, PNG, WebP)."""
    if len(header) >= 3 and header[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if len(header) >= 4 and header[:4] == b"\x89PNG":
        return "image/png"
    if len(header) >= 12 and header[:4] == b"RIFF" and header[8:12] == b"WEBP":
        return "image/webp"
    return None


def _compute_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def c2pa_adapter() -> C2PAAdapter:
    return C2PAAdapter(settings.c2patool_path, settings.c2patool_timeout_seconds)


async def _get_evidence_or_404(
    db: AsyncSession,
    case_id: uuid.UUID,
    evidence_id: uuid.UUID,
) -> Evidence:
    result = await db.execute(
        select(Evidence).where(
            Evidence.id == evidence_id,
            Evidence.case_id == case_id,
        )
    )
    ev = result.scalar_one_or_none()
    if ev is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Evidence not found",
        )
    return ev


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.post(
    "/{case_id}/evidence",
    response_model=EvidenceResponse,
    status_code=status.HTTP_200_OK,
    summary="Upload a new evidence file (INVESTIGATOR only).",
)
async def upload_evidence(
    case_id: uuid.UUID,
    file: UploadFile = File(...),
    db: AsyncSession = Depends(get_db),
    current_user: Any = Depends(get_current_user),
) -> EvidenceResponse:
    """Upload and register an evidence image file.

    Processing pipeline (spec §4B):
    1. Read (<= 100MB) and validate MIME by magic bytes (JPEG / PNG / WebP).
    2. SHA-256 + byte size.
    3. Store the original in MinIO under a fresh UUID key (never overwritten).
    4. Extract EXIF and C2PA status (c2patool adapter).
    5. Compute the 64-bit pHash.
    6. Insert the Evidence row and append a signed EVIDENCE_REGISTERED event
       to the RFC 9162 log in one transaction.
    7. Sign a checkpoint and obtain the witness co-signature.
    """
    actor_id = _require_investigator(current_user)

    # Verify case exists
    case_res = await db.execute(select(Case).where(Case.id == case_id))
    if case_res.scalar_one_or_none() is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Case not found",
        )

    # 1. Read file bytes into memory; enforce max 100MB
    data = await file.read()
    if len(data) > MAX_FILE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="File size exceeds maximum limit of 100MB",
        )

    # 2. Validate MIME type via magic bytes
    mime_type = _detect_mime(data[:16])
    if mime_type is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Unsupported file type. Only JPEG, PNG, and WebP images are allowed.",
        )

    # 3. Compute SHA-256 + byte size
    sha256_digest = await asyncio.to_thread(_compute_sha256, data)

    # 4. Store the original (immutable, UUID key — client filename never used as a path)
    extension = MIME_EXTENSIONS[mime_type]
    storage_key = f"{uuid.uuid4()}{extension}"
    try:
        await minio_client.put_object(storage_key, data, mime_type)
    except S3Error as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Storage error: {exc}",
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to upload to storage: {exc}",
        )

    # 5. EXIF + C2PA
    exif = await asyncio.to_thread(extract_exif, data)
    c2pa = await asyncio.to_thread(c2pa_adapter().inspect_bytes, data, extension)

    # 6. pHash
    phash_str = await asyncio.to_thread(compute_phash, data)

    # 7. Evidence row + signed EVIDENCE_REGISTERED event in one transaction
    evidence = Evidence(
        id=uuid.uuid4(),
        case_id=case_id,
        original_filename=(file.filename or "unknown")[:500],
        storage_key=storage_key,
        sha256_digest=sha256_digest,
        file_size=len(data),
        mime_type=mime_type,
        phash=phash_str,
        c2pa_status=C2PAStatus(c2pa.status),
        c2pa_summary_json=json.dumps(c2pa.to_dict()),
        exif_json=json.dumps(exif),
        uploaded_by=actor_id,
    )
    async with tlog.log_transaction(db) as log:
        db.add(evidence)
        await db.flush()
        event = await log.append(
            evidence_id=evidence.id,
            actor_id=actor_id,
            event_type=EventType.EVIDENCE_REGISTERED,
            payload={
                "case_id": str(case_id),
                "sha256": sha256_digest,
                "file_size": len(data),
                "mime_type": mime_type,
                "storage_key": storage_key,
                "original_filename": evidence.original_filename,
                "phash": phash_str,
                "c2pa_status": c2pa.status,
            },
        )

    # 8. Signed checkpoint + witness co-signature
    cp = await tlog.create_checkpoint(db) if settings.auto_checkpoint else None

    await db.refresh(evidence)
    resp = EvidenceResponse.model_validate(evidence)
    resp.log_index = event.log_index
    if cp is not None:
        resp.checkpoint_tree_size = cp.tree_size
        resp.witness_status = cp.witness_status
    return resp


@router.get(
    "/{case_id}/evidence",
    response_model=List[EvidenceResponse],
    summary="List evidence items for a case.",
)
async def list_evidence(
    case_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: Any = Depends(get_current_user),
) -> List[EvidenceResponse]:
    """List all evidence registered under the specified case."""
    result = await db.execute(
        select(Evidence).where(Evidence.case_id == case_id).order_by(Evidence.created_at.desc())
    )
    items = result.scalars().all()
    return [EvidenceResponse.model_validate(ev) for ev in items]


@router.get(
    "/{case_id}/evidence/{evidence_id}",
    response_model=EvidenceResponse,
    summary="Get single evidence item metadata.",
)
async def get_evidence(
    case_id: uuid.UUID,
    evidence_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: Any = Depends(get_current_user),
) -> EvidenceResponse:
    """Fetch evidence metadata by ID."""
    ev = await _get_evidence_or_404(db, case_id, evidence_id)
    return EvidenceResponse.model_validate(ev)


@router.get(
    "/{case_id}/evidence/{evidence_id}/download",
    summary="Return a presigned MinIO download URL.",
)
async def download_evidence(
    case_id: uuid.UUID,
    evidence_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: Any = Depends(get_current_user),
) -> dict:
    """Return a presigned MinIO GET URL as {'url': '...'."""
    ev = await _get_evidence_or_404(db, case_id, evidence_id)
    try:
        url = await minio_client.get_presigned_url(ev.storage_key, expires_hours=1)
    except S3Error as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Storage error: {exc}",
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Storage error: {exc}",
        )
    return {"url": url}


@router.post(
    "/{case_id}/evidence/{evidence_id}/verify-integrity",
    response_model=IntegrityVerifyResponse,
    summary="Verify evidence file integrity against stored SHA-256.",
)
@router.post(
    "/{case_id}/evidence/{evidence_id}/verify",
    response_model=IntegrityVerifyResponse,
    summary="Alias for verify-integrity.",
)
async def verify_evidence_integrity(
    case_id: uuid.UUID,
    evidence_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: Any = Depends(get_current_user),
) -> IntegrityVerifyResponse:
    """Re-download from MinIO, recompute SHA-256, compare with stored digest.

    The outcome (PASS / FAIL / ERROR) is itself recorded as a signed
    EVIDENCE_VERIFIED custody event in the transparency log.
    """
    ev = await _get_evidence_or_404(db, case_id, evidence_id)
    return await run_integrity_check(db, ev, current_user)


async def run_integrity_check(db: AsyncSession, ev: Evidence, current_user: Any) -> IntegrityVerifyResponse:
    actor_id, _ = _extract_user_info(current_user)
    computed: Optional[str] = None
    try:
        raw = await minio_client.get_object_bytes(ev.storage_key)
        computed = await asyncio.to_thread(_compute_sha256, raw)
        status_str = "PASS" if computed == ev.sha256_digest else "FAIL"
    except Exception:
        status_str = "ERROR"

    event = await tlog.append_and_checkpoint(
        db,
        evidence_id=ev.id,
        actor_id=actor_id,
        event_type=EventType.EVIDENCE_VERIFIED,
        payload={
            "check": "STORAGE_SHA256",
            "result": status_str,
            "registered_sha256": ev.sha256_digest,
            "computed_sha256": computed,
        },
    )
    return IntegrityVerifyResponse(
        status=status_str,
        stored_digest=ev.sha256_digest,
        computed_digest=computed,
        log_index=event.log_index,
    )
