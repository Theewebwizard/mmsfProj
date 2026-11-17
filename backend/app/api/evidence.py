"""Evidence upload, download, and integrity-verification routes.

Mounted under /cases by the top-level API router.
"""

import asyncio
import hashlib
import io
import json
import uuid
from datetime import datetime
from typing import Any, List, Optional

import imagehash
from fastapi import APIRouter, Depends, File, HTTPException, UploadFile, status
from minio.error import S3Error
from PIL import Image
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.deps import get_current_user, get_db
from app.models.case import Case
from app.models.custody import CustodyEvent, EventType
from app.models.evidence import C2PAStatus, Evidence
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

    model_config = {"from_attributes": True}


class IntegrityVerifyResponse(BaseModel):
    status: str
    stored_digest: str
    computed_digest: Optional[str] = None


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


def _compute_phash(data: bytes) -> Optional[str]:
    try:
        img = Image.open(io.BytesIO(data))
        return str(imagehash.phash(img))
    except Exception:
        return None


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

    Processing pipeline:
    1. Read file into memory (reject if > 100MB).
    2. Validate MIME type via magic bytes (JPEG, PNG, WebP only).
    3. Compute SHA-256 of full file bytes.
    4. Compute pHash via imagehash library.
    5. Generate UUID-based storage key.
    6. Upload to MinIO.
    7. Create Evidence row in DB (c2pa_status=PENDING).
    8. Create CustodyEvent row (event_type=EVIDENCE_REGISTERED).
    9. Commit transaction.
    10. Return EvidenceResponse.
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

    # 3. Compute SHA-256
    sha256_digest = await asyncio.to_thread(_compute_sha256, data)

    # 4. Compute pHash
    phash_str = await asyncio.to_thread(_compute_phash, data)

    # 5. Generate storage_key = str(uuid.uuid4()) + extension
    extension = MIME_EXTENSIONS[mime_type]
    storage_key = f"{uuid.uuid4()}{extension}"

    # 6. Upload to MinIO
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

    # 7. Create Evidence row in DB
    evidence = Evidence(
        id=uuid.uuid4(),
        case_id=case_id,
        original_filename=file.filename or "unknown",
        storage_key=storage_key,
        sha256_digest=sha256_digest,
        file_size=len(data),
        mime_type=mime_type,
        phash=phash_str,
        c2pa_status=C2PAStatus.PENDING,
        uploaded_by=actor_id,
    )
    db.add(evidence)
    await db.flush()

    # 8. Create CustodyEvent row
    payload = json.dumps(
        {"storage_key": storage_key, "sha256": sha256_digest},
        separators=(",", ":"),
        sort_keys=True,
    )
    custody_event = CustodyEvent(
        id=uuid.uuid4(),
        evidence_id=evidence.id,
        actor_id=actor_id,
        event_type=EventType.EVIDENCE_REGISTERED,
        payload_json=payload,
        canonical_bytes=None,
        signature=None,
        key_id=None,
        log_index=None,
    )
    db.add(custody_event)

    # 9. Commit transaction
    await db.commit()
    await db.refresh(evidence)

    # 10. Return EvidenceResponse
    return EvidenceResponse.model_validate(evidence)


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
    _: Any = Depends(get_current_user),
) -> IntegrityVerifyResponse:
    """Re-download from MinIO, recompute SHA-256, compare with stored digest."""
    ev = await _get_evidence_or_404(db, case_id, evidence_id)

    try:
        raw = await minio_client.get_object_bytes(ev.storage_key)
    except Exception:
        return IntegrityVerifyResponse(
            status="ERROR",
            stored_digest=ev.sha256_digest,
            computed_digest=None,
        )

    computed = await asyncio.to_thread(_compute_sha256, raw)
    status_str = "PASS" if computed == ev.sha256_digest else "FAIL"

    return IntegrityVerifyResponse(
        status=status_str,
        stored_digest=ev.sha256_digest,
        computed_digest=computed,
    )
