"""MediaTrace search + Provenance Recovery routes.

Workflow:
  POST /trace/search            -> ranked *candidates* (forensic retrieval)
  POST /trace/verify-candidate  -> TrustChain verification of one candidate's
                                   registered record + final assessment

Final assessment states:
  VERIFIED_REGISTERED_ORIGINAL  the candidate's registered original passed every
                                cryptographic check (storage SHA-256, signed
                                registration, event signatures, Merkle inclusion,
                                checkpoint signature, witness co-signature)
  CANDIDATE_ONLY                the query resembles a registered item, but its
                                record could not be fully verified (some check
                                INCONCLUSIVE, e.g. no witness co-signature yet)
  INTEGRITY_FAILURE             at least one cryptographic check FAILED
  NO_MATCH                      the query does not match the selected item

The *relationship* between query and original is reported separately
(BYTE_IDENTICAL / PERCEPTUAL_CANDIDATE / GEOMETRIC_CANDIDATE).  A perceptual or
geometric link is never proof that the query derives from the original.
"""

from __future__ import annotations

import asyncio
import hashlib
import time
import uuid
from collections import OrderedDict
from typing import Any, Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.evidence import MAX_FILE_BYTES, _detect_mime
from app.api.evidence_ops import evidence_dict, get_evidence_or_404
from app.deps import get_current_user, get_db, require_role
from app.mediatrace import engine, orb
from app.mediatrace.metadata import extract_exif
from app.mediatrace.phash import hamming, load_image, phash_image
from app.models.custody import EventType
from app.models.evidence import Evidence
from app.models.user import User, UserRole
from app.services import transparency_log as tlog
from app.services.verification import FAIL, INCONCLUSIVE, verify_evidence_record
from app.storage.minio_client import minio_client

router = APIRouter()

VERIFIED = "VERIFIED_REGISTERED_ORIGINAL"
CANDIDATE_ONLY = "CANDIDATE_ONLY"
INTEGRITY_FAILURE = "INTEGRITY_FAILURE"
NO_MATCH = "NO_MATCH"

# ORB features of registered originals (immutable objects -> safe to cache by storage key).
_FEATURE_CACHE: "OrderedDict[str, orb.OrbFeatures]" = OrderedDict()
_FEATURE_CACHE_MAX = 512


async def _features_for(ev: Evidence) -> Optional[orb.OrbFeatures]:
    if ev.storage_key in _FEATURE_CACHE:
        _FEATURE_CACHE.move_to_end(ev.storage_key)
        return _FEATURE_CACHE[ev.storage_key]
    try:
        data = await minio_client.get_object_bytes(ev.storage_key)
        feats = await asyncio.to_thread(lambda: orb.extract(load_image(data)))
    except Exception:
        return None
    _FEATURE_CACHE[ev.storage_key] = feats
    if len(_FEATURE_CACHE) > _FEATURE_CACHE_MAX:
        _FEATURE_CACHE.popitem(last=False)
    return feats


async def _read_query(file: UploadFile) -> tuple[bytes, str]:
    data = await file.read()
    if len(data) > MAX_FILE_BYTES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "file exceeds 100MB")
    mime = _detect_mime(data[:16])
    if mime is None:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "only JPEG, PNG and WebP are supported")
    return data, mime


@router.post("/search")
async def search(
    file: UploadFile = File(...),
    exact_only: bool = Form(False),
    phash_threshold: int = Form(10, ge=0, le=64),
    use_orb: bool = Form(False),
    orb_top_k: int = Form(10, ge=1, le=100),
    orb_min_inliers: int = Form(15, ge=4, le=1000),
    limit: int = Form(10, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_role(UserRole.INVESTIGATOR)),
) -> dict[str, Any]:
    t0 = time.perf_counter()
    data, mime = await _read_query(file)
    sha = hashlib.sha256(data).hexdigest()
    img = await asyncio.to_thread(load_image, data)
    qphash = await asyncio.to_thread(phash_image, img)
    t_hash = time.perf_counter()

    rows = (await db.execute(select(Evidence))).scalars().all()
    by_id = {str(r.id): r for r in rows}
    gallery = [engine.GalleryItem(str(r.id), r.sha256_digest, r.phash) for r in rows]
    params = engine.SearchParams(exact_only, phash_threshold, use_orb, orb_top_k, orb_min_inliers, limit)

    qfeats = None
    cand_feats: dict[str, Optional[orb.OrbFeatures]] = {}
    if use_orb and not exact_only:
        qfeats = await asyncio.to_thread(orb.extract, img)
        top = sorted(
            (g for g in gallery if g.phash), key=lambda g: hamming(qphash, g.phash)
        )[:orb_top_k]
        for g in top:
            cand_feats[g.id] = await _features_for(by_id[g.id])

    candidates = await asyncio.to_thread(
        engine.search,
        sha,
        qphash,
        gallery,
        params,
        None,
        qfeats,
        (lambda i: cand_feats.get(i)) if qfeats is not None else None,
    )
    t_end = time.perf_counter()

    exif = extract_exif(data)
    return {
        "query": {
            "sha256": sha,
            "phash": qphash,
            "mime_type": mime,
            "file_size": len(data),
            "exif_present": any(k for k in exif if not k.startswith("_")),
            "width": img.width,
            "height": img.height,
        },
        "params": params.__dict__,
        "gallery_size": len(gallery),
        "outcome": "CANDIDATES_FOUND" if candidates else NO_MATCH,
        "candidates": [
            {**c.to_dict(), "evidence": evidence_dict(by_id[c.evidence_id])} for c in candidates
        ],
        "notice": "Candidates are forensic leads only. A perceptual or geometric match is not proof of origin; "
        "use 'Verify Candidate Provenance' to check the registered record cryptographically.",
        "timings_ms": {
            "hashing": round((t_hash - t0) * 1000, 2),
            "search": round((t_end - t_hash) * 1000, 2),
            "total": round((t_end - t0) * 1000, 2),
        },
    }


@router.post("/verify-candidate")
async def verify_candidate(
    file: UploadFile = File(...),
    evidence_id: uuid.UUID = Form(...),
    phash_threshold: int = Form(10, ge=0, le=64),
    orb_min_inliers: int = Form(15, ge=4, le=1000),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    data, _ = await _read_query(file)
    ev = await get_evidence_or_404(db, evidence_id)
    qsha = hashlib.sha256(data).hexdigest()
    img = await asyncio.to_thread(load_image, data)
    qphash = await asyncio.to_thread(phash_image, img)

    # Re-derive the relationship server-side; never trust the client's claim.
    dist = hamming(qphash, ev.phash) if ev.phash else None
    orb_res = None
    if qsha == ev.sha256_digest:
        relationship = "BYTE_IDENTICAL"
    elif dist is not None and dist <= phash_threshold:
        relationship = "PERCEPTUAL_CANDIDATE"
    else:
        cfeats = await _features_for(ev)
        if cfeats is not None:
            qfeats = await asyncio.to_thread(orb.extract, img)
            orb_res = await asyncio.to_thread(orb.match, qfeats, cfeats)
        relationship = (
            "GEOMETRIC_CANDIDATE" if orb_res and orb_res.inliers >= orb_min_inliers else "NONE"
        )

    report = await verify_evidence_record(db, ev)

    if relationship == "NONE":
        assessment = NO_MATCH
        explanation = "The query image does not match this registered item (pHash distance above threshold and no ORB geometric confirmation)."
    elif report.overall == FAIL:
        assessment = INTEGRITY_FAILURE
        failed = [c.name for c in report.checks if c.status == FAIL]
        explanation = f"The registered record failed cryptographic verification: {', '.join(failed)}. Do not rely on it."
    elif report.overall == INCONCLUSIVE:
        assessment = CANDIDATE_ONLY
        pending = [c.name for c in report.checks if c.status == INCONCLUSIVE]
        explanation = f"A registered candidate was found but its record could not be fully verified ({', '.join(pending)} inconclusive)."
    else:
        assessment = VERIFIED
        if relationship == "BYTE_IDENTICAL":
            explanation = "The query is byte-identical to a registered original whose full TrustChain record verifies."
        else:
            explanation = (
                "The registered original's TrustChain record verifies. The link between your query and that "
                "original is perceptual/geometric similarity only — it is NOT proof that the query derives from it."
            )

    await tlog.append_and_checkpoint(
        db,
        evidence_id=ev.id,
        actor_id=current_user.id,
        event_type=EventType.EVIDENCE_VERIFIED,
        payload={
            "context": "provenance_recovery",
            "assessment": assessment,
            "relationship": relationship,
            "query_sha256": qsha,
            "query_phash": qphash,
            "hamming": dist,
            "record_overall": report.overall,
        },
    )

    return {
        "assessment": assessment,
        "relationship": relationship,
        "explanation": explanation,
        "query": {"sha256": qsha, "phash": qphash},
        "similarity": {
            "hamming": dist,
            "phash_threshold": phash_threshold,
            "orb": orb_res.to_dict() if orb_res else None,
        },
        "evidence": evidence_dict(ev),
        "verification": report.to_dict(),
    }
