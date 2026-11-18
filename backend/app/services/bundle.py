"""Offline verification bundle (consumed by ``trustchain-verify``).

The bundle is self-contained: canonical event bytes, signatures, inclusion
proofs, the signed checkpoint, a consistency proof from the first witnessed
checkpoint that contained the registration, the witness co-signatures, and
the public keys.  Public keys inside the bundle are *claims*; an auditor should
pin them out-of-band (``--log-key`` / ``--custody-key`` / ``--witness-key``).
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.crypto import merkle
from app.models.evidence import Evidence
from app.services import transparency_log as tlog
from app.services.crypto_context import checkpoint_signer, custody_signer
from app.services.verification import load_events

BUNDLE_VERSION = 1


async def build_bundle(db: AsyncSession, evidence: Evidence) -> dict[str, Any]:
    events = await load_events(db, evidence.id)
    if not events:
        raise ValueError("evidence has no custody events")
    max_index = max(e.log_index for e in events)
    reg_index = min(e.log_index for e in events)

    cp = await tlog.latest_checkpoint(db, acknowledged_only=True, min_size=max_index + 1)
    if cp is None:
        cp = await tlog.latest_checkpoint(db, min_size=max_index + 1)
    if cp is None:
        cp = await tlog.create_checkpoint(db)
    if cp is None:
        raise ValueError("log is empty")

    leaves = await tlog.load_leaves(db, cp.tree_size)

    anchor = await tlog.earliest_acknowledged_checkpoint(db, min_size=reg_index + 1)
    consistency = None
    if anchor is not None and anchor.tree_size <= cp.tree_size:
        consistency = {
            "from": tlog.checkpoint_to_dict(anchor),
            "to_tree_size": cp.tree_size,
            "proof": [p.hex() for p in merkle.consistency_proof(anchor.tree_size, leaves)],
        }

    cs, ks = custody_signer(), checkpoint_signer()
    return {
        "bundle_version": BUNDLE_VERSION,
        "generated_at": tlog.utc_now_iso(),
        "log_id": settings.log_id,
        "evidence": {
            "id": str(evidence.id),
            "case_id": str(evidence.case_id),
            "original_filename": evidence.original_filename,
            "sha256_digest": evidence.sha256_digest,
            "file_size": evidence.file_size,
            "mime_type": evidence.mime_type,
            "phash": evidence.phash,
            "c2pa_status": evidence.c2pa_status.value if hasattr(evidence.c2pa_status, "value") else evidence.c2pa_status,
        },
        "sha256_digest": evidence.sha256_digest,
        "public_keys": {
            "custody": {"key_id": cs.key_id, "public_key": cs.public_key_hex, "algorithm": "Ed25519"},
            "checkpoint": {"key_id": ks.key_id, "public_key": ks.public_key_hex, "algorithm": "Ed25519"},
            "witness": (
                {"key_id": cp.witness_key_id, "public_key": cp.witness_public_key, "algorithm": "Ed25519"}
                if cp.witness_public_key
                else None
            ),
        },
        "events": [
            {
                "event_id": str(e.id),
                "event_type": e.event_type.value,
                "log_index": e.log_index,
                "canonical_event": e.canonical_bytes.decode("utf-8"),
                "signature": e.signature,
                "key_id": e.key_id,
                "leaf_hash": merkle.leaf_hash(e.canonical_bytes).hex(),
                "inclusion_proof": [p.hex() for p in merkle.inclusion_proof(e.log_index, leaves)],
            }
            for e in events
        ],
        "checkpoint": tlog.checkpoint_to_dict(cp),
        "consistency": consistency,
    }
