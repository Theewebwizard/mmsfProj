"""Full TrustChain verification of a registered evidence record.

Used by the Evidence Inspector, the Provenance Recovery workflow and the
bundle exporter.  Every check returns PASS / FAIL / INCONCLUSIVE with a
human-readable detail; nothing is assumed.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.crypto import merkle
from app.crypto.keys import key_id_for, verify_signature
from app.crypto.statements import checkpoint_statement, witness_ack_statement
from app.models.checkpoint import LogCheckpoint
from app.models.custody import CustodyEvent, EventType
from app.models.evidence import Evidence
from app.models.log_entry import LogEntry
from app.services import transparency_log as tlog
from app.services.crypto_context import checkpoint_signer, custody_signer
from app.storage.minio_client import minio_client

PASS, FAIL, INCONCLUSIVE = "PASS", "FAIL", "INCONCLUSIVE"


@dataclass
class Check:
    name: str
    status: str
    detail: str
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class VerificationReport:
    evidence_id: str
    overall: str
    checks: list[Check]
    checkpoint: Optional[dict[str, Any]]
    events: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        return d


def combine(statuses: list[str]) -> str:
    if any(s == FAIL for s in statuses):
        return FAIL
    if any(s == INCONCLUSIVE for s in statuses):
        return INCONCLUSIVE
    return PASS


async def load_events(db: AsyncSession, evidence_id) -> list[CustodyEvent]:
    res = await db.execute(
        select(CustodyEvent)
        .where(CustodyEvent.evidence_id == evidence_id)
        .order_by(CustodyEvent.log_index.asc())
    )
    return list(res.scalars())


def verify_checkpoint_signature(cp: LogCheckpoint) -> bool:
    signer = checkpoint_signer()
    if cp.key_id != signer.key_id:
        return False
    stmt = checkpoint_statement(cp.log_id, cp.tree_size, cp.root_hash, cp.timestamp, cp.key_id)
    return verify_signature(signer.public_key_hex, stmt, cp.signature)


def verify_witness_ack(cp: LogCheckpoint) -> tuple[str, str]:
    if cp.witness_status != "ACKNOWLEDGED" or not cp.witness_ack_signature:
        return INCONCLUSIVE, f"checkpoint at size {cp.tree_size} has no witness co-signature ({cp.witness_status})"
    if not cp.witness_public_key or key_id_for(bytes.fromhex(cp.witness_public_key)) != cp.witness_key_id:
        return FAIL, "witness key id does not match witness public key"
    stmt = witness_ack_statement(
        cp.log_id, cp.tree_size, cp.root_hash, cp.signature, cp.witness_timestamp_str, cp.witness_key_id
    )
    if verify_signature(cp.witness_public_key, stmt, cp.witness_ack_signature):
        return PASS, f"witness {cp.witness_key_id} co-signed tree size {cp.tree_size}"
    return FAIL, "witness co-signature does not verify"


async def verify_evidence_record(
    db: AsyncSession, evidence: Evidence, *, check_storage: bool = True
) -> VerificationReport:
    checks: list[Check] = []
    events = await load_events(db, evidence.id)

    # 1. Byte integrity of the stored original (live MinIO re-hash).
    if check_storage:
        try:
            raw = await minio_client.get_object_bytes(evidence.storage_key)
            computed = await asyncio.to_thread(lambda: hashlib.sha256(raw).hexdigest())
            if computed == evidence.sha256_digest:
                checks.append(Check("STORAGE_SHA256", PASS, "stored object matches registered SHA-256", {"computed": computed}))
            else:
                checks.append(Check("STORAGE_SHA256", FAIL, "stored object bytes differ from registered SHA-256", {"computed": computed, "registered": evidence.sha256_digest}))
        except Exception as exc:  # storage unreachable / object missing
            checks.append(Check("STORAGE_SHA256", FAIL, f"stored object could not be read: {type(exc).__name__}"))

    # 2. Registration event binds the digest (signed statement, not a mutable DB column).
    reg = next((e for e in events if e.event_type == EventType.EVIDENCE_REGISTERED), None)
    if reg is None or not reg.canonical_bytes:
        checks.append(Check("REGISTRATION_BINDING", FAIL, "no signed EVIDENCE_REGISTERED event"))
    else:
        stmt = json.loads(reg.canonical_bytes)
        signed_digest = stmt.get("payload", {}).get("sha256")
        if signed_digest == evidence.sha256_digest and stmt.get("evidence_id") == str(evidence.id):
            checks.append(Check("REGISTRATION_BINDING", PASS, "signed registration event binds this SHA-256 to this evidence id"))
        else:
            checks.append(Check("REGISTRATION_BINDING", FAIL, "registered digest in DB differs from the signed registration event", {"signed": signed_digest, "db": evidence.sha256_digest}))

    # 3. Ed25519 signatures + per-evidence hash chain.
    signer = custody_signer()
    sig_fail, chain_fail = [], []
    prev_hash = None
    event_rows = []
    for e in events:
        ok = bool(e.canonical_bytes and e.signature) and e.key_id == signer.key_id and verify_signature(
            signer.public_key_hex, e.canonical_bytes, e.signature
        )
        stmt = json.loads(e.canonical_bytes) if e.canonical_bytes else {}
        if not ok or stmt.get("event_id") != str(e.id) or stmt.get("event_type") != e.event_type.value:
            sig_fail.append(str(e.id))
            ok = False
        if stmt.get("prev_event_hash") != prev_hash:
            chain_fail.append(str(e.id))
        prev_hash = hashlib.sha256(e.canonical_bytes).hexdigest() if e.canonical_bytes else None
        d = tlog.event_to_dict(e)
        d["signature_valid"] = ok
        event_rows.append(d)
    if not events:
        checks.append(Check("EVENT_SIGNATURES", FAIL, "no custody events"))
    elif sig_fail:
        checks.append(Check("EVENT_SIGNATURES", FAIL, f"{len(sig_fail)} event signature(s) invalid", {"failed": sig_fail}))
    else:
        checks.append(Check("EVENT_SIGNATURES", PASS, f"{len(events)} Ed25519 event signature(s) valid (key {signer.key_id})"))
    if events:
        checks.append(
            Check("EVENT_HASH_CHAIN", FAIL, "per-evidence event hash chain broken", {"failed": chain_fail})
            if chain_fail
            else Check("EVENT_HASH_CHAIN", PASS, "prev_event_hash chain intact")
        )

    # 4. Merkle inclusion against the newest signed checkpoint covering all events.
    max_index = max((e.log_index for e in events if e.log_index is not None), default=-1)
    cp = await tlog.latest_checkpoint(db, acknowledged_only=True, min_size=max_index + 1)
    if cp is None:
        cp = await tlog.latest_checkpoint(db, min_size=max_index + 1)
    cp_dict = tlog.checkpoint_to_dict(cp) if cp else None

    if cp is None or max_index < 0:
        checks.append(Check("MERKLE_INCLUSION", INCONCLUSIVE, "no signed checkpoint covers these events yet"))
        checks.append(Check("CHECKPOINT_SIGNATURE", INCONCLUSIVE, "no checkpoint"))
        checks.append(Check("WITNESS_COSIGNATURE", INCONCLUSIVE, "no checkpoint"))
    else:
        try:
            leaves = await tlog.load_leaves(db, cp.tree_size)
            entries = {
                le.index: le
                for le in (await db.execute(select(LogEntry).where(LogEntry.index.in_([e.log_index for e in events])))).scalars()
            }
            root = bytes.fromhex(cp.root_hash)
            bad = []
            for e, row in zip(events, event_rows):
                le = entries.get(e.log_index)
                expected_leaf = merkle.leaf_hash(e.canonical_bytes)
                proof = merkle.inclusion_proof(e.log_index, leaves)
                ok = (
                    le is not None
                    and le.event_id == e.id
                    and le.leaf_hash == expected_leaf.hex()
                    and merkle.verify_inclusion(e.log_index, cp.tree_size, expected_leaf, proof, root)
                )
                row["inclusion_valid"] = ok
                row["inclusion_proof"] = [p.hex() for p in proof]
                if not ok:
                    bad.append(e.log_index)
            if bad:
                checks.append(Check("MERKLE_INCLUSION", FAIL, f"inclusion proof failed for log indices {bad}"))
            else:
                checks.append(Check("MERKLE_INCLUSION", PASS, f"{len(events)} event(s) included in signed tree of size {cp.tree_size}"))
        except (ValueError, RuntimeError) as exc:
            checks.append(Check("MERKLE_INCLUSION", FAIL, f"log could not be reconstructed: {exc}"))

        checks.append(
            Check("CHECKPOINT_SIGNATURE", PASS, f"STH size {cp.tree_size} signed by log key {cp.key_id}")
            if verify_checkpoint_signature(cp)
            else Check("CHECKPOINT_SIGNATURE", FAIL, "checkpoint signature does not verify")
        )
        status, detail = verify_witness_ack(cp)
        checks.append(Check("WITNESS_COSIGNATURE", status, detail))

    return VerificationReport(
        evidence_id=str(evidence.id),
        overall=combine([c.status for c in checks]),
        checks=checks,
        checkpoint=cp_dict,
        events=event_rows,
    )
