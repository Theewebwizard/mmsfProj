"""Offline bundle verification.  Never contacts the TrustChain API."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

from nacl.exceptions import BadSignatureError
from nacl.signing import VerifyKey

from trustchain_verify.rfc9162 import leaf_hash, verify_consistency, verify_inclusion

PASS, FAIL, INCONCLUSIVE = "PASS", "FAIL", "INCONCLUSIVE"

EVENT_TYPE = "trustchain-custody-event/v1"
CHECKPOINT_TYPE = "trustchain-checkpoint/v1"
WITNESS_ACK_TYPE = "trustchain-witness-ack/v1"


def canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def key_id_for(pub_hex: str) -> str:
    return hashlib.sha256(bytes.fromhex(pub_hex)).hexdigest()[:16]


def ed25519_ok(pub_hex: str, msg: bytes, sig_hex: Optional[str]) -> bool:
    if not sig_hex:
        return False
    try:
        VerifyKey(bytes.fromhex(pub_hex)).verify(msg, bytes.fromhex(sig_hex))
        return True
    except (BadSignatureError, ValueError, TypeError):
        return False


def checkpoint_statement(cp: dict) -> bytes:
    return canonical_json(
        {
            "type": CHECKPOINT_TYPE,
            "log_id": cp["log_id"],
            "tree_size": cp["tree_size"],
            "root_hash": cp["root_hash"],
            "timestamp": cp["timestamp"],
            "key_id": cp["key_id"],
        }
    )


def witness_statement(cp: dict) -> bytes:
    w = cp.get("witness") or {}
    return canonical_json(
        {
            "type": WITNESS_ACK_TYPE,
            "log_id": cp["log_id"],
            "tree_size": cp["tree_size"],
            "root_hash": cp["root_hash"],
            "log_signature": cp["signature"],
            "witness_timestamp": w.get("timestamp"),
            "witness_key_id": w.get("key_id"),
        }
    )


@dataclass
class CheckResult:
    name: str
    status: str
    details: list[str] = field(default_factory=list)


@dataclass
class Report:
    overall: str
    checks: list[CheckResult]
    warnings: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


def _worst(statuses: list[str]) -> str:
    if FAIL in statuses:
        return FAIL
    if INCONCLUSIVE in statuses:
        return INCONCLUSIVE
    return PASS


class _Keys:
    """Resolve each key from a pinned value, falling back to the bundle's claim."""

    def __init__(self, bundle: dict, pinned: dict[str, Optional[str]]) -> None:
        self.bundle_keys = bundle.get("public_keys") or {}
        self.pinned = {k: v.strip().lower() for k, v in pinned.items() if v}
        self.warnings: list[str] = []

    def get(self, purpose: str) -> tuple[Optional[str], Optional[str]]:
        """Return (public_key_hex, error)."""
        claimed = (self.bundle_keys.get(purpose) or {}).get("public_key")
        if purpose in self.pinned:
            pinned = self.pinned[purpose]
            if claimed and claimed.lower() != pinned:
                return None, f"bundle {purpose} key {key_id_for(claimed)} != pinned key {key_id_for(pinned)}"
            return pinned, None
        if claimed:
            self.warnings.append(
                f"{purpose} key {key_id_for(claimed)} taken from the bundle (not pinned) — "
                f"proves internal consistency only; pin it with --{'log' if purpose == 'checkpoint' else purpose}-key"
            )
            return claimed, None
        return None, None


def verify_bundle(file_bytes: bytes, bundle: dict, pinned: Optional[dict[str, Optional[str]]] = None) -> Report:
    keys = _Keys(bundle, pinned or {})
    events = bundle.get("events") or []
    cp = bundle.get("checkpoint") or {}
    evidence = bundle.get("evidence") or {}
    checks: list[CheckResult] = []

    parsed: list[dict] = []
    for e in events:
        try:
            parsed.append(json.loads(e["canonical_event"]))
        except (KeyError, TypeError, json.JSONDecodeError):
            parsed.append({})

    # 1. File SHA-256 vs the digest bound in the *signed* registration event.
    c = CheckResult("FILE_SHA256", PASS)
    computed = hashlib.sha256(file_bytes).hexdigest()
    reg = next((p for p in parsed if p.get("event_type") == "EVIDENCE_REGISTERED"), None)
    if reg is None:
        c.status = FAIL
        c.details.append("bundle has no EVIDENCE_REGISTERED event")
    else:
        signed = (reg.get("payload") or {}).get("sha256")
        c.details.append(f"file SHA-256       {computed}")
        c.details.append(f"registered SHA-256 {signed}")
        if computed != signed:
            c.status = FAIL
            c.details.append("file bytes differ from the registered original")
        if evidence.get("sha256_digest") and evidence["sha256_digest"] != signed:
            c.status = FAIL
            c.details.append("bundle evidence.sha256_digest disagrees with the signed registration")
    checks.append(c)

    # 2. Custody event signatures + structure + per-evidence hash chain.
    c = CheckResult("CUSTODY_SIGNATURES", PASS)
    pub, err = keys.get("custody")
    if err:
        c.status, c.details = FAIL, [err]
    elif pub is None:
        c.status, c.details = INCONCLUSIVE, ["no custody public key available"]
    elif not events:
        c.status, c.details = FAIL, ["bundle contains no events"]
    else:
        kid = key_id_for(pub)
        prev = None
        for e, p in zip(events, parsed):
            raw = (e.get("canonical_event") or "").encode("utf-8")
            problems = []
            if canonical_json(p) != raw:
                problems.append("event bytes are not canonical")
            if p.get("type") != EVENT_TYPE:
                problems.append("wrong statement type")
            if p.get("key_id") != kid or e.get("key_id") != kid:
                problems.append("key id mismatch")
            if p.get("evidence_id") != evidence.get("id"):
                problems.append("event is for a different evidence id")
            if p.get("event_id") != e.get("event_id") or p.get("event_type") != e.get("event_type"):
                problems.append("event envelope disagrees with signed body")
            if bundle.get("log_id") and p.get("log_id") != bundle["log_id"]:
                problems.append("event log_id mismatch")
            if p.get("prev_event_hash") != prev:
                problems.append("prev_event_hash chain broken")
            if not ed25519_ok(pub, raw, e.get("signature")):
                problems.append("Ed25519 signature INVALID")
            prev = hashlib.sha256(raw).hexdigest()
            label = f"#{e.get('log_index')} {e.get('event_type')}"
            if problems:
                c.status = FAIL
                c.details.append(f"{label}: " + "; ".join(problems))
            else:
                c.details.append(f"{label}: signature valid")
    checks.append(c)

    # 3. Merkle inclusion of every event in the checkpoint's tree.
    c = CheckResult("MERKLE_INCLUSION", PASS)
    try:
        root = bytes.fromhex(cp["root_hash"])
        size = int(cp["tree_size"])
    except (KeyError, ValueError, TypeError):
        root, size = None, 0
    if root is None:
        c.status, c.details = INCONCLUSIVE, ["bundle has no checkpoint"]
    else:
        for e in events:
            raw = (e.get("canonical_event") or "").encode("utf-8")
            lh = leaf_hash(raw)
            try:
                proof = [bytes.fromhex(h) for h in e.get("inclusion_proof") or []]
                ok = verify_inclusion(int(e["log_index"]), size, lh, proof, root)
            except (KeyError, ValueError, TypeError):
                ok = False
            if ok:
                c.details.append(f"#{e.get('log_index')} included in tree size {size}")
            else:
                c.status = FAIL
                c.details.append(f"#{e.get('log_index')} inclusion proof FAILED against root {cp.get('root_hash', '')[:16]}…")
    checks.append(c)

    # 4. Checkpoint signature + consistency from the first witnessed checkpoint.
    c = CheckResult("CHECKPOINT_AND_CONSISTENCY", PASS)
    log_pub, err = keys.get("checkpoint")
    if err:
        c.status, c.details = FAIL, [err]
    elif log_pub is None or not cp:
        c.status, c.details = INCONCLUSIVE, ["no checkpoint or log key"]
    else:
        lkid = key_id_for(log_pub)
        if cp.get("key_id") != lkid or not ed25519_ok(log_pub, checkpoint_statement(cp), cp.get("signature")):
            c.status = FAIL
            c.details.append(f"checkpoint (size {cp.get('tree_size')}) signature INVALID")
        else:
            c.details.append(f"checkpoint size {cp['tree_size']} signed by log key {lkid}")
        cons = bundle.get("consistency")
        if not cons:
            if c.status == PASS:
                c.status = INCONCLUSIVE
            c.details.append("no witnessed anchor checkpoint — consistency not demonstrated")
        else:
            anchor = cons.get("from") or {}
            if anchor.get("key_id") != lkid or not ed25519_ok(log_pub, checkpoint_statement(anchor), anchor.get("signature")):
                c.status = FAIL
                c.details.append(f"anchor checkpoint (size {anchor.get('tree_size')}) signature INVALID")
            try:
                ok = cons.get("to_tree_size") == cp.get("tree_size") and verify_consistency(
                    int(anchor["tree_size"]),
                    int(cp["tree_size"]),
                    bytes.fromhex(anchor["root_hash"]),
                    bytes.fromhex(cp["root_hash"]),
                    [bytes.fromhex(h) for h in cons.get("proof") or []],
                )
            except (KeyError, ValueError, TypeError):
                ok = False
            if ok:
                c.details.append(f"consistency {anchor['tree_size']} -> {cp['tree_size']} verified (append-only)")
            else:
                c.status = FAIL
                c.details.append("consistency proof FAILED — log history was rewritten or the proof is wrong")
    checks.append(c)

    # 5. Witness co-signature(s).
    c = CheckResult("WITNESS_COSIGNATURE", PASS)
    wpub, err = keys.get("witness")
    targets = [("checkpoint", cp)]
    if bundle.get("consistency"):
        targets.append(("anchor", bundle["consistency"].get("from") or {}))
    if err:
        c.status, c.details = FAIL, [err]
    elif wpub is None:
        c.status, c.details = INCONCLUSIVE, ["no witness key — checkpoint was not witnessed"]
    else:
        wkid = key_id_for(wpub)
        for label, target in targets:
            w = target.get("witness") or {}
            if not w.get("signature"):
                if c.status == PASS:
                    c.status = INCONCLUSIVE
                c.details.append(f"{label} size {target.get('tree_size')}: not co-signed ({w.get('status')})")
            elif w.get("key_id") != wkid or not ed25519_ok(wpub, witness_statement(target), w.get("signature")):
                c.status = FAIL
                c.details.append(f"{label} size {target.get('tree_size')}: witness signature INVALID")
            else:
                c.details.append(f"{label} size {target.get('tree_size')}: co-signed by witness {wkid} at {w.get('timestamp')}")
    checks.append(c)

    return Report(overall=_worst([x.status for x in checks]), checks=checks, warnings=keys.warnings)


def load_key_arg(value: Optional[str]) -> Optional[str]:
    """Accept a hex key or a path to a file containing one."""
    if not value:
        return None
    p = Path(value)
    if p.is_file():
        return p.read_text().strip()
    return value.strip()
