"""Witness-side cryptography.

Deliberately an *independent* implementation of the verification half of
RFC 9162 and of the TrustChain statements: the witness exists to audit the
primary log, so it must not share code with it.  Cross-implementation tests
in the backend suite check that both agree byte-for-byte.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Sequence

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

CHECKPOINT_TYPE = "trustchain-checkpoint/v1"
WITNESS_ACK_TYPE = "trustchain-witness-ack/v1"


def canonical_json(obj: Any) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def key_id_for(public_key: bytes) -> str:
    return hashlib.sha256(public_key).hexdigest()[:16]


def checkpoint_statement(
    log_id: str, tree_size: int, root_hash: str, timestamp: str, key_id: str
) -> bytes:
    return canonical_json(
        {
            "type": CHECKPOINT_TYPE,
            "log_id": log_id,
            "tree_size": tree_size,
            "root_hash": root_hash,
            "timestamp": timestamp,
            "key_id": key_id,
        }
    )


def witness_ack_statement(
    log_id: str,
    tree_size: int,
    root_hash: str,
    log_signature: str,
    witness_timestamp: str,
    witness_key_id: str,
) -> bytes:
    return canonical_json(
        {
            "type": WITNESS_ACK_TYPE,
            "log_id": log_id,
            "tree_size": tree_size,
            "root_hash": root_hash,
            "log_signature": log_signature,
            "witness_timestamp": witness_timestamp,
            "witness_key_id": witness_key_id,
        }
    )


def verify_ed25519(public_key_hex: str, message: bytes, signature_hex: str) -> bool:
    try:
        VerifyKey(bytes.fromhex(public_key_hex)).verify(message, bytes.fromhex(signature_hex))
        return True
    except (BadSignatureError, ValueError, TypeError):
        return False


def sign_ed25519(sk: SigningKey, message: bytes) -> str:
    return sk.sign(message).signature.hex()


def _node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def verify_consistency(
    first: int, second: int, first_root: bytes, second_root: bytes, proof: Sequence[bytes]
) -> bool:
    """RFC 9162 §2.1.4.2."""
    if first < 0 or second < first:
        return False
    if first == 0:
        return len(proof) == 0
    if first == second:
        return len(proof) == 0 and first_root == second_root
    if not proof:
        return False
    path = list(proof)
    if first & (first - 1) == 0:
        path.insert(0, first_root)
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = _node(c, fr)
            sr = _node(c, sr)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = _node(sr, c)
        fn >>= 1
        sn >>= 1
    return fr == first_root and sr == second_root and sn == 0
