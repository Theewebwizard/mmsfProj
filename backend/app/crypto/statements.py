"""The exact signed statements of the TrustChain protocol.

Every signer and every verifier (backend, witness, offline CLI) must build
these byte strings identically, so they are defined in one place per
implementation and pinned by tests.  Each carries a ``type`` field for
domain separation so a signature over one kind of statement can never be
replayed as another.
"""

from __future__ import annotations

from app.crypto.canonical import canonical_json

EVENT_TYPE = "trustchain-custody-event/v1"
CHECKPOINT_TYPE = "trustchain-checkpoint/v1"
WITNESS_ACK_TYPE = "trustchain-witness-ack/v1"


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
