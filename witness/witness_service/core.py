"""Pure witness decision logic (no I/O) — easy to test and benchmark."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Sequence

from witness_service.crypto import checkpoint_statement, verify_consistency, verify_ed25519

ACCEPTED = "ACCEPTED"
REJECTED = "REJECTED"

# Alert reasons
BAD_LOG_SIGNATURE = "BAD_LOG_SIGNATURE"
UNKNOWN_LOG = "UNKNOWN_LOG"
ROLLBACK = "ROLLBACK"
EQUIVOCATION = "EQUIVOCATION"
MALFORMED = "MALFORMED"


@dataclass(frozen=True)
class WitnessState:
    """The last checkpoint this witness accepted (tree_size 0 = nothing yet)."""

    tree_size: int = 0
    root_hash: Optional[str] = None


@dataclass(frozen=True)
class Submission:
    log_id: str
    tree_size: int
    root_hash: str
    timestamp: str
    key_id: str
    signature: str
    consistency_proof: Sequence[str] = ()


@dataclass(frozen=True)
class Decision:
    status: str
    reason: Optional[str] = None
    detail: Optional[str] = None


def evaluate(
    sub: Submission,
    state: WitnessState,
    log_public_key: str,
    log_key_id: str,
    expected_log_id: Optional[str] = None,
) -> Decision:
    """Spec order: signature -> rollback -> consistency (equivocation)."""
    try:
        root = bytes.fromhex(sub.root_hash)
        proof = [bytes.fromhex(p) for p in sub.consistency_proof]
    except ValueError:
        return Decision(REJECTED, MALFORMED, "non-hex root or proof element")
    if len(root) != 32 or any(len(p) != 32 for p in proof) or sub.tree_size < 1:
        return Decision(REJECTED, MALFORMED, "bad hash length or tree size")

    if expected_log_id is not None and sub.log_id != expected_log_id:
        return Decision(REJECTED, UNKNOWN_LOG, f"log_id {sub.log_id!r} is not witnessed here")

    # 1. The checkpoint must be signed by the pinned log key.
    if sub.key_id != log_key_id:
        return Decision(REJECTED, BAD_LOG_SIGNATURE, "checkpoint key_id does not match pinned log key")
    stmt = checkpoint_statement(sub.log_id, sub.tree_size, sub.root_hash, sub.timestamp, sub.key_id)
    if not verify_ed25519(log_public_key, stmt, sub.signature):
        return Decision(REJECTED, BAD_LOG_SIGNATURE, "Ed25519 checkpoint signature invalid")

    # 2. Rollback: the log may never shrink.
    if sub.tree_size < state.tree_size:
        return Decision(
            REJECTED,
            ROLLBACK,
            f"tree_size {sub.tree_size} < last seen {state.tree_size}",
        )

    # 3. Equivocation / split view: new tree must extend the one we saw.
    if state.tree_size == 0:
        return Decision(ACCEPTED)
    if sub.tree_size == state.tree_size:
        if sub.root_hash != state.root_hash:
            return Decision(
                REJECTED, EQUIVOCATION, "same tree_size, different root hash (split view)"
            )
        return Decision(ACCEPTED)
    if not verify_consistency(
        state.tree_size, sub.tree_size, bytes.fromhex(state.root_hash), root, proof
    ):
        return Decision(
            REJECTED,
            EQUIVOCATION,
            f"consistency proof {state.tree_size}->{sub.tree_size} does not verify against last seen root",
        )
    return Decision(ACCEPTED)
