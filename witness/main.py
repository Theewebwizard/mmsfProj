"""Independent Witness microservice.

The Witness service runs in its own container with its own Ed25519 key
and database state. It provides a single endpoint:

    POST /witness/checkpoint

which accepts a signed checkpoint + consistency proof from the primary
TrustChain log, verifies them, and returns a Witness-signed acknowledgement
(or records a security alert on failure).

Business logic is implemented in Phase 2.
"""

from fastapi import FastAPI, Header, HTTPException, status
from pydantic import BaseModel

app = FastAPI(title="TrustChain Witness Service", version="0.1.0")


# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------

class CheckpointSubmission(BaseModel):
    """Payload sent by the primary TrustChain server to the Witness."""
    log_id: str
    tree_size: int
    root_hash: str                # hex SHA-256
    timestamp: str                # ISO 8601
    key_id: str
    signature: str                # hex Ed25519 signature over canonical STH bytes
    consistency_proof: list[str]  # list of hex hashes (RFC 9162 consistency proof)
    previous_tree_size: int       # size at last seen checkpoint (0 for first)
    previous_root_hash: str | None = None


class WitnessAck(BaseModel):
    """Witness-signed acknowledgement returned to the primary server."""
    status: str                   # "ACCEPTED" | "REJECTED"
    tree_size: int
    root_hash: str
    witness_signature: str | None = None  # hex Ed25519, present on ACCEPTED
    witness_key_id: str | None = None
    witness_timestamp: str | None = None
    alert_reason: str | None = None       # present on REJECTED


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.post(
    "/witness/checkpoint",
    response_model=WitnessAck,
    summary="Submit a signed checkpoint + consistency proof for independent verification.",
)
async def witness_checkpoint(
    body: CheckpointSubmission,
    x_witness_token: str = Header(..., alias="X-Witness-Token"),
) -> WitnessAck:
    """Verify and counter-sign a TrustChain Signed Tree Head (STH).

    Verification steps (Phase 2):
    1. Authenticate caller via X-Witness-Token.
    2. Verify Ed25519 signature on the checkpoint using primary server's public key.
    3. Reject if new tree_size < last_seen_size (rollback attack detection).
    4. Verify RFC 9162 consistency proof against last_seen_root (equivocation detection).
    5. Persist checkpoint and return Witness-signed acknowledgement.

    TODO (Phase 2): implement full verification pipeline.
    """
    raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="Not implemented yet")

