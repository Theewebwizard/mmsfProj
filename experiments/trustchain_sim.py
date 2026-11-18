"""An in-memory TrustChain built from the *production* crypto modules.

Registers originals exactly like the API does (canonical signed event ->
RFC 9162 leaf -> signed checkpoint -> witness evaluation + co-signature) and
verifies records exactly like app.services.verification does, but without
PostgreSQL/MinIO so benchmarks measure the cryptography, not I/O.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field

from nacl.signing import SigningKey

from app.crypto import merkle
from app.crypto.canonical import canonical_json
from app.crypto.keys import Signer, key_id_for, verify_signature
from app.crypto.statements import EVENT_TYPE, checkpoint_statement, witness_ack_statement

from witness_service import core as witness_core
from witness_service.crypto import sign_ed25519

LOG_ID = "trustchain-experiments"
TS = "2026-11-17T00:00:00.000000Z"  # fixed so runs are reproducible


@dataclass
class Record:
    evidence_id: str
    sha256: str
    canonical: bytes
    signature: str
    log_index: int


@dataclass
class TrustChainSim:
    seed: int
    custody: Signer = field(init=False)
    checkpoint: Signer = field(init=False)
    witness: SigningKey = field(init=False)
    records: dict[int, Record] = field(default_factory=dict)
    storage: dict[int, bytes] = field(default_factory=dict)
    leaves: list[bytes] = field(default_factory=list)
    cp: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        def sk(tag: int) -> SigningKey:
            return SigningKey(hashlib.sha256(f"{self.seed}:{tag}".encode()).digest())

        self.custody = Signer("custody", sk(1))
        self.checkpoint = Signer("checkpoint", sk(2))
        self.witness = sk(3)

    def register(self, key: int, data: bytes) -> Record:
        sha = hashlib.sha256(data).hexdigest()
        ev_id = str(uuid.UUID(int=(self.seed << 64) + key))
        stmt = {
            "type": EVENT_TYPE,
            "log_id": LOG_ID,
            "event_id": ev_id,
            "event_type": "EVIDENCE_REGISTERED",
            "evidence_id": ev_id,
            "actor_id": ev_id,
            "timestamp": TS,
            "payload": {"sha256": sha},
            "prev_event_hash": None,
            "key_id": self.custody.key_id,
        }
        canonical = canonical_json(stmt)
        rec = Record(ev_id, sha, canonical, self.custody.sign(canonical), len(self.leaves))
        self.leaves.append(merkle.leaf_hash(canonical))
        self.records[key] = rec
        self.storage[key] = data
        return rec

    def publish_checkpoint(self) -> None:
        size = len(self.leaves)
        root = merkle.root_hash(self.leaves).hex()
        sig = self.checkpoint.sign(checkpoint_statement(LOG_ID, size, root, TS, self.checkpoint.key_id))
        decision = witness_core.evaluate(
            witness_core.Submission(LOG_ID, size, root, TS, self.checkpoint.key_id, sig),
            witness_core.WitnessState(),
            self.checkpoint.public_key_hex,
            self.checkpoint.key_id,
        )
        assert decision.status == witness_core.ACCEPTED
        wkid = key_id_for(bytes(self.witness.verify_key))
        wsig = sign_ed25519(self.witness, witness_ack_statement(LOG_ID, size, root, sig, TS, wkid))
        self.cp = {"tree_size": size, "root_hash": root, "signature": sig, "witness_key_id": wkid, "witness_signature": wsig}

    def verify(self, key: int) -> tuple[str, list[str]]:
        """Full record verification -> (PASS|FAIL, failed check names)."""
        rec = self.records[key]
        failed = []
        if hashlib.sha256(self.storage[key]).hexdigest() != rec.sha256:
            failed.append("STORAGE_SHA256")
        if not verify_signature(self.custody.public_key_hex, rec.canonical, rec.signature):
            failed.append("EVENT_SIGNATURES")
        proof = merkle.inclusion_proof(rec.log_index, self.leaves)
        if not merkle.verify_inclusion(
            rec.log_index, self.cp["tree_size"], merkle.leaf_hash(rec.canonical), proof, bytes.fromhex(self.cp["root_hash"])
        ):
            failed.append("MERKLE_INCLUSION")
        if not verify_signature(
            self.checkpoint.public_key_hex,
            checkpoint_statement(LOG_ID, self.cp["tree_size"], self.cp["root_hash"], TS, self.checkpoint.key_id),
            self.cp["signature"],
        ):
            failed.append("CHECKPOINT_SIGNATURE")
        if not verify_signature(
            bytes(self.witness.verify_key).hex(),
            witness_ack_statement(LOG_ID, self.cp["tree_size"], self.cp["root_hash"], self.cp["signature"], TS, self.cp["witness_key_id"]),
            self.cp["witness_signature"],
        ):
            failed.append("WITNESS_COSIGNATURE")
        return ("FAIL" if failed else "PASS"), failed
