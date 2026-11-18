"""Phase 2 integration tests: signed custody events, Merkle log, checkpoints,
witness co-signing, custody transfer workflow, bundle export + offline CLI."""

import io
import json

import pytest
from PIL import Image
from sqlalchemy import select

from app.crypto import merkle
from app.crypto.canonical import CanonicalizationError, canonical_json
from app.crypto.keys import verify_signature
from app.crypto import statements as backend_statements
from app.models.custody import CustodyEvent, ImmutableRecordError
from app.models.log_entry import LogEntry
from app.services.crypto_context import custody_signer
from conftest import mock_storage

from trustchain_verify import rfc9162 as cli_merkle
from trustchain_verify.verifier import FAIL, INCONCLUSIVE, PASS, verify_bundle
from trustchain_verify import verifier as cli_verifier
from witness_service import crypto as witness_crypto


def jpeg(color=(200, 30, 30), size=(96, 96)) -> bytes:
    img = Image.new("RGB", size, color)
    for x in range(0, size[0], 8):
        for y in range(0, size[1], 8):
            if (x + y) % 16 == 0:
                img.putpixel((x, y), (0, 0, 0))
    buf = io.BytesIO()
    img.save(buf, format="JPEG", quality=92)
    return buf.getvalue()


async def register(client, email, role="INVESTIGATOR"):
    r = await client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": "password123", "full_name": email.split("@")[0], "role": role},
    )
    body = r.json()
    return {"Authorization": f"Bearer {body['access_token']}"}, body["user_id"]


async def setup_evidence(client, email="inv@example.com", data=None):
    h, uid = await register(client, email)
    case = (await client.post("/api/v1/cases", json={"title": "C"}, headers=h)).json()
    data = data or jpeg()
    r = await client.post(
        f"/api/v1/cases/{case['id']}/evidence",
        files={"file": ("photo.jpg", data, "image/jpeg")},
        headers=h,
    )
    assert r.status_code == 200, r.text
    return h, uid, r.json(), data


# ---------------------------------------------------------------------------
# Canonical JSON
# ---------------------------------------------------------------------------


def test_canonical_json_rules():
    assert canonical_json({"b": 1, "a": [True, None, "é"]}) == '{"a":[true,null,"é"],"b":1}'.encode()
    with pytest.raises(CanonicalizationError):
        canonical_json({"x": 1.5})


def test_statements_identical_across_implementations():
    """Backend, witness and offline CLI must build byte-identical statements."""
    args = ("log", 7, "ab" * 32, "2026-01-01T00:00:00.000000Z", "kid")
    b = backend_statements.checkpoint_statement(*args)
    w = witness_crypto.checkpoint_statement(*args)
    c = cli_verifier.checkpoint_statement(
        {"log_id": "log", "tree_size": 7, "root_hash": "ab" * 32, "timestamp": args[3], "key_id": "kid"}
    )
    assert b == w == c
    ack_args = ("log", 7, "ab" * 32, "cd" * 64, "2026-01-01T00:00:01.000000Z", "wkid")
    cp = {"log_id": "log", "tree_size": 7, "root_hash": "ab" * 32, "signature": "cd" * 64,
          "witness": {"timestamp": ack_args[4], "key_id": "wkid"}}
    assert (
        backend_statements.witness_ack_statement(*ack_args)
        == witness_crypto.witness_ack_statement(*ack_args)
        == cli_verifier.witness_statement(cp)
    )


def test_merkle_verifiers_agree_across_implementations():
    leaves = [merkle.leaf_hash(bytes([i])) for i in range(23)]
    for n in (1, 2, 5, 8, 13, 23):
        root = merkle.root_hash(leaves[:n])
        for m in range(n):
            p = merkle.inclusion_proof(m, leaves[:n])
            assert cli_merkle.verify_inclusion(m, n, leaves[m], p, root)
        for m in range(1, n + 1):
            p = merkle.consistency_proof(m, leaves[:n])
            old = merkle.root_hash(leaves[:m])
            assert cli_merkle.verify_consistency(m, n, old, root, p)
            assert witness_crypto.verify_consistency(m, n, old, root, p)


# ---------------------------------------------------------------------------
# Registration -> signed event -> log -> checkpoint -> witness
# ---------------------------------------------------------------------------


async def test_upload_appends_signed_event_and_witnessed_checkpoint(client, db_session):
    h, uid, ev, data = await setup_evidence(client)
    assert ev["log_index"] == 0
    assert ev["checkpoint_tree_size"] == 1
    assert ev["witness_status"] == "ACKNOWLEDGED"

    row = (await db_session.execute(select(CustodyEvent))).scalar_one()
    stmt = json.loads(row.canonical_bytes)
    assert stmt["type"] == "trustchain-custody-event/v1"
    assert stmt["payload"]["sha256"] == ev["sha256_digest"]
    assert stmt["prev_event_hash"] is None
    assert verify_signature(custody_signer().public_key_hex, row.canonical_bytes, row.signature)

    entry = (await db_session.execute(select(LogEntry))).scalar_one()
    assert entry.index == 0
    assert entry.leaf_hash == merkle.leaf_hash(row.canonical_bytes).hex()

    latest = (await client.get("/api/v1/log/checkpoints/latest", headers=h)).json()
    assert latest["tree_size"] == 1
    assert latest["root_hash"] == entry.leaf_hash  # single-leaf tree
    assert latest["witness"]["status"] == "ACKNOWLEDGED"


async def test_log_indices_dense_and_consistency_endpoint(client):
    h, _, ev, _ = await setup_evidence(client)
    case_id = ev["case_id"]
    for i in range(4):
        r = await client.post(
            f"/api/v1/cases/{case_id}/evidence",
            files={"file": (f"{i}.jpg", jpeg((i * 40, 10, 10)), "image/jpeg")},
            headers=h,
        )
        assert r.json()["log_index"] == i + 1
    stats = (await client.get("/api/v1/log/stats", headers=h)).json()
    assert stats["tree_size"] == 5
    cons = (await client.get("/api/v1/log/proof/consistency?first=2&second=5", headers=h)).json()
    assert merkle.verify_consistency(
        2, 5, bytes.fromhex(cons["first_root"]), bytes.fromhex(cons["second_root"]),
        [bytes.fromhex(p) for p in cons["proof"]],
    )
    inc = (await client.get("/api/v1/log/proof/inclusion?index=3&tree_size=5", headers=h)).json()
    assert merkle.verify_inclusion(
        3, 5, bytes.fromhex(inc["leaf_hash"]), [bytes.fromhex(p) for p in inc["proof"]],
        bytes.fromhex(inc["root_hash"]),
    )


async def test_full_verification_passes(client):
    h, _, ev, _ = await setup_evidence(client)
    r = await client.post(f"/api/v1/evidence/{ev['id']}/verify", headers=h)
    rep = r.json()
    assert rep["overall"] == "PASS", rep
    names = {c["name"]: c["status"] for c in rep["checks"]}
    assert names == {
        "STORAGE_SHA256": "PASS",
        "REGISTRATION_BINDING": "PASS",
        "EVENT_SIGNATURES": "PASS",
        "EVENT_HASH_CHAIN": "PASS",
        "MERKLE_INCLUSION": "PASS",
        "CHECKPOINT_SIGNATURE": "PASS",
        "WITNESS_COSIGNATURE": "PASS",
    }


async def test_minio_tampering_detected(client):
    h, _, ev, data = await setup_evidence(client)
    # Attacker with bucket access overwrites the stored original.
    mock_storage[ev["storage_key"]] = data[:-10] + b"\x00" * 10
    integ = (await client.post(f"/api/v1/evidence/{ev['id']}/verify-integrity", headers=h)).json()
    assert integ["status"] == "FAIL"
    rep = (await client.post(f"/api/v1/evidence/{ev['id']}/verify", headers=h)).json()
    assert rep["overall"] == "FAIL"
    assert {c["name"]: c["status"] for c in rep["checks"]}["STORAGE_SHA256"] == "FAIL"


async def test_integrity_check_is_logged_as_signed_event(client):
    h, _, ev, _ = await setup_evidence(client)
    integ = (await client.post(f"/api/v1/evidence/{ev['id']}/verify-integrity", headers=h)).json()
    assert integ["status"] == "PASS" and integ["log_index"] == 1
    tl = (await client.get(f"/api/v1/evidence/{ev['id']}/custody", headers=h)).json()
    types = [e["event_type"] for e in tl["events"]]
    assert types == ["EVIDENCE_REGISTERED", "EVIDENCE_VERIFIED"]
    assert all(e["signature_valid"] and e["inclusion_valid"] for e in tl["events"])
    assert tl["events"][1]["prev_event_hash"] is not None


async def test_witness_unavailable_is_inconclusive_not_pass(client, witness_down):
    h, _, ev, _ = await setup_evidence(client)
    assert ev["witness_status"] == "UNAVAILABLE"
    rep = (await client.post(f"/api/v1/evidence/{ev['id']}/verify", headers=h)).json()
    assert rep["overall"] == "INCONCLUSIVE"


async def test_committed_events_are_append_only(client, db_session):
    await setup_evidence(client)
    row = (await db_session.execute(select(CustodyEvent))).scalar_one()
    row.signature = "00" * 64
    with pytest.raises(ImmutableRecordError):
        await db_session.flush()
    await db_session.rollback()


# ---------------------------------------------------------------------------
# Custody transfer workflow
# ---------------------------------------------------------------------------


async def test_custody_transfer_and_acknowledge(client):
    h, uid, ev, _ = await setup_evidence(client, "owner@example.com")
    h2, uid2 = await register(client, "recipient@example.com")
    h3, _ = await register(client, "bystander@example.com")

    # Only the custodian can initiate.
    r = await client.post(f"/api/v1/evidence/{ev['id']}/custody/transfer", json={"to_user_id": uid2}, headers=h2)
    assert r.status_code == 403
    r = await client.post(
        f"/api/v1/evidence/{ev['id']}/custody/transfer", json={"to_user_id": uid2, "reason": "lab analysis"}, headers=h
    )
    assert r.status_code == 201
    # Only the named recipient can acknowledge.
    r = await client.post(f"/api/v1/evidence/{ev['id']}/custody/acknowledge", json={}, headers=h3)
    assert r.status_code == 403
    r = await client.post(f"/api/v1/evidence/{ev['id']}/custody/acknowledge", json={"note": "received"}, headers=h2)
    assert r.status_code == 201

    detail = (await client.get(f"/api/v1/evidence/{ev['id']}", headers=h)).json()
    assert detail["custody"]["custodian_id"] == uid2
    assert detail["custody"]["pending_transfer_to"] is None
    # Former custodian can no longer transfer.
    r = await client.post(f"/api/v1/evidence/{ev['id']}/custody/transfer", json={"to_user_id": uid}, headers=h)
    assert r.status_code == 403
    rep = (await client.post(f"/api/v1/evidence/{ev['id']}/verify", headers=h)).json()
    assert rep["overall"] == "PASS"


async def test_auditor_cannot_transfer_but_can_verify_and_export(client):
    h, uid, ev, _ = await setup_evidence(client)
    ha, _ = await register(client, "audit@example.com", "AUDITOR")
    r = await client.post(f"/api/v1/evidence/{ev['id']}/custody/transfer", json={"to_user_id": uid}, headers=ha)
    assert r.status_code == 403
    assert (await client.post(f"/api/v1/evidence/{ev['id']}/verify", headers=ha)).status_code == 200
    assert (await client.post(f"/api/v1/evidence/{ev['id']}/bundle", headers=ha)).status_code == 200


# ---------------------------------------------------------------------------
# Bundle export + offline CLI verifier
# ---------------------------------------------------------------------------


async def _bundle(client, h, ev_id):
    r = await client.post(f"/api/v1/evidence/{ev_id}/bundle", headers=h)
    assert r.status_code == 200
    return r.json()


async def test_bundle_verifies_offline(client):
    h, _, ev, data = await setup_evidence(client)
    # grow the log with unrelated evidence so proofs are non-trivial
    for i in range(5):
        await client.post(
            f"/api/v1/cases/{ev['case_id']}/evidence",
            files={"file": (f"x{i}.jpg", jpeg((10, i * 50, 90)), "image/jpeg")},
            headers=h,
        )
    await client.post(f"/api/v1/evidence/{ev['id']}/verify-integrity", headers=h)
    bundle = await _bundle(client, h, ev["id"])
    assert [e["event_type"] for e in bundle["events"]] == [
        "EVIDENCE_REGISTERED", "EVIDENCE_VERIFIED", "REPORT_EXPORTED"
    ]
    assert bundle["consistency"]["from"]["tree_size"] == 1

    keys = (await client.get("/api/v1/log/public-keys", headers=h)).json()
    pinned = {
        "checkpoint": keys["checkpoint"]["public_key"],
        "custody": keys["custody"]["public_key"],
        "witness": bundle["public_keys"]["witness"]["public_key"],
    }
    rep = verify_bundle(data, bundle, pinned)
    assert rep.overall == PASS, rep
    assert rep.warnings == []


async def test_cli_detects_modified_file(client):
    h, _, ev, data = await setup_evidence(client)
    bundle = await _bundle(client, h, ev["id"])
    rep = verify_bundle(data + b"\x00", bundle)
    assert rep.overall == FAIL
    assert rep.checks[0].name == "FILE_SHA256" and rep.checks[0].status == FAIL


async def test_cli_detects_forged_event(client):
    h, _, ev, data = await setup_evidence(client)
    bundle = await _bundle(client, h, ev["id"])
    forged = json.loads(bundle["events"][0]["canonical_event"])
    forged["actor_id"] = "00000000-0000-0000-0000-000000000000"
    bundle["events"][0]["canonical_event"] = canonical_json(forged).decode()
    rep = verify_bundle(data, bundle)
    status = {c.name: c.status for c in rep.checks}
    assert status["CUSTODY_SIGNATURES"] == FAIL
    assert status["MERKLE_INCLUSION"] == FAIL
    assert rep.overall == FAIL


async def test_cli_detects_swapped_digest(client):
    """Swapping in another file's digest breaks the signed registration binding."""
    h, _, ev, data = await setup_evidence(client)
    bundle = await _bundle(client, h, ev["id"])
    other = jpeg((1, 2, 3))
    import hashlib
    bundle["evidence"]["sha256_digest"] = hashlib.sha256(other).hexdigest()
    bundle["sha256_digest"] = bundle["evidence"]["sha256_digest"]
    assert verify_bundle(other, bundle).overall == FAIL


async def test_cli_rejects_wrong_pinned_key(client):
    h, _, ev, data = await setup_evidence(client)
    bundle = await _bundle(client, h, ev["id"])
    rep = verify_bundle(data, bundle, {"checkpoint": "aa" * 32})
    assert {c.name: c.status for c in rep.checks}["CHECKPOINT_AND_CONSISTENCY"] == FAIL


async def test_cli_unwitnessed_bundle_is_inconclusive(client, witness_down):
    h, _, ev, data = await setup_evidence(client)
    bundle = await _bundle(client, h, ev["id"])
    rep = verify_bundle(data, bundle)
    assert rep.overall == INCONCLUSIVE
    assert {c.name: c.status for c in rep.checks}["WITNESS_COSIGNATURE"] == INCONCLUSIVE


async def test_cli_entrypoint(client, tmp_path):
    from trustchain_verify.__main__ import main

    h, _, ev, data = await setup_evidence(client)
    bundle = await _bundle(client, h, ev["id"])
    (tmp_path / "img.jpg").write_bytes(data)
    (tmp_path / "b.json").write_text(json.dumps(bundle))
    assert main(["verify", "--file", str(tmp_path / "img.jpg"), "--bundle", str(tmp_path / "b.json")]) == 0
    (tmp_path / "bad.jpg").write_bytes(data[:-1])
    assert main(["verify", "--file", str(tmp_path / "bad.jpg"), "--bundle", str(tmp_path / "b.json")]) == 1
