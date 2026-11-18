import hashlib

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from nacl.signing import SigningKey
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from witness_service import main as wmain
from witness_service.crypto import (
    checkpoint_statement,
    key_id_for,
    verify_ed25519,
    witness_ack_statement,
)
from witness_service.db import init_db

TOKEN = "test-witness-token"
LOG_ID = "trustchain-log-v1"
LOG_KEY = SigningKey(bytes(range(32)))
LOG_PUB = bytes(LOG_KEY.verify_key).hex()
LOG_KID = key_id_for(bytes(LOG_KEY.verify_key))


# --- tiny independent RFC 9162 tree builder for test fixtures ---------------
def lh(d: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + d).digest()


def nh(a: bytes, b: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + a + b).digest()


def k_of(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def mth(d):
    if len(d) == 1:
        return d[0]
    k = k_of(len(d))
    return nh(mth(d[:k]), mth(d[k:]))


def subproof(m, d, b):
    n = len(d)
    if m == n:
        return [] if b else [mth(d)]
    k = k_of(n)
    if m <= k:
        return subproof(m, d[:k], b) + [mth(d[k:])]
    return subproof(m - k, d[k:], False) + [mth(d[:k])]


def leaves(n, salt=b""):
    return [lh(salt + i.to_bytes(4, "big")) for i in range(n)]


def submission(tree, prev_size=0, key=LOG_KEY, ts="2026-11-17T00:00:00.000000Z", kid=LOG_KID):
    root = mth(tree).hex()
    sig = key.sign(checkpoint_statement(LOG_ID, len(tree), root, ts, kid)).signature.hex()
    proof = [p.hex() for p in subproof(prev_size, tree, True)] if 0 < prev_size < len(tree) else []
    return {
        "log_id": LOG_ID,
        "tree_size": len(tree),
        "root_hash": root,
        "timestamp": ts,
        "key_id": kid,
        "signature": sig,
        "consistency_proof": proof,
        "previous_tree_size": prev_size,
    }


@pytest_asyncio.fixture
async def client(tmp_path, monkeypatch):
    monkeypatch.setenv("TRUSTCHAIN_CHECKPOINT_PUBKEY", LOG_PUB)
    monkeypatch.setenv("TRUSTCHAIN_WITNESS_KEY", "11" * 32)
    monkeypatch.setattr(wmain.settings, "witness_token", TOKEN)
    wmain.witness_key.cache_clear()
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/w.db")
    await init_db(engine)
    factory = async_sessionmaker(engine, expire_on_commit=False)

    async def override():
        async with factory() as s:
            yield s

    wmain.app.dependency_overrides[wmain.get_session] = override
    async with AsyncClient(
        transport=ASGITransport(app=wmain.app),
        base_url="http://w",
        headers={"X-Witness-Token": TOKEN},
    ) as c:
        yield c
    wmain.app.dependency_overrides.clear()
    await engine.dispose()


async def test_first_checkpoint_accepted_and_ack_verifies(client):
    tree = leaves(5)
    r = await client.post("/witness/checkpoint", json=submission(tree))
    assert r.status_code == 200, r.text
    ack = r.json()
    assert ack["status"] == "ACCEPTED"
    wpub = (await client.get("/witness/public-key")).json()
    assert ack["witness_key_id"] == wpub["key_id"]
    stmt = witness_ack_statement(
        LOG_ID, 5, mth(tree).hex(), submission(tree)["signature"], ack["witness_timestamp"], ack["witness_key_id"]
    )
    assert verify_ed25519(wpub["public_key"], stmt, ack["witness_signature"])
    latest = (await client.get("/witness/latest")).json()
    assert latest["tree_size"] == 5


async def test_honest_growth_accepted(client):
    tree = leaves(20)
    for size, prev in [(3, 0), (4, 3), (8, 4), (13, 8), (20, 13), (20, 20)]:
        r = await client.post("/witness/checkpoint", json=submission(tree[:size], prev))
        assert r.status_code == 200, (size, r.text)
    assert (await client.get("/witness/alerts")).json() == []


async def test_rollback_rejected(client):
    tree = leaves(10)
    assert (await client.post("/witness/checkpoint", json=submission(tree))).status_code == 200
    r = await client.post("/witness/checkpoint", json=submission(tree[:7]))
    assert r.status_code == 409
    assert r.json()["alert_reason"] == "ROLLBACK"
    alerts = (await client.get("/witness/alerts")).json()
    assert len(alerts) == 1 and alerts[0]["alert_reason"].startswith("ROLLBACK")
    # witness state unchanged
    assert (await client.get("/witness/latest")).json()["tree_size"] == 10


async def test_same_size_split_view_rejected(client):
    honest = leaves(6)
    forked = leaves(6, salt=b"evil")
    assert (await client.post("/witness/checkpoint", json=submission(honest))).status_code == 200
    r = await client.post("/witness/checkpoint", json=submission(forked))
    assert r.status_code == 409
    assert r.json()["alert_reason"] == "EQUIVOCATION"


async def test_forked_history_equivocation_rejected(client):
    honest = leaves(6)
    assert (await client.post("/witness/checkpoint", json=submission(honest))).status_code == 200
    forked = list(leaves(10))
    forked[2] = lh(b"rewritten entry")
    r = await client.post("/witness/checkpoint", json=submission(forked, prev_size=6))
    assert r.status_code == 409
    assert r.json()["alert_reason"] == "EQUIVOCATION"


async def test_bad_signature_rejected(client):
    tree = leaves(4)
    sub = submission(tree)
    sub["signature"] = "00" * 64
    r = await client.post("/witness/checkpoint", json=sub)
    assert r.status_code == 409
    assert r.json()["alert_reason"] == "BAD_LOG_SIGNATURE"


async def test_wrong_key_rejected(client):
    other = SigningKey(bytes([7]) * 32)
    sub = submission(leaves(4), key=other, kid=key_id_for(bytes(other.verify_key)))
    r = await client.post("/witness/checkpoint", json=sub)
    assert r.status_code == 409
    assert r.json()["alert_reason"] == "BAD_LOG_SIGNATURE"


async def test_missing_token_rejected(client):
    r = await client.post(
        "/witness/checkpoint", json=submission(leaves(2)), headers={"X-Witness-Token": "nope"}
    )
    assert r.status_code == 401


async def test_growth_without_proof_rejected(client):
    tree = leaves(9)
    assert (await client.post("/witness/checkpoint", json=submission(tree[:5]))).status_code == 200
    sub = submission(tree)  # no consistency proof from 5
    r = await client.post("/witness/checkpoint", json=sub)
    assert r.status_code == 409
    assert r.json()["alert_reason"] == "EQUIVOCATION"
