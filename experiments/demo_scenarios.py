#!/usr/bin/env python3
"""End-to-end demo scenarios against the LIVE docker-compose stack.

    docker compose up -d --build
    python experiments/demo_scenarios.py

  1. Normal recovery     — stripped + recompressed share recovered and verified;
                           exported bundle verified offline by the CLI with pinned keys.
  2. MinIO tampering     — attacker overwrites the stored original in the bucket;
                           integrity check, recovery and offline CLI all detect it.
  3. Witness rollback    — a stale (genuinely signed) checkpoint is replayed to the
                           witness, and a forked tree head signed with the log key
                           (compromised-log model) is submitted; both raise alerts.
  4. Negative image      — an unrelated image yields NO_MATCH.

Writes experiments/results/demo-scenarios.json.  Nothing is simulated except
the attacker's actions, which are performed against the real services.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path

import httpx

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "backend"))

from experiments.dataset import TRANSFORMS, _scene, encode, make_base  # noqa: E402

API = os.environ.get("TC_API", "http://localhost:8000/api/v1")
WITNESS = os.environ.get("TC_WITNESS", "http://localhost:8001")
WITNESS_TOKEN = os.environ.get("TC_WITNESS_TOKEN", "witness_secret_token_change_me")
MINIO = os.environ.get("TC_MINIO", "localhost:9000")
KEYS = REPO / "keys"

results: list[dict] = []


def step(name: str, ok: bool, **detail) -> bool:
    results.append({"scenario": name, "result": "PASS" if ok else "FAIL", **detail})
    print(f"  [{'✓' if ok else '✗'}] {name}  {json.dumps(detail)[:220]}")
    return ok


def main() -> int:
    c = httpx.Client(base_url=API, timeout=120)
    run = uuid.uuid4().hex[:8]

    def user(role: str) -> dict:
        r = c.post("/auth/register", json={"email": f"{role.lower()}-{run}@example.com", "password": "demo-password-1",
                                           "full_name": f"Demo {role.title()}", "role": role})
        r.raise_for_status()
        return {"Authorization": f"Bearer {r.json()['access_token']}"}

    inv, aud = user("INVESTIGATOR"), user("AUDITOR")
    case = c.post("/cases", json={"title": f"Demo case {run}", "description": "end-to-end demo scenarios"}, headers=inv).json()

    def upload(name: str, data: bytes) -> dict:
        r = c.post(f"/cases/{case['id']}/evidence", files={"file": (name, data, "image/jpeg")}, headers=inv)
        r.raise_for_status()
        return r.json()

    def search(data: bytes, **form) -> dict:
        r = c.post("/trace/search", files={"file": ("q.jpg", data, "image/jpeg")},
                   data={k: str(v).lower() if isinstance(v, bool) else str(v) for k, v in form.items()}, headers=inv)
        r.raise_for_status()
        return r.json()

    def verify_candidate(data: bytes, evidence_id: str, headers=aud) -> dict:
        r = c.post("/trace/verify-candidate", files={"file": ("q.jpg", data, "image/jpeg")},
                   data={"evidence_id": evidence_id}, headers=headers)
        r.raise_for_status()
        return r.json()

    seed = int(time.time()) % 100_000
    # register a small gallery so search is non-trivial
    gallery = {i: make_base(seed * 10 + i) for i in range(6)}
    regs = {i: upload(f"original-{i}.jpg", d) for i, d in gallery.items()}
    print(f"registered {len(regs)} originals in case {case['id']}")

    # ---------------------------------------------------------------- 1
    print("\nScenario 1 — normal recovery of a stripped, recompressed share")
    social = next(t for t in TRANSFORMS if t.name == "social_pipeline")
    query = social.fn(gallery[2], 0)
    s = search(query)
    top = s["candidates"][0] if s["candidates"] else None
    step("1a search ranks true source first", bool(top) and top["evidence_id"] == regs[2]["id"],
         hamming=top and top["hamming"], sha256_match=top and top["sha256_match"], query_exif=s["query"]["exif_present"])
    v = verify_candidate(query, regs[2]["id"])
    step("1b verify-candidate (auditor)", v["assessment"] == "VERIFIED_REGISTERED_ORIGINAL",
         assessment=v["assessment"], relationship=v["relationship"])
    b = c.post(f"/evidence/{regs[2]['id']}/bundle", headers=aud)
    b.raise_for_status()
    out = REPO / "experiments" / "results" / "demo"
    out.mkdir(parents=True, exist_ok=True)
    (out / "bundle.json").write_bytes(b.content)
    (out / "original.jpg").write_bytes(gallery[2])
    pub = json.loads((KEYS / "public.json").read_text())
    cli = subprocess.run(
        [sys.executable, "-m", "trustchain_verify", "verify", "--file", str(out / "original.jpg"), "--bundle", str(out / "bundle.json"),
         "--log-key", pub["checkpoint"]["public_key"], "--custody-key", pub["custody"]["public_key"],
         "--witness-key", pub["witness"]["public_key"]],
        cwd=REPO / "cli", capture_output=True, text=True,
    )
    (out / "cli-pass.txt").write_text(cli.stdout)
    step("1c offline CLI with pinned keys", cli.returncode == 0, exit_code=cli.returncode, overall=cli.stdout.strip().splitlines()[-1] if cli.stdout else cli.stderr[-200:])
    (out / "share.jpg").write_bytes(query)
    cli2 = subprocess.run([sys.executable, "-m", "trustchain_verify", "verify", "--file", str(out / "share.jpg"), "--bundle", str(out / "bundle.json")],
                          cwd=REPO / "cli", capture_output=True, text=True)
    step("1d CLI rejects the share itself as byte-identical original", cli2.returncode == 1, exit_code=cli2.returncode)

    # ---------------------------------------------------------------- 2
    print("\nScenario 2 — MinIO object tampering")
    from minio import Minio

    victim = regs[4]
    m = Minio(MINIO, access_key="minioadmin", secret_key="minioadmin", secure=False)
    forged = encode(_scene(999_999 + seed), quality=95)
    m.put_object("trustchain-evidence", victim["storage_key"], io.BytesIO(forged), len(forged), content_type="image/jpeg")
    integ = c.post(f"/evidence/{victim['id']}/verify-integrity", headers=aud).json()
    step("2a byte-integrity check detects overwrite", integ["status"] == "FAIL",
         registered=integ["stored_digest"][:16], recomputed=(integ["computed_digest"] or "")[:16])
    v = verify_candidate(gallery[4], victim["id"])
    failed = [x["name"] for x in v["verification"]["checks"] if x["status"] == "FAIL"]
    step("2b recovery reports INTEGRITY_FAILURE", v["assessment"] == "INTEGRITY_FAILURE", failed_checks=failed)
    b = c.post(f"/evidence/{victim['id']}/bundle", headers=aud)
    (out / "tampered-bundle.json").write_bytes(b.content)
    (out / "tampered-download.jpg").write_bytes(forged)
    cli = subprocess.run([sys.executable, "-m", "trustchain_verify", "verify", "--file", str(out / "tampered-download.jpg"),
                          "--bundle", str(out / "tampered-bundle.json")], cwd=REPO / "cli", capture_output=True, text=True)
    (out / "cli-fail.txt").write_text(cli.stdout)
    step("2c offline CLI fails the tampered bytes", cli.returncode == 1, exit_code=cli.returncode)

    # ---------------------------------------------------------------- 3
    print("\nScenario 3 — witness rollback / equivocation detection")
    w = httpx.Client(base_url=WITNESS, timeout=30, headers={"X-Witness-Token": WITNESS_TOKEN})
    latest = w.get("/witness/latest").json()
    cps = c.get("/log/checkpoints?limit=500", headers=aud).json()
    stale = next(cp for cp in cps if cp["tree_size"] < latest["tree_size"] and cp["witness"]["status"] == "ACKNOWLEDGED")
    r = w.post("/witness/checkpoint", json={k: stale[k] for k in ("log_id", "tree_size", "root_hash", "timestamp", "key_id", "signature")})
    step("3a replayed stale checkpoint rejected", r.status_code == 409 and r.json()["alert_reason"] == "ROLLBACK",
         replayed_size=stale["tree_size"], witness_size=latest["tree_size"], reason=r.json().get("alert_reason"))

    # compromised-log model: an attacker holding the checkpoint key signs a forked tree head
    sys.path.insert(0, str(REPO / "backend"))
    from app.crypto.keys import Signer
    from app.crypto.statements import checkpoint_statement
    from nacl.signing import SigningKey

    sk = Signer("checkpoint", SigningKey(bytes.fromhex((KEYS / "api" / "checkpoint_ed25519.key").read_text().strip())))
    forked_root = hashlib.sha256(b"forked view " + run.encode()).hexdigest()
    ts = "2026-11-17T00:00:00.000000Z"
    sub = {"log_id": latest["log_id"], "tree_size": latest["tree_size"], "root_hash": forked_root, "timestamp": ts,
           "key_id": sk.key_id, "signature": sk.sign(checkpoint_statement(latest["log_id"], latest["tree_size"], forked_root, ts, sk.key_id))}
    r = w.post("/witness/checkpoint", json=sub)
    step("3b split-view (same size, different root) rejected", r.status_code == 409 and r.json()["alert_reason"] == "EQUIVOCATION",
         reason=r.json().get("alert_reason"))
    sub2 = dict(sub, tree_size=latest["tree_size"] + 5, consistency_proof=["00" * 32] * 3)
    sub2["signature"] = sk.sign(checkpoint_statement(sub2["log_id"], sub2["tree_size"], forked_root, ts, sk.key_id))
    r = w.post("/witness/checkpoint", json=sub2)
    step("3c growth with forged consistency proof rejected", r.status_code == 409 and r.json()["alert_reason"] == "EQUIVOCATION",
         reason=r.json().get("alert_reason"))
    alerts = w.get("/witness/alerts").json()
    step("3d alerts persisted in witness DB", len(alerts) >= 3, alerts=len(alerts))
    # honest log keeps working after the attack attempts
    after = upload("after-attack.jpg", make_base(seed * 10 + 77))
    step("3e honest checkpoint still acknowledged", after["witness_status"] == "ACKNOWLEDGED", tree_size=after["checkpoint_tree_size"])

    # ---------------------------------------------------------------- 4
    print("\nScenario 4 — unrelated negative image")
    neg = encode(_scene(424_242 + seed), quality=85)
    s = search(neg, use_orb=True)
    step("4a search returns NO_MATCH", s["outcome"] == "NO_MATCH" and not s["candidates"], gallery=s["gallery_size"])
    v = verify_candidate(neg, regs[0]["id"])
    step("4b verify-candidate returns NO_MATCH", v["assessment"] == "NO_MATCH", relationship=v["relationship"])

    report = {"run": run, "case_id": case["id"], "api": API, "steps": results,
              "passed": sum(r["result"] == "PASS" for r in results), "total": len(results)}
    (REPO / "experiments" / "results" / "demo-scenarios.json").write_text(json.dumps(report, indent=2))
    print(f"\n{report['passed']}/{report['total']} demo checks passed")
    return 0 if report["passed"] == report["total"] else 1


if __name__ == "__main__":
    sys.exit(main())
