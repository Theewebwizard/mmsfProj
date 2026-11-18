"""Cryptographic overhead + witness attack-detection benchmarks."""

from __future__ import annotations

import hashlib
import random
import time

from nacl.signing import SigningKey

from app.crypto import merkle
from app.crypto.canonical import canonical_json
from app.crypto.keys import Signer, key_id_for, verify_signature
from app.crypto.statements import EVENT_TYPE, checkpoint_statement

from witness_service import core as wcore

from experiments.common import BenchmarkResult, Out, time_us


def _event(i: int, key_id: str) -> bytes:
    return canonical_json(
        {
            "type": EVENT_TYPE,
            "log_id": "bench",
            "event_id": f"00000000-0000-0000-0000-{i:012d}",
            "event_type": "EVIDENCE_REGISTERED",
            "evidence_id": f"00000000-0000-0000-0000-{i:012d}",
            "actor_id": "00000000-0000-0000-0000-000000000001",
            "timestamp": "2026-11-17T00:00:00.000000Z",
            "payload": {"sha256": hashlib.sha256(str(i).encode()).hexdigest(), "file_size": 123456},
            "prev_event_hash": None,
            "key_id": key_id,
        }
    )


# ---------------------------------------------------------------------------
# 4. Primitive latency
# ---------------------------------------------------------------------------


def crypto_latency(out: Out, seed: int, quick: bool) -> BenchmarkResult:
    res = BenchmarkResult(
        "crypto_latency",
        "Cryptographic primitive latency",
        "Wall-clock latency (µs) of SHA-256 over evidence-sized inputs, RFC 8785-style canonical JSON, Ed25519 "
        "(PyNaCl/libsodium) sign + verify of a custody event, RFC 9162 leaf hashing, and witness evaluation "
        "of one checkpoint. Single-threaded on the benchmark host; absolute numbers are machine-dependent.",
    )
    reps = 200 if quick else 1000
    rng = random.Random(seed)
    signer = Signer("custody", SigningKey(hashlib.sha256(f"{seed}".encode()).digest()))
    ev = _event(1, signer.key_id)
    sig = signer.sign(ev)
    rows = []
    for size, label in [(100_000, "SHA-256 100 KB"), (1_000_000, "SHA-256 1 MB"), (10_000_000, "SHA-256 10 MB")]:
        blob = rng.randbytes(size)
        r = time_us(lambda: hashlib.sha256(blob).digest(), max(20, reps // (size // 100_000)))
        r["throughput_MBps"] = round(size / r["median_us"], 1)
        rows.append({"operation": label, **r})
    stmt = {"payload": {"sha256": "ab" * 32, "n": 1}, "b": "x", "a": [1, 2, 3]}
    rows.append({"operation": "canonical JSON (event)", **time_us(lambda: canonical_json(stmt), reps)})
    rows.append({"operation": "Ed25519 sign (event)", **time_us(lambda: signer.sign(ev), reps)})
    rows.append({"operation": "Ed25519 verify (event)", **time_us(lambda: verify_signature(signer.public_key_hex, ev, sig), reps)})
    rows.append({"operation": "RFC 9162 leaf hash", **time_us(lambda: merkle.leaf_hash(ev), reps)})

    leaves = [merkle.leaf_hash(_event(i, signer.key_id)) for i in range(1024)]
    root = merkle.root_hash(leaves).hex()
    ck = Signer("checkpoint", SigningKey(hashlib.sha256(f"{seed}:cp".encode()).digest()))
    sub = wcore.Submission("bench", 1024, root, "t", ck.key_id, ck.sign(checkpoint_statement("bench", 1024, root, "t", ck.key_id)),
                           [p.hex() for p in merkle.consistency_proof(512, leaves)])
    state = wcore.WitnessState(512, merkle.root_hash(leaves[:512]).hex())
    rows.append({"operation": "Witness evaluate (sig + consistency 512→1024)",
                 **time_us(lambda: wcore.evaluate(sub, state, ck.public_key_hex, ck.key_id), max(50, reps // 4))})
    out.csv(res, "crypto_latency.csv", rows)
    out.chart(res, "crypto_latency.png", title="Cryptographic primitive latency (median)", kind="bar", x="operation",
              series=["median_us"], data=[{"operation": r["operation"], "median_us": r["median_us"]} for r in rows],
              y_label="µs (log scale)", log_y=True)
    res.table = rows
    by = {r["operation"]: r for r in rows}
    res.summary = {
        "ed25519_sign_median_us": by["Ed25519 sign (event)"]["median_us"],
        "ed25519_verify_median_us": by["Ed25519 verify (event)"]["median_us"],
        "sha256_1MB_median_us": by["SHA-256 1 MB"]["median_us"],
    }
    return res


# ---------------------------------------------------------------------------
# 5. Merkle scaling
# ---------------------------------------------------------------------------


def merkle_scaling(out: Out, seed: int, quick: bool) -> BenchmarkResult:
    res = BenchmarkResult(
        "merkle_scaling",
        "RFC 9162 Merkle log scaling",
        "Root computation, inclusion-proof generation/verification and consistency-proof generation/verification "
        "(n/2 → n) as the log grows. Proof length grows as ⌈log2 n⌉; verification stays in the microsecond range. "
        "Generation here recomputes subtree hashes from leaves (no cached interior nodes).",
    )
    rng = random.Random(seed)
    max_exp = 14 if quick else 16
    rows = []
    for e in range(4, max_exp + 1, 2 if quick else 1):
        n = 2**e + rng.randrange(0, 2**e // 3)  # include non-power-of-two sizes
        leaves = [merkle.leaf_hash(rng.randbytes(64)) for _ in range(n)]
        reps = 3 if n > 20_000 else 10
        root = merkle.root_hash(leaves)
        idx = rng.randrange(n)
        proof = merkle.inclusion_proof(idx, leaves)
        m = n // 2
        cproof = merkle.consistency_proof(m, leaves)
        old = merkle.root_hash(leaves[:m])
        assert merkle.verify_inclusion(idx, n, leaves[idx], proof, root)
        assert merkle.verify_consistency(m, n, old, root, cproof)
        rows.append(
            {
                "tree_size": n,
                "root_ms": round(time_us(lambda: merkle.root_hash(leaves), reps)["median_us"] / 1000, 3),
                "inclusion_gen_ms": round(time_us(lambda: merkle.inclusion_proof(idx, leaves), reps)["median_us"] / 1000, 3),
                "inclusion_verify_us": time_us(lambda: merkle.verify_inclusion(idx, n, leaves[idx], proof, root), 200)["median_us"],
                "inclusion_proof_len": len(proof),
                "consistency_gen_ms": round(time_us(lambda: merkle.consistency_proof(m, leaves), reps)["median_us"] / 1000, 3),
                "consistency_verify_us": time_us(lambda: merkle.verify_consistency(m, n, old, root, cproof), 200)["median_us"],
                "consistency_proof_len": len(cproof),
            }
        )
    out.csv(res, "merkle_scaling.csv", rows)
    out.chart(res, "merkle_generation.png", title="Proof generation time vs tree size", kind="line", x="tree_size",
              series=["root_ms", "inclusion_gen_ms", "consistency_gen_ms"], data=rows, x_label="tree size", y_label="ms",
              log_x=True, log_y=True)
    out.chart(res, "merkle_verification.png", title="Proof verification time vs tree size", kind="line", x="tree_size",
              series=["inclusion_verify_us", "consistency_verify_us"], data=rows, x_label="tree size", y_label="µs", log_x=True)
    out.chart(res, "merkle_proof_size.png", title="Proof length (hashes) vs tree size", kind="line", x="tree_size",
              series=["inclusion_proof_len", "consistency_proof_len"], data=rows, x_label="tree size", y_label="hashes", log_x=True)
    res.table = rows
    res.summary = {"merkle_largest_tree": rows[-1]["tree_size"], "merkle_inclusion_verify_us_largest": rows[-1]["inclusion_verify_us"]}
    return res


# ---------------------------------------------------------------------------
# 6. Witness rollback / equivocation detection
# ---------------------------------------------------------------------------


def witness_detection(out: Out, seed: int, quick: bool) -> BenchmarkResult:
    res = BenchmarkResult(
        "witness_detection",
        "Witness rollback / equivocation detection",
        "Randomised trials against the production witness decision logic. Each trial: the witness has accepted "
        "an honest checkpoint of size m; the (malicious) log then submits a checkpoint of size n. Attacks: "
        "rollback (n < m), same-size split view, forked history (an earlier entry rewritten, proof generated "
        "honestly from the forked tree), fork + replayed honest proof, and a checkpoint signed by an attacker "
        "key. Honest growth trials measure the false-alarm rate.",
    )
    rng = random.Random(seed)
    trials = 200 if quick else 1000
    log_key = SigningKey(hashlib.sha256(f"{seed}:log".encode()).digest())
    evil_key = SigningKey(hashlib.sha256(f"{seed}:evil".encode()).digest())
    log_pub = bytes(log_key.verify_key).hex()
    log_kid = key_id_for(bytes(log_key.verify_key))

    def leaves(n: int, salt: bytes = b"") -> list[bytes]:
        return [merkle.leaf_hash(salt + i.to_bytes(4, "big")) for i in range(n)]

    def submit(tree: list[bytes], prev: int, key=log_key, proof_tree=None) -> wcore.Submission:
        root = merkle.root_hash(tree).hex()
        kid = key_id_for(bytes(key.verify_key)) if key is not log_key else log_kid
        sig = key.sign(checkpoint_statement("bench", len(tree), root, "t", kid)).signature.hex()
        pt = proof_tree if proof_tree is not None else tree
        proof = [p.hex() for p in merkle.consistency_proof(prev, pt)] if 0 < prev < len(pt) else []
        return wcore.Submission("bench", len(tree), root, "t", kid, sig, proof)

    stats: dict[str, dict[str, float]] = {}

    def record(name: str, decision: wcore.Decision, expect_reject: bool, dt: float) -> None:
        s = stats.setdefault(name, {"trials": 0, "flagged": 0, "time_us": 0.0, "reasons": {}})
        s["trials"] += 1
        s["flagged"] += decision.status == wcore.REJECTED
        s["time_us"] += dt
        if decision.reason:
            s["reasons"][decision.reason] = s["reasons"].get(decision.reason, 0) + 1

    for _ in range(trials):
        m = rng.randint(2, 300)
        n = m + rng.randint(1, 300)
        honest = leaves(n)
        state = wcore.WitnessState(m, merkle.root_hash(honest[:m]).hex())
        cases = {
            "honest_growth": (submit(honest, m), False),
            "rollback": (submit(honest[: rng.randint(1, m - 1)], 0), True),
            "split_view_same_size": (submit(leaves(m, b"fork"), 0), True),
        }
        forked = list(honest)
        forked[rng.randrange(m)] = merkle.leaf_hash(b"rewritten" + rng.randbytes(8))
        cases["forked_history"] = (submit(forked, m), True)
        cases["fork_with_replayed_honest_proof"] = (submit(forked, m, proof_tree=honest), True)
        cases["forged_signature_attacker_key"] = (submit(honest, m, key=evil_key), True)
        for name, (sub, bad) in cases.items():
            t0 = time.perf_counter_ns()
            d = wcore.evaluate(sub, state, log_pub, log_kid)
            record(name, d, bad, (time.perf_counter_ns() - t0) / 1000)

    rows = []
    for name, s in stats.items():
        honest_case = name == "honest_growth"
        rows.append(
            {
                "scenario": name,
                "trials": int(s["trials"]),
                "detection_rate": None if honest_case else round(s["flagged"] / s["trials"], 4),
                "false_alarm_rate": round(s["flagged"] / s["trials"], 4) if honest_case else None,
                "mean_eval_us": round(s["time_us"] / s["trials"], 2),
                "reasons": ";".join(f"{k}={v}" for k, v in sorted(s["reasons"].items())) or "-",
            }
        )
    out.csv(res, "witness_detection.csv", rows)
    out.chart(res, "witness_detection.png", title="Witness outcome by scenario", kind="bar", x="scenario",
              series=["detection_rate", "false_alarm_rate"], data=rows, y_label="rate")
    res.table = rows
    attacks = [r for r in rows if r["detection_rate"] is not None]
    res.summary = {
        "witness_min_detection_rate": min(r["detection_rate"] for r in attacks),
        "witness_false_alarm_rate": next(r["false_alarm_rate"] for r in rows if r["scenario"] == "honest_growth"),
    }
    return res
