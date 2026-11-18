"""Retrieval-side benchmarks (MediaTrace) + ablation + metadata stripping."""

from __future__ import annotations

import time
from collections import defaultdict

from app.mediatrace import engine
from app.mediatrace.metadata import extract_exif

from experiments.common import BenchmarkResult, Out
from experiments.dataset import TRANSFORMS, decode, encode
from experiments.prepared import Prepared, make_item
from experiments.trustchain_sim import TrustChainSim

DEFAULT_TAU = 10
ORB_TOP_K = 10
ORB_MIN_INLIERS = 15
FAMILY = {t.name: t.family for t in TRANSFORMS}


def _r(x: float) -> float:
    return round(x, 4)


# ---------------------------------------------------------------------------
# 1. Retrieval accuracy per transformation
# ---------------------------------------------------------------------------


def retrieval_accuracy(p: Prepared, out: Out, tau: int = DEFAULT_TAU) -> BenchmarkResult:
    res = BenchmarkResult(
        "retrieval_accuracy",
        "Retrieval accuracy by transformation (SHA-256 + pHash)",
        f"Gallery of {len(p.gallery)} registered originals. For every transformed query: "
        f"Precision@1 = correct top-1 among queries returning a candidate; Recall@1/Recall@5 = true source "
        f"within the top-1/top-5 candidates (Hamming ≤ {tau}); SHA-256 exact = byte-identical lookup. "
        f"FPR = unrelated negative queries returning any candidate.",
    )
    params = engine.SearchParams(phash_threshold=tau, limit=5)
    by_t: dict[str, list] = defaultdict(list)
    for src, tname, q in p.queries:
        cands = p.search(q, params)
        ids = [int(c.evidence_id) for c in cands]
        by_t[tname].append(
            {
                "returned": bool(ids),
                "top1": bool(ids) and ids[0] == src,
                "top5": src in ids,
                "sha": p.gallery[src].sha256 == q.sha256,
                "dist": next((c.hamming for c in cands if int(c.evidence_id) == src), None),
            }
        )
    rows = []
    for t in TRANSFORMS:
        rs = by_t[t.name]
        n, ret = len(rs), sum(r["returned"] for r in rs)
        dists = [r["dist"] for r in rs if r["dist"] is not None]
        rows.append(
            {
                "transform": t.name,
                "family": t.family,
                "queries": n,
                "precision_at_1": _r(sum(r["top1"] for r in rs) / ret) if ret else None,
                "recall_at_1": _r(sum(r["top1"] for r in rs) / n),
                "recall_at_5": _r(sum(r["top5"] for r in rs) / n),
                "sha256_exact_rate": _r(sum(r["sha"] for r in rs) / n),
                "mean_hamming_true_source": _r(sum(dists) / len(dists)) if dists else None,
            }
        )
    neg_fp = sum(bool(p.search(q, params)) for q in p.negatives)
    fpr = _r(neg_fp / len(p.negatives)) if p.negatives else 0.0
    rows.append({"transform": "NEGATIVES (unrelated)", "family": "negative", "queries": len(p.negatives),
                 "precision_at_1": None, "recall_at_1": None, "recall_at_5": None,
                 "sha256_exact_rate": 0.0, "mean_hamming_true_source": None})
    out.csv(res, "retrieval_accuracy.csv", rows)
    chart_rows = [r for r in rows if r["family"] != "negative"]
    out.chart(res, "retrieval_accuracy.png", title=f"Retrieval accuracy by transformation (τ={tau})", kind="bar",
              x="transform", series=["sha256_exact_rate", "precision_at_1", "recall_at_1", "recall_at_5"],
              data=chart_rows, y_label="rate")
    res.table = rows
    pos = [r for r in chart_rows]
    res.summary = {
        "retrieval_recall_at_1_mean": _r(sum(r["recall_at_1"] for r in pos) / len(pos)),
        "retrieval_recall_at_5_mean": _r(sum(r["recall_at_5"] for r in pos) / len(pos)),
        "retrieval_fpr_negatives": fpr,
        "sha256_only_recall": _r(sum(r["sha256_exact_rate"] for r in pos) / len(pos)),
    }
    res.description += f" Measured FPR on {len(p.negatives)} negatives: {fpr}."
    return res


# ---------------------------------------------------------------------------
# 2. Hamming threshold sweep (ROC)
# ---------------------------------------------------------------------------


def threshold_sweep(p: Prepared, out: Out) -> BenchmarkResult:
    res = BenchmarkResult(
        "threshold_sweep",
        "Hamming threshold sweep (ROC)",
        "True-positive rate (correct top-1 within threshold, all transformed queries) and false-positive "
        "rate (negatives with any candidate within threshold) as the pHash Hamming threshold τ varies.",
    )
    top1 = []
    for src, tname, q in p.queries:
        ranked = p.ranked(q)
        exact, d, i = ranked[0]
        top1.append((exact == 0, d, i == src, FAMILY[tname]))
    neg_min = [p.ranked(q)[0][1] for q in p.negatives]
    rows = []
    for tau in range(0, 33, 2):
        tp = sum(1 for ex, d, ok, _ in top1 if ok and (ex or d <= tau))
        row = {"threshold": tau, "tpr": _r(tp / len(top1)), "fpr": _r(sum(d <= tau for d in neg_min) / max(len(neg_min), 1))}
        for fam in ("jpeg", "resize", "crop", "photometric", "format", "combined"):
            fam_rows = [x for x in top1 if x[3] == fam]
            if fam_rows:
                row[f"tpr_{fam}"] = _r(sum(1 for ex, d, ok, _ in fam_rows if ok and (ex or d <= tau)) / len(fam_rows))
        rows.append(row)
    out.csv(res, "threshold_sweep.csv", rows)
    out.chart(res, "threshold_sweep.png", title="TPR / FPR vs Hamming threshold", kind="line", x="threshold",
              series=["tpr", "fpr"], data=rows, x_label="Hamming threshold τ", y_label="rate")
    fam_series = [k for k in rows[0] if k.startswith("tpr_")]
    out.chart(res, "threshold_sweep_by_family.png", title="TPR by transformation family vs threshold", kind="line",
              x="threshold", series=fam_series, data=rows, x_label="Hamming threshold τ", y_label="TPR")
    roc = sorted({(r["fpr"], r["tpr"]) for r in rows})
    out.chart(res, "roc.png", title="ROC (pHash, sweep over τ)", kind="line", x="fpr", series=["tpr"],
              data=[{"fpr": f, "tpr": t} for f, t in roc], x_label="FPR", y_label="TPR")
    best = max(rows, key=lambda r: r["tpr"] - r["fpr"])
    res.summary = {"best_threshold_youden": best["threshold"], "tpr_at_best": best["tpr"], "fpr_at_best": best["fpr"]}
    res.table = rows
    return res


# ---------------------------------------------------------------------------
# 3. Cropping resilience: pHash vs pHash + ORB
# ---------------------------------------------------------------------------


def cropping(p: Prepared, out: Out, tau: int = DEFAULT_TAU) -> BenchmarkResult:
    res = BenchmarkResult(
        "cropping_resilience",
        "Cropping resilience: pHash vs pHash + ORB/RANSAC",
        f"Recall@1 on crop queries with pHash alone (τ={tau}) versus pHash plus ORB geometric verification of the "
        f"top-{ORB_TOP_K} pHash neighbours (accept if RANSAC inliers ≥ {ORB_MIN_INLIERS}). FPR measured on negatives.",
    )
    ph = engine.SearchParams(phash_threshold=tau, limit=1)
    po = engine.SearchParams(phash_threshold=tau, use_orb=True, orb_top_k=ORB_TOP_K, orb_min_inliers=ORB_MIN_INLIERS, limit=1)
    rows = []
    agg = {"phash": 0, "orb": 0, "n": 0}
    true_inl, false_inl = [], []
    crop_ts = [t.name for t in TRANSFORMS if t.family == "crop"]
    for tname in crop_ts:
        qs = [(s, q) for s, t, q in p.queries if t == tname]
        hp = ho = 0
        t0 = time.perf_counter()
        for src, q in qs:
            a = p.search(q, ph)
            b = p.search(q, po)
            hp += bool(a) and int(a[0].evidence_id) == src
            ho += bool(b) and int(b[0].evidence_id) == src
        elapsed = (time.perf_counter() - t0) * 1000 / max(len(qs), 1)
        # inlier statistics (true source vs best wrong candidate)
        for src, q in qs:
            for c in p.search(q, engine.SearchParams(phash_threshold=64, use_orb=True, orb_top_k=ORB_TOP_K, orb_min_inliers=10**6, limit=100)):
                if c.orb:
                    (true_inl if int(c.evidence_id) == src else false_inl).append(c.orb["inliers"])
        rows.append({"transform": tname, "queries": len(qs), "phash_recall_at_1": _r(hp / len(qs)),
                     "phash_orb_recall_at_1": _r(ho / len(qs)), "ms_per_query_both": round(elapsed, 2)})
        agg["phash"] += hp
        agg["orb"] += ho
        agg["n"] += len(qs)
    neg_fp_ph = sum(bool(p.search(q, ph)) for q in p.negatives)
    neg_fp_orb = sum(bool(p.search(q, po)) for q in p.negatives)
    out.csv(res, "cropping_resilience.csv", rows)
    out.chart(res, "cropping_resilience.png", title="Crop recovery: pHash vs pHash+ORB (Recall@1)", kind="bar",
              x="transform", series=["phash_recall_at_1", "phash_orb_recall_at_1"], data=rows, y_label="Recall@1")
    hist = []
    edges = [0, 5, 10, 15, 20, 30, 50, 100, 200, 10**9]
    for lo, hi in zip(edges, edges[1:]):
        label = f"{lo}-{hi - 1}" if hi < 10**9 else f"{lo}+"
        hist.append({"inliers": label, "true_source": sum(lo <= v < hi for v in true_inl),
                     "wrong_candidate": sum(lo <= v < hi for v in false_inl)})
    out.csv(res, "orb_inlier_histogram.csv", hist)
    out.chart(res, "orb_inlier_histogram.png", title="RANSAC inliers: true source vs wrong candidates (crop queries)",
              kind="bar", x="inliers", series=["true_source", "wrong_candidate"], data=hist, y_label="pairs")
    res.table = rows
    res.summary = {
        "crop_recall_phash": _r(agg["phash"] / agg["n"]),
        "crop_recall_phash_orb": _r(agg["orb"] / agg["n"]),
        "crop_fpr_phash": _r(neg_fp_ph / max(len(p.negatives), 1)),
        "crop_fpr_phash_orb": _r(neg_fp_orb / max(len(p.negatives), 1)),
    }
    return res


# ---------------------------------------------------------------------------
# 7. Ablation A/B/C/D
# ---------------------------------------------------------------------------


def ablation(p: Prepared, out: Out, seed: int, tamper_fraction: float = 0.1, tau: int = DEFAULT_TAU) -> BenchmarkResult:
    res = BenchmarkResult(
        "ablation",
        "Ablation: (A) SHA-256 → (B) +pHash → (C) +ORB → (D) full TrustChain + MediaTrace",
        f"All transformed queries + negatives. {int(tamper_fraction * 100)}% of registered originals are tampered "
        "in storage after registration (one byte flipped) to measure silent-corruption exposure. "
        "Recovery = correct top-1 candidate. Configurations A–C cannot tell a tampered original from a good one; "
        "D runs full cryptographic verification (storage SHA-256, Ed25519 event signature, RFC 9162 inclusion, "
        "checkpoint signature, witness co-signature) on the recovered record.",
    )
    sim = TrustChainSim(seed)
    for i, it in p.gallery.items():
        sim.register(i, it.data)
    sim.publish_checkpoint()
    n_tamper = max(1, int(round(len(p.gallery) * tamper_fraction)))
    tampered = set(sorted(p.gallery)[:: max(1, len(p.gallery) // n_tamper)][:n_tamper])
    for i in tampered:
        b = bytearray(sim.storage[i])
        b[len(b) // 2] ^= 0xFF
        sim.storage[i] = bytes(b)

    # Pre-extract ORB features for every image so per-config latency compares
    # matching + verification only (extraction cost is reported separately).
    t0 = time.perf_counter()
    for it in list(p.gallery.values()) + [q for _, _, q in p.queries] + p.negatives:
        it.orb_features()
    orb_extract_ms = (time.perf_counter() - t0) * 1000 / (len(p.gallery) + len(p.queries) + len(p.negatives))

    configs = {
        "A_sha256_only": engine.SearchParams(exact_only=True, limit=1),
        "B_sha256_phash": engine.SearchParams(phash_threshold=tau, limit=1),
        "C_sha256_phash_orb": engine.SearchParams(phash_threshold=tau, use_orb=True, orb_top_k=ORB_TOP_K, orb_min_inliers=ORB_MIN_INLIERS, limit=1),
        "D_full_trustchain_mediatrace": engine.SearchParams(phash_threshold=tau, use_orb=True, orb_top_k=ORB_TOP_K, orb_min_inliers=ORB_MIN_INLIERS, limit=1),
    }
    rows = []
    for name, params in configs.items():
        full = name.startswith("D_")
        recovered = verified = tampered_returned = tampered_flagged = 0
        lat = []
        for src, _, q in p.queries:
            t0 = time.perf_counter()
            c = p.search(q, params)
            outcome = None
            if c and full:
                outcome, _ = sim.verify(int(c[0].evidence_id))
            lat.append((time.perf_counter() - t0) * 1000)
            hit = bool(c) and int(c[0].evidence_id) == src
            recovered += hit
            if hit and src in tampered:
                tampered_returned += 1
                tampered_flagged += full and outcome == "FAIL"
            if hit and full and outcome == "PASS":
                verified += 1
        fp = sum(bool(p.search(q, params)) for q in p.negatives)
        n = len(p.queries)
        rows.append(
            {
                "config": name,
                "recovery_rate": _r(recovered / n),
                "verified_provenance_rate": _r(verified / n) if full else 0.0,
                "fpr_negatives": _r(fp / max(len(p.negatives), 1)),
                "tampered_originals_returned": tampered_returned,
                "tampered_detected_rate": _r(tampered_flagged / tampered_returned) if tampered_returned else 0.0,
                "mean_latency_ms": round(sum(lat) / len(lat), 3),
            }
        )
    out.csv(res, "ablation.csv", rows)
    out.chart(res, "ablation.png", title="Ablation study", kind="bar", x="config",
              series=["recovery_rate", "verified_provenance_rate", "fpr_negatives", "tampered_detected_rate"],
              data=rows, y_label="rate")
    out.chart(res, "ablation_latency.png", title="Ablation: mean per-query latency", kind="bar", x="config",
              series=["mean_latency_ms"], data=rows, y_label="ms")
    res.table = rows
    res.summary = {f"ablation_{r['config'][0]}_recovery": r["recovery_rate"] for r in rows}
    res.summary["ablation_D_tamper_detection"] = rows[-1]["tampered_detected_rate"]
    res.summary["orb_extract_ms_mean"] = round(orb_extract_ms, 2)
    res.description += (
        f" Latency excludes one-off ORB feature extraction (pre-computed; mean {orb_extract_ms:.1f} ms per image) "
        "and pHash computation, and includes candidate ranking, ORB matching and (D) verification."
    )
    return res


# ---------------------------------------------------------------------------
# 8. Metadata stripping: exact hashing vs pHash
# ---------------------------------------------------------------------------


def metadata_stripping(p: Prepared, out: Out) -> BenchmarkResult:
    from app.mediatrace.metadata import strip_jpeg_metadata

    res = BenchmarkResult(
        "metadata_stripping",
        "Metadata stripping: SHA-256 vs pHash",
        "Each registered original (JPEG with EXIF) is stripped of EXIF/XMP/C2PA/IPTC APP segments at the byte "
        "level (pixels untouched), stripped + re-encoded (Q95), and stripped + converted to PNG. "
        "Measures whether SHA-256 still matches, EXIF survival, and pHash distance to the original. "
        "Note: the synthetic originals carry EXIF but no C2PA manifest (embedding one requires a signing "
        "certificate); APP11 (C2PA/JUMBF) removal is exercised by the same stripping code path.",
    )
    variants = {
        "byte_strip": lambda d: strip_jpeg_metadata(d),
        "strip_reencode_q95": lambda d: encode(decode(strip_jpeg_metadata(d)), quality=95),
        "strip_to_png": lambda d: encode(decode(strip_jpeg_metadata(d)), fmt="PNG"),
    }
    rows = []
    for vname, fn in variants.items():
        sha_same = exif_left = 0
        dists = []
        for i, it in p.gallery.items():
            q = make_item(fn(it.data))
            sha_same += q.sha256 == it.sha256
            exif_left += any(not k.startswith("_") for k in extract_exif(q.data))
            from app.mediatrace.phash import hamming

            dists.append(hamming(q.phash, it.phash))
        n = len(p.gallery)
        rows.append({"variant": vname, "originals": n, "sha256_match_rate": _r(sha_same / n),
                     "exif_retained_rate": _r(exif_left / n), "phash_mean_distance": _r(sum(dists) / n),
                     "phash_max_distance": max(dists), "phash_match_rate_tau10": _r(sum(d <= DEFAULT_TAU for d in dists) / n)})
    out.csv(res, "metadata_stripping.csv", rows)
    out.chart(res, "metadata_stripping.png", title="After metadata stripping", kind="bar", x="variant",
              series=["sha256_match_rate", "exif_retained_rate", "phash_match_rate_tau10"], data=rows, y_label="rate")
    res.table = rows
    res.summary = {"strip_sha256_match_rate": rows[0]["sha256_match_rate"], "strip_phash_match_rate": rows[0]["phash_match_rate_tau10"]}
    return res
