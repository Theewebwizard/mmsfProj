#!/usr/bin/env python3
"""Run the full reproducible benchmark suite.

    python experiments/run_all.py [--quick] [--seed 1337] [--run-id NAME]

Writes experiments/results/<run-id>/{manifest.json, *.csv, *.png}.
The dataset is regenerated from the seed on every run (bit-reproducible);
timing measurements are real wall-clock numbers from this machine.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import sys
import time
import traceback
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, os.environ.get("TRUSTCHAIN_BACKEND_DIR", str(REPO / "backend")))
sys.path.insert(0, os.environ.get("TRUSTCHAIN_WITNESS_DIR", str(REPO / "witness")))
if not (HERE.parent / "experiments").is_dir():  # e.g. mounted at /experiments in Docker
    sys.path.insert(0, str(HERE.parent))

from experiments import bench_crypto, bench_retrieval  # noqa: E402
from experiments.common import Out  # noqa: E402
from experiments.dataset import TRANSFORMS, build  # noqa: E402
from experiments.prepared import prepare  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--quick", action="store_true", help="smaller dataset / fewer repetitions")
    ap.add_argument("--seed", type=int, default=1337)
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--n-base", type=int, default=None)
    ap.add_argument("--n-negative", type=int, default=None)
    args = ap.parse_args()

    n_base = args.n_base or (20 if args.quick else 60)
    n_neg = args.n_negative or (20 if args.quick else 60)
    run_id = args.run_id or datetime.now(timezone.utc).strftime("run-%Y%m%dT%H%M%SZ")
    root = HERE / "results" / run_id
    out = Out(root)
    started = datetime.now(timezone.utc).isoformat()
    config = {
        "seed": args.seed,
        "quick": args.quick,
        "n_base_originals": n_base,
        "n_negatives": n_neg,
        "transforms": [t.name for t in TRANSFORMS],
        "phash_threshold_default": bench_retrieval.DEFAULT_TAU,
        "orb_top_k": bench_retrieval.ORB_TOP_K,
        "orb_min_inliers": bench_retrieval.ORB_MIN_INLIERS,
        "python": platform.python_version(),
        "platform": platform.platform(),
        "processor": platform.processor() or platform.machine(),
    }

    def write_manifest(status: str, results: list, error: str | None = None) -> None:
        summary: dict = {}
        files: list[str] = []
        for r in results:
            summary.update(r.summary)
            files += r.files
        manifest = {
            "run_id": run_id,
            "name": f"{'Quick' if args.quick else 'Full'} benchmark suite (seed {args.seed})",
            "status": status,
            "started_at": started,
            "finished_at": datetime.now(timezone.utc).isoformat(),
            "config": config,
            "summary": summary,
            "files": files + ["manifest.json"],
            "benchmarks": {r.key: r.manifest() for r in results},
        }
        if error:
            manifest["error"] = error
        (root / "manifest.json").write_text(json.dumps(manifest, indent=2))

    results = []
    t0 = time.perf_counter()
    try:
        print(f"[run_all] generating dataset: {n_base} originals x {len(TRANSFORMS)} transforms + {n_neg} negatives (seed {args.seed})", flush=True)
        ds = build(args.seed, n_base, n_neg)
        prepared = prepare(ds)
        print(f"[run_all] dataset ready in {time.perf_counter() - t0:.1f}s", flush=True)
        steps = [
            ("1/8 retrieval accuracy", lambda: bench_retrieval.retrieval_accuracy(prepared, out)),
            ("2/8 threshold sweep", lambda: bench_retrieval.threshold_sweep(prepared, out)),
            ("3/8 cropping resilience", lambda: bench_retrieval.cropping(prepared, out)),
            ("4/8 crypto latency", lambda: bench_crypto.crypto_latency(out, args.seed, args.quick)),
            ("5/8 merkle scaling", lambda: bench_crypto.merkle_scaling(out, args.seed, args.quick)),
            ("6/8 witness detection", lambda: bench_crypto.witness_detection(out, args.seed, args.quick)),
            ("7/8 ablation", lambda: bench_retrieval.ablation(prepared, out, args.seed)),
            ("8/8 metadata stripping", lambda: bench_retrieval.metadata_stripping(prepared, out)),
        ]
        for label, fn in steps:
            ts = time.perf_counter()
            r = fn()
            results.append(r)
            print(f"[run_all] {label}: {time.perf_counter() - ts:.1f}s  {json.dumps(r.summary)}", flush=True)
            write_manifest("running", results)
    except Exception:
        tb = traceback.format_exc()
        print(tb, flush=True)
        write_manifest("failed", results, tb)
        return 1
    write_manifest("completed", results)
    print(f"[run_all] completed in {time.perf_counter() - t0:.1f}s -> {root}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
