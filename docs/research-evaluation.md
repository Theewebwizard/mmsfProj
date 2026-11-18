# Research Evaluation

Every number in this document comes from an actual execution:

- **Benchmarks:** `experiments/run_all.py --seed 1337 --run-id full-seed1337`. Artifacts (CSV, PNG and `manifest.json`) are copied to [`docs/results/full-seed1337/`](results/full-seed1337/).
- **Demo scenarios:** `experiments/demo_scenarios.py`, run against the live Docker stack. Results are in [`docs/results/demo-scenarios.json`](results/demo-scenarios.json).

To reproduce:

```bash
.venv/bin/python experiments/run_all.py --seed 1337          # ~50 s on an idle machine
docker compose up -d --build && .venv/bin/python experiments/demo_scenarios.py
```

**Reproducibility.** The dataset is regenerated from the seed on every run. Accuracy, detection and ablation metrics were bit-identical across three full runs. Latencies are wall-clock measurements from the run host (Linux x86-64, Python 3.12.3, single thread, Docker stack stopped). Two earlier runs that shared the CPU with other jobs gave 2–5× higher latencies and were discarded for latency reporting.

## Dataset

| Set | Composition |
|---|---|
| Originals (registered gallery) | 60 procedural scenes, 640×480 (seeded gradients, shapes, strokes and Gaussian texture via NumPy PCG64), saved as JPEG Q95 **with EXIF** |
| Positive queries | 60 × 20 transformations = 1,200 |
| Negatives | 60 unrelated scenes from a disjoint seed range, JPEG Q85 |

The 20 transformations:

| Family | Transformations |
|---|---|
| none | identity |
| metadata | byte-level EXIF/XMP/C2PA/IPTC strip (APP1/APP11/APP13 removed; pixels untouched) |
| jpeg | Q90, Q70, Q50, Q30 |
| resize | 75%, 50%, 25% |
| crop | center 80%, center 60%, random 80%, random 60% |
| photometric | brightness ±25%, contrast ±30% |
| format | PNG, WebP Q80 |
| combined | social-media pipeline: strip, 50% downscale, JPEG Q70 |

**Limitation:** the images are synthetic. Natural photographs have different pHash statistics, with more near-duplicate structure (skies, documents), so the false-positive rates measured here are optimistic for real collections.

---

## 1. Retrieval accuracy (SHA-256 + pHash, τ = 10)

| Transformation | P@1 | Recall@1 | Recall@5 | SHA-256 exact | Mean d(true) |
|---|---|---|---|---|---|
| identity | 1.00 | 1.00 | 1.00 | **1.00** | 0.00 |
| strip_metadata | 1.00 | 1.00 | 1.00 | **0.00** | 0.00 |
| JPEG Q90 / Q70 / Q50 / Q30 | 1.00 | 1.00 | 1.00 | 0.00 | 0.03–0.13 |
| resize 75 / 50 / 25 % | 1.00 | 1.00 | 1.00 | 0.00 | 0.07–0.10 |
| brightness +25 / −25 % | 1.00 | 1.00 | 1.00 | 0.00 | 2.60 / 0.07 |
| contrast +30 / −30 % | 1.00 | 1.00 | 1.00 | 0.00 | 1.50 / 0.00 |
| PNG / WebP | 1.00 | 1.00 | 1.00 | 0.00 | 0.00 / 0.03 |
| social pipeline | 1.00 | 1.00 | 1.00 | 0.00 | 0.10 |
| crop center 80 % | 1.00 (2 returned) | 0.03 | 0.03 | 0.00 | 9.0 |
| crop center 60 % / random 80 % / random 60 % | — (none returned) | 0.00 | 0.00 | 0.00 | — |
| **Negatives (60)** | | | | | **FPR 0.00** |

**Findings:**
- SHA-256 recovers only the byte-identical query (5% of positives). It fails even for lossless metadata stripping, the core motivating problem.
- pHash recovers every non-geometric transformation, including JPEG Q30 and 25% downscaling, at mean distance ≤ 2.6.
- pHash is essentially blind to cropping, because the DCT low frequencies shift.
- Mean Recall@1 over all 20 transformations is 0.80, with zero false positives.

Charts: `retrieval_accuracy.png`.

## 2. Hamming threshold sweep (ROC)

| τ | TPR (all) | FPR | TPR crop | TPR photometric |
|---|---|---|---|---|
| 0 | 0.704 | 0.000 | 0.000 | 0.608 |
| 4 | 0.797 | 0.000 | 0.000 | 0.983 |
| 10 (default) | 0.802 | 0.000 | 0.008 | 1.000 |
| 16 | 0.815 | 0.000 | 0.075 | 1.000 |
| 18 | 0.828 | 0.083 | 0.138 | 1.000 |
| 20 | 0.848 | 0.267 | 0.242 | 1.000 |
| 24 | 0.864 | 0.983 | 0.321 | 1.000 |

**Findings:**
- On this data, the Youden-optimal threshold is τ = 16 (TPR 0.815, FPR 0).
- False positives appear at τ = 18 and saturate by τ = 24, which is close to the ~32 expected for independent 64-bit hashes.
- All non-crop families reach TPR = 1.0 by τ = 8.
- Raising τ buys only a few crops, at a steep FPR cost. Crops need a different tool.
- The default τ = 10 keeps a safety margin of 8 bits below the first false positive.

Charts: `threshold_sweep.png`, `threshold_sweep_by_family.png`, `roc.png`.

## 3. Cropping resilience: pHash vs pHash + ORB/RANSAC

| Crop | pHash Recall@1 | pHash + ORB Recall@1 |
|---|---|---|
| center 80 % | 0.033 | **0.983** |
| random 80 % | 0.000 | **0.683** |
| center 60 % | 0.000 | **0.367** |
| random 60 % | 0.000 | **0.167** |
| **all crops** | 0.008 | **0.550** |

FPR on negatives was 0.00 for both methods.

The RANSAC inlier distribution (`orb_inlier_histogram.csv`) separates cleanly:

| Pair type | Inlier counts |
|---|---|
| True source vs crop (132 pairs) | always ≥ 30, mostly ≥ 100 |
| Wrong candidates (2,268 pairs) | always ≤ 9 |

**Finding:** the remaining crop misses are *not* inlier-threshold errors. ORB only re-checks the top-K = 10 pHash neighbours, and for crops the pHash ranking is close to random, so the true source is often not among them. That is also why crop recall with ORB fell from 0.78 with a 20-image gallery (quick run) to 0.55 with 60 images.

**Recommendation:** scale K with gallery size, or use a descriptor index for the ORB stage. The `orb_top_k` parameter is exposed in the API and UI for this reason.

## 4. Cryptographic primitive latency (median, µs)

| Operation | Median | p95 | Notes |
|---|---|---|---|
| SHA-256 100 KB | 47.1 | 51.9 | ≈ 2.1 GB/s |
| SHA-256 1 MB | 494.1 | 642.6 | ≈ 2.0 GB/s |
| SHA-256 10 MB | 4,807 | 4,971 | ≈ 2.1 GB/s |
| Canonical JSON (event) | 4.2 | 4.6 | |
| Ed25519 sign (event) | 16.4 | 18.7 | PyNaCl / libsodium |
| Ed25519 verify (event) | 38.0 | 42.2 | |
| RFC 9162 leaf hash | 0.57 | 0.64 | |
| Witness evaluate (sig + consistency 512 → 1024) | 43.6 | 47.5 | |

**Finding:** cryptographic overhead per evidence registration is under 0.1 ms plus SHA-256 time. That is negligible next to network and storage I/O.

## 5. Merkle log scaling

| Tree size | Root (ms) | Inclusion gen (ms) | Inclusion verify (µs) | Inclusion len | Consistency gen (ms) | Consistency verify (µs) | Consistency len |
|---|---|---|---|---|---|---|---|
| 1,177 | 0.45 | 0.47 | 4.9 | 11 | 0.48 | 5.4 | 10 |
| 9,060 | 3.57 | 3.67 | 6.4 | 14 | 3.67 | 8.1 | 14 |
| 33,127 | 13.2 | 13.7 | 7.2 | 16 | 14.0 | 9.3 | 17 |
| 71,557 | 29.7 | 29.5 | 7.5 | 17 | 29.7 | 9.7 | 17 |

**Findings:**
- Proof length grows as ⌈log₂ n⌉.
- Verification, which is what auditors and the witness pay, stays below 10 µs even at 71k entries.
- Generation is O(n) because the implementation recomputes subtree hashes from the stored leaves without an interior-node cache: about 30 ms at 71k entries.
- This is acceptable for a course-scale log. A production log would cache the "frontier" subtree hashes to make generation O(log n).

Charts: `merkle_generation.png`, `merkle_verification.png`, `merkle_proof_size.png`.

## 6. Witness rollback / equivocation detection

There were 1,000 randomised trials per scenario. In each, the witness had accepted an honest checkpoint of size *m* ∈ [2, 300], and the log then submitted size *n* ∈ (m, m+300].

| Scenario | Outcome | Reason | Mean eval (µs) |
|---|---|---|---|
| honest growth | **false-alarm rate 0.000** | — | 57.4 |
| rollback (n < m) | **detected 1.000** | ROLLBACK | 47.7 |
| split view, same size | **detected 1.000** | EQUIVOCATION | 46.5 |
| forked history (entry rewritten; proof honestly derived from fork) | **detected 1.000** | EQUIVOCATION | 53.4 |
| fork + replayed honest consistency proof | **detected 1.000** | EQUIVOCATION | 52.0 |
| checkpoint signed by attacker key | **detected 1.000** | BAD_LOG_SIGNATURE | 2.4 |

**Finding:** detection is deterministic rather than statistical. RFC 9162 consistency verification is sound, so any rewrite of the first *m* leaves changes the reconstructed old root. The 100% rate confirms that the implementation has no gaps; it is not a probabilistic result.

## 7. Ablation study

All 1,200 positive queries and 60 negatives were used. 10% of registered originals (6 of 60) were tampered in storage *after* registration (one byte flipped).

| Config | Recovery (top-1 correct) | Verified provenance | FPR | Tampered originals returned | Tamper detected | Mean latency (ms) |
|---|---|---|---|---|---|---|
| A — SHA-256 only | 0.050 | — | 0.00 | 6 | 0 % | 0.08 |
| B — + pHash (τ = 10) | 0.802 | — | 0.00 | 96 | 0 % | 0.08 |
| C — + ORB (K = 10, ≥ 15 inliers) | 0.910 | — | 0.00 | 111 | 0 % | 5.27 |
| **D — full TrustChain + MediaTrace** | **0.910** | **0.818** | 0.00 | 111 | **100 %** | 7.32 |

Latency excludes one-off feature extraction: pHash, and ORB at a mean 1.6 ms per image.

**Findings:**
- Each retrieval stage adds recall: A → B gives ×16, and B → C adds 11 points, all from crops.
- **Configurations A–C would silently hand an investigator 111 tampered "originals".** D detects all of them as `INTEGRITY_FAILURE` via the live storage re-hash.
- D's verified-provenance rate (0.818) is exactly the recovery rate minus the queries whose source was tampered (0.910 − 111/1200 = 0.8175).
- Full cryptographic verification adds about 2 ms per recovered candidate.

Charts: `ablation.png`, `ablation_latency.png`.

## 8. Metadata stripping: SHA-256 vs pHash

| Variant (60 originals) | SHA-256 still matches | EXIF retained | pHash mean / max distance | pHash match (τ = 10) |
|---|---|---|---|---|
| byte-level strip (pixels identical) | 0.00 | 0.00 | 0.00 / 0 | 1.00 |
| strip + re-encode Q95 | 0.00 | 0.00 | 0.03 / 2 | 1.00 |
| strip + PNG | 0.00 | 0.00 | 0.00 / 0 | 1.00 |

**Finding:** removing a few hundred bytes of metadata, without touching a single pixel, defeats exact hashing every time, while pHash is unaffected.

**C2PA note:** the synthetic originals carry EXIF but no C2PA manifest, because embedding one requires a signing certificate. APP11 (C2PA/JUMBF) removal runs through the same stripping code. The C2PA adapter itself was validated against the real `c2patool` 0.27.23 in the API container: signed with the development certificate → `VALID` (`trusted=false`); one byte flipped → `INVALID` (`assertion.dataHash.mismatch`); unsigned → `ABSENT`.

---

## End-to-end demo scenarios (live Docker stack)

The stack was postgres, MinIO (built from source), api (with c2patool 0.27.23), the witness (with its own SQLite DB) and the nginx frontend. Result: **14/14 checks passed**.

| # | Scenario | Checks | Result |
|---|---|---|---|
| 1 | **Normal recovery** — original registered; a stripped + 50%-downscaled + Q70 share is queried | search ranks the true source first (Hamming 0, no SHA match, EXIF absent); auditor `verify-candidate` → `VERIFIED_REGISTERED_ORIGINAL` / `PERCEPTUAL_CANDIDATE`; exported bundle → offline CLI with pinned keys **PASS**; CLI on the share → **FAIL** (correctly: not the original bytes) | ✅ 4/4 |
| 2 | **MinIO tampering** — attacker overwrites the stored object using bucket credentials | `verify-integrity` → FAIL (registered `e07ff4f9…` ≠ recomputed `eb7b69d0…`); `verify-candidate` → `INTEGRITY_FAILURE` (`STORAGE_SHA256`); CLI on the downloaded bytes → **FAIL** | ✅ 3/3 |
| 3 | **Witness rollback / equivocation** | replay of a genuinely signed stale checkpoint (size 10 < 11) → `ROLLBACK`; same-size forked root signed with the log key (compromised-log model) → `EQUIVOCATION`; growth with a forged consistency proof → `EQUIVOCATION`; 3 alerts persisted; the next honest checkpoint (size 12) is still `ACKNOWLEDGED` | ✅ 5/5 |
| 4 | **Negative unrelated image** | search (with ORB) → `NO_MATCH`; `verify-candidate` → `NO_MATCH` / `NONE` | ✅ 2/2 |

Also verified live:
- PostgreSQL triggers reject `UPDATE custody_events` and `DELETE FROM log_entries` (`table … is append-only`).
- A quick benchmark run triggered through `/api/v1/experiments/run`, via the nginx proxy, completed and was served to the Research page API.

## Threats to validity

- **Synthetic imagery.** The FPR = 0 results do not transfer directly to natural photo collections with near-duplicates.
- **Small gallery.** With 60 originals, the ORB top-K limitation (§3) is already visible; it worsens with gallery size.
- **Single-host latency.** Latency was measured on one host and single-threaded. Absolute numbers will vary; relative orderings were stable across runs.
- **Simulated tampering in the ablation.** Tampering in the ablation (§7) uses an in-memory TrustChain built from the production crypto modules (no PostgreSQL/MinIO). The same detection was confirmed against the real stack in demo scenario 2.
