
# MASTER ENGINEERING PROMPT

## PROJECT: TRUSTCHAIN + MEDIATRACE

**Resilient Multimedia Provenance: Forensic Recovery and Cryptographic Verification Under Metadata Stripping and Content Transformations**

You are acting as a principal software architect, applied cryptography engineer, and digital forensics researcher. Build a complete, research-oriented multimedia security platform called **TrustChain + MediaTrace** for a Multimedia Security and Forensics course.

Prioritize **cryptographic correctness, clean architecture, reproducible experiments, and end-to-end testability** over enterprise CRUD bloat.

---

### 1. CORE RESEARCH PROBLEM & ARCHITECTURE

Digital images lose metadata and embedded C2PA credentials when shared across social networks or messaging apps (via JPEG recompression, resizing, cropping, format conversion, brightness/contrast shifts). Because a 1-byte change alters a SHA-256 hash, exact hashing fails after transformation.

**System Modules:**

1. **TrustChain (Cryptographic Provenance):** Evidence registration, SHA-256 integrity checks, Ed25519 signed custody events, RFC 9162 Merkle transparency log, signed checkpoints, an independent Witness service (to detect log rollback/equivocation), C2PA inspection, and an offline CLI verifier.
2. **MediaTrace (Forensic Discovery):** Exact SHA-256 lookup, perceptual hashing (`pHash`), optional local-feature matching (`ORB` + RANSAC), similarity ranking, and a unified provenance recovery workflow.

**Critical Domain Invariant:** A perceptual match is **never** proof of authenticity or origin. The system must strictly separate *forensic candidate retrieval* (MediaTrace) from *cryptographic record verification* (TrustChain).

---

### 2. NON-NEGOTIABLE RULES

1. **No ML/DL training.** Use deterministic perceptual hashing (`ImageHash`) and classical computer vision (`OpenCV ORB`).
2. **No custom cryptography.** Use `PyNaCl` (Ed25519) and `hashlib` (SHA-256). Do not use a blockchain.
3. **Strict Security Semantics:**
   - SHA-256 proves byte-level integrity against a registered digest, not truth.
   - Missing C2PA (`ABSENT`) does not mean manipulated.
   - A perceptual hash match is a *candidate*, never proof of origin.
4. **Immutability:** Never overwrite uploaded media in MinIO or committed database log entries.
5. **No Mocked Data:** Never fake API responses, verification results, or research metrics. Every chart and metric must come from actual execution.
6. **Incremental Execution:** Build and test phase-by-phase. Never attempt to generate the entire codebase in one pass.

---

### 3. TECH STACK

- **Backend:** Python 3.12+, FastAPI, Pydantic v2, SQLAlchemy 2.x, Alembic, PostgreSQL, `PyNaCl`, `uvicorn`.
- **Forensics & Provenance:** `Pillow`, `opencv-python-headless`, `NumPy`, `ImageHash`, and `c2patool` (invoked via a clean Python subprocess adapter—verify binary availability in Docker).
- **Frontend:** React, TypeScript, Vite, Tailwind CSS, `shadcn/ui`, React Router, TanStack Query, `Recharts`.
- **Infrastructure:** PostgreSQL, MinIO (S3-compatible object storage), Docker Compose, `pytest`. *(No Redis, Celery, Kafka, or Kubernetes).*

---

### 4. SYSTEM COMPONENTS & MODULE SPECS

#### A. Simplified Auth & Case Management

- **Roles:** `INVESTIGATOR` (create cases, upload evidence, transfer custody, run searches) and `AUDITOR` (read-only access, run verification, export bundles).
- **Witness Identity:** Separate Ed25519 keypair and static API token for the Witness service (not a UI user).
- Standard JWT authentication (`passlib`/`bcrypt` + `PyJWT`). Enforce authorization on every FastAPI route.

#### B. Evidence Registration & Integrity

- Support `JPEG`, `PNG`, `WebP`. Validate MIME types via magic bytes; never trust client filenames for storage paths (use UUID object keys in MinIO).
- Process uploads synchronously in a clean transaction: stream to compute SHA-256 & byte size $\rightarrow$ store original in MinIO $\rightarrow$ extract EXIF & C2PA status $\rightarrow$ compute `pHash` $\rightarrow$ append `EVIDENCE_REGISTERED` event to Merkle log.
- **Integrity Check:** Re-stream object from MinIO, recompute SHA-256, compare with stored digest (`PASS` / `FAIL` / `ERROR`).

#### C. Cryptographic Chain of Custody

- **Events:** `EVIDENCE_REGISTERED`, `CUSTODY_TRANSFER_INITIATED`, `CUSTODY_TRANSFER_ACKNOWLEDGED`, `EVIDENCE_VERIFIED`, `REPORT_EXPORTED`.
- **Canonical Serialization:** Use RFC 8785 (JCS) or strict sorted-key UTF-8 JSON (`separators=(',', ':')`) before Ed25519 signing.
- Separate Ed25519 keypairs for: (1) Custody Events, (2) Log Checkpoints, and (3) Witness Acknowledgements. Load keys via environment variables/mounted files; never commit keys to Git.

#### D. RFC 9162 Merkle Transparency Log

- Implement RFC 9162 Section 2.1 exact tree hashing:
  - Leaf hash: `SHA-256(0x00 || canonical_event_bytes)`
  - Node hash: `SHA-256(0x01 || left_hash || right_hash)`
- Implement:
  - Dynamic **Inclusion Proofs** (`PATH(m, D[n])`) for any log index.
  - Dynamic **Consistency Proofs** (`PROOF(m, D[n])`) between any two tree sizes.
  - **Signed Tree Heads (Checkpoints):** `{log_id, tree_size, root_hash, timestamp, key_id, signature}`.
- Validate your tree implementation directly against RFC 9162 test vectors in `pytest`.

#### E. Independent Witness Service

- Deployed as a **separate container/process** with its own SQLite/PostgreSQL state and Ed25519 key.
- **Endpoints:** `POST /witness/checkpoint` (accepts a signed checkpoint + consistency proof from the primary server).
- **Verification Logic:** Verify primary log's Ed25519 signature $\rightarrow$ reject if `new_tree_size < last_seen_size` (rollback attack) $\rightarrow$ verify RFC 9162 consistency proof against `last_seen_root` (equivocation/split-view attack) $\rightarrow$ persist checkpoint and return a Witness-signed acknowledgement (or record a security alert on failure).

#### F. C2PA Provenance Adapter

- Wrap `c2patool` via Python `subprocess` with timeouts and safe path handling.
- Normalize output into: `VALID`, `INVALID`, `ABSENT`, `ERROR`. Extract signer CN/issuer and assertion titles when present.

#### G. MediaTrace Forensic Engine & Recovery Workflow

- **Step 1 (Exact Match):** Check SHA-256 in database.
- **Step 2 (Perceptual Search):** Compute `pHash` (64-bit DCT hash) and rank registered evidence by Hamming distance. Support configurable distance thresholds.
- **Step 3 (Optional ORB Matching):** Compute OpenCV ORB keypoints/descriptors + Lowe's ratio test + RANSAC homography inlier count to detect cropped/partial overlaps.
- **Step 4 (Provenance Recovery):** When an investigator selects a candidate match, TrustChain verifies the candidate's original MinIO file hash, event signatures, Merkle inclusion proof, and Witness checkpoint.
- **Final Recovery States:** `VERIFIED_REGISTERED_ORIGINAL`, `CANDIDATE_ONLY`, `INTEGRITY_FAILURE`, `NO_MATCH`.

#### H. Offline CLI Verifier (`trustchain-verify`)

- Standalone Python CLI script (`python -m trustchain_verify verify --file <img_path> --bundle <bundle.json>`).
- Must **never** call the backend API. Independently verifies:
  1. File SHA-256 vs. bundle's registered digest.
  2. Ed25519 signatures on all custody events.
  3. RFC 9162 Merkle inclusion proof against the checkpoint root.
  4. Log checkpoint signature + consistency proof.
  5. Witness counter-signature.
- Outputs `PASS`, `FAIL`, or `INCONCLUSIVE` per check and overall.

#### I. Reproducible Research & Evaluation Suite (`experiments/`)

- Include a deterministic synthetic dataset generator (base images + controlled transformations: JPEG Q=90/70/50/30, resize 75%/50%/25%, center/random crops 80%/60%, brightness/contrast shifts, EXIF/C2PA stripping, plus unrelated negative images) with fixed random seeds.
- Run and export CSV/JSON + Matplotlib PNG charts for:
  1. **Retrieval Accuracy:** Precision@1, Recall@5, False-Positive Rate across transformation types and Hamming thresholds.
  2. **Cropping Resilience:** pHash vs. pHash + ORB inlier verification.
  3. **Cryptographic & Witness Overhead:** Latency of SHA-256, Ed25519, Merkle proof generation/verification, and Witness rollback/equivocation detection rate.
  4. **Ablation Study:** (A) SHA-256 only vs. (B) SHA-256 + pHash vs. (C) SHA-256 + pHash + ORB vs. (D) Full TrustChain + MediaTrace.

---

### 5. DATABASE SCHEMA (9 CORE TABLES)

Use PostgreSQL + SQLAlchemy + Alembic (`UUID` primary keys, UTC timestamps):

1. `users` (`id`, `email`, `password_hash`, `full_name`, `role`, `created_at`)
2. `cases` (`id`, `title`, `description`, `created_by`, `status`, `created_at`)
3. `evidence` (`id`, `case_id`, `original_filename`, `storage_key`, `sha256_digest`, `file_size`, `mime_type`, `phash`, `c2pa_status`, `c2pa_summary_json`, `uploaded_by`, `created_at`)
4. `custody_events` (`id`, `evidence_id`, `actor_id`, `event_type`, `payload_json`, `canonical_bytes`, `signature`, `key_id`, `log_index`, `created_at`)
5. `log_entries` (`index` [serial/bigint], `event_id`, `leaf_hash`, `created_at`)
6. `log_checkpoints` (`id`, `tree_size`, `root_hash`, `signature`, `key_id`, `witness_ack_signature`, `witness_timestamp`, `created_at`)
7. `witness_checkpoints` *(in Witness DB)* (`id`, `tree_size`, `root_hash`, `log_signature`, `witness_signature`, `status`, `alert_reason`, `created_at`)
8. `experiment_runs` (`id`, `name`, `config_json`, `metrics_json`, `artifacts_dir`, `created_at`)

---

### 6. STREAMLINED FRONTEND (4 FOCUSED VIEWS)

Build a clean, dark/light-mode enterprise forensics UI with `shadcn/ui` and Tailwind CSS (no decorative fluff):

1. **Vault & Cases (`/cases`):** Case selector/creator, evidence upload dropzone (shows live SHA-256, C2PA badge, and Merkle log index upon upload), and evidence table.
2. **Evidence Inspector (`/evidence/:id`):** Image preview, metadata/EXIF & C2PA panel, "Verify Byte Integrity" button (triggers live MinIO re-hash), chronological Custody Timeline with Ed25519 verification badges, Merkle Inclusion Proof inspector, and "Export Verification Bundle (JSON)" button.
3. **MediaTrace & Provenance Recovery (`/trace`):** Upload a stripped/transformed query image $\rightarrow$ configure search mode (Exact, pHash threshold, ORB toggle) $\rightarrow$ view ranked candidates with side-by-side comparison and Hamming distance $\rightarrow$ click "Verify Candidate Provenance" to run the full TrustChain cryptographic check and display the final assessment banner.
4. **Research & Benchmarks (`/research`):** Trigger or inspect reproducible experiment runs, view interactive `Recharts` plots (ROC/threshold curves, ablation comparison, latency breakdown), and download CSV results.

---

### 7. TEAM DIVISION (3 STUDENTS)

Structure the repository cleanly into isolated packages:

- **`backend/app/crypto/` & `cli/` (Member 1):** Canonical JSON, Ed25519 keys/signing, RFC 9162 Merkle tree + proofs, C2PA adapter, `trustchain-verify` CLI.
- **`backend/app/api/` & `witness/` (Member 2):** FastAPI endpoints, PostgreSQL/Alembic models, MinIO storage service, JWT auth, Custody transfer workflows, standalone Witness service.
- **`backend/app/mediatrace/`, `experiments/`, & `frontend/` (Member 3):** `pHash` + `ORB` engine, image transformation pipeline, benchmark scripts, 4-page React + `shadcn/ui` application.

---

### 8. EXECUTION ROADMAP (WORK PHASE BY PHASE)

Execute **one phase at a time**. After each phase, list modified files, run `pytest` (or build checks), report actual test outputs, and wait for confirmation before starting the next phase:

- **Phase 1 — Foundation:** Repo structure, Docker Compose (`api`, `witness`, `postgres`, `minio`), Alembic migrations, JWT auth, Case & Evidence upload/download with SHA-256 + MinIO.
- **Phase 2 — Cryptography, Merkle Log & Witness:** Canonical JSON, Ed25519 custody events, RFC 9162 Merkle tree (with RFC test vectors), Witness service (with rollback & equivocation tests), and `trustchain-verify` offline CLI.
- **Phase 3 — C2PA & MediaTrace Engine:** `c2patool` adapter, `pHash` indexing/search, `ORB` geometric verification, and unified Provenance Recovery endpoint.
- **Phase 4 — Frontend Application:** Build the 4 React views wired to live API endpoints, including bundle export and interactive recovery workflow.
- **Phase 5 — Research Experiments & Documentation:** Run the 8 reproducible benchmarks, generate CSVs/charts, verify all 4 end-to-end demo scenarios (normal recovery, MinIO file tampering detection, Witness rollback detection, negative unrelated image), and finalize `README.md`, `docs/architecture-and-threat-model.md`, and `docs/research-evaluation.md`.
