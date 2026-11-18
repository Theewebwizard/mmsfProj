# TrustChain + MediaTrace

**Resilient Multimedia Provenance: Forensic Recovery and Cryptographic Verification Under Metadata Stripping and Content Transformations**

A research platform built for a Multimedia Security and Forensics course. It has two modules:

- **TrustChain** — cryptographic provenance:
  - SHA-256 integrity checks
  - Ed25519-signed custody events
  - an RFC 9162 Merkle transparency log with signed checkpoints
  - an independent **Witness** service that detects rollback and equivocation
  - C2PA inspection
  - an offline CLI verifier
- **MediaTrace** — forensic discovery: exact SHA-256 lookup, pHash ranking, ORB + RANSAC confirmation for crops, and a unified provenance-recovery workflow.

> **Domain invariant:** a perceptual match is a *candidate*, never proof of origin. SHA-256 proves byte integrity against a registered digest, not truth. A missing C2PA manifest (`ABSENT`) does not mean the image was manipulated.

## Documentation

- [Architecture and threat model](docs/architecture-and-threat-model.md)
- [Research evaluation](docs/research-evaluation.md) — the eight benchmarks and four end-to-end demo scenarios, with measured results

## Repository layout

```
backend/            FastAPI + SQLAlchemy (async) + Alembic
  app/crypto/       canonical JSON, Ed25519 keys, RFC 9162 Merkle tree, statements, C2PA adapter
  app/services/     transparency log + witness client, verification, bundle export
  app/mediatrace/   pHash, ORB/RANSAC, ranking engine, EXIF / metadata stripping
  app/api/          auth, cases, evidence, /evidence/{id} ops, /log, /trace, /experiments
  alembic/          0001 schema, 0002 log fields + append-only triggers
witness/            independent Witness service (own key, own SQLite DB, own verifier code)
cli/                trustchain-verify offline verifier (PyNaCl + stdlib only)
frontend/           React + TS + Vite + Tailwind + shadcn-style UI + TanStack Query + Recharts
experiments/        seeded dataset, 8 benchmarks (run_all.py), live demo (demo_scenarios.py)
infra/minio/        MinIO built from its official source tag (upstream images/binaries are discontinued)
scripts/            generate_keys.py
```

## Quick start (Docker)

```bash
python3 -m pip install pynacl            # only needed for the key script
python3 scripts/generate_keys.py         # writes ./keys (git-ignored), never commit it
docker compose up -d --build
```

| Service | URL |
|---|---|
| UI | http://localhost:8080 |
| API + OpenAPI docs | http://localhost:8000/docs |
| Witness | http://localhost:8001/docs |
| MinIO console | http://localhost:9001 (minioadmin / minioadmin) |

On start, the API container runs `alembic upgrade head`. The API image installs `c2patool` v0.27.23.

1. Register an **Investigator** account in the UI to create cases, upload evidence, transfer custody and search.
2. Register an **Auditor** account for read-only access, verification and bundle export.

The first build compiles MinIO from source, which takes a few minutes: upstream MinIO has archived the community edition and no longer publishes images or binaries.

## Development

```bash
python3 -m venv .venv && .venv/bin/pip install -r backend/requirements.txt -r witness/requirements.txt
(cd backend && ../.venv/bin/pytest -q)     # 78 tests: crypto, RFC vectors, API, witness integration, CLI, MediaTrace
(cd witness && ../.venv/bin/pytest -q)     # 9 tests: rollback / equivocation / signature / auth
(cd frontend && npm install && npm run dev)   # http://localhost:5173, proxies /api -> :8000
```

The backend tests run against SQLite and an in-memory object store. The **real Witness app runs in-process** through an ASGI transport, so every checkpoint in the tests is actually witnessed.

## Offline verification

```bash
# in the UI: Evidence Inspector -> "Export Verification Bundle (JSON)"
cd cli
python -m trustchain_verify verify --file original.jpg --bundle trustchain-bundle-<id>.json \
    --log-key <checkpoint pubkey> --custody-key <custody pubkey> --witness-key <witness pubkey>
# public keys: keys/public.json   exit codes: 0 PASS, 1 FAIL, 3 INCONCLUSIVE
```

The CLI never contacts the API. It checks five things:

1. The file's SHA-256 against the signed registration event.
2. Every custody-event signature and the per-evidence hash chain.
3. RFC 9162 inclusion of every event in the checkpoint.
4. The checkpoint signature, plus consistency from the first witnessed checkpoint.
5. The witness co-signatures.

## Experiments

```bash
.venv/bin/python experiments/run_all.py              # full: 60 originals x 20 transforms + 60 negatives (~1 min)
.venv/bin/python experiments/run_all.py --quick      # 20 + 20 (~30 s); also triggerable from /research
.venv/bin/python experiments/demo_scenarios.py       # 4 end-to-end scenarios against the running stack
```

Results go to `experiments/results/<run-id>/`: `manifest.json`, CSV files and Matplotlib PNG charts. The same data is shown as interactive Recharts plots on the `/research` page. Datasets are regenerated from the seed on each run; timing numbers are real measurements from the host that ran them.

## Development phases

| Phase | Scope | Status |
|---|---|---|
| 1 | Foundation: repo, Docker, Alembic, JWT auth, evidence upload with SHA-256 + MinIO | ✅ |
| 2 | Canonical JSON, Ed25519 custody events, RFC 9162 log (RFC test vectors), Witness, offline CLI | ✅ |
| 3 | C2PA adapter, pHash search, ORB/RANSAC, provenance-recovery endpoint | ✅ |
| 4 | Frontend: 4 views wired to the live API | ✅ |
| 5 | 8 benchmarks, 4 end-to-end demo scenarios, documentation | ✅ |

## Team

- **Member 1:** `backend/app/crypto/` + `cli/`
- **Member 2:** `backend/app/api/` + `witness/`
- **Member 3:** `backend/app/mediatrace/` + `experiments/` + `frontend/`

## Security notes

- Never commit `keys/`, `.env` files or secrets. In Docker, keys are mounted read-only, and key auto-generation is disabled in the compose file.
- The default credentials in `docker-compose.yml` (Postgres, MinIO, JWT secret, witness token) are for local development only.
