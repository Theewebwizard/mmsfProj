# TrustChain + MediaTrace

**Resilient Multimedia Provenance: Forensic Recovery and Cryptographic Verification Under Metadata Stripping and Content Transformations**

A research-oriented multimedia security platform built for a Multimedia Security and Forensics course.

---

## Overview

TrustChain + MediaTrace is a two-module system:

1. **TrustChain** — Cryptographic evidence provenance: SHA-256 integrity, Ed25519 custody events, RFC 9162 Merkle transparency log, signed checkpoints, an independent Witness service, and an offline CLI verifier.
2. **MediaTrace** — Forensic discovery engine: exact SHA-256 lookup, perceptual hashing (pHash), optional ORB + RANSAC geometric matching, and a unified provenance recovery workflow.

---

## Architecture

```
mmsfProj/
├── backend/          # FastAPI + SQLAlchemy + Alembic (Python 3.12)
│   ├── app/
│   │   ├── api/      # REST endpoints (auth, cases, evidence)
│   │   ├── crypto/   # Ed25519, Merkle tree, C2PA adapter
│   │   ├── mediatrace/ # pHash + ORB engine
│   │   └── storage/  # MinIO client wrapper
│   └── alembic/      # DB migrations
├── witness/          # Independent Witness microservice
├── cli/              # Offline trustchain-verify CLI
├── frontend/         # React + TypeScript + Vite + Tailwind
├── experiments/      # Reproducible research benchmarks
└── docker-compose.yml
```

---

## Quick Start

```bash
# 1. Copy and configure environment
cp backend/.env.example backend/.env
# Edit backend/.env with your secrets

# 2. Start all services
docker compose up --build

# 3. API available at http://localhost:8000
# 4. MinIO console at http://localhost:9001
# 5. Witness service at http://localhost:8001
```

---

## Development Phases

| Phase | Scope | Status |
|-------|-------|--------|
| 1 | Foundation: repo structure, Docker, JWT auth, Evidence upload/SHA-256 | 🔧 In Progress |
| 2 | Cryptography: Ed25519, RFC 9162 Merkle log, Witness service, CLI | ⏳ Pending |
| 3 | C2PA adapter, pHash, ORB matching, Provenance Recovery | ⏳ Pending |
| 4 | Frontend: 4 React views | ⏳ Pending |
| 5 | Research experiments, benchmarks, documentation | ⏳ Pending |

---

## Team

- **Member 1:** `backend/app/crypto/` + `cli/` — Ed25519, Merkle tree, C2PA, CLI verifier
- **Member 2:** `backend/app/api/` + `witness/` — FastAPI endpoints, auth, MinIO, Witness service
- **Member 3:** `backend/app/mediatrace/` + `experiments/` + `frontend/` — pHash, ORB, benchmarks, React UI

---

## Tech Stack

- **Backend:** Python 3.12, FastAPI, Pydantic v2, SQLAlchemy 2.x (async), Alembic, PostgreSQL
- **Cryptography:** PyNaCl (Ed25519), hashlib (SHA-256)
- **Forensics:** Pillow, ImageHash (pHash), opencv-python-headless (ORB/RANSAC)
- **Storage:** MinIO (S3-compatible)
- **Frontend:** React, TypeScript, Vite, Tailwind CSS, shadcn/ui, TanStack Query, Recharts
- **Infrastructure:** Docker Compose, pytest

---

## Security Notes

> **Never** commit cryptographic keys, `.env` files, or secrets to this repository.
> All key material lives in mounted Docker volumes (`/app/keys`).

