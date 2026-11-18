"""Research & benchmark routes.

Experiment runs are produced by ``experiments/run_all.py`` which writes
``<experiments_dir>/results/<run_id>/manifest.json`` plus CSV/JSON/PNG
artefacts.  This router indexes those manifests into ``experiment_runs``,
serves the artefacts, and can launch a new run as a background subprocess.
Nothing is synthesised here: every number shown comes from a real run.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.deps import get_current_user, get_db
from app.models.experiment import ExperimentRun
from app.models.user import User

router = APIRouter()

_SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]+$")
_running: dict[str, Any] = {"proc": None, "run_id": None, "started_at": None, "log": None}


def results_dir() -> Path:
    return Path(settings.experiments_dir) / "results"


def _manifest(run_id: str) -> Optional[dict[str, Any]]:
    if not _SAFE_NAME.match(run_id):
        return None
    p = results_dir() / run_id / "manifest.json"
    if not p.is_file():
        return None
    try:
        return json.loads(p.read_text())
    except json.JSONDecodeError:
        return None


async def _sync(db: AsyncSession) -> None:
    root = results_dir()
    if not root.is_dir():
        return
    known = {r.artifacts_dir for r in (await db.execute(select(ExperimentRun))).scalars()}
    for d in sorted(root.iterdir()):
        m = _manifest(d.name) if d.is_dir() else None
        if m is None or d.name in known or m.get("status") != "completed":
            continue
        db.add(
            ExperimentRun(
                id=uuid.uuid4(),
                name=m.get("name", d.name),
                config_json=json.dumps(m.get("config", {})),
                metrics_json=json.dumps(m.get("summary", {})),
                artifacts_dir=d.name,
                created_at=datetime.now(timezone.utc),
            )
        )
    await db.commit()


@router.get("")
async def list_runs(db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)) -> list[dict[str, Any]]:
    await _sync(db)
    rows = (await db.execute(select(ExperimentRun).order_by(ExperimentRun.created_at.desc()))).scalars()
    out = []
    for r in rows:
        m = _manifest(r.artifacts_dir or "") or {}
        out.append(
            {
                "id": r.artifacts_dir,
                "db_id": str(r.id),
                "name": r.name,
                "created_at": m.get("finished_at") or (r.created_at.isoformat() if r.created_at else None),
                "config": json.loads(r.config_json or "{}"),
                "summary": json.loads(r.metrics_json or "{}"),
                "benchmarks": sorted((m.get("benchmarks") or {}).keys()),
            }
        )
    return out


@router.get("/status")
async def run_status(_: User = Depends(get_current_user)) -> dict[str, Any]:
    proc = _running["proc"]
    state = "idle"
    rc = None
    if proc is not None:
        rc = proc.returncode
        state = "running" if rc is None else ("completed" if rc == 0 else "failed")
    tail = None
    if _running["log"] and Path(_running["log"]).exists():
        tail = Path(_running["log"]).read_text()[-4000:]
    return {"state": state, "run_id": _running["run_id"], "started_at": _running["started_at"], "returncode": rc, "log_tail": tail}


class RunRequest(BaseModel):
    quick: bool = True
    seed: int = 1337


@router.post("/run", status_code=status.HTTP_202_ACCEPTED)
async def start_run(body: RunRequest, _: User = Depends(get_current_user)) -> dict[str, Any]:
    proc = _running["proc"]
    if proc is not None and proc.returncode is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "an experiment run is already in progress")
    script = Path(settings.experiments_dir) / "run_all.py"
    if not script.is_file():
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, f"experiment suite not found at {script}")
    run_id = datetime.now(timezone.utc).strftime("run-%Y%m%dT%H%M%SZ")
    results_dir().mkdir(parents=True, exist_ok=True)
    log_path = results_dir() / f"{run_id}.log"
    args = [sys.executable, str(script), "--run-id", run_id, "--seed", str(body.seed)]
    if body.quick:
        args.append("--quick")
    log_fh = open(log_path, "w")
    _running.update(
        proc=await asyncio.create_subprocess_exec(*args, stdout=log_fh, stderr=asyncio.subprocess.STDOUT, env=os.environ.copy()),
        run_id=run_id,
        started_at=datetime.now(timezone.utc).isoformat(),
        log=str(log_path),
    )
    return {"state": "running", "run_id": run_id}


@router.get("/{run_id}")
async def get_run(run_id: str, _: User = Depends(get_current_user)) -> dict[str, Any]:
    m = _manifest(run_id)
    if m is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "run not found")
    return m


@router.get("/{run_id}/files/{name}")
async def get_file(run_id: str, name: str, _: User = Depends(get_current_user)) -> FileResponse:
    m = _manifest(run_id)
    if m is None or not _SAFE_NAME.match(name) or name not in (m.get("files") or []):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "file not found")
    return FileResponse(results_dir() / run_id / name, filename=name)
