"""Top-level API router — includes all sub-routers."""

from fastapi import APIRouter

from app.api import auth, cases, evidence, evidence_ops, log, trace, experiments

router = APIRouter()

router.include_router(auth.router, prefix="/auth", tags=["auth"])
router.include_router(cases.router, prefix="/cases", tags=["cases"])
router.include_router(evidence.router, prefix="/cases", tags=["evidence"])
router.include_router(evidence_ops.router, prefix="/evidence", tags=["evidence"])
router.include_router(log.router, prefix="/log", tags=["transparency-log"])
router.include_router(trace.router, prefix="/trace", tags=["mediatrace"])
router.include_router(experiments.router, prefix="/experiments", tags=["research"])
