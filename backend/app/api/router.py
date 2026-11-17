"""Top-level API router — includes all sub-routers."""

from fastapi import APIRouter

from app.api import auth, cases, evidence

router = APIRouter()

router.include_router(auth.router, prefix="/auth", tags=["auth"])
router.include_router(cases.router, prefix="/cases", tags=["cases"])
router.include_router(evidence.router, prefix="/cases", tags=["evidence"])

