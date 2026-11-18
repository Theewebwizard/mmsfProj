"""FastAPI application factory for TrustChain."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.router import router
from app.database import Base, engine
from app.config import settings
from app.services.crypto_context import checkpoint_signer, custody_signer
from app.storage.minio_client import init_minio_bucket


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: create DB tables and ensure MinIO bucket exists."""
    # Production schema is managed by Alembic (`alembic upgrade head`).
    # AUTO_CREATE_TABLES=true is a convenience for local SQLite development.
    if settings.auto_create_tables:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    # Load (or, in dev, generate) signing keys at startup so failures are loud.
    custody_signer()
    checkpoint_signer()

    # Ensure MinIO bucket exists
    await init_minio_bucket()

    yield

    # Cleanup on shutdown (dispose connection pool)
    await engine.dispose()


def create_app() -> FastAPI:
    application = FastAPI(
        title="TrustChain API",
        version="1.0.0",
        description=(
            "Cryptographic evidence provenance and multimedia forensic discovery platform."
        ),
        lifespan=lifespan,
    )

    # CORS — allow all origins in development; tighten in production
    application.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Mount versioned API router
    application.include_router(router, prefix="/api/v1")

    @application.get("/health", tags=["health"])
    async def health() -> dict:
        return {"status": "ok"}

    return application


app = create_app()

