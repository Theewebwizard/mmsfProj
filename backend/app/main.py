"""FastAPI application factory for TrustChain."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.router import router
from app.database import Base, engine
from app.storage.minio_client import init_minio_bucket


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: create DB tables and ensure MinIO bucket exists."""
    # Create all tables (convenient for testing without running Alembic)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Ensure MinIO bucket exists
    await init_minio_bucket()

    yield

    # Cleanup on shutdown (dispose connection pool)
    await engine.dispose()


def create_app() -> FastAPI:
    application = FastAPI(
        title="TrustChain API",
        version="0.1.0",
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

    return application


app = create_app()

