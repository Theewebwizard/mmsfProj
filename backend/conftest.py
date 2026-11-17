import os
import io
import pytest
import pytest_asyncio
from unittest.mock import patch
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from app.main import app
from app.database import Base
from app import deps
from app.storage.minio_client import MinIOClient, minio_client

TEST_DB_URL = "sqlite+aiosqlite:///./test.db"

# In-memory store for mocked MinIO
mock_storage = {}


async def _mock_put_object(*args, **kwargs):
    if len(args) == 4:
        _, object_key, data, _ = args
    elif len(args) == 3:
        object_key, data, _ = args
    else:
        object_key = kwargs.get("object_key")
        data = kwargs.get("data")
    mock_storage[object_key] = data


async def _mock_get_object_bytes(*args, **kwargs):
    if len(args) >= 2:
        _, object_key = args[:2]
    elif len(args) == 1:
        object_key = args[0]
    else:
        object_key = kwargs.get("object_key")
    if object_key in mock_storage:
        return mock_storage[object_key]
    raise Exception(f"Key {object_key} not found in mock storage")


async def _mock_ensure_bucket(*args, **kwargs):
    pass


async def _mock_get_presigned_url(*args, **kwargs):
    if len(args) >= 2:
        object_key = args[1]
    elif len(args) == 1:
        object_key = args[0]
    else:
        object_key = kwargs.get("object_key")
    return f"http://mock-minio/{object_key}"


@pytest_asyncio.fixture(scope="function")
async def db_engine():
    engine = create_async_engine(TEST_DB_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()
    if os.path.exists("./test.db"):
        try:
            os.remove("./test.db")
        except OSError:
            pass


@pytest_asyncio.fixture(scope="function")
async def db_session(db_engine):
    session_factory = async_sessionmaker(db_engine, expire_on_commit=False)
    async with session_factory() as session:
        yield session


@pytest_asyncio.fixture(scope="function")
async def client(db_session, monkeypatch):
    mock_storage.clear()

    # Monkeypatch MinIOClient methods
    monkeypatch.setattr(MinIOClient, "put_object", _mock_put_object)
    monkeypatch.setattr(MinIOClient, "get_object_bytes", _mock_get_object_bytes)
    monkeypatch.setattr(MinIOClient, "ensure_bucket", _mock_ensure_bucket)
    monkeypatch.setattr(MinIOClient, "get_presigned_url", _mock_get_presigned_url)

    # Also patch minio_client instance methods
    monkeypatch.setattr(minio_client, "put_object", _mock_put_object)
    monkeypatch.setattr(minio_client, "get_object_bytes", _mock_get_object_bytes)
    monkeypatch.setattr(minio_client, "ensure_bucket", _mock_ensure_bucket)
    monkeypatch.setattr(minio_client, "get_presigned_url", _mock_get_presigned_url)

    # Override get_db dependency
    async def override_get_db():
        yield db_session

    app.dependency_overrides[deps.get_db] = override_get_db

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        yield ac

    app.dependency_overrides.clear()
