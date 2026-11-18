import os
import sys
import tempfile
from pathlib import Path

# --- deterministic, throw-away test keys (never used outside the test suite) ---
_TEST_KEY_DIR = tempfile.mkdtemp(prefix="tc-test-keys-")
os.environ["KEY_DIR"] = _TEST_KEY_DIR
os.environ["TRUSTCHAIN_CUSTODY_KEY"] = "01" * 32
os.environ["TRUSTCHAIN_CHECKPOINT_KEY"] = "02" * 32
os.environ["TRUSTCHAIN_WITNESS_KEY"] = "03" * 32
os.environ["WITNESS_KEY_DIR"] = _TEST_KEY_DIR
os.environ["EXPERIMENTS_DIR"] = tempfile.mkdtemp(prefix="tc-test-exp-")

from nacl.signing import SigningKey  # noqa: E402

os.environ["TRUSTCHAIN_CHECKPOINT_PUBKEY"] = bytes(SigningKey(bytes.fromhex("02" * 32)).verify_key).hex()

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "witness"))
sys.path.insert(0, str(REPO_ROOT / "cli"))

import pytest  # noqa: E402
import pytest_asyncio  # noqa: E402
import httpx  # noqa: E402
from httpx import AsyncClient, ASGITransport  # noqa: E402
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession  # noqa: E402

from app.main import app  # noqa: E402
from app.database import Base  # noqa: E402
from app import deps  # noqa: E402
from app.storage.minio_client import MinIOClient, minio_client  # noqa: E402
from app.services.witness_client import witness_client  # noqa: E402

from witness_service import main as witness_main  # noqa: E402
from witness_service.db import init_db as witness_init_db  # noqa: E402

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
async def witness(tmp_path):
    """The real Witness service, in-process, with its own SQLite database."""
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path}/witness.db")
    await witness_init_db(engine)
    factory = async_sessionmaker(engine, expire_on_commit=False)

    async def override():
        async with factory() as s:
            yield s

    witness_main.app.dependency_overrides[witness_main.get_session] = override
    witness_main.witness_key.cache_clear()
    witness_client.transport = ASGITransport(app=witness_main.app)
    witness_client.base_url = "http://witness"
    yield witness_main.app
    witness_client.transport = None
    witness_client.base_url = None
    witness_main.app.dependency_overrides.clear()
    await engine.dispose()


class _DownTransport(httpx.AsyncBaseTransport):
    async def handle_async_request(self, request):
        raise httpx.ConnectError("witness down (test)")


@pytest.fixture
def witness_down():
    prev = witness_client.transport
    witness_client.transport = _DownTransport()
    yield
    witness_client.transport = prev


@pytest_asyncio.fixture(scope="function")
async def client(db_session, monkeypatch, witness):
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
