"""MinIO object storage wrapper.

Provides async-compatible helpers for uploading, downloading, and
managing objects in a MinIO (S3-compatible) bucket.

All synchronous minio-py SDK calls are offloaded via asyncio.to_thread()
to avoid blocking the event loop.
"""

import asyncio
import io
import logging
from datetime import timedelta

from minio import Minio
from minio.error import S3Error

from app.config import settings

logger = logging.getLogger(__name__)


class MinIOClient:
    """Thin async wrapper around the synchronous minio-py SDK."""

    def __init__(self) -> None:
        self._client = Minio(
            settings.minio_endpoint,
            access_key=settings.minio_access_key,
            secret_key=settings.minio_secret_key,
            secure=settings.minio_secure,
        )

    async def ensure_bucket(self) -> None:
        """Check if the configured bucket exists; create it if not.

        Uses asyncio.to_thread() to avoid blocking the event loop.
        """
        def _sync_ensure() -> None:
            if not self._client.bucket_exists(settings.minio_bucket):
                self._client.make_bucket(settings.minio_bucket)

        await asyncio.to_thread(_sync_ensure)

    async def put_object(
        self,
        object_key: str,
        data: bytes,
        content_type: str,
    ) -> None:
        """Upload raw bytes to MinIO under *object_key*.

        Args:
            object_key:   The MinIO object name (UUID-based, never from client input).
            data:         Raw file bytes.
            content_type: MIME type string, e.g. "image/jpeg".
        """
        def _sync_put() -> None:
            self._client.put_object(
                settings.minio_bucket,
                object_key,
                io.BytesIO(data),
                length=len(data),
                content_type=content_type,
            )

        await asyncio.to_thread(_sync_put)

    async def get_object_bytes(self, object_key: str) -> bytes:
        """Download an object from MinIO and return its raw bytes.

        Args:
            object_key: The MinIO object name.

        Returns:
            Raw bytes of the stored object.

        Raises:
            S3Error: Propagated from minio-py on any storage error.
        """
        def _sync_get() -> bytes:
            response = self._client.get_object(settings.minio_bucket, object_key)
            try:
                return response.read()
            finally:
                response.close()
                response.release_conn()

        return await asyncio.to_thread(_sync_get)

    async def get_presigned_url(
        self,
        object_key: str,
        expires_hours: int = 1,
    ) -> str:
        """Generate a presigned GET URL for the given object.

        Args:
            object_key:    The MinIO object name.
            expires_hours: How long the URL remains valid (default 1 h).

        Returns:
            Presigned URL string.
        """
        def _sync_presign() -> str:
            return self._client.presigned_get_object(
                settings.minio_bucket,
                object_key,
                expires=timedelta(hours=expires_hours),
            )

        return await asyncio.to_thread(_sync_presign)


# Module-level singleton — imported by API routes and the FastAPI lifespan.
minio_client = MinIOClient()


async def init_minio_bucket() -> None:
    """Ensure the configured MinIO bucket exists.

    Called from the FastAPI lifespan context on startup.
    Errors are logged but do not crash the server (MinIO may not yet be healthy).
    """
    try:
        await minio_client.ensure_bucket()
    except Exception as exc:
        logger.warning("MinIO bucket init warning: %s", exc)
