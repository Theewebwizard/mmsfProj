"""Storage package — MinIO client wrapper."""

from app.storage.minio_client import MinIOClient, init_minio_bucket

__all__ = ["MinIOClient", "init_minio_bucket"]

