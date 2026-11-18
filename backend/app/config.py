"""Application settings via pydantic-settings."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Database
    database_url: str = "postgresql+asyncpg://trustchain:trustchain@localhost:5432/trustchain"

    # MinIO / Object Storage
    minio_endpoint: str = "localhost:9000"
    minio_access_key: str = "minioadmin"
    minio_secret_key: str = "minioadmin"
    minio_bucket: str = "trustchain-evidence"
    minio_secure: bool = False

    # JWT
    jwt_secret: str = "change_me_in_production_min_32_chars_long"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60

    # Keys directory (Ed25519 key files)
    key_dir: str = "/app/keys"
    allow_key_generation: bool = True
    auto_create_tables: bool = False

    # Transparency log
    log_id: str = "trustchain-log-v1"
    auto_checkpoint: bool = True

    # Witness service
    witness_url: str = "http://witness:8001"
    witness_token: str = "witness_secret_token_change_me"
    witness_timeout_seconds: float = 5.0

    # C2PA
    c2patool_path: str = "c2patool"
    c2patool_timeout_seconds: float = 20.0

    # Research experiments (results are read from <experiments_dir>/results)
    experiments_dir: str = "/experiments"


settings = Settings()

