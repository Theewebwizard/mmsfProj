from __future__ import annotations

import os
from pathlib import Path

from nacl.signing import SigningKey
from pydantic_settings import BaseSettings, SettingsConfigDict


class WitnessSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # The witness keeps its OWN state, separate from the primary database.
    witness_db_url: str = "sqlite+aiosqlite:///./witness.db"
    witness_token: str = "witness_secret_token_change_me"
    witness_key_dir: str = "/run/keys"
    witness_allow_key_generation: bool = True
    # Pinned primary-log identity.
    witness_log_id: str | None = "trustchain-log-v1"


settings = WitnessSettings()


def load_witness_signing_key() -> SigningKey:
    env_val = os.environ.get("TRUSTCHAIN_WITNESS_KEY")
    if env_val:
        return SigningKey(bytes.fromhex(env_val.strip()))
    path = Path(settings.witness_key_dir) / "witness_ed25519.key"
    if path.exists():
        return SigningKey(bytes.fromhex(path.read_text().strip()))
    if not settings.witness_allow_key_generation:
        raise FileNotFoundError(f"witness key not found at {path}")
    sk = SigningKey.generate()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(bytes(sk).hex())
    return sk


def load_log_public_key() -> str | None:
    """The primary log's checkpoint public key, pinned out-of-band."""
    env_val = os.environ.get("TRUSTCHAIN_CHECKPOINT_PUBKEY")
    if env_val:
        return env_val.strip()
    path = Path(settings.witness_key_dir) / "checkpoint_ed25519.pub"
    if path.exists():
        return path.read_text().strip()
    return None
