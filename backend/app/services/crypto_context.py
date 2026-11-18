"""Process-wide signing keys for the primary TrustChain server."""

from __future__ import annotations

from functools import lru_cache

from app.config import settings
from app.crypto.keys import Signer, load_public_key, load_signer


@lru_cache(maxsize=1)
def custody_signer() -> Signer:
    return load_signer("custody", settings.key_dir, settings.allow_key_generation)


@lru_cache(maxsize=1)
def checkpoint_signer() -> Signer:
    return load_signer("checkpoint", settings.key_dir, settings.allow_key_generation)


def pinned_witness_public_key() -> str | None:
    """Witness public key pinned by the operator (file or env), if any."""
    return load_public_key("witness", settings.key_dir)


def reset_cache() -> None:
    custody_signer.cache_clear()
    checkpoint_signer.cache_clear()
