"""Ed25519 key management (PyNaCl).

Three independent key purposes exist in the system:
  * ``custody``    — signs custody events (primary server)
  * ``checkpoint`` — signs Signed Tree Heads (primary server)
  * ``witness``    — signs witness acknowledgements (witness service only)

Key material is a 32-byte Ed25519 seed. Resolution order for a purpose P:
  1. env var ``TRUSTCHAIN_<P>_KEY`` (hex seed);
  2. file ``<KEY_DIR>/<p>_ed25519.key`` (hex seed);
  3. if ``allow_generate`` — generate a fresh seed and persist it to (2)
     with mode 0600.  Keys are never written anywhere else.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey


def key_id_for(public_key: bytes) -> str:
    """Stable short identifier: first 16 hex chars of SHA-256(public key)."""
    return hashlib.sha256(public_key).hexdigest()[:16]


@dataclass(frozen=True)
class Signer:
    purpose: str
    signing_key: SigningKey

    @property
    def public_key(self) -> bytes:
        return bytes(self.signing_key.verify_key)

    @property
    def public_key_hex(self) -> str:
        return self.public_key.hex()

    @property
    def key_id(self) -> str:
        return key_id_for(self.public_key)

    def sign(self, message: bytes) -> str:
        """Return the detached Ed25519 signature as hex."""
        return self.signing_key.sign(message).signature.hex()


def verify_signature(public_key_hex: str, message: bytes, signature_hex: str) -> bool:
    try:
        VerifyKey(bytes.fromhex(public_key_hex)).verify(message, bytes.fromhex(signature_hex))
        return True
    except (BadSignatureError, ValueError, TypeError):
        return False


def load_signer(purpose: str, key_dir: str | Path, allow_generate: bool = True) -> Signer:
    env_val = os.environ.get(f"TRUSTCHAIN_{purpose.upper()}_KEY")
    if env_val:
        return Signer(purpose, SigningKey(bytes.fromhex(env_val.strip())))

    path = Path(key_dir) / f"{purpose}_ed25519.key"
    if path.exists():
        return Signer(purpose, SigningKey(bytes.fromhex(path.read_text().strip())))

    if not allow_generate:
        raise FileNotFoundError(f"No Ed25519 key for purpose '{purpose}' at {path}")

    sk = SigningKey.generate()
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(bytes(sk).hex())
    return Signer(purpose, sk)


def load_public_key(purpose: str, key_dir: str | Path) -> str | None:
    """Load a *pinned* public key (hex) for a remote party, if configured.

    env ``TRUSTCHAIN_<P>_PUBKEY`` or file ``<KEY_DIR>/<p>_ed25519.pub``.
    """
    env_val = os.environ.get(f"TRUSTCHAIN_{purpose.upper()}_PUBKEY")
    if env_val:
        return env_val.strip()
    path = Path(key_dir) / f"{purpose}_ed25519.pub"
    if path.exists():
        return path.read_text().strip()
    return None
