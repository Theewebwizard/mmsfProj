#!/usr/bin/env python3
"""Generate the three independent Ed25519 keypairs and lay them out for Docker.

    keys/api/custody_ed25519.key        (secret, api only)
    keys/api/checkpoint_ed25519.key     (secret, api only)
    keys/api/witness_ed25519.pub        (witness public key, pinned by the api)
    keys/witness/witness_ed25519.key    (secret, witness only)
    keys/witness/checkpoint_ed25519.pub (log public key, pinned by the witness)
    keys/public.json                    (all public keys, for offline auditors)

`keys/` is git-ignored.  Existing keys are never overwritten (use --force).
"""

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

from nacl.signing import SigningKey


def write(path: Path, text: str, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w") as fh:
        fh.write(text + "\n")
    os.chmod(path, mode)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(Path(__file__).resolve().parent.parent / "keys"))
    ap.add_argument("--force", action="store_true")
    args = ap.parse_args()
    out = Path(args.out)
    if (out / "api" / "custody_ed25519.key").exists() and not args.force:
        print(f"keys already exist in {out} (use --force to replace)")
        return 0

    keys = {p: SigningKey.generate() for p in ("custody", "checkpoint", "witness")}
    pub = {p: bytes(k.verify_key).hex() for p, k in keys.items()}

    write(out / "api" / "custody_ed25519.key", bytes(keys["custody"]).hex(), 0o600)
    write(out / "api" / "checkpoint_ed25519.key", bytes(keys["checkpoint"]).hex(), 0o600)
    write(out / "api" / "witness_ed25519.pub", pub["witness"], 0o644)
    write(out / "witness" / "witness_ed25519.key", bytes(keys["witness"]).hex(), 0o600)
    write(out / "witness" / "checkpoint_ed25519.pub", pub["checkpoint"], 0o644)
    write(
        out / "public.json",
        json.dumps(
            {p: {"public_key": h, "key_id": hashlib.sha256(bytes.fromhex(h)).hexdigest()[:16]} for p, h in pub.items()},
            indent=2,
        ),
        0o644,
    )
    print(f"wrote Ed25519 keys to {out}")
    for p, h in pub.items():
        print(f"  {p:<10} key_id={hashlib.sha256(bytes.fromhex(h)).hexdigest()[:16]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
