"""trustchain-verify — Offline CLI verifier for TrustChain evidence bundles.

Usage:
    python -m trustchain_verify verify --file <img_path> --bundle <bundle.json>

This tool NEVER calls the backend API. It independently verifies:
  1. File SHA-256 vs. the bundle's registered digest.
  2. Ed25519 signatures on all custody events.
  3. RFC 9162 Merkle inclusion proof against the checkpoint root.
  4. Log checkpoint signature + consistency proof.
  5. Witness counter-signature.

Output per check: PASS | FAIL | INCONCLUSIVE
Overall result:   PASS | FAIL | INCONCLUSIVE

Business logic implemented in Phase 2.
"""

import argparse
import json
import sys
from pathlib import Path


# ---------------------------------------------------------------------------
# Check result constants
# ---------------------------------------------------------------------------

PASS = "PASS"
FAIL = "FAIL"
INCONCLUSIVE = "INCONCLUSIVE"


def _check_sha256(file_path: Path, bundle: dict) -> tuple[str, str]:
    """Compare the file's SHA-256 against the bundle's registered digest."""
    import hashlib

    registered = bundle.get("sha256_digest", "")
    if not registered:
        return INCONCLUSIVE, "Bundle missing sha256_digest"

    sha = hashlib.sha256()
    try:
        with file_path.open("rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                sha.update(chunk)
    except OSError as exc:
        return FAIL, f"Cannot read file: {exc}"

    computed = sha.hexdigest()
    if computed == registered:
        return PASS, f"SHA-256 match: {computed}"
    return FAIL, f"SHA-256 mismatch: file={computed} bundle={registered}"


def _check_custody_signatures(bundle: dict) -> tuple[str, str]:
    """Verify Ed25519 signatures on all custody events (Phase 2)."""
    # TODO (Phase 2): load public key from bundle, verify each event's signature
    return INCONCLUSIVE, "Custody signature verification not yet implemented (Phase 2)"


def _check_merkle_inclusion(bundle: dict) -> tuple[str, str]:
    """Verify RFC 9162 Merkle inclusion proof (Phase 2)."""
    # TODO (Phase 2): reconstruct root from leaf + proof, compare with checkpoint root
    return INCONCLUSIVE, "Merkle inclusion proof verification not yet implemented (Phase 2)"


def _check_checkpoint_signature(bundle: dict) -> tuple[str, str]:
    """Verify the log checkpoint Ed25519 signature (Phase 2)."""
    # TODO (Phase 2): verify checkpoint signature using checkpoint public key
    return INCONCLUSIVE, "Checkpoint signature verification not yet implemented (Phase 2)"


def _check_witness_signature(bundle: dict) -> tuple[str, str]:
    """Verify the Witness counter-signature (Phase 2)."""
    # TODO (Phase 2): verify witness_ack_signature using witness public key
    return INCONCLUSIVE, "Witness signature verification not yet implemented (Phase 2)"


def verify(file_path: Path, bundle_path: Path) -> int:
    """Run all verification checks and print a report. Returns exit code."""
    if not file_path.exists():
        print(f"ERROR: File not found: {file_path}", file=sys.stderr)
        return 2
    if not bundle_path.exists():
        print(f"ERROR: Bundle not found: {bundle_path}", file=sys.stderr)
        return 2

    with bundle_path.open() as fh:
        bundle = json.load(fh)

    checks = [
        ("SHA-256 Integrity",          _check_sha256(file_path, bundle)),
        ("Custody Event Signatures",   _check_custody_signatures(bundle)),
        ("Merkle Inclusion Proof",     _check_merkle_inclusion(bundle)),
        ("Checkpoint Signature",       _check_checkpoint_signature(bundle)),
        ("Witness Counter-Signature",  _check_witness_signature(bundle)),
    ]

    print(f"\nTrustChain Verification Report")
    print(f"File:   {file_path}")
    print(f"Bundle: {bundle_path}")
    print("-" * 60)

    results = []
    for name, (result, detail) in checks:
        icon = {"PASS": "✓", "FAIL": "✗", "INCONCLUSIVE": "?"}.get(result, "?")
        print(f"  [{icon}] {name}: {result}")
        print(f"       {detail}")
        results.append(result)

    print("-" * 60)
    if all(r == PASS for r in results):
        overall = PASS
    elif FAIL in results:
        overall = FAIL
    else:
        overall = INCONCLUSIVE

    print(f"  Overall: {overall}\n")
    return 0 if overall == PASS else (1 if overall == FAIL else 3)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="trustchain-verify",
        description="Offline verifier for TrustChain evidence bundles.",
    )
    subparsers = parser.add_subparsers(dest="command")

    verify_parser = subparsers.add_parser("verify", help="Verify an evidence bundle.")
    verify_parser.add_argument("--file", required=True, type=Path, help="Path to the evidence file.")
    verify_parser.add_argument("--bundle", required=True, type=Path, help="Path to the verification bundle JSON.")

    args = parser.parse_args()

    if args.command == "verify":
        sys.exit(verify(args.file, args.bundle))
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()

