"""trustchain-verify — offline verifier for TrustChain evidence bundles.

    python -m trustchain_verify verify --file IMG --bundle BUNDLE.json \
        [--log-key HEX|FILE] [--custody-key HEX|FILE] [--witness-key HEX|FILE] [--json]

Exit codes: 0 PASS, 1 FAIL, 3 INCONCLUSIVE, 2 usage / IO error.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from trustchain_verify.verifier import FAIL, PASS, load_key_arg, verify_bundle

ICONS = {"PASS": "✓", "FAIL": "✗", "INCONCLUSIVE": "?"}


def _cmd_verify(args: argparse.Namespace) -> int:
    try:
        file_bytes = Path(args.file).read_bytes()
        bundle = json.loads(Path(args.bundle).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    report = verify_bundle(
        file_bytes,
        bundle,
        {
            "checkpoint": load_key_arg(args.log_key),
            "custody": load_key_arg(args.custody_key),
            "witness": load_key_arg(args.witness_key),
        },
    )

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        ev = bundle.get("evidence") or {}
        print("\nTrustChain offline verification")
        print(f"  file     : {args.file}")
        print(f"  bundle   : {args.bundle}")
        print(f"  evidence : {ev.get('id')} ({ev.get('original_filename')})")
        print("-" * 72)
        for c in report.checks:
            print(f" [{ICONS[c.status]}] {c.name:<28} {c.status}")
            for d in c.details:
                print(f"       {d}")
        for w in report.warnings:
            print(f" [!] {w}")
        print("-" * 72)
        print(f" OVERALL: {report.overall}\n")
    return 0 if report.overall == PASS else (1 if report.overall == FAIL else 3)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="trustchain-verify", description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    v = sub.add_parser("verify", help="verify a file against an exported bundle")
    v.add_argument("--file", required=True)
    v.add_argument("--bundle", required=True)
    v.add_argument("--log-key", help="pinned checkpoint (log) public key, hex or file")
    v.add_argument("--custody-key", help="pinned custody-event public key, hex or file")
    v.add_argument("--witness-key", help="pinned witness public key, hex or file")
    v.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args(argv)
    return _cmd_verify(args)


if __name__ == "__main__":
    sys.exit(main())
