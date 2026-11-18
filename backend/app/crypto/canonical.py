"""Canonical JSON serialization used for everything that gets signed or hashed.

Rules (a strict subset of RFC 8785 / JCS that is unambiguous for our data):
  * keys sorted lexicographically (by code point), recursively;
  * separators ``(",", ":")`` — no insignificant whitespace;
  * UTF-8 output, non-ASCII characters emitted literally;
  * only str / int / bool / None / list / dict are allowed — floats are rejected
    because their textual form is not canonical across implementations.
"""

from __future__ import annotations

import json
from typing import Any


class CanonicalizationError(ValueError):
    pass


def _check(value: Any, path: str = "$") -> None:
    if value is None or isinstance(value, (str, bool)):
        return
    if isinstance(value, int):
        return
    if isinstance(value, float):
        raise CanonicalizationError(f"floats are not allowed in canonical JSON ({path})")
    if isinstance(value, (list, tuple)):
        for i, item in enumerate(value):
            _check(item, f"{path}[{i}]")
        return
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise CanonicalizationError(f"non-string key at {path}")
            _check(v, f"{path}.{k}")
        return
    raise CanonicalizationError(f"unsupported type {type(value).__name__} at {path}")


def canonical_json(obj: Any) -> bytes:
    """Return the canonical UTF-8 byte encoding of *obj*."""
    _check(obj)
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")
