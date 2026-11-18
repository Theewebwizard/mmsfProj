"""Verification half of RFC 9162 §2.1 — independent of the backend code."""

from __future__ import annotations

import hashlib
from typing import Sequence


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def verify_inclusion(index: int, tree_size: int, leaf: bytes, proof: Sequence[bytes], root: bytes) -> bool:
    """RFC 9162 §2.1.3.2."""
    if index < 0 or index >= tree_size:
        return False
    fn, sn, r = index, tree_size - 1, leaf
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def verify_consistency(first: int, second: int, first_root: bytes, second_root: bytes, proof: Sequence[bytes]) -> bool:
    """RFC 9162 §2.1.4.2."""
    if first < 0 or second < first:
        return False
    if first == 0:
        return len(proof) == 0
    if first == second:
        return len(proof) == 0 and first_root == second_root
    if not proof:
        return False
    path = list(proof)
    if first & (first - 1) == 0:
        path.insert(0, first_root)
    fn, sn = first - 1, second - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return fr == first_root and sr == second_root and sn == 0
