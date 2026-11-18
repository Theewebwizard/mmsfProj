"""RFC 9162 (Certificate Transparency v2) Merkle tree — Section 2.1.

All functions operate on *leaf hashes* (``bytes`` of length 32) except
``leaf_hash`` itself.  Indices are 0-based, matching the RFC.

  MTH({})        = SHA-256()
  MTH({d0})      = SHA-256(0x00 || d0)
  MTH(D[n])      = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))
                   where k is the largest power of two smaller than n.
"""

from __future__ import annotations

import hashlib
from typing import Sequence

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"
EMPTY_ROOT = hashlib.sha256(b"").digest()


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(LEAF_PREFIX + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def _split(n: int) -> int:
    """Largest power of two strictly smaller than n (n >= 2)."""
    k = 1
    while k << 1 < n:
        k <<= 1
    return k


# ---------------------------------------------------------------------------
# Tree head
# ---------------------------------------------------------------------------


def root_hash(leaves: Sequence[bytes]) -> bytes:
    """MTH(D[n]) over a list of leaf hashes (iterative, O(n))."""
    n = len(leaves)
    if n == 0:
        return EMPTY_ROOT
    # Bottom-up reduction that reproduces the RFC's left-balanced shape:
    # pair adjacent nodes; an odd node at the end is promoted unchanged.
    level = list(leaves)
    while len(level) > 1:
        nxt = [node_hash(level[i], level[i + 1]) for i in range(0, len(level) - 1, 2)]
        if len(level) % 2 == 1:
            nxt.append(level[-1])
        level = nxt
    return level[0]


# ---------------------------------------------------------------------------
# Inclusion proofs — RFC 9162 §2.1.3
# ---------------------------------------------------------------------------


def inclusion_proof(index: int, leaves: Sequence[bytes]) -> list[bytes]:
    """PATH(m, D[n])."""
    n = len(leaves)
    if not 0 <= index < n:
        raise ValueError(f"leaf index {index} out of range for tree size {n}")
    return _path(index, leaves)


def _path(m: int, d: Sequence[bytes]) -> list[bytes]:
    n = len(d)
    if n == 1:
        return []
    k = _split(n)
    if m < k:
        return _path(m, d[:k]) + [root_hash(d[k:])]
    return _path(m - k, d[k:]) + [root_hash(d[:k])]


def verify_inclusion(
    index: int, tree_size: int, leaf: bytes, proof: Sequence[bytes], root: bytes
) -> bool:
    """RFC 9162 §2.1.3.2 verification algorithm."""
    if index >= tree_size or index < 0:
        return False
    fn, sn = index, tree_size - 1
    r = leaf
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


# ---------------------------------------------------------------------------
# Consistency proofs — RFC 9162 §2.1.4
# ---------------------------------------------------------------------------


def consistency_proof(first: int, leaves: Sequence[bytes]) -> list[bytes]:
    """PROOF(m, D[n]) for 0 < m <= n.  (m == n yields the empty proof.)"""
    n = len(leaves)
    if not 0 < first <= n:
        raise ValueError(f"invalid consistency range {first} -> {n}")
    return _subproof(first, leaves, True)


def _subproof(m: int, d: Sequence[bytes], b: bool) -> list[bytes]:
    n = len(d)
    if m == n:
        return [] if b else [root_hash(d)]
    k = _split(n)
    if m <= k:
        return _subproof(m, d[:k], b) + [root_hash(d[k:])]
    return _subproof(m - k, d[k:], False) + [root_hash(d[:k])]


def verify_consistency(
    first: int,
    second: int,
    first_root: bytes,
    second_root: bytes,
    proof: Sequence[bytes],
) -> bool:
    """RFC 9162 §2.1.4.2 verification algorithm.

    ``first == 0`` is treated as trivially consistent (an empty tree is a
    prefix of every tree) provided the proof is empty.
    """
    if first < 0 or second < first:
        return False
    if first == 0:
        return len(proof) == 0
    if first == second:
        return len(proof) == 0 and first_root == second_root
    if not proof:
        return False
    path = list(proof)
    if first & (first - 1) == 0:  # exact power of two
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
