"""RFC 9162 Merkle tree tests.

RFC 9162 defines the algorithms (§2.1) but ships no test-vector appendix.
The vectors below are the canonical reference vectors used by the
Certificate Transparency reference implementations (certificate-transparency-go
``merkle`` package / Trillian), whose hashing is byte-identical to RFC 9162
§2.1 (RFC 9162 kept RFC 6962's tree hashing and proof formats).
"""

import hashlib
import random

import pytest

from app.crypto import merkle

LEAF_INPUTS = [
    bytes.fromhex(h)
    for h in [
        "",
        "00",
        "10",
        "2021",
        "3031",
        "40414243",
        "5051525354555657",
        "606162636465666768696a6b6c6d6e6f",
    ]
]
LEAVES = [merkle.leaf_hash(d) for d in LEAF_INPUTS]

ROOTS = {
    1: "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    2: "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    3: "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
    4: "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    5: "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
    6: "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
    7: "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
    8: "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
}

INCLUSION_VECTORS = [
    # (leaf index, tree size, proof)
    (0, 1, []),
    (
        0,
        8,
        [
            "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
            "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
            "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
        ],
    ),
    (
        5,
        8,
        [
            "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
            "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
            "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
        ],
    ),
    (2, 3, ["fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125"]),
    (
        1,
        5,
        [
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
            "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
            "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
        ],
    ),
]

CONSISTENCY_VECTORS = [
    # (first size, second size, proof)
    (1, 1, []),
    (
        1,
        8,
        [
            "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
            "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
            "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
        ],
    ),
    (
        6,
        8,
        [
            "0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
            "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
            "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
        ],
    ),
    (
        2,
        5,
        [
            "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
            "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
        ],
    ),
]


def test_empty_root():
    assert merkle.root_hash([]).hex() == hashlib.sha256(b"").hexdigest()
    assert (
        merkle.root_hash([]).hex()
        == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )


def test_leaf_and_node_domain_separation():
    assert merkle.leaf_hash(b"x") == hashlib.sha256(b"\x00x").digest()
    a, b = b"a" * 32, b"b" * 32
    assert merkle.node_hash(a, b) == hashlib.sha256(b"\x01" + a + b).digest()


@pytest.mark.parametrize("size,expected", sorted(ROOTS.items()))
def test_rfc_roots(size, expected):
    assert merkle.root_hash(LEAVES[:size]).hex() == expected


@pytest.mark.parametrize("index,size,proof", INCLUSION_VECTORS)
def test_rfc_inclusion_proofs(index, size, proof):
    generated = merkle.inclusion_proof(index, LEAVES[:size])
    assert [p.hex() for p in generated] == proof
    root = bytes.fromhex(ROOTS[size])
    assert merkle.verify_inclusion(index, size, LEAVES[index], generated, root)


@pytest.mark.parametrize("first,second,proof", CONSISTENCY_VECTORS)
def test_rfc_consistency_proofs(first, second, proof):
    generated = merkle.consistency_proof(first, LEAVES[:second])
    assert [p.hex() for p in generated] == proof
    assert merkle.verify_consistency(
        first, second, bytes.fromhex(ROOTS[first]), bytes.fromhex(ROOTS[second]), generated
    )


def test_exhaustive_proofs_small_trees():
    rng = random.Random(9162)
    leaves = [merkle.leaf_hash(rng.randbytes(rng.randint(0, 40))) for _ in range(33)]
    for n in range(1, len(leaves) + 1):
        tree = leaves[:n]
        root = merkle.root_hash(tree)
        for m in range(n):
            proof = merkle.inclusion_proof(m, tree)
            assert merkle.verify_inclusion(m, n, tree[m], proof, root)
            # wrong index / wrong leaf must fail
            assert not merkle.verify_inclusion(m, n, b"\x00" * 32, proof, root)
            if n > 1:
                assert not merkle.verify_inclusion((m + 1) % n, n, tree[m], proof, root)
        for m in range(1, n + 1):
            proof = merkle.consistency_proof(m, tree)
            old_root = merkle.root_hash(leaves[:m])
            assert merkle.verify_consistency(m, n, old_root, root, proof)


def test_consistency_detects_rewritten_history():
    honest = [merkle.leaf_hash(bytes([i])) for i in range(10)]
    forked = list(honest)
    forked[3] = merkle.leaf_hash(b"rewritten")
    old_root = merkle.root_hash(honest[:6])
    proof = merkle.consistency_proof(6, forked)
    assert not merkle.verify_consistency(6, 10, old_root, merkle.root_hash(forked), proof)


def test_tampered_proof_rejected():
    tree = LEAVES[:8]
    root = merkle.root_hash(tree)
    proof = merkle.inclusion_proof(5, tree)
    bad = list(proof)
    bad[1] = bytes(32)
    assert not merkle.verify_inclusion(5, 8, tree[5], bad, root)
    assert not merkle.verify_inclusion(5, 8, tree[5], proof[:-1], root)
    assert not merkle.verify_inclusion(5, 8, tree[5], proof + [bytes(32)], root)


def test_invalid_ranges():
    with pytest.raises(ValueError):
        merkle.inclusion_proof(3, LEAVES[:3])
    with pytest.raises(ValueError):
        merkle.consistency_proof(0, LEAVES[:3])
    assert not merkle.verify_consistency(5, 3, b"", b"", [])
    assert merkle.verify_consistency(0, 5, b"", merkle.root_hash(LEAVES[:5]), [])
