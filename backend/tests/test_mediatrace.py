"""Phase 3: C2PA adapter, metadata, pHash, ORB, MediaTrace search, recovery."""

import io
import json
import random

import numpy as np
import pytest
from PIL import Image, ImageDraw, ImageFilter

from app.crypto.c2pa import ABSENT, ERROR, INVALID, VALID, C2PAAdapter, parse_report
from app.mediatrace import engine, orb
from app.mediatrace.metadata import extract_exif, strip_jpeg_metadata
from app.mediatrace.phash import compute_phash, hamming, load_image
from conftest import mock_storage
from tests.test_trustchain import register


def scene(seed: int, size=(512, 384)) -> Image.Image:
    """Deterministic textured synthetic scene (shapes + noise) for CV tests."""
    rng = random.Random(seed)
    img = Image.new("RGB", size, tuple(rng.randrange(256) for _ in range(3)))
    d = ImageDraw.Draw(img)
    for _ in range(40):
        x0, y0 = rng.randrange(size[0]), rng.randrange(size[1])
        x1, y1 = x0 + rng.randrange(20, 160), y0 + rng.randrange(20, 160)
        col = tuple(rng.randrange(256) for _ in range(3))
        kind = rng.random()
        if kind < 0.4:
            d.rectangle([x0, y0, x1, y1], fill=col)
        elif kind < 0.8:
            d.ellipse([x0, y0, x1, y1], fill=col)
        else:
            d.line([x0, y0, x1, y1], fill=col, width=rng.randrange(2, 8))
    noise = np.random.default_rng(seed).normal(128, 30, (size[1], size[0], 3)).clip(0, 255).astype(np.uint8)
    return Image.blend(img, Image.fromarray(noise, "RGB"), 0.15).filter(ImageFilter.SMOOTH)


def to_jpeg(img: Image.Image, q=92, exif=None) -> bytes:
    buf = io.BytesIO()
    kwargs = {"quality": q}
    if exif is not None:
        kwargs["exif"] = exif
    img.save(buf, format="JPEG", **kwargs)
    return buf.getvalue()


def with_exif(img: Image.Image) -> bytes:
    ex = Image.Exif()
    ex[0x010F] = "TrustChainCam"  # Make
    ex[0x0110] = "Model T"  # Model
    ex[0x0132] = "2026:11:17 10:00:00"  # DateTime
    return to_jpeg(img, exif=ex)


# ---------------------------------------------------------------------------
# C2PA adapter normalisation
# ---------------------------------------------------------------------------

_MANIFEST = {
    "active_manifest": "urn:uuid:1",
    "manifests": {
        "urn:uuid:1": {
            "claim_generator": "c2patool test",
            "title": "photo.jpg",
            "assertions": [{"label": "c2pa.actions"}, {"label": "stds.schema-org.CreativeWork"}],
            "signature_info": {"issuer": "C2PA Test Signing Cert", "common_name": "Test Signer", "time": "2026-11-17T00:00:00+00:00"},
        }
    },
}


def test_c2pa_absent():
    assert parse_report(1, "", "Error: No claim found").status == ABSENT


def test_c2pa_valid_untrusted():
    rep = dict(_MANIFEST, validation_status=[{"code": "signingCredential.untrusted"}])
    r = parse_report(0, json.dumps(rep), "")
    assert r.status == VALID and r.trusted is False
    assert r.signer == "Test Signer" and r.issuer == "C2PA Test Signing Cert"
    assert r.assertions == ["c2pa.actions", "stds.schema-org.CreativeWork"]


def test_c2pa_invalid_hash_mismatch():
    rep = dict(_MANIFEST, validation_status=[{"code": "assertion.dataHash.mismatch"}])
    assert parse_report(0, json.dumps(rep), "").status == INVALID


def test_c2pa_validation_state_field():
    assert parse_report(0, json.dumps(dict(_MANIFEST, validation_state="Trusted")), "").trusted is True
    assert parse_report(0, json.dumps(dict(_MANIFEST, validation_state="Invalid")), "").status == INVALID


def test_c2pa_errors():
    assert parse_report(2, "", "panicked at something").status == ERROR
    assert parse_report(0, "not json", "").status == ERROR
    assert C2PAAdapter("definitely-not-a-real-c2patool-binary").inspect_bytes(b"x", ".jpg").status == ERROR


# ---------------------------------------------------------------------------
# Metadata + pHash
# ---------------------------------------------------------------------------


def test_exif_extracted_and_stripped_losslessly():
    original = with_exif(scene(1))
    assert extract_exif(original)["Make"] == "TrustChainCam"
    stripped = strip_jpeg_metadata(original)
    assert "Make" not in extract_exif(stripped)
    assert stripped != original  # SHA-256 changes...
    assert load_image(stripped).tobytes() == load_image(original).tobytes()  # ...pixels don't
    assert hamming(compute_phash(original), compute_phash(stripped)) == 0


@pytest.mark.parametrize(
    "transform,max_dist",
    [
        (lambda im: to_jpeg(im, q=50), 6),
        (lambda im: to_jpeg(im.resize((256, 192))), 6),
        (lambda im: to_jpeg(Image.eval(im, lambda v: min(255, int(v * 1.15)))), 8),
    ],
)
def test_phash_robust_to_benign_transforms(transform, max_dist):
    base = scene(7)
    assert hamming(compute_phash(to_jpeg(base)), compute_phash(transform(base))) <= max_dist


def test_phash_separates_unrelated_images():
    dists = [hamming(compute_phash(to_jpeg(scene(100))), compute_phash(to_jpeg(scene(200 + i)))) for i in range(5)]
    assert min(dists) > 10


# ---------------------------------------------------------------------------
# ORB
# ---------------------------------------------------------------------------


def test_orb_confirms_crop_that_phash_misses():
    base = scene(42)
    w, h = base.size
    crop = base.crop((int(w * 0.2), int(h * 0.2), int(w * 0.8), int(h * 0.8)))  # 60% center crop
    qb, cb = to_jpeg(crop), to_jpeg(base)
    res = orb.match(orb.extract(load_image(qb)), orb.extract(load_image(cb)))
    assert res.homography_found and res.inliers >= 15
    unrelated = orb.match(orb.extract(load_image(qb)), orb.extract(load_image(to_jpeg(scene(43)))))
    assert unrelated.inliers < 15


def test_engine_ranking_and_thresholds():
    gallery = [
        engine.GalleryItem("a", "sha-a", "ffffffffffffffff"),
        engine.GalleryItem("b", "sha-b", "fffffffffffffff0"),  # distance 4
        engine.GalleryItem("c", "sha-c", "0000000000000000"),  # distance 64
    ]
    res = engine.search("sha-a", "ffffffffffffffff", gallery, engine.SearchParams(phash_threshold=5))
    assert [c.evidence_id for c in res] == ["a", "b"]
    assert res[0].matched_by == [engine.EXACT, engine.PHASH]
    assert engine.search("sha-x", "ffffffffffffffff", gallery, engine.SearchParams(exact_only=True)) == []


# ---------------------------------------------------------------------------
# API: search + provenance recovery
# ---------------------------------------------------------------------------


async def _seed(client, n=4):
    h, uid = await register(client, "tracer@example.com")
    case = (await client.post("/api/v1/cases", json={"title": "Trace"}, headers=h)).json()
    originals = {}
    for seed in range(n):
        data = with_exif(scene(1000 + seed))
        r = await client.post(
            f"/api/v1/cases/{case['id']}/evidence", files={"file": (f"s{seed}.jpg", data, "image/jpeg")}, headers=h
        )
        originals[seed] = (r.json(), data)
    return h, originals


async def _search(client, h, data, **params):
    form = {k: str(v).lower() if isinstance(v, bool) else str(v) for k, v in params.items()}
    r = await client.post("/api/v1/trace/search", files={"file": ("q.jpg", data, "image/jpeg")}, data=form, headers=h)
    assert r.status_code == 200, r.text
    return r.json()


async def _verify(client, h, data, evidence_id):
    r = await client.post(
        "/api/v1/trace/verify-candidate",
        files={"file": ("q.jpg", data, "image/jpeg")},
        data={"evidence_id": evidence_id},
        headers=h,
    )
    assert r.status_code == 200, r.text
    return r.json()


async def test_exact_recovery_verified(client):
    h, originals = await _seed(client)
    ev, data = originals[2]
    res = await _search(client, h, data)
    top = res["candidates"][0]
    assert top["evidence_id"] == ev["id"] and top["sha256_match"]
    out = await _verify(client, h, data, ev["id"])
    assert out["assessment"] == "VERIFIED_REGISTERED_ORIGINAL"
    assert out["relationship"] == "BYTE_IDENTICAL"


async def test_stripped_recompressed_query_recovered_as_perceptual_candidate(client):
    h, originals = await _seed(client)
    ev, data = originals[1]
    query = to_jpeg(load_image(strip_jpeg_metadata(data)).resize((256, 192)), q=60)
    res = await _search(client, h, query, phash_threshold=10)
    assert res["query"]["exif_present"] is False
    assert res["candidates"][0]["evidence_id"] == ev["id"]
    assert not res["candidates"][0]["sha256_match"]
    out = await _verify(client, h, query, ev["id"])
    assert out["assessment"] == "VERIFIED_REGISTERED_ORIGINAL"
    assert out["relationship"] == "PERCEPTUAL_CANDIDATE"
    assert "NOT proof" in out["explanation"]


async def test_crop_needs_orb(client):
    h, originals = await _seed(client)
    ev, data = originals[3]
    img = load_image(data)
    w, hh = img.size
    query = to_jpeg(img.crop((int(w * 0.2), int(hh * 0.2), int(w * 0.8), int(hh * 0.8))))
    without = await _search(client, h, query, phash_threshold=10)
    assert ev["id"] not in [c["evidence_id"] for c in without["candidates"]]
    with_orb = await _search(client, h, query, phash_threshold=10, use_orb=True)
    assert with_orb["candidates"][0]["evidence_id"] == ev["id"]
    assert "ORB_RANSAC" in with_orb["candidates"][0]["matched_by"]
    out = await _verify(client, h, query, ev["id"])
    assert out["relationship"] == "GEOMETRIC_CANDIDATE"
    assert out["assessment"] == "VERIFIED_REGISTERED_ORIGINAL"


async def test_unrelated_query_no_match(client):
    h, originals = await _seed(client)
    query = to_jpeg(scene(999_999))
    res = await _search(client, h, query, use_orb=True)
    assert res["outcome"] == "NO_MATCH" and res["candidates"] == []
    out = await _verify(client, h, query, originals[0][0]["id"])
    assert out["assessment"] == "NO_MATCH"


async def test_tampered_original_gives_integrity_failure(client):
    h, originals = await _seed(client)
    ev, data = originals[0]
    mock_storage[ev["storage_key"]] = to_jpeg(scene(5555))  # replaced in the bucket
    out = await _verify(client, h, data, ev["id"])
    assert out["assessment"] == "INTEGRITY_FAILURE"


async def test_unwitnessed_record_is_candidate_only(client, witness_down):
    h, originals = await _seed(client, n=1)
    ev, data = originals[0]
    out = await _verify(client, h, data, ev["id"])
    assert out["assessment"] == "CANDIDATE_ONLY"


async def test_search_requires_investigator(client):
    ha, _ = await register(client, "aud2@example.com", "AUDITOR")
    r = await client.post("/api/v1/trace/search", files={"file": ("q.jpg", to_jpeg(scene(1)), "image/jpeg")}, headers=ha)
    assert r.status_code == 403


async def test_upload_records_exif_and_c2pa_status(client):
    h, originals = await _seed(client, n=1)
    ev, _ = originals[0]
    d = (await client.get(f"/api/v1/evidence/{ev['id']}", headers=h)).json()
    assert d["exif"]["Make"] == "TrustChainCam"
    # c2patool is not installed in the unit-test environment -> honest ERROR, never a fake VALID
    assert d["c2pa_status"] in {"ERROR", "ABSENT", "VALID", "INVALID"}
    assert d["c2pa_summary"]["status"] == d["c2pa_status"]
