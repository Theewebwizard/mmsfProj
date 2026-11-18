"""MediaTrace candidate retrieval (DB-agnostic core).

Stage 1  exact SHA-256 lookup
Stage 2  pHash Hamming ranking with a configurable threshold
Stage 3  (optional) ORB + RANSAC geometric confirmation of the top-K pHash
         neighbours, regardless of threshold, to recover crops

Output is a ranked list of *candidates*.  Nothing here asserts authenticity —
that is TrustChain's job (see app.services.verification).
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Callable, Iterable, Optional

from PIL import Image

from app.mediatrace import orb
from app.mediatrace.phash import hamming

EXACT = "SHA256_EXACT"
PHASH = "PHASH"
ORB = "ORB_RANSAC"


@dataclass
class SearchParams:
    exact_only: bool = False
    phash_threshold: int = 10
    use_orb: bool = False
    orb_top_k: int = 10
    orb_min_inliers: int = 15
    limit: int = 10


@dataclass
class GalleryItem:
    id: str
    sha256: str
    phash: Optional[str]


@dataclass
class Candidate:
    evidence_id: str
    hamming: Optional[int]
    phash_similarity: Optional[float]
    sha256_match: bool
    matched_by: list[str] = field(default_factory=list)
    orb: Optional[dict] = None

    def to_dict(self) -> dict:
        return asdict(self)


def search(
    query_sha256: str,
    query_phash: Optional[str],
    gallery: Iterable[GalleryItem],
    params: SearchParams,
    load_candidate_image: Optional[Callable[[str], Optional[Image.Image]]] = None,
    query_features: Optional[orb.OrbFeatures] = None,
    candidate_features: Optional[Callable[[str], Optional[orb.OrbFeatures]]] = None,
) -> list[Candidate]:
    items = list(gallery)
    scored: list[Candidate] = []
    for it in items:
        h = hamming(query_phash, it.phash) if (query_phash and it.phash) else None
        c = Candidate(
            evidence_id=it.id,
            hamming=h,
            phash_similarity=None if h is None else round(1 - h / 64, 4),
            sha256_match=(it.sha256 == query_sha256),
        )
        if c.sha256_match:
            c.matched_by.append(EXACT)
        if not params.exact_only and h is not None and h <= params.phash_threshold:
            c.matched_by.append(PHASH)
        scored.append(c)

    if params.use_orb and not params.exact_only and query_features is not None:
        ranked = sorted(
            (c for c in scored if c.hamming is not None),
            key=lambda c: c.hamming,
        )[: params.orb_top_k]
        for c in ranked:
            feats = None
            if candidate_features is not None:
                feats = candidate_features(c.evidence_id)
            elif load_candidate_image is not None:
                img = load_candidate_image(c.evidence_id)
                feats = orb.extract(img) if img is not None else None
            if feats is None:
                continue
            res = orb.match(query_features, feats)
            c.orb = res.to_dict()
            if res.inliers >= params.orb_min_inliers:
                c.matched_by.append(ORB)

    accepted = [c for c in scored if c.matched_by]
    accepted.sort(
        # exact matches, then pHash matches by distance, then ORB-only by inliers
        key=lambda c: (
            not c.sha256_match,
            PHASH not in c.matched_by,
            c.hamming if PHASH in c.matched_by else -(c.orb or {}).get("inliers", 0),
        )
    )
    return accepted[: params.limit]
