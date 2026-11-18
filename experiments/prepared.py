"""Precomputed features shared by the retrieval benchmarks.

Uses the production MediaTrace code (app.mediatrace.*) so measured behaviour
is the deployed behaviour.
"""

from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from typing import Optional

from app.mediatrace import engine, orb
from app.mediatrace.phash import hamming, load_image, phash_image

from experiments.dataset import Dataset


@dataclass
class Item:
    data: bytes
    sha256: str
    phash: str
    _img: object = None
    _orb: Optional[orb.OrbFeatures] = None
    hash_ms: float = 0.0

    def image(self):
        if self._img is None:
            self._img = load_image(self.data)
        return self._img

    def orb_features(self) -> orb.OrbFeatures:
        if self._orb is None:
            self._orb = orb.extract(self.image())
        return self._orb


def make_item(data: bytes) -> Item:
    t0 = time.perf_counter()
    sha = hashlib.sha256(data).hexdigest()
    img = load_image(data)
    ph = phash_image(img)
    it = Item(data, sha, ph, _img=img)
    it.hash_ms = (time.perf_counter() - t0) * 1000
    return it


@dataclass
class Prepared:
    ds: Dataset
    gallery: dict[int, Item] = field(default_factory=dict)
    queries: list[tuple[int, str, Item]] = field(default_factory=list)
    negatives: list[Item] = field(default_factory=list)

    @property
    def gallery_items(self) -> list[engine.GalleryItem]:
        return [engine.GalleryItem(str(i), it.sha256, it.phash) for i, it in self.gallery.items()]

    def ranked(self, q: Item) -> list[tuple[int, int]]:
        """All gallery ids ranked by (exact first, Hamming, id)."""
        return sorted(
            ((0 if it.sha256 == q.sha256 else 1, hamming(q.phash, it.phash), i) for i, it in self.gallery.items())
        )

    def search(self, q: Item, params: engine.SearchParams) -> list[engine.Candidate]:
        return engine.search(
            q.sha256,
            q.phash,
            self.gallery_items,
            params,
            query_features=q.orb_features() if params.use_orb and not params.exact_only else None,
            candidate_features=(lambda i: self.gallery[int(i)].orb_features()) if params.use_orb else None,
        )


def prepare(ds: Dataset) -> Prepared:
    p = Prepared(ds)
    p.gallery = {i: make_item(d) for i, d in ds.originals.items()}
    p.queries = [(i, t, make_item(d)) for i, t, d in ds.queries]
    p.negatives = [make_item(d) for d in ds.negatives]
    return p
