"""ORB keypoint matching + Lowe ratio test + RANSAC homography (OpenCV).

Used to confirm candidates that pHash misses — chiefly crops and partial
overlaps, which shift the DCT low frequencies.  A high inlier count means
the two images share a planar-consistent set of local features; it is still
only *candidate* evidence, never proof of origin.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Optional

import cv2
import numpy as np
from PIL import Image

MAX_DIM = 800
N_FEATURES = 1500
RATIO = 0.75
RANSAC_REPROJ_THRESHOLD = 5.0


@dataclass
class OrbFeatures:
    keypoints: np.ndarray  # (N, 2) float32 coordinates
    descriptors: Optional[np.ndarray]


@dataclass
class OrbResult:
    query_keypoints: int
    candidate_keypoints: int
    good_matches: int
    inliers: int
    inlier_ratio: float
    homography_found: bool

    def to_dict(self) -> dict:
        return asdict(self)


_orb = None


def _detector():
    global _orb
    if _orb is None:
        _orb = cv2.ORB_create(nfeatures=N_FEATURES)
    return _orb


def extract(img: Image.Image) -> OrbFeatures:
    gray = np.asarray(img.convert("L"))
    h, w = gray.shape
    scale = min(1.0, MAX_DIM / max(h, w))
    if scale < 1.0:
        gray = cv2.resize(gray, (int(w * scale), int(h * scale)), interpolation=cv2.INTER_AREA)
    kps, desc = _detector().detectAndCompute(gray, None)
    pts = np.array([k.pt for k in kps], dtype=np.float32).reshape(-1, 2)
    return OrbFeatures(pts, desc)


def match(q: OrbFeatures, c: OrbFeatures, min_matches_for_h: int = 8) -> OrbResult:
    nq, nc = len(q.keypoints), len(c.keypoints)
    if q.descriptors is None or c.descriptors is None or nq < 2 or nc < 2:
        return OrbResult(nq, nc, 0, 0, 0.0, False)
    matcher = cv2.BFMatcher(cv2.NORM_HAMMING)
    pairs = matcher.knnMatch(q.descriptors, c.descriptors, k=2)
    good = [p[0] for p in pairs if len(p) == 2 and p[0].distance < RATIO * p[1].distance]
    if len(good) < min_matches_for_h:
        return OrbResult(nq, nc, len(good), 0, 0.0, False)
    src = q.keypoints[[m.queryIdx for m in good]].reshape(-1, 1, 2)
    dst = c.keypoints[[m.trainIdx for m in good]].reshape(-1, 1, 2)
    H, mask = cv2.findHomography(src, dst, cv2.RANSAC, RANSAC_REPROJ_THRESHOLD)
    if H is None or mask is None:
        return OrbResult(nq, nc, len(good), 0, 0.0, False)
    inliers = int(mask.sum())
    return OrbResult(nq, nc, len(good), inliers, round(inliers / len(good), 4), True)
