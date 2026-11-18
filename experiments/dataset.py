"""Deterministic synthetic dataset for MediaTrace / TrustChain experiments.

Base images are procedural scenes (gradients, shapes, text-like strokes and
seeded Gaussian texture) generated purely from integer seeds with NumPy's PCG64
and Pillow drawing — no downloaded data, no ML.  Every transformation is a
pure function of (image, seed), so the full dataset is bit-reproducible.

Each base original is saved as a JPEG *with EXIF* (camera make/model/time),
so metadata stripping is a real byte-level operation.
"""

from __future__ import annotations

import io
from dataclasses import dataclass
from typing import Callable

import numpy as np
from PIL import Image, ImageDraw, ImageEnhance, ImageFilter

from app.mediatrace.metadata import strip_jpeg_metadata

WIDTH, HEIGHT = 640, 480
BASE_QUALITY = 95


def _scene(seed: int) -> Image.Image:
    rng = np.random.default_rng(seed)
    # smooth two-colour gradient background
    c0, c1 = rng.integers(0, 256, 3), rng.integers(0, 256, 3)
    angle = rng.uniform(0, np.pi)
    yy, xx = np.mgrid[0:HEIGHT, 0:WIDTH]
    t = (np.cos(angle) * xx / WIDTH + np.sin(angle) * yy / HEIGHT)
    t = (t - t.min()) / (np.ptp(t) + 1e-9)
    bg = (c0[None, None, :] * (1 - t[..., None]) + c1[None, None, :] * t[..., None]).astype(np.uint8)
    img = Image.fromarray(bg, "RGB")
    d = ImageDraw.Draw(img)
    for _ in range(int(rng.integers(25, 45))):
        x0, y0 = int(rng.integers(-40, WIDTH)), int(rng.integers(-40, HEIGHT))
        w, h = int(rng.integers(15, 220)), int(rng.integers(15, 220))
        col = tuple(int(v) for v in rng.integers(0, 256, 3))
        kind = rng.random()
        if kind < 0.35:
            d.rectangle([x0, y0, x0 + w, y0 + h], fill=col)
        elif kind < 0.7:
            d.ellipse([x0, y0, x0 + w, y0 + h], fill=col)
        elif kind < 0.85:
            pts = [(int(rng.integers(0, WIDTH)), int(rng.integers(0, HEIGHT))) for _ in range(int(rng.integers(3, 7)))]
            d.polygon(pts, fill=col)
        else:
            d.line([x0, y0, x0 + w, y0 + h], fill=col, width=int(rng.integers(2, 10)))
    noise = rng.normal(0, 12, (HEIGHT, WIDTH, 3))
    arr = np.clip(np.asarray(img, dtype=np.float32) + noise, 0, 255).astype(np.uint8)
    return Image.fromarray(arr, "RGB").filter(ImageFilter.GaussianBlur(0.6))


def _exif(seed: int) -> Image.Exif:
    ex = Image.Exif()
    ex[0x010F] = "SynthCam"
    ex[0x0110] = f"Model-{seed % 7}"
    ex[0x0132] = f"2026:{1 + seed % 12:02d}:{1 + seed % 28:02d} 12:00:00"
    ex[0x0131] = "trustchain-experiments"
    return ex


def encode(img: Image.Image, fmt: str = "JPEG", quality: int = BASE_QUALITY, exif: Image.Exif | None = None) -> bytes:
    buf = io.BytesIO()
    kw: dict = {}
    if fmt == "JPEG":
        kw["quality"] = quality
        if exif is not None:
            kw["exif"] = exif
    elif fmt == "WEBP":
        kw["quality"] = quality
    img.save(buf, format=fmt, **kw)
    return buf.getvalue()


def decode(data: bytes) -> Image.Image:
    return Image.open(io.BytesIO(data)).convert("RGB")


def make_base(seed: int) -> bytes:
    """A registered 'original': JPEG Q95 with EXIF."""
    return encode(_scene(seed), exif=_exif(seed))


# ---------------------------------------------------------------------------
# Transformations: (original_bytes, seed) -> query_bytes
# ---------------------------------------------------------------------------


def _crop(data: bytes, frac: float, seed: int, center: bool) -> bytes:
    img = decode(data)
    w, h = img.size
    cw, ch = int(w * frac), int(h * frac)
    if center:
        x, y = (w - cw) // 2, (h - ch) // 2
    else:
        rng = np.random.default_rng(seed)
        x, y = int(rng.integers(0, w - cw + 1)), int(rng.integers(0, h - ch + 1))
    return encode(img.crop((x, y, x + cw, y + ch)), quality=90)


def _resize(data: bytes, frac: float) -> bytes:
    img = decode(data)
    return encode(img.resize((int(img.width * frac), int(img.height * frac)), Image.LANCZOS), quality=90)


def _enhance(data: bytes, kind: str, factor: float) -> bytes:
    img = decode(data)
    enh = ImageEnhance.Brightness(img) if kind == "brightness" else ImageEnhance.Contrast(img)
    return encode(enh.enhance(factor), quality=90)


def _social(data: bytes) -> bytes:
    """Typical messaging pipeline: strip metadata, downscale to 50%, JPEG Q70."""
    img = decode(strip_jpeg_metadata(data))
    return encode(img.resize((img.width // 2, img.height // 2), Image.LANCZOS), quality=70)


@dataclass(frozen=True)
class Transform:
    name: str
    family: str
    fn: Callable[[bytes, int], bytes]


TRANSFORMS: list[Transform] = [
    Transform("identity", "none", lambda d, s: d),
    Transform("strip_metadata", "metadata", lambda d, s: strip_jpeg_metadata(d)),
    Transform("jpeg_q90", "jpeg", lambda d, s: encode(decode(d), quality=90)),
    Transform("jpeg_q70", "jpeg", lambda d, s: encode(decode(d), quality=70)),
    Transform("jpeg_q50", "jpeg", lambda d, s: encode(decode(d), quality=50)),
    Transform("jpeg_q30", "jpeg", lambda d, s: encode(decode(d), quality=30)),
    Transform("resize_75", "resize", lambda d, s: _resize(d, 0.75)),
    Transform("resize_50", "resize", lambda d, s: _resize(d, 0.50)),
    Transform("resize_25", "resize", lambda d, s: _resize(d, 0.25)),
    Transform("crop_center_80", "crop", lambda d, s: _crop(d, 0.8, s, True)),
    Transform("crop_center_60", "crop", lambda d, s: _crop(d, 0.6, s, True)),
    Transform("crop_random_80", "crop", lambda d, s: _crop(d, 0.8, s, False)),
    Transform("crop_random_60", "crop", lambda d, s: _crop(d, 0.6, s, False)),
    Transform("brightness_+25", "photometric", lambda d, s: _enhance(d, "brightness", 1.25)),
    Transform("brightness_-25", "photometric", lambda d, s: _enhance(d, "brightness", 0.75)),
    Transform("contrast_+30", "photometric", lambda d, s: _enhance(d, "contrast", 1.30)),
    Transform("contrast_-30", "photometric", lambda d, s: _enhance(d, "contrast", 0.70)),
    Transform("format_png", "format", lambda d, s: encode(decode(d), fmt="PNG")),
    Transform("format_webp", "format", lambda d, s: encode(decode(d), fmt="WEBP", quality=80)),
    Transform("social_pipeline", "combined", lambda d, s: _social(d)),
]


@dataclass
class Dataset:
    seed: int
    originals: dict[int, bytes]           # base id -> original bytes
    queries: list[tuple[int, str, bytes]]  # (base id, transform name, bytes)
    negatives: list[bytes]                 # unrelated images (no registered source)


def build(seed: int, n_base: int, n_negative: int, transforms: list[Transform] | None = None) -> Dataset:
    transforms = transforms or TRANSFORMS
    originals = {i: make_base(seed * 100_003 + i) for i in range(n_base)}
    queries = [
        (i, t.name, t.fn(originals[i], seed * 7919 + i * 31 + k))
        for i in range(n_base)
        for k, t in enumerate(transforms)
    ]
    # Negatives come from a disjoint seed range and are re-encoded like real shares.
    negatives = [encode(_scene(seed * 100_003 + 50_000 + j), quality=85) for j in range(n_negative)]
    return Dataset(seed, originals, queries, negatives)
