"""Perceptual hashing (64-bit DCT pHash via ImageHash)."""

from __future__ import annotations

import io
from typing import Optional

import imagehash
from PIL import Image, ImageOps

HASH_BITS = 64


def load_image(data: bytes) -> Image.Image:
    img = Image.open(io.BytesIO(data))
    img = ImageOps.exif_transpose(img)  # orientation-normalise so EXIF stripping is neutral
    return img.convert("RGB")


def phash_image(img: Image.Image) -> str:
    return str(imagehash.phash(img, hash_size=8))


def compute_phash(data: bytes) -> Optional[str]:
    try:
        return phash_image(load_image(data))
    except Exception:
        return None


def hamming(a: str, b: str) -> int:
    return bin(int(a, 16) ^ int(b, 16)).count("1")
