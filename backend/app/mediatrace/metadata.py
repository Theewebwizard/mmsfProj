"""EXIF extraction and metadata stripping helpers."""

from __future__ import annotations

import io
from typing import Any

from PIL import ExifTags, Image

_MAX_VALUE_LEN = 256


def _jsonable(value: Any) -> Any:
    if isinstance(value, bytes):
        return f"<{len(value)} bytes>"
    if isinstance(value, (int, str, bool)) or value is None:
        return value if not isinstance(value, str) else value[:_MAX_VALUE_LEN]
    if isinstance(value, (tuple, list)):
        return [_jsonable(v) for v in value[:32]]
    return str(value)[:_MAX_VALUE_LEN]


def extract_exif(data: bytes) -> dict[str, Any]:
    """Return EXIF tags as {name: value} (strings/ints only).  Empty if none."""
    try:
        with Image.open(io.BytesIO(data)) as img:
            exif = img.getexif()
            out: dict[str, Any] = {}
            for tag_id, value in exif.items():
                name = ExifTags.TAGS.get(tag_id, f"0x{tag_id:04x}")
                out[name] = _jsonable(value)
            try:
                for tag_id, value in exif.get_ifd(ExifTags.IFD.Exif).items():
                    name = ExifTags.TAGS.get(tag_id, f"0x{tag_id:04x}")
                    out.setdefault(name, _jsonable(value))
            except Exception:
                pass
            out["_image"] = {"width": img.width, "height": img.height, "mode": img.mode, "format": img.format}
            return out
    except Exception:
        return {}


# JPEG APPn markers that carry metadata: APP1 (EXIF/XMP), APP11 (JUMBF / C2PA),
# APP13 (IPTC/Photoshop).
_STRIP_MARKERS = {0xE1, 0xEB, 0xED}


def strip_jpeg_metadata(data: bytes) -> bytes:
    """Remove EXIF/XMP/C2PA/IPTC segments from a JPEG *without re-encoding*.

    Pixel data are untouched, so decoded images are identical while the
    SHA-256 of the file changes — exactly what a metadata-stripping upload
    pipeline does.
    """
    if data[:2] != b"\xff\xd8":
        raise ValueError("not a JPEG")
    out = bytearray(b"\xff\xd8")
    i = 2
    n = len(data)
    while i < n:
        if data[i] != 0xFF:
            raise ValueError("corrupt JPEG marker stream")
        marker = data[i + 1]
        if marker == 0xDA:  # start of scan — copy the rest verbatim
            out += data[i:]
            break
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            out += data[i : i + 2]
            i += 2
            continue
        seg_len = int.from_bytes(data[i + 2 : i + 4], "big")
        segment = data[i : i + 2 + seg_len]
        if marker not in _STRIP_MARKERS:
            out += segment
        i += 2 + seg_len
    return bytes(out)
