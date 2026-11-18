"""C2PA provenance adapter around the ``c2patool`` CLI.

Normalised states:
  VALID   — a manifest store is present and c2patool reports no validation
            failures (``trusted`` says whether the signer chains to a trust list);
  INVALID — a manifest store is present but validation failed (tampered
            content hash, bad claim signature, ...);
  ABSENT  — no C2PA manifest in the file.  **Not** evidence of manipulation:
            most real-world sharing pipelines strip manifests;
  ERROR   — the tool is missing, timed out, or produced unparseable output.

Safety: the file is always passed as a single argv element (no shell), the
path is a server-generated temp file (never a client filename), and every run
has a timeout.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import asdict, dataclass, field
from typing import Any, Optional

VALID, INVALID, ABSENT, ERROR = "VALID", "INVALID", "ABSENT", "ERROR"

_ABSENT_MARKERS = (
    "no claim found",
    "no manifest",
    "manifest not found",
    "jumbfnotfound",
    "jumbf not found",
    "no jumbf",
    "manifestnotfound",
)
# validation_status codes that do not invalidate the manifest's integrity.
_NON_FATAL_SUFFIXES = (".untrusted", ".trusted", ".validated", ".match", ".insideValidity")


@dataclass
class C2PAResult:
    status: str
    trusted: Optional[bool] = None
    signer: Optional[str] = None
    issuer: Optional[str] = None
    signed_at: Optional[str] = None
    claim_generator: Optional[str] = None
    title: Optional[str] = None
    assertions: list[str] = field(default_factory=list)
    validation_codes: list[str] = field(default_factory=list)
    error: Optional[str] = None
    tool_version: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _failure_codes(report: dict[str, Any]) -> list[str]:
    codes: list[str] = []
    vr = report.get("validation_results") or {}
    active = vr.get("activeManifest") or {}
    for item in active.get("failure") or []:
        codes.append(str(item.get("code")))
    for item in report.get("validation_status") or []:
        code = str(item.get("code", ""))
        if code and not code.endswith(_NON_FATAL_SUFFIXES):
            codes.append(code)
    return sorted(set(codes))


def parse_report(returncode: int, stdout: str, stderr: str) -> C2PAResult:
    """Normalise one c2patool invocation (pure function; unit tested)."""
    text = f"{stdout}\n{stderr}".lower()
    if returncode != 0:
        if any(m in text for m in _ABSENT_MARKERS):
            return C2PAResult(status=ABSENT)
        return C2PAResult(status=ERROR, error=(stderr or stdout).strip()[:500] or f"exit {returncode}")

    try:
        report = json.loads(stdout)
    except json.JSONDecodeError:
        if any(m in text for m in _ABSENT_MARKERS):
            return C2PAResult(status=ABSENT)
        return C2PAResult(status=ERROR, error="unparseable c2patool output")

    manifests = report.get("manifests") or {}
    active_label = report.get("active_manifest")
    if not manifests or not active_label or active_label not in manifests:
        return C2PAResult(status=ABSENT)

    m = manifests[active_label]
    sig = m.get("signature_info") or {}
    all_codes = [str(i.get("code")) for i in report.get("validation_status") or []]
    failures = _failure_codes(report)

    state = report.get("validation_state")
    if state is not None:
        status = INVALID if str(state).lower() == "invalid" else VALID
        trusted = str(state).lower() == "trusted"
    else:
        status = INVALID if failures else VALID
        trusted = None if status == INVALID else not any(c.endswith(".untrusted") for c in all_codes)

    return C2PAResult(
        status=status,
        trusted=trusted,
        signer=sig.get("common_name") or sig.get("issuer"),
        issuer=sig.get("issuer"),
        signed_at=sig.get("time"),
        claim_generator=m.get("claim_generator")
        or ", ".join(g.get("name", "") for g in m.get("claim_generator_info") or []),
        title=m.get("title"),
        assertions=[a.get("label", "") for a in m.get("assertions") or []],
        validation_codes=failures or all_codes,
    )


class C2PAAdapter:
    def __init__(self, binary: str = "c2patool", timeout: float = 20.0) -> None:
        self.binary = binary
        self.timeout = timeout

    def resolve(self) -> Optional[str]:
        return shutil.which(self.binary)

    def inspect_bytes(self, data: bytes, suffix: str) -> C2PAResult:
        exe = self.resolve()
        if exe is None:
            return C2PAResult(status=ERROR, error=f"c2patool binary '{self.binary}' not found")
        fd, path = tempfile.mkstemp(prefix="tc-c2pa-", suffix=suffix)
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            return self.inspect_path(path, exe)
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass

    def inspect_path(self, path: str, exe: Optional[str] = None) -> C2PAResult:
        exe = exe or self.resolve()
        if exe is None:
            return C2PAResult(status=ERROR, error=f"c2patool binary '{self.binary}' not found")
        try:
            proc = subprocess.run(
                [exe, os.path.abspath(path)],
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
                env={"PATH": os.environ.get("PATH", ""), "HOME": tempfile.gettempdir()},
            )
        except subprocess.TimeoutExpired:
            return C2PAResult(status=ERROR, error=f"c2patool timed out after {self.timeout}s")
        except OSError as exc:
            return C2PAResult(status=ERROR, error=f"c2patool could not run: {exc}")
        return parse_report(proc.returncode, proc.stdout, proc.stderr)
