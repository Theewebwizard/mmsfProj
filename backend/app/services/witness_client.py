"""HTTP client for the independent Witness service."""

from __future__ import annotations

from typing import Any, Optional

import httpx

from app.config import settings


class WitnessClient:
    def __init__(self) -> None:
        # Tests inject an ASGI transport pointing at the in-process witness app.
        self.transport: Optional[httpx.AsyncBaseTransport] = None
        self.base_url: Optional[str] = None

    def _client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=self.base_url or settings.witness_url,
            transport=self.transport,
            timeout=settings.witness_timeout_seconds,
            headers={"X-Witness-Token": settings.witness_token},
        )

    async def latest(self) -> dict[str, Any]:
        async with self._client() as c:
            r = await c.get("/witness/latest")
            r.raise_for_status()
            return r.json()

    async def public_key(self) -> dict[str, Any]:
        async with self._client() as c:
            r = await c.get("/witness/public-key")
            r.raise_for_status()
            return r.json()

    async def submit(self, submission: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        async with self._client() as c:
            r = await c.post("/witness/checkpoint", json=submission)
            try:
                body = r.json()
            except ValueError:
                body = {"detail": r.text}
            return r.status_code, body


witness_client = WitnessClient()
