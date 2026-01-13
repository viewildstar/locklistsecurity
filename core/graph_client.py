from __future__ import annotations

from typing import Any, AsyncIterator, Dict, Optional

import httpx


class GraphClient:
    def __init__(self, access_token: str, base_url: str = "https://graph.microsoft.com/v1.0"):
        self.access_token = access_token
        self.base_url = base_url.rstrip("/")

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self.access_token}",
            "Accept": "application/json",
        }

    async def get_json(self, path_or_url: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        url = path_or_url if path_or_url.startswith("http") else f"{self.base_url}{path_or_url}"
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.get(url, headers=self._headers(), params=params)
            r.raise_for_status()
            return r.json()

    async def get_paged(self, path: str, params: Optional[Dict[str, Any]] = None) -> AsyncIterator[Dict[str, Any]]:
        """Yield items across @odata.nextLink."""
        data = await self.get_json(path, params=params)
        for item in data.get("value", []):
            yield item
        next_link = data.get("@odata.nextLink")
        while next_link:
            data = await self.get_json(next_link)
            for item in data.get("value", []):
                yield item
            next_link = data.get("@odata.nextLink")
