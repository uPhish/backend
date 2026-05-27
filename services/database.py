from dotenv import load_dotenv
import os
from supabase import create_async_client, AsyncClient
from urllib.parse import urlparse
import hashlib

load_dotenv()

class DatabaseManager:
    def __init__(self):
        self._client: AsyncClient | None = None

    async def _get_client(self) -> AsyncClient:
        if self._client is None:
            self._client = await create_async_client(
                os.environ["SUPABASE_URL"],
                os.environ["SUPABASE_SERVICE_KEY"],
            )
        return self._client

    def _extract_tld(self, url: str) -> str:
        netloc = urlparse(url).netloc
        parts = netloc.split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return netloc

    async def report_url(self, domain: str | None, url: str, useragent: str, threat_type: str | None, reported_by: str):
        client = await self._get_client()
        domain = domain or self._extract_tld(url)
        url_hash = hashlib.md5(url.encode("utf-8")).hexdigest()
        await client.table("reported_urls").insert({
            "domain": domain,
            "url": url,
            "url_hash": url_hash,
            "useragent": useragent,
            "threat_type": threat_type,
            "reported_by": reported_by
        }).execute()

    async def block_url(self, domain: str | None, url: str, threat_type: str, reported_by: str):
        """Block a specific URL (unique by `url`). Domain is stored for convenience."""
        client = await self._get_client()
        domain = domain or self._extract_tld(url)
        url_hash = hashlib.md5(url.encode("utf-8")).hexdigest()
        await client.table("blocked_urls").upsert({
            "domain": domain,
            "url": url,
            "url_hash": url_hash,
            "threat_type": threat_type,
            "reported_by": reported_by
        }, on_conflict="url_hash", ignore_duplicates=False).execute()

    async def batch_block_urls(self, rows: list[dict]):
        """Upsert a batch of rows into `blocked_urls`. Rows must include a `url` key."""
        client = await self._get_client()
        # Ensure each row has a url_hash for the unique index
        for r in rows:
            if "url" in r and "url_hash" not in r:
                r["url_hash"] = hashlib.md5(r["url"].encode("utf-8")).hexdigest()
            if "domain" not in r and "url" in r:
                r["domain"] = self._extract_tld(r["url"])
        await client.table("blocked_urls").upsert(
            rows, on_conflict="url_hash", ignore_duplicates=False
        ).execute()

    async def is_blocked(self, url: str) -> dict:
        client = await self._get_client()
        url_hash = hashlib.md5(url.encode("utf-8")).hexdigest()
        response = await client.table("blocked_urls").select("*").eq("url_hash", url_hash).execute()
        data = response.data or []
        if not data:
            return {"is_blocked": False, "reported_by": None}
        reported_by = data[0].get("reported_by")
        return {"is_blocked": True, "reported_by": reported_by}
    
db_manager = DatabaseManager()