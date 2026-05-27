from dotenv import load_dotenv
import os
from supabase import create_async_client, AsyncClient

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

    async def report_url(self, domain: str, url: str, useragent: str, threat_type: str, reported_by: str):
        client = await self._get_client()
        await client.table("reported_domains").insert({
            "domain": domain,
            "url": url,
            "useragent": useragent,
            "threat_type": threat_type,
            "reported_by": reported_by
        }).execute()

    async def block_url(self, domain: str, threat_type: str, reported_by: str):
        client = await self._get_client()
        await client.table("blocked_domains").upsert({
            "domain": domain,
            "threat_type": threat_type,
            "reported_by": reported_by
        }, on_conflict="domain", ignore_duplicates=False).execute()

    async def batch_block_urls(self, rows: list[dict]):
        client = await self._get_client()
        await client.table("blocked_domains").upsert(
            rows, on_conflict="domain", ignore_duplicates=False
        ).execute()

    async def is_blocked(self, domain: str) -> bool:
        client = await self._get_client()
        response = await client.table("blocked_domains").select("*").eq("domain", domain).execute()
        return len(response.data) > 0
    
db_manager = DatabaseManager()