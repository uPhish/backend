import requests
import csv
import gzip
import asyncio
from urllib.parse import urlparse
from services.database import db_manager as db

BATCH_SIZE = 200

def _extract_tld(url: str) -> str:
    t = urlparse(url).netloc
    return '.'.join(t.split('.')[-2:])

async def fetch_phishtank_data():
    url = 'https://data.phishtank.com/data/online-valid.csv'
    response = requests.get(url)

    content = response.content
    if content[:2] == b'\x1f\x8b':
        content = gzip.decompress(content)
    decoded_content = content.decode('utf-8')
    csv_reader = csv.DictReader(decoded_content.splitlines())

    batch: list[dict] = []
    for row in csv_reader:
        if row["verified"] == "yes":
            tld = _extract_tld(row["url"])
            if row["url"]:
                batch.append({
                    "domain": tld,
                    "url": row["url"],
                    "threat_type": "Phishing",
                    "reported_by": "PhishTank"
                })
            if len(batch) >= BATCH_SIZE:
                deduped = {item["url"]: item for item in batch}.values()
                await db.batch_block_urls(list(deduped))
                batch.clear()

    if batch:
        deduped = {item["url"]: item for item in batch}.values()
        await db.batch_block_urls(list(deduped))