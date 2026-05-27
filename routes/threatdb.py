import fastapi
from fastapi import Depends

from services.database import db_manager as db

router = fastapi.APIRouter(
    prefix="/threatdb",
    tags=["threatdb"]
)

@router.get("/check/{domain}")
async def check_domain(domain: str):
    is_blocked = await db.is_blocked(domain)
    return is_blocked

@router.post("/report")
async def report_domain(domain: str, url: str, useragent: str):
    await db.report_url(domain, url, useragent, None, "Extension")
    return 200