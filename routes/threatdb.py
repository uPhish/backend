import fastapi
from fastapi import Depends

from services.database import db_manager as db

router = fastapi.APIRouter(
    prefix="/threatdb",
    tags=["threatdb"]
)

@router.get("/check")
async def check_url(url: str):
    result = await db.is_blocked(url)
    return result

@router.post("/report")
async def report_url(url: str, useragent: str):
    await db.report_url(None, url, useragent, None, "Extension")
    return 200