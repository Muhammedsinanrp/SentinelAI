from fastapi import APIRouter
from cyberfusion.app.schemas.schemas import APIScanRequest
from cyberfusion.app.modules.api_sec.auditor import api_auditor

router = APIRouter(prefix="/api/apisec", tags=["API Security"])

@router.post("/scan")
async def scan_apis(req: APIScanRequest):
    return await api_auditor.audit_api_surface(req.base_url)

@router.get("/inventory")
async def get_inventory():
    res = await api_auditor.audit_api_surface()
    return res
