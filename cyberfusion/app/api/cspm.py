from fastapi import APIRouter
from cyberfusion.app.schemas.schemas import CloudScanRequest
from cyberfusion.app.modules.cspm.scanner import cspm_scanner

router = APIRouter(prefix="/api/cspm", tags=["Cloud Security (CSPM)"])

@router.post("/scan")
async def audit_cloud(req: CloudScanRequest):
    return await cspm_scanner.audit_cloud_account(req.provider, req.account_id)

@router.get("/findings")
async def get_cloud_findings():
    res = await cspm_scanner.audit_cloud_account("aws", "123456789012")
    return res["findings"]
