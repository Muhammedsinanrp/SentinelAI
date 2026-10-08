from fastapi import APIRouter
from cyberfusion.app.modules.threat_intel.engine import threat_intel_engine, MOCK_IOC_DATABASE

router = APIRouter(prefix="/api/intel", tags=["Threat Intelligence"])

@router.get("/lookup/{ioc}")
async def lookup_indicator(ioc: str):
    return threat_intel_engine.lookup_ioc(ioc)

@router.get("/feeds")
async def get_feeds():
    return [{"indicator": k, **v} for k, v in MOCK_IOC_DATABASE.items()]
