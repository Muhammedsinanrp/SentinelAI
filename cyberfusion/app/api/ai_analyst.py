from fastapi import APIRouter
from cyberfusion.app.schemas.schemas import AIInvestigationRequest
from cyberfusion.app.modules.ai_analyst.correlation import unified_correlator
from cyberfusion.app.modules.ai_analyst.analyst import ai_analyst

router = APIRouter(prefix="/api/ai", tags=["AI Security Analyst"])

@router.post("/investigate")
async def run_investigation(req: AIInvestigationRequest):
    # Correlate cross-domain multi-vector incident
    incident = unified_correlator.build_cross_domain_incident()
    dossier = await ai_analyst.investigate(incident, req.query)
    return {
        "status": "success",
        "incident": incident,
        "dossier": dossier,
        "timeline": incident["timeline"]
    }

@router.get("/timeline")
async def get_unified_timeline():
    incident = unified_correlator.build_cross_domain_incident()
    return incident["timeline"]
