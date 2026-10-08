from fastapi import APIRouter
from cyberfusion.app.schemas.schemas import IdentityAuthEventRequest
from cyberfusion.app.modules.identity.detector import identity_detector

router = APIRouter(prefix="/api/identity", tags=["Identity & IAM Threat Detection"])

@router.post("/auth-event")
async def evaluate_auth(req: IdentityAuthEventRequest):
    return identity_detector.analyze_auth_event(
        user_email=req.user_email,
        source_ip=req.source_ip,
        location=req.location,
        device=req.device_fingerprint
    )

@router.get("/users")
async def get_user_profiles():
    return [
        {"user_email": "admin@company.com", "department": "Infrastructure", "baseline_country": "India", "overall_risk_score": 88, "active_threats": "Impossible Travel + Off-Hours Login"},
        {"user_email": "dev.lead@company.com", "department": "Engineering", "baseline_country": "Germany", "overall_risk_score": 24, "active_threats": "None"},
        {"user_email": "finance@company.com", "department": "Finance", "baseline_country": "United States", "overall_risk_score": 15, "active_threats": "None"}
    ]
