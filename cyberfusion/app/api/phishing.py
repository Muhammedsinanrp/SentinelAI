from fastapi import APIRouter
from cyberfusion.app.schemas.schemas import PhishingAnalysisRequest
from cyberfusion.app.modules.phishing.analyzer import phishing_analyzer

router = APIRouter(prefix="/api/phishing", tags=["Phishing Defense & Response"])

@router.post("/analyze")
async def analyze_phishing(req: PhishingAnalysisRequest):
    return phishing_analyzer.analyze(
        target_url=req.target_url,
        sender_email=req.sender_email,
        subject=req.subject,
        content=req.content
    )

@router.get("/recent")
async def get_recent_phishing():
    return [
        {
            "id": 1,
            "target_url": "https://auth-secure-update.xyz/login/verify",
            "sender_email": "security-alert@update-notice.xyz",
            "subject": "URGENT: Re-authenticate Corporate Portal Access",
            "domain": "auth-secure-update.xyz",
            "domain_age_days": 12,
            "risk_score": 94.0,
            "risk_verdict": "CRITICAL",
            "indicators": ["Credential harvesting lure pattern", "High-risk abuse TLD (.xyz)", "SPF/DKIM Validation Failed"]
        }
    ]
