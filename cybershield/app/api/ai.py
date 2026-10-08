"""
CYBERSHIELD X - AI Security Analyst API
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from typing import Optional, List, Dict, Any
from pydantic import BaseModel

from cybershield.app.database import get_db
from cybershield.app.models.incident import SecurityAlert, IncidentTimeline
from cybershield.app.models.asset import Asset
from cybershield.app.models.vulnerability import Vulnerability
from cybershield.app.schemas.schemas import AIInvestigationRequest
from cybershield.app.modules.ai_analyst.timeline import TimelineBuilder
from cybershield.app.modules.ai_analyst.correlation import IncidentContextAggregator
from cybershield.app.modules.ai_analyst.analyst import ai_analyst_service

router = APIRouter(prefix="/api/ai", tags=["AI Security Analyst"])

class AIChatRequest(BaseModel):
    message: str
    alert_id: Optional[int] = None

@router.post("/investigate")
async def investigate_alert(req: AIInvestigationRequest, db: AsyncSession = Depends(get_db)):
    alert_dict = {}
    timeline_events = []
    asset_dict = None
    vuln_dicts = []

    if req.alert_id:
        res = await db.execute(select(SecurityAlert).where(SecurityAlert.id == req.alert_id))
        alert_obj = res.scalar_one_or_none()
        if alert_obj:
            alert_dict = alert_obj.to_dict()

            # Timeline
            tl_res = await db.execute(
                select(IncidentTimeline).where(IncidentTimeline.alert_id == req.alert_id).order_by(IncidentTimeline.timestamp)
            )
            raw_tl = [t.to_dict() for t in tl_res.scalars().all()]
            timeline_events = TimelineBuilder.format_timeline_chain(raw_tl)

            # Asset context
            host = alert_obj.target_host or ""
            domain = host.split(":")[0]
            ast_res = await db.execute(select(Asset).where(Asset.domain == domain))
            ast = ast_res.scalar_one_or_none()
            if ast:
                asset_dict = ast.to_dict()

            # Vulns
            vl_res = await db.execute(select(Vulnerability).where(Vulnerability.asset_target.like(f"%{domain}%")))
            vuln_dicts = [v.to_dict() for v in vl_res.scalars().all()]
    else:
        # Fallback to latest alert
        res = await db.execute(select(SecurityAlert).order_by(desc(SecurityAlert.created_at)).limit(1))
        alert_obj = res.scalar_one_or_none()
        if alert_obj:
            alert_dict = alert_obj.to_dict()
            tl_res = await db.execute(
                select(IncidentTimeline).where(IncidentTimeline.alert_id == alert_obj.id).order_by(IncidentTimeline.timestamp)
            )
            raw_tl = [t.to_dict() for t in tl_res.scalars().all()]
            timeline_events = TimelineBuilder.format_timeline_chain(raw_tl)
        else:
            alert_dict = {
                "title": "SSH Brute Force with Compromise",
                "severity": "CRITICAL",
                "source_ip": "185.220.101.5",
                "target_host": "server-01",
                "mitre_technique": "T1110.001",
                "description": "Observed 47 failed attempts followed by interactive login and privilege escalation."
            }

    # Build multi-source security context
    context_text = IncidentContextAggregator.build_security_context(
        alert=alert_dict,
        asset=asset_dict,
        vulns=vuln_dicts,
        timeline=timeline_events
    )

    if req.incident_context:
        context_text += f"\n--- USER SUPPLEMENTAL INTEL ---\n{req.incident_context}"

    # Query AI Analyst
    dossier = await ai_analyst_service.investigate(context_text, alert_dict, timeline_events)

    return {
        "status": "success",
        "alert": alert_dict,
        "timeline": timeline_events,
        "dossier": dossier,
        "context_brief": context_text
    }

@router.get("/timeline/{alert_id}")
async def get_alert_timeline(alert_id: int, db: AsyncSession = Depends(get_db)):
    res = await db.execute(
        select(IncidentTimeline).where(IncidentTimeline.alert_id == alert_id).order_by(IncidentTimeline.timestamp)
    )
    raw_events = [e.to_dict() for e in res.scalars().all()]
    formatted = TimelineBuilder.format_timeline_chain(raw_events)
    return {"alert_id": alert_id, "timeline": formatted}

@router.post("/chat")
async def chat_with_analyst(req: AIChatRequest, db: AsyncSession = Depends(get_db)):
    alert_info = {}
    if req.alert_id:
        res = await db.execute(select(SecurityAlert).where(SecurityAlert.id == req.alert_id))
        al = res.scalar_one_or_none()
        if al:
            alert_info = al.to_dict()

    prompt = f"Security Analyst Question: {req.message}\nActive Alert Context: {alert_info}"
    dossier = await ai_analyst_service.investigate(prompt, alert_info)
    return {
        "response": dossier.get("incident_summary", "Analysis completed."),
        "details": dossier
    }
