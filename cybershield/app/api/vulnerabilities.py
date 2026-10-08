"""
CYBERSHIELD X - Vulnerability Management API
"""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from typing import List, Optional

from cybershield.app.database import get_db
from cybershield.app.models.vulnerability import Vulnerability
from cybershield.app.schemas.schemas import VulnerabilityCreateRequest
from cybershield.app.modules.vuln.manager import VulnerabilityManager

router = APIRouter(prefix="/api/vulns", tags=["Vulnerability Management"])

@router.get("")
async def list_vulnerabilities(
    severity: Optional[str] = Query(None),
    tool_source: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db)
):
    query = select(Vulnerability).order_by(desc(Vulnerability.cvss_score))
    if severity:
        query = query.where(Vulnerability.severity == severity.upper())
    if tool_source:
        query = query.where(Vulnerability.tool_source == tool_source)
    if status:
        query = query.where(Vulnerability.status == status.upper())

    res = await db.execute(query)
    vulns = res.scalars().all()
    return [v.to_dict() for v in vulns]

@router.post("")
async def create_vulnerability(req: VulnerabilityCreateRequest, db: AsyncSession = Depends(get_db)):
    v_obj = Vulnerability(
        asset_target=req.asset_target,
        title=req.title,
        severity=req.severity.upper(),
        cvss_score=req.cvss_score,
        cve_id=req.cve_id,
        vulnerability_type=req.vulnerability_type,
        evidence=req.evidence,
        business_impact=req.business_impact,
        remediation=req.remediation,
        tool_source=req.tool_source,
        status="OPEN"
    )
    db.add(v_obj)
    await db.commit()
    await db.refresh(v_obj)
    return v_obj.to_dict()

@router.post("/nuclei-import")
async def import_nuclei_findings(payload: List[dict], db: AsyncSession = Depends(get_db)):
    imported = []
    for item in payload:
        norm = VulnerabilityManager.normalize_nuclei_finding(item)
        v_obj = Vulnerability(**norm)
        db.add(v_obj)
        imported.append(norm)
    await db.commit()
    return {"status": "success", "imported_count": len(imported)}

@router.patch("/{vuln_id}/status")
async def update_vuln_status(vuln_id: int, status: str, db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    v = res.scalar_one_or_none()
    if not v:
        raise HTTPException(status_code=404, detail="Finding not found")
    v.status = status.upper()
    await db.commit()
    return {"status": "success", "new_status": v.status}
