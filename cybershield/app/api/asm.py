"""
CYBERSHIELD X - Attack Surface Management (ASM) API
"""
import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from cybershield.app.database import get_db
from cybershield.app.config import settings
from cybershield.app.models.asset import Asset
from cybershield.app.models.vulnerability import Vulnerability
from cybershield.app.schemas.schemas import ScopeCheckRequest, ScopeCheckResponse, ScanRequest
from cybershield.app.modules.asm.scope import check_scope, extract_host
from cybershield.app.modules.asm.scanner import ASMScanner
from cybershield.app.modules.vuln.manager import VulnerabilityManager

router = APIRouter(prefix="/api/asm", tags=["Attack Surface Management"])
scanner = ASMScanner()
vuln_manager = VulnerabilityManager()

@router.post("/check-scope", response_model=ScopeCheckResponse)
async def check_target_scope(req: ScopeCheckRequest):
    is_in_scope, reason = check_scope(req.target, settings.in_scope, settings.out_of_scope)
    return ScopeCheckResponse(
        target=req.target,
        is_in_scope=is_in_scope,
        reason=reason
    )

@router.post("/scan")
async def scan_target(req: ScanRequest, db: AsyncSession = Depends(get_db)):
    # 1. Scope Gate Check
    host = extract_host(req.domain)
    is_allowed, reason = check_scope(host, settings.in_scope, settings.out_of_scope)
    if not is_allowed:
        raise HTTPException(
            status_code=403,
            detail=f"SECURITY VIOLATION: Target '{host}' is OUT OF SCOPE. Reason: {reason}"
        )

    # 2. ASM Discovery
    asm_result = await scanner.scan_domain(host, discover_subdomains=True)

    # 3. Store / Update Asset in DB
    existing = await db.execute(select(Asset).where(Asset.domain == host))
    asset = existing.scalar_one_or_none()

    if not asset:
        asset = Asset(
            domain=host,
            root_domain=asm_result["root_domain"],
            ip_addresses=json.dumps(asm_result["ip_addresses"]),
            dns_records=json.dumps(asm_result["dns_records"]),
            open_ports=json.dumps(asm_result["open_ports"]),
            technologies=json.dumps(asm_result["technologies"]),
            security_headers=json.dumps(asm_result["security_headers"]),
            tls_info=json.dumps(asm_result["tls_info"]),
            is_in_scope=True,
            status="active"
        )
        db.add(asset)
    else:
        asset.ip_addresses = json.dumps(asm_result["ip_addresses"])
        asset.dns_records = json.dumps(asm_result["dns_records"])
        asset.open_ports = json.dumps(asm_result["open_ports"])
        asset.technologies = json.dumps(asm_result["technologies"])
        asset.security_headers = json.dumps(asm_result["security_headers"])
        asset.tls_info = json.dumps(asm_result["tls_info"])

    await db.flush()

    # 4. Optional Automated Vulnerability Assessment
    new_findings = []
    if req.run_vuln_scan:
        findings = await vuln_manager.run_owasp_checks(host, asm_result)
        for f in findings:
            v_obj = Vulnerability(
                asset_id=asset.id,
                asset_target=f["asset_target"],
                title=f["title"],
                severity=f["severity"],
                cvss_score=f["cvss_score"],
                cve_id=f.get("cve_id"),
                vulnerability_type=f["vulnerability_type"],
                evidence=f.get("evidence"),
                business_impact=f.get("business_impact"),
                remediation=f.get("remediation"),
                tool_source=f.get("tool_source", "OWASP-Audit"),
                status="OPEN"
            )
            db.add(v_obj)
            new_findings.append(f)

    # Add discovered subdomains if any
    for sub in asm_result.get("discovered_subdomains", []):
        if sub != host:
            sub_exist = await db.execute(select(Asset).where(Asset.domain == sub))
            if not sub_exist.scalar_one_or_none():
                db.add(Asset(
                    domain=sub,
                    root_domain=host,
                    is_in_scope=True,
                    status="discovered"
                ))

    await db.commit()
    await db.refresh(asset)

    return {
        "status": "success",
        "asset": asset.to_dict(),
        "discovered_subdomains_count": len(asm_result.get("discovered_subdomains", [])),
        "vulnerabilities_identified": len(new_findings)
    }

@router.get("/assets")
async def list_assets(db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(Asset).order_by(desc(Asset.created_at)))
    assets = res.scalars().all()
    return [a.to_dict() for a in assets]

@router.get("/assets/{asset_id}")
async def get_asset_detail(asset_id: int, db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = res.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=404, detail="Asset not found")
    return asset.to_dict()
