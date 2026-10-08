"""
CYBERSHIELD X - Dashboard & Metrics API
"""
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from datetime import datetime, timezone, timedelta
import json

from cybershield.app.database import get_db
from cybershield.app.models.asset import Asset
from cybershield.app.models.vulnerability import Vulnerability
from cybershield.app.models.incident import SecurityAlert, IncidentTimeline
from cybershield.app.models.log import SecurityLog
from cybershield.app.modules.vuln.cvss import calculate_org_risk_score

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])

@router.get("/stats")
async def get_dashboard_stats(db: AsyncSession = Depends(get_db)):
    # Total Assets
    assets_res = await db.execute(select(func.count(Asset.id)))
    total_assets = assets_res.scalar() or 0

    # Vulnerabilities
    vuln_res = await db.execute(select(Vulnerability))
    all_vulns = vuln_res.scalars().all()
    vuln_dicts = [v.to_dict() for v in all_vulns]

    crit_count = sum(1 for v in all_vulns if v.severity == "CRITICAL")
    high_count = sum(1 for v in all_vulns if v.severity == "HIGH")
    med_count = sum(1 for v in all_vulns if v.severity == "MEDIUM")
    low_count = sum(1 for v in all_vulns if v.severity in ["LOW", "INFO"])

    # Alerts
    alerts_res = await db.execute(select(func.count(SecurityAlert.id)))
    total_alerts = alerts_res.scalar() or 0

    # Recent Alerts
    recent_alerts_res = await db.execute(
        select(SecurityAlert).order_by(desc(SecurityAlert.created_at)).limit(6)
    )
    recent_incidents = [a.to_dict() for a in recent_alerts_res.scalars().all()]

    # Risk Score Calculation
    risk_score = calculate_org_risk_score(vuln_dicts, total_alerts, max(1, total_assets))

    return {
        "total_assets": total_assets,
        "critical_vulnerabilities": crit_count,
        "high_vulnerabilities": high_count,
        "total_alerts": total_alerts,
        "risk_score": risk_score,
        "severity_breakdown": {
            "Critical": crit_count,
            "High": high_count,
            "Medium": med_count,
            "Low": low_count
        },
        "recent_incidents": recent_incidents
    }

@router.post("/seed-demo")
async def seed_demo_data(db: AsyncSession = Depends(get_db)):
    """
    Populates rich, realistic demo data matching the CYBERSHIELD X specification.
    """
    # 1. Assets
    demo_assets = [
        {
            "domain": "example.com",
            "root_domain": "example.com",
            "ip_addresses": json.dumps(["93.184.216.34"]),
            "open_ports": json.dumps([{"port": 80, "service": "HTTP"}, {"port": 443, "service": "HTTPS"}]),
            "technologies": json.dumps(["Nginx/1.24", "Cloudflare", "OpenSSL 3.0"]),
            "is_in_scope": True,
            "status": "active"
        },
        {
            "domain": "api.example.com",
            "root_domain": "example.com",
            "ip_addresses": json.dumps(["93.184.216.35"]),
            "open_ports": json.dumps([{"port": 443, "service": "HTTPS"}, {"port": 8443, "service": "API Gateway"}]),
            "technologies": json.dumps(["Node.js", "Express", "PostgreSQL"]),
            "is_in_scope": True,
            "status": "active"
        },
        {
            "domain": "vpn.example.com",
            "root_domain": "example.com",
            "ip_addresses": json.dumps(["93.184.216.40"]),
            "open_ports": json.dumps([{"port": 443, "service": "OpenVPN"}, {"port": 22, "service": "SSH"}]),
            "technologies": json.dumps(["OpenVPN Access Server", "Ubuntu 22.04"]),
            "is_in_scope": True,
            "status": "active"
        },
        {
            "domain": "dev.example.com",
            "root_domain": "example.com",
            "ip_addresses": json.dumps(["93.184.216.45"]),
            "open_ports": json.dumps([{"port": 8080, "service": "Jenkins"}, {"port": 22, "service": "SSH"}]),
            "technologies": json.dumps(["Jenkins CI", "Docker"]),
            "is_in_scope": True,
            "status": "active"
        }
    ]
    for da in demo_assets:
        existing = await db.execute(select(Asset).where(Asset.domain == da["domain"]))
        if not existing.scalar_one_or_none():
            db.add(Asset(**da))

    # 2. Vulnerabilities
    demo_vulns = [
        {
            "asset_target": "api.example.com",
            "title": "SQL Injection in User Authentication Endpoint",
            "severity": "CRITICAL",
            "cvss_score": 9.8,
            "cve_id": "CVE-2024-3400",
            "vulnerability_type": "Injection (OWASP A03)",
            "evidence": "Payload: ' UNION SELECT null, username, password_hash FROM admin_users-- returned 200 OK with table records.",
            "business_impact": "Potential unauthorized database access, full credential exfiltration, and tenant compromise.",
            "remediation": "Implement parameterized queries (prepared statements) and ORM-level input sanitization.",
            "tool_source": "Nuclei",
            "status": "OPEN"
        },
        {
            "asset_target": "vpn.example.com",
            "title": "Exposed SSH Port with Outdated OpenSSH Version",
            "severity": "HIGH",
            "cvss_score": 7.8,
            "cve_id": "CVE-2024-6387",
            "vulnerability_type": "Vulnerable Software (regreSSHion)",
            "evidence": "Banner: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6 vulnerable to remote code execution signal race condition.",
            "business_impact": "Unauthenticated remote code execution as root under specific timing conditions.",
            "remediation": "Upgrade OpenSSH to version 9.8p1 or newer, and restrict port 22 access via IP whitelist.",
            "tool_source": "Nmap",
            "status": "OPEN"
        },
        {
            "asset_target": "example.com",
            "title": "Missing HTTP Strict Transport Security (HSTS)",
            "severity": "MEDIUM",
            "cvss_score": 5.3,
            "cve_id": None,
            "vulnerability_type": "Cryptographic Failure (OWASP A02)",
            "evidence": "Header 'Strict-Transport-Security' not present in response from https://example.com",
            "business_impact": "Enables adversary to execute SSL stripping attacks on unencrypted WiFi networks.",
            "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' header.",
            "tool_source": "OWASP-Audit",
            "status": "OPEN"
        }
    ]
    for dv in demo_vulns:
        existing = await db.execute(select(Vulnerability).where(Vulnerability.title == dv["title"]))
        if not existing.scalar_one_or_none():
            db.add(Vulnerability(**dv))

    # 3. Security Alert & Attack Timeline
    existing_alert = await db.execute(
        select(SecurityAlert).where(SecurityAlert.title == "CRITICAL: Successful Logon Followed by Brute Force")
    )
    alert_obj = existing_alert.scalar_one_or_none()
    if not alert_obj:
        alert_obj = SecurityAlert(
            title="CRITICAL: Successful Logon Followed by Brute Force",
            severity="CRITICAL",
            category="Account Compromise",
            source_ip="185.220.101.5",
            target_host="server-01.example.com",
            alert_rule="CS-RULE-002",
            description="47 failed authentication attempts within 4 minutes from 185.220.101.5 followed by successful root session and privilege escalation.",
            raw_events_count=52,
            mitre_technique="T1078.003",
            status="INVESTIGATING"
        )
        db.add(alert_obj)
        await db.flush()

        # Timeline steps
        now = datetime.now(timezone.utc)
        timeline_steps = [
            ("Failed SSH login", "Failed password for root from 185.220.101.5 port 42818", "185.220.101.5", "server-01", "T1110.001", "Credential Access", 240),
            ("Failed SSH login", "Failed password for admin from 185.220.101.5 port 42822", "185.220.101.5", "server-01", "T1110.001", "Credential Access", 180),
            ("Failed SSH login", "Failed password for ubuntu from 185.220.101.5 port 42830", "185.220.101.5", "server-01", "T1110.001", "Credential Access", 120),
            ("Successful login", "Accepted password for deployer from 185.220.101.5 port 42850", "185.220.101.5", "server-01", "T1078", "Initial Access", 90),
            ("Privilege escalation", "sudo: deployer : USER=root ; COMMAND=/bin/bash", "deployer", "server-01", "T1548.003", "Privilege Escalation", 60),
            ("Suspicious command execution", "whoami && uname -a && cat /etc/shadow", "root", "server-01", "T1059", "Execution", 30),
            ("Outbound connection", "Outbound TCP session established to 185.220.101.5:4444", "server-01", "185.220.101.5", "T1071.001", "Command and Control", 5)
        ]
        for name, desc_text, actor, target, mitre, phase, sec_ago in timeline_steps:
            db.add(IncidentTimeline(
                alert_id=alert_obj.id,
                timestamp=now - timedelta(seconds=sec_ago),
                event_name=name,
                description=desc_text,
                actor=actor,
                target=target,
                mitre_id=mitre,
                phase=phase
            ))

    await db.commit()
    return {"status": "success", "message": "Demo security operations environment seeded successfully."}
