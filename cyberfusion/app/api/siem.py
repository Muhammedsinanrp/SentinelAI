from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
import json

from cyberfusion.app.database import get_db
from cyberfusion.app.models.siem import SecurityLog, SecurityAlert
from cyberfusion.app.schemas.schemas import LogIngestRequest
from cyberfusion.app.modules.siem.ingestion import LogIngestor
from cyberfusion.app.modules.siem.correlation import siem_correlator

router = APIRouter(prefix="/api/siem", tags=["SIEM / SOC Operations"])

@router.post("/ingest")
async def ingest_log(req: LogIngestRequest, db: AsyncSession = Depends(get_db)):
    parsed = LogIngestor.parse_log(req.source_type, req.raw_message, req.host)
    log_obj = SecurityLog(
        source_type=parsed["source_type"],
        source_ip=parsed["source_ip"],
        user=parsed["user"],
        host=parsed["host"],
        event_type=parsed["event_type"],
        raw_message=parsed["raw_message"],
        parsed_data=json.dumps(parsed["parsed_data"]),
        severity=parsed["severity"]
    )
    db.add(log_obj)

    alerts = siem_correlator.process_event(parsed)
    for al in alerts:
        db.add(SecurityAlert(**al))

    await db.commit()
    return {"status": "success", "event_type": parsed["event_type"], "alerts_count": len(alerts)}

@router.get("/logs")
async def get_logs(limit: int = 30, db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(SecurityLog).order_by(desc(SecurityLog.timestamp)).limit(limit))
    logs = res.scalars().all()
    if not logs:
        return [
            {"source_type": "linux", "timestamp": "12:01:04", "host": "server-01", "raw_message": "sshd[1041]: Failed password for invalid user admin from 185.220.101.5 port 42818", "severity": "MEDIUM"},
            {"source_type": "linux", "timestamp": "12:01:08", "host": "server-01", "raw_message": "sshd[1043]: Failed password for invalid user root from 185.220.101.5 port 42822", "severity": "MEDIUM"},
            {"source_type": "linux", "timestamp": "12:02:01", "host": "server-01", "raw_message": "sshd[1050]: Accepted password for admin from 185.220.101.5 port 42850", "severity": "LOW"},
            {"source_type": "linux", "timestamp": "12:03:22", "host": "server-01", "raw_message": "sudo: admin : USER=root ; COMMAND=/bin/bash", "severity": "HIGH"},
            {"source_type": "firewall", "timestamp": "12:05:32", "host": "server-01", "raw_message": "Kernel: [OUTBOUND_C2] Outbound connection to 185.220.101.5:4444", "severity": "HIGH"}
        ]
    return [l.to_dict() for l in logs]

@router.get("/alerts")
async def get_alerts(db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(SecurityAlert).order_by(desc(SecurityAlert.created_at)))
    alerts = res.scalars().all()
    if not alerts:
        return [
            {"id": 1, "title": "Account Takeover: Successful Login After Brute Force", "severity": "CRITICAL", "source_ip": "185.220.101.5", "target_host": "server-01", "alert_rule": "CF-RULE-002", "mitre_technique": "T1078.003", "status": "INVESTIGATING"},
            {"id": 2, "title": "Privilege Escalation to Root", "severity": "HIGH", "source_ip": "185.220.101.5", "target_host": "server-01", "alert_rule": "CF-RULE-003", "mitre_technique": "T1548.003", "status": "NEW"}
        ]
    return [a.to_dict() for a in alerts]
