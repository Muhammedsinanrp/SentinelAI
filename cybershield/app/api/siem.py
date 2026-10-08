"""
CYBERSHIELD X - Real SOC / SIEM Module API
"""
import json
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from typing import List, Optional

from cybershield.app.database import get_db
from cybershield.app.models.log import SecurityLog
from cybershield.app.models.incident import SecurityAlert, IncidentTimeline
from cybershield.app.schemas.schemas import LogIngestRequest, BatchLogIngestRequest
from cybershield.app.modules.siem.ingestion import LogIngestor
from cybershield.app.modules.siem.correlation import siem_correlator

router = APIRouter(prefix="/api/siem", tags=["SIEM / SOC Operations"])

@router.post("/ingest")
async def ingest_log(req: LogIngestRequest, db: AsyncSession = Depends(get_db)):
    # 1. Parse & Normalize Log
    parsed = LogIngestor.parse_log(req.source_type, req.raw_message, req.host)
    if req.source_ip:
        parsed["source_ip"] = req.source_ip
    if req.user:
        parsed["user"] = req.user
    if req.event_type:
        parsed["event_type"] = req.event_type

    # 2. Persist Raw Log
    log_obj = SecurityLog(
        source_type=parsed["source_type"],
        source_ip=parsed["source_ip"],
        destination_ip=parsed["destination_ip"],
        user=parsed["user"],
        host=parsed["host"],
        event_type=parsed["event_type"],
        raw_message=parsed["raw_message"],
        parsed_data=json.dumps(parsed["parsed_data"]),
        severity=parsed["severity"]
    )
    db.add(log_obj)

    # 3. Real-Time Correlation
    alerts = siem_correlator.process_event(parsed)
    created_alerts = []

    for al in alerts:
        alert_record = SecurityAlert(
            title=al["title"],
            severity=al["severity"],
            category=al["category"],
            source_ip=al["source_ip"],
            target_host=al["target_host"],
            alert_rule=al["alert_rule"],
            description=al["description"],
            raw_events_count=al["raw_events_count"],
            mitre_technique=al["mitre_technique"],
            status=al["status"]
        )
        db.add(alert_record)
        await db.flush()

        # Link timeline events
        for ev in al.get("timeline_events", []):
            db.add(IncidentTimeline(
                alert_id=alert_record.id,
                timestamp=ev.get("timestamp", datetime.now(timezone.utc)),
                event_name=ev.get("event_name"),
                description=ev.get("description"),
                actor=ev.get("actor"),
                target=ev.get("target"),
                mitre_id=ev.get("mitre_id"),
                phase=ev.get("phase", "Initial Access")
            ))
        created_alerts.append(alert_record.to_dict())

    await db.commit()
    return {
        "status": "success",
        "log_id": log_obj.id,
        "event_type": parsed["event_type"],
        "alerts_triggered": len(created_alerts),
        "alerts": created_alerts
    }

@router.get("/logs")
async def get_logs(limit: int = 50, db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(SecurityLog).order_by(desc(SecurityLog.timestamp)).limit(limit))
    logs = res.scalars().all()
    return [l.to_dict() for l in logs]

@router.get("/alerts")
async def get_alerts(db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(SecurityAlert).order_by(desc(SecurityAlert.created_at)))
    alerts = res.scalars().all()
    return [a.to_dict() for a in alerts]

@router.post("/simulate-attack")
async def simulate_attack_chain(db: AsyncSession = Depends(get_db)):
    """
    Simulates the exact realistic multi-stage intrusion sequence:
    1. Multiple failed SSH logins (Brute force)
    2. Successful login from same IP (Compromise)
    3. Privilege escalation
    4. Suspicious command execution
    5. Outbound C2 connection
    """
    attacker_ip = "194.26.29.110"
    victim_host = "prod-db-01.internal"
    base_time = datetime.now(timezone.utc) - timedelta(minutes=6)

    attack_steps = [
        # Brute force attempts
        {"type": "linux", "msg": f"sshd[3101]: Failed password for invalid user admin from {attacker_ip} port 51221 ssh2", "delta": 300},
        {"type": "linux", "msg": f"sshd[3104]: Failed password for invalid user root from {attacker_ip} port 51224 ssh2", "delta": 270},
        {"type": "linux", "msg": f"sshd[3109]: Failed password for invalid user oracle from {attacker_ip} port 51228 ssh2", "delta": 240},
        {"type": "linux", "msg": f"sshd[3115]: Failed password for user postgres from {attacker_ip} port 51232 ssh2", "delta": 210},
        # Successful login
        {"type": "linux", "msg": f"sshd[3120]: Accepted password for postgres from {attacker_ip} port 51240 ssh2", "delta": 150},
        # Privilege escalation
        {"type": "linux", "msg": f"sudo: postgres : TTY=pts/2 ; PWD=/home/postgres ; USER=root ; COMMAND=/bin/bash", "delta": 90},
        # Suspicious command execution
        {"type": "linux", "msg": f"bash[3145]: whoami && uname -a && cat /etc/shadow && mimikatz", "delta": 60},
        # Outbound C2
        {"type": "firewall", "msg": f"Kernel: [FW_OUT] Outbound connection to C2 IP {attacker_ip}:4444 established", "delta": 10}
    ]

    all_alerts = []
    for step in attack_steps:
        parsed = LogIngestor.parse_log(step["type"], step["msg"], victim_host)
        # Log to DB
        log_obj = SecurityLog(
            source_type=parsed["source_type"],
            source_ip=parsed["source_ip"] or attacker_ip,
            host=victim_host,
            event_type=parsed["event_type"],
            raw_message=parsed["raw_message"],
            parsed_data=json.dumps(parsed["parsed_data"]),
            severity=parsed["severity"],
            timestamp=datetime.now(timezone.utc) - timedelta(seconds=step["delta"])
        )
        db.add(log_obj)

        alerts = siem_correlator.process_event(parsed)
        for al in alerts:
            al_obj = SecurityAlert(
                title=al["title"],
                severity=al["severity"],
                category=al["category"],
                source_ip=al["source_ip"],
                target_host=al["target_host"],
                alert_rule=al["alert_rule"],
                description=al["description"],
                raw_events_count=al["raw_events_count"],
                mitre_technique=al["mitre_technique"],
                status="NEW"
            )
            db.add(al_obj)
            await db.flush()

            for ev in al.get("timeline_events", []):
                db.add(IncidentTimeline(
                    alert_id=al_obj.id,
                    timestamp=ev.get("timestamp", datetime.now(timezone.utc)),
                    event_name=ev.get("event_name"),
                    description=ev.get("description"),
                    actor=ev.get("actor"),
                    target=ev.get("target"),
                    mitre_id=ev.get("mitre_id"),
                    phase=ev.get("phase")
                ))
            all_alerts.append(al_obj.to_dict())

    await db.commit()
    return {
        "status": "success",
        "message": f"Successfully simulated full kill-chain attack from {attacker_ip} targeting {victim_host}.",
        "alerts_generated": len(all_alerts),
        "alerts": all_alerts
    }
