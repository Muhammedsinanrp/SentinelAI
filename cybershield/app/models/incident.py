from datetime import datetime, timezone
import json
from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey
from cybershield.app.database import Base

class SecurityAlert(Base):
    __tablename__ = "security_alerts"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    severity = Column(String(50), index=True, nullable=False) # CRITICAL, HIGH, MEDIUM, LOW
    category = Column(String(100), default="Intrusion Detection")
    source_ip = Column(String(100), index=True, nullable=True)
    target_host = Column(String(255), index=True, nullable=True)
    alert_rule = Column(String(100), nullable=False)
    description = Column(Text, nullable=False)
    raw_events_count = Column(Integer, default=1)
    mitre_technique = Column(String(100), default="T1110") # MITRE ATT&CK
    status = Column(String(50), default="NEW") # NEW, INVESTIGATING, CONTAINED, CLOSED
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "source_ip": self.source_ip,
            "target_host": self.target_host,
            "alert_rule": self.alert_rule,
            "description": self.description,
            "raw_events_count": self.raw_events_count,
            "mitre_technique": self.mitre_technique,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

class IncidentTimeline(Base):
    __tablename__ = "incident_timelines"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(Integer, ForeignKey("security_alerts.id", ondelete="CASCADE"), nullable=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    event_name = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    actor = Column(String(100), nullable=True)
    target = Column(String(100), nullable=True)
    mitre_id = Column(String(50), nullable=True)
    phase = Column(String(100), default="Initial Access") # Recon, Initial Access, Execution, Persistence, PrivEsc, C2, Exfil

    def to_dict(self):
        return {
            "id": self.id,
            "alert_id": self.alert_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "event_name": self.event_name,
            "description": self.description,
            "actor": self.actor,
            "target": self.target,
            "mitre_id": self.mitre_id,
            "phase": self.phase,
        }
