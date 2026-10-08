from datetime import datetime, timezone
import json
from sqlalchemy import Column, Integer, String, Float, DateTime, Text, ForeignKey
from cyberfusion.app.database import Base

class UnifiedIncident(Base):
    __tablename__ = "unified_incidents"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    severity = Column(String(50), index=True, default="CRITICAL") # CRITICAL, HIGH, MEDIUM, LOW
    root_cause = Column(Text, nullable=True)
    attack_vector = Column(String(100), default="Multi-Stage Kill-Chain")
    risk_score = Column(Integer, default=95) # 0-100
    mitre_chain = Column(Text, default="[]") # JSON list of TTPs
    containment_status = Column(String(50), default="CONTAINED") # OPEN, CONTAINED, REMEDIATED
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "root_cause": self.root_cause,
            "attack_vector": self.attack_vector,
            "risk_score": self.risk_score,
            "mitre_chain": json.loads(self.mitre_chain or "[]"),
            "containment_status": self.containment_status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }

class UnifiedTimeline(Base):
    __tablename__ = "unified_timelines"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("unified_incidents.id", ondelete="CASCADE"), nullable=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    module_source = Column(String(50), default="SIEM") # Phishing, Identity, Endpoint, API, SIEM, Cloud
    phase = Column(String(100), default="Execution") # Initial Access, Execution, Persistence, PrivEsc, Defense Evasion, C2, Impact
    event_name = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    actor = Column(String(100), nullable=True)
    target = Column(String(100), nullable=True)
    mitre_id = Column(String(50), default="T1059")

    def to_dict(self):
        return {
            "id": self.id,
            "incident_id": self.incident_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "module_source": self.module_source,
            "phase": self.phase,
            "event_name": self.event_name,
            "description": self.description,
            "actor": self.actor,
            "target": self.target,
            "mitre_id": self.mitre_id,
        }
