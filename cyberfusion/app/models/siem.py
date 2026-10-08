from datetime import datetime, timezone
import json
from sqlalchemy import Column, Integer, String, DateTime, Text
from cyberfusion.app.database import Base

class SecurityLog(Base):
    __tablename__ = "security_logs"

    id = Column(Integer, primary_key=True, index=True)
    source_type = Column(String(50), index=True, nullable=False) # linux, windows, wazuh, syslog, web, firewall, cloud
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    source_ip = Column(String(100), index=True, nullable=True)
    destination_ip = Column(String(100), nullable=True)
    user = Column(String(100), index=True, nullable=True)
    host = Column(String(255), index=True, nullable=True)
    event_type = Column(String(100), index=True, nullable=False)
    raw_message = Column(Text, nullable=False)
    parsed_data = Column(Text, default="{}")
    severity = Column(String(50), default="INFO")

    def to_dict(self):
        return {
            "id": self.id,
            "source_type": self.source_type,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "user": self.user,
            "host": self.host,
            "event_type": self.event_type,
            "raw_message": self.raw_message,
            "parsed_data": json.loads(self.parsed_data or "{}"),
            "severity": self.severity,
        }

class SecurityAlert(Base):
    __tablename__ = "security_alerts"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    severity = Column(String(50), index=True, nullable=False)
    category = Column(String(100), default="Intrusion Detection")
    source_ip = Column(String(100), index=True, nullable=True)
    target_host = Column(String(255), index=True, nullable=True)
    alert_rule = Column(String(100), nullable=False)
    description = Column(Text, nullable=False)
    raw_events_count = Column(Integer, default=1)
    mitre_technique = Column(String(100), default="T1110")
    status = Column(String(50), default="NEW")
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
