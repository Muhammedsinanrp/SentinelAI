from datetime import datetime, timezone
import json
from sqlalchemy import Column, Integer, String, DateTime, Text
from cybershield.app.database import Base

class SecurityLog(Base):
    __tablename__ = "security_logs"

    id = Column(Integer, primary_key=True, index=True)
    source_type = Column(String(50), index=True, nullable=False) # linux, windows, wazuh, syslog, web, firewall
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    source_ip = Column(String(100), index=True, nullable=True)
    destination_ip = Column(String(100), nullable=True)
    user = Column(String(100), index=True, nullable=True)
    host = Column(String(255), index=True, nullable=True)
    event_type = Column(String(100), index=True, nullable=False) # failed_login, successful_login, priv_esc, cmd_exec, etc.
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
