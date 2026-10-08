from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Float, DateTime
from cyberfusion.app.database import Base

class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"

    id = Column(Integer, primary_key=True, index=True)
    indicator_value = Column(String(255), unique=True, index=True, nullable=False) # IP, Domain, Hash
    indicator_type = Column(String(50), index=True, nullable=False) # IP, DOMAIN, HASH, CVE, TTP
    threat_name = Column(String(100), default="Known Malicious Actor")
    confidence = Column(Float, default=95.0) # 0-100%
    mitre_id = Column(String(50), default="T1071")
    source = Column(String(100), default="CyberFusion Threat Feed")
    last_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id": self.id,
            "indicator_value": self.indicator_value,
            "indicator_type": self.indicator_type,
            "threat_name": self.threat_name,
            "confidence": self.confidence,
            "mitre_id": self.mitre_id,
            "source": self.source,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
        }
