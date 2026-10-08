from datetime import datetime, timezone
import json
from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text
from cyberfusion.app.database import Base

class IdentityEvent(Base):
    __tablename__ = "identity_events"

    id = Column(Integer, primary_key=True, index=True)
    user_email = Column(String(255), index=True, nullable=False)
    source_ip = Column(String(100), index=True, nullable=False)
    location = Column(String(100), default="Unknown") # "India", "Russia", etc.
    device_fingerprint = Column(String(255), default="Unknown Device")
    is_impossible_travel = Column(Boolean, default=False)
    speed_kmh = Column(Float, default=0.0)
    anomaly_reasons = Column(Text, default="[]") # JSON list of reasons
    risk_score = Column(Integer, default=10) # 0-100
    status = Column(String(50), default="REVIEW")
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    def to_dict(self):
        return {
            "id": self.id,
            "user_email": self.user_email,
            "source_ip": self.source_ip,
            "location": self.location,
            "device_fingerprint": self.device_fingerprint,
            "is_impossible_travel": self.is_impossible_travel,
            "speed_kmh": self.speed_kmh,
            "anomaly_reasons": json.loads(self.anomaly_reasons or "[]"),
            "risk_score": self.risk_score,
            "status": self.status,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }

class UserRiskProfile(Base):
    __tablename__ = "user_risk_profiles"

    id = Column(Integer, primary_key=True, index=True)
    user_email = Column(String(255), unique=True, index=True, nullable=False)
    department = Column(String(100), default="Engineering")
    baseline_country = Column(String(100), default="India")
    baseline_device = Column(String(100), default="Windows 11")
    overall_risk_score = Column(Integer, default=15)
    active_threats_count = Column(Integer, default=0)

    def to_dict(self):
        return {
            "id": self.id,
            "user_email": self.user_email,
            "department": self.department,
            "baseline_country": self.baseline_country,
            "baseline_device": self.baseline_device,
            "overall_risk_score": self.overall_risk_score,
            "active_threats_count": self.active_threats_count,
        }
