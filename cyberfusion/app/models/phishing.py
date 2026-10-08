from datetime import datetime, timezone
import json
from sqlalchemy import Column, Integer, String, Float, DateTime, Text
from cyberfusion.app.database import Base

class PhishingSubmission(Base):
    __tablename__ = "phishing_submissions"

    id = Column(Integer, primary_key=True, index=True)
    target_url = Column(String(500), nullable=True)
    sender_email = Column(String(255), nullable=True)
    subject = Column(String(255), nullable=True)
    domain = Column(String(255), index=True, nullable=True)
    domain_age_days = Column(Integer, default=0)
    risk_score = Column(Float, default=0.0) # 0-100%
    risk_verdict = Column(String(50), default="CLEAN") # CRITICAL, HIGH, MEDIUM, CLEAN
    indicators = Column(Text, default="[]") # JSON list of flags
    headers_analysis = Column(Text, default="{}") # SPF, DKIM, DMARC
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    def to_dict(self):
        return {
            "id": self.id,
            "target_url": self.target_url,
            "sender_email": self.sender_email,
            "subject": self.subject,
            "domain": self.domain,
            "domain_age_days": self.domain_age_days,
            "risk_score": self.risk_score,
            "risk_verdict": self.risk_verdict,
            "indicators": json.loads(self.indicators or "[]"),
            "headers_analysis": json.loads(self.headers_analysis or "{}"),
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }
