from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text
from cyberfusion.app.database import Base

class APIEndpoint(Base):
    __tablename__ = "api_endpoints"

    id = Column(Integer, primary_key=True, index=True)
    path = Column(String(255), index=True, nullable=False) # /api/login, /api/users, /api/orders, /api/admin
    method = Column(String(20), nullable=False) # GET, POST, PUT, DELETE
    service_name = Column(String(100), default="Core API")
    auth_type = Column(String(50), default="Bearer JWT")
    requires_auth = Column(Boolean, default=True)
    rate_limited = Column(Boolean, default=True)
    sensitivity_level = Column(String(50), default="MEDIUM") # CRITICAL, HIGH, MEDIUM, LOW
    risk_score = Column(Integer, default=20) # 0-100
    status = Column(String(50), default="MONITORED")

    def to_dict(self):
        return {
            "id": self.id,
            "path": self.path,
            "method": self.method,
            "service_name": self.service_name,
            "auth_type": self.auth_type,
            "requires_auth": self.requires_auth,
            "rate_limited": self.rate_limited,
            "sensitivity_level": self.sensitivity_level,
            "risk_score": self.risk_score,
            "status": self.status,
        }

class APIFinding(Base):
    __tablename__ = "api_findings"

    id = Column(Integer, primary_key=True, index=True)
    endpoint_path = Column(String(255), index=True, nullable=False)
    method = Column(String(20), nullable=False)
    finding_type = Column(String(100), nullable=False) # BOLA, Broken Auth, Excessive Data Exposure, Rate Limit
    severity = Column(String(50), index=True, nullable=False)
    cvss_score = Column(Float, default=7.5)
    details = Column(Text, nullable=False)
    remediation = Column(Text, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id": self.id,
            "endpoint_path": self.endpoint_path,
            "method": self.method,
            "finding_type": self.finding_type,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "details": self.details,
            "remediation": self.remediation,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
