from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Float, DateTime, Text
from cyberfusion.app.database import Base

class CloudAccount(Base):
    __tablename__ = "cloud_accounts"

    id = Column(Integer, primary_key=True, index=True)
    provider = Column(String(50), nullable=False) # aws, azure, gcp
    account_id = Column(String(100), unique=True, index=True, nullable=False)
    account_name = Column(String(100), nullable=False)
    total_resources = Column(Integer, default=0)
    compliance_score = Column(Float, default=100.0) # 0-100%
    status = Column(String(50), default="CONNECTED")

    def to_dict(self):
        return {
            "id": self.id,
            "provider": self.provider,
            "account_id": self.account_id,
            "account_name": self.account_name,
            "total_resources": self.total_resources,
            "compliance_score": self.compliance_score,
            "status": self.status,
        }

class CloudFinding(Base):
    __tablename__ = "cloud_findings"

    id = Column(Integer, primary_key=True, index=True)
    provider = Column(String(50), index=True, nullable=False) # aws, azure, gcp
    service = Column(String(50), index=True, nullable=False) # S3, EC2, IAM, SecurityGroups, CloudTrail, KMS
    resource_id = Column(String(255), index=True, nullable=False)
    title = Column(String(255), nullable=False)
    severity = Column(String(50), index=True, nullable=False) # CRITICAL, HIGH, MEDIUM, LOW
    rule_id = Column(String(100), nullable=False) # CIS-AWS-1.1, etc.
    evidence = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    status = Column(String(50), default="OPEN")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id": self.id,
            "provider": self.provider,
            "service": self.service,
            "resource_id": self.resource_id,
            "title": self.title,
            "severity": self.severity,
            "rule_id": self.rule_id,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
