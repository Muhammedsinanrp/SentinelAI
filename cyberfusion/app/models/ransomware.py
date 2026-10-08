from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime
from cyberfusion.app.database import Base

class RansomwareTelemetry(Base):
    __tablename__ = "ransomware_telemetry"

    id = Column(Integer, primary_key=True, index=True)
    host = Column(String(255), index=True, nullable=False)
    process_name = Column(String(255), nullable=False) # suspicious.exe
    pid = Column(Integer, default=1337)
    files_modified_count = Column(Integer, default=0) # 1,284
    duration_seconds = Column(Integer, default=45)
    entropy_score = Column(Float, default=7.9) # > 7.5 indicates encrypted data
    behavior_flag = Column(String(100), default="Mass File Encryption Spike")
    severity = Column(String(50), default="CRITICAL")
    is_isolated = Column(Boolean, default=True) # Automated Endpoint Isolation
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    def to_dict(self):
        return {
            "id": self.id,
            "host": self.host,
            "process_name": self.process_name,
            "pid": self.pid,
            "files_modified_count": self.files_modified_count,
            "duration_seconds": self.duration_seconds,
            "entropy_score": self.entropy_score,
            "behavior_flag": self.behavior_flag,
            "severity": self.severity,
            "is_isolated": self.is_isolated,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }
