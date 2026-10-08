from datetime import datetime, timezone
import json
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text
from cyberfusion.app.database import Base

class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String(255), unique=True, index=True, nullable=False)
    root_domain = Column(String(255), index=True, nullable=False)
    asset_type = Column(String(50), default="subdomain") # domain, subdomain, api, cloud
    ip_addresses = Column(Text, default="[]")
    dns_records = Column(Text, default="{}")
    open_ports = Column(Text, default="[]")
    technologies = Column(Text, default="[]")
    security_headers = Column(Text, default="{}")
    tls_info = Column(Text, default="{}")
    is_in_scope = Column(Boolean, default=True)
    status = Column(String(50), default="active")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id": self.id,
            "domain": self.domain,
            "root_domain": self.root_domain,
            "asset_type": self.asset_type,
            "ip_addresses": json.loads(self.ip_addresses or "[]"),
            "dns_records": json.loads(self.dns_records or "{}"),
            "open_ports": json.loads(self.open_ports or "[]"),
            "technologies": json.loads(self.technologies or "[]"),
            "security_headers": json.loads(self.security_headers or "{}"),
            "tls_info": json.loads(self.tls_info or "{}"),
            "is_in_scope": self.is_in_scope,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
