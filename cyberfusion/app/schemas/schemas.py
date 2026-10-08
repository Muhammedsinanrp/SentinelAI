from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class ScopeCheckRequest(BaseModel):
    target: str

class ScopeCheckResponse(BaseModel):
    target: str
    is_in_scope: bool
    reason: str

class ASMScanRequest(BaseModel):
    domain: str
    run_vuln_scan: bool = True

class LogIngestRequest(BaseModel):
    source_type: str = "linux"
    raw_message: str
    host: Optional[str] = "server-01"
    source_ip: Optional[str] = None
    user: Optional[str] = None
    event_type: Optional[str] = None

class CloudScanRequest(BaseModel):
    provider: str = "aws"
    account_id: str = "123456789012"
    account_name: str = "Production Cloud"

class IdentityAuthEventRequest(BaseModel):
    user_email: str
    source_ip: str
    location: str
    device_fingerprint: str = "Unknown Device"

class APIScanRequest(BaseModel):
    service_name: str = "Core API"
    base_url: str = "https://api.example.com"

class PhishingAnalysisRequest(BaseModel):
    target_url: Optional[str] = None
    sender_email: Optional[str] = None
    subject: Optional[str] = None
    content: Optional[str] = None

class RansomwareSimulationRequest(BaseModel):
    host: str = "workstation-09.corp"
    process_name: str = "cryptolocker.exe"
    files_modified: int = 1284
    duration_seconds: int = 45

class AIInvestigationRequest(BaseModel):
    incident_id: Optional[int] = None
    query: Optional[str] = None

class MainDashboardStats(BaseModel):
    assets_count: int = 1248
    critical_count: int = 12
    incidents_count: int = 8
    risk_score: int = 76
    attack_surface: Dict[str, int] = Field(default_factory=lambda: {
        "domains": 12,
        "subdomains": 247,
        "apis": 84,
        "cloud": 391
    })
    security_operations: List[Dict[str, Any]] = Field(default_factory=list)
