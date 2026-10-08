from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class ScopeCheckRequest(BaseModel):
    target: str

class ScopeCheckResponse(BaseModel):
    target: str
    is_in_scope: bool
    reason: str

class ScanRequest(BaseModel):
    domain: str
    run_vuln_scan: bool = True
    deep_port_scan: bool = False

class LogIngestRequest(BaseModel):
    source_type: str = "linux" # linux, windows, wazuh, syslog, web, firewall
    raw_message: str
    host: Optional[str] = "server-01"
    source_ip: Optional[str] = None
    user: Optional[str] = None
    event_type: Optional[str] = None

class BatchLogIngestRequest(BaseModel):
    logs: List[LogIngestRequest]

class VulnerabilityCreateRequest(BaseModel):
    asset_target: str
    title: str
    severity: str # CRITICAL, HIGH, MEDIUM, LOW, INFO
    cvss_score: float = 0.0
    cve_id: Optional[str] = None
    vulnerability_type: str = "Misconfiguration"
    evidence: Optional[str] = None
    business_impact: Optional[str] = None
    remediation: Optional[str] = None
    tool_source: str = "Manual"

class AIInvestigationRequest(BaseModel):
    alert_id: Optional[int] = None
    incident_context: Optional[str] = None
    target: Optional[str] = None

class SystemOverviewStats(BaseModel):
    total_assets: int
    critical_vulnerabilities: int
    high_vulnerabilities: int
    total_alerts: int
    active_incidents: int
    risk_score: int # 0-100
    severity_breakdown: Dict[str, int]
    mitre_attack_breakdown: Dict[str, int]
