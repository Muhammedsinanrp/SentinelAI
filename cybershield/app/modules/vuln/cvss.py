"""
CYBERSHIELD X - CVSS v3.1 Scoring & Risk Metric Calculator
"""
from typing import Dict, Any

def score_to_severity(cvss: float) -> str:
    if cvss >= 9.0:
        return "CRITICAL"
    elif cvss >= 7.0:
        return "HIGH"
    elif cvss >= 4.0:
        return "MEDIUM"
    elif cvss > 0.0:
        return "LOW"
    return "INFO"

def calculate_org_risk_score(vulnerabilities: list, active_alerts: int, total_assets: int) -> int:
    """
    Computes unified organization security risk score on a 0-100 scale.
    Higher score indicates higher risk posture.
    """
    if not total_assets:
        return 10

    weights = {
        "CRITICAL": 25.0,
        "HIGH": 12.0,
        "MEDIUM": 4.0,
        "LOW": 1.0,
        "INFO": 0.2
    }

    vuln_sum = 0.0
    for v in vulnerabilities:
        sev = v.get("severity", "LOW").upper()
        vuln_sum += weights.get(sev, 1.0)

    # Alerts penalty
    alert_penalty = active_alerts * 3.5

    # Asset normalizer
    raw_score = (vuln_sum + alert_penalty) / max(1, (total_assets * 0.4))
    clamped = min(100, max(0, int(raw_score)))
    return clamped
