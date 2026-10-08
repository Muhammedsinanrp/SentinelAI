from typing import Dict, List, Any

DEFAULT_API_ENDPOINTS = [
    {"path": "/api/login", "method": "POST", "auth": False, "rate_limit": False, "sens": "CRITICAL"},
    {"path": "/api/users", "method": "GET", "auth": True, "rate_limit": True, "sens": "HIGH"},
    {"path": "/api/orders", "method": "GET", "auth": True, "rate_limit": True, "sens": "MEDIUM"},
    {"path": "/api/admin", "method": "POST", "auth": True, "rate_limit": False, "sens": "CRITICAL"},
    {"path": "/api/v1/users/{id}/profile", "method": "GET", "auth": False, "rate_limit": True, "sens": "HIGH"}
]

class APISecurityAuditor:
    async def audit_api_surface(self, base_url: str = "https://api.example.com") -> Dict[str, Any]:
        endpoints = []
        findings = []

        for ep in DEFAULT_API_ENDPOINTS:
            ep_risk = 20
            # Check 1: Lack of Rate Limiting on Authentication
            if not ep["rate_limit"] and "login" in ep["path"]:
                findings.append({
                    "endpoint_path": ep["path"],
                    "method": ep["method"],
                    "finding_type": "Lack of Resources & Rate Limiting (API4:2023)",
                    "severity": "HIGH",
                    "cvss_score": 7.5,
                    "details": f"Endpoint {ep['path']} lacks rate-limiting thresholds, permitting high-frequency credential stuffing.",
                    "remediation": "Enforce strict IP/user token throttling (max 5 failed attempts per minute) with exponential backoff."
                })
                ep_risk += 40

            # Check 2: BOLA / Missing authorization
            if "{id}" in ep["path"] and not ep["auth"]:
                findings.append({
                    "endpoint_path": ep["path"],
                    "method": ep["method"],
                    "finding_type": "Broken Object Level Authorization / BOLA (API1:2023)",
                    "severity": "CRITICAL",
                    "cvss_score": 8.8,
                    "details": f"Endpoint {ep['path']} accepts arbitrary user ID parameters without validating tenant authorization context.",
                    "remediation": "Enforce fine-grained ACL validation in business logic to ensure requester owns the referenced resource."
                })
                ep_risk += 50

            # Check 3: Excessive Data Exposure
            if ep["path"] == "/api/admin":
                findings.append({
                    "endpoint_path": ep["path"],
                    "method": ep["method"],
                    "finding_type": "Broken Function Level Authorization (API5:2023)",
                    "severity": "HIGH",
                    "cvss_score": 7.9,
                    "details": "Administrative API action accessible through standard bearer token without role-based access check.",
                    "remediation": "Enforce RBAC policy checks with cryptographic role claims verification."
                })
                ep_risk += 30

            endpoints.append({
                "path": ep["path"],
                "method": ep["method"],
                "service_name": "Gateway API",
                "auth_type": "Bearer JWT" if ep["auth"] else "None",
                "requires_auth": ep["auth"],
                "rate_limited": ep["rate_limit"],
                "sensitivity_level": ep["sens"],
                "risk_score": min(100, ep_risk),
                "status": "MONITORED"
            })

        return {
            "base_url": base_url,
            "total_endpoints": len(endpoints),
            "findings_count": len(findings),
            "endpoints": endpoints,
            "findings": findings
        }

api_auditor = APISecurityAuditor()
