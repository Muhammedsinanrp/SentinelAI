"""
CYBERSHIELD X - Vulnerability Management & Assessment Engine
Normalizes findings from Native OWASP probes, Nuclei outputs, Nmap scans, and Custom rules into a unified schema.
"""
import asyncio
import json
from typing import List, Dict, Any, Optional
import aiohttp
from cybershield.app.modules.vuln.cvss import score_to_severity

class VulnerabilityManager:
    def __init__(self, timeout: float = 4.0):
        self.timeout = timeout

    async def run_owasp_checks(self, domain: str, asm_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Runs automated, benign OWASP Top 10 web security checks against the target.
        """
        findings = []
        missing_headers = asm_data.get("missing_headers", [])

        # 1. Missing HSTS Check
        if "Strict-Transport-Security" in missing_headers:
            findings.append({
                "asset_target": domain,
                "title": "Missing HTTP Strict Transport Security (HSTS)",
                "severity": "HIGH",
                "cvss_score": 7.4,
                "cve_id": None,
                "vulnerability_type": "Cryptographic Failure (OWASP A02)",
                "evidence": f"Response headers from https://{domain} do not include 'Strict-Transport-Security'.",
                "business_impact": "Allows Man-In-The-Middle (MITM) downgrade attacks and SSL stripping against client sessions.",
                "remediation": "Configure 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' in web server configuration.",
                "tool_source": "OWASP-Audit"
            })

        # 2. Missing Content Security Policy (CSP)
        if "Content-Security-Policy" in missing_headers:
            findings.append({
                "asset_target": domain,
                "title": "Missing Content Security Policy (CSP)",
                "severity": "MEDIUM",
                "cvss_score": 5.4,
                "cve_id": None,
                "vulnerability_type": "Security Misconfiguration (OWASP A05)",
                "evidence": f"Web application header 'Content-Security-Policy' is absent.",
                "business_impact": "Leaves the application susceptible to Cross-Site Scripting (XSS), data injection, and clickjacking.",
                "remediation": "Define a restrictive CSP directive (e.g., default-src 'self'; script-src 'self' 'nonce-...') restricting script sources.",
                "tool_source": "OWASP-Audit"
            })

        # 3. Missing Clickjacking Protection
        if "X-Frame-Options" in missing_headers:
            findings.append({
                "asset_target": domain,
                "title": "Missing Clickjacking Protection (X-Frame-Options)",
                "severity": "MEDIUM",
                "cvss_score": 4.8,
                "cve_id": None,
                "vulnerability_type": "Security Misconfiguration (OWASP A05)",
                "evidence": "Neither 'X-Frame-Options' nor 'frame-ancestors' are enforced.",
                "business_impact": "An adversary can frame the web page inside an invisible iframe to trick users into unintended actions.",
                "remediation": "Set 'X-Frame-Options: DENY' or 'SAMEORIGIN' on all rendered endpoints.",
                "tool_source": "OWASP-Audit"
            })

        # 4. Active probes for sensitive exposure
        probes = [
            {"path": "/.env", "type": "Information Disclosure", "title": "Exposed Environment Configuration (.env)", "sev": "CRITICAL", "cvss": 9.3},
            {"path": "/.git/HEAD", "type": "Source Code Exposure", "title": "Exposed Git Repository Directory (/.git)", "sev": "HIGH", "cvss": 8.6},
            {"path": "/robots.txt", "type": "Information Disclosure", "title": "Information Disclosure via robots.txt", "sev": "INFO", "cvss": 0.0},
        ]

        connector = aiohttp.TCPConnector(ssl=False)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        headers = {"User-Agent": "CyberShield-X/2.0"}

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            for probe in probes:
                target_url = f"https://{domain}{probe['path']}"
                try:
                    async with session.get(target_url, headers=headers, allow_redirects=False) as resp:
                        if resp.status == 200:
                            content = (await resp.text())[:300]
                            # Verify true positive for .git or .env
                            is_hit = False
                            if probe["path"] == "/.git/HEAD" and "ref:" in content:
                                is_hit = True
                            elif probe["path"] == "/.env" and ("=" in content or "DB_" in content or "SECRET" in content):
                                is_hit = True
                            elif probe["path"] == "/robots.txt" and ("User-agent" in content or "Disallow" in content):
                                is_hit = True

                            if is_hit:
                                findings.append({
                                    "asset_target": domain,
                                    "title": probe["title"],
                                    "severity": probe["sev"],
                                    "cvss_score": probe["cvss"],
                                    "cve_id": None,
                                    "vulnerability_type": probe["type"],
                                    "evidence": f"Endpoint {target_url} returned HTTP 200 with payload signature: {content[:100]}...",
                                    "business_impact": f"Unauthorized external access to sensitive assets or source control metadata.",
                                    "remediation": f"Block public web server access to '{probe['path']}' via reverse proxy rules.",
                                    "tool_source": "OWASP-Audit"
                                })
                except Exception:
                    continue

        return findings

    @staticmethod
    def normalize_nuclei_finding(nuclei_json: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parses and standardizes Nuclei JSON output into CyberShield Vulnerability model.
        """
        info = nuclei_json.get("info", {})
        classification = info.get("classification", {})
        sev = info.get("severity", "medium").upper()
        cvss_val = classification.get("cvss-score", 5.0)

        return {
            "asset_target": nuclei_json.get("host", nuclei_json.get("matched-at", "Unknown")),
            "title": info.get("name", nuclei_json.get("template-id", "Nuclei Finding")),
            "severity": sev if sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"] else "INFO",
            "cvss_score": float(cvss_val) if cvss_val else 5.0,
            "cve_id": classification.get("cve-id", [None])[0] if isinstance(classification.get("cve-id"), list) else None,
            "vulnerability_type": classification.get("cwe-id", ["Vulnerability"])[0] if isinstance(classification.get("cwe-id"), list) else "Vulnerability",
            "evidence": nuclei_json.get("curl-command") or nuclei_json.get("matched-at") or str(nuclei_json.get("extracted-results", "")),
            "business_impact": info.get("description", "Vulnerability detected by template."),
            "remediation": info.get("remediation", "Review vendor patch or configuration guidelines."),
            "tool_source": "Nuclei"
        }

    @staticmethod
    def normalize_nmap_finding(host: str, port: int, service: str, script_output: str) -> Dict[str, Any]:
        """
        Parses Nmap NSE script findings into standard vulnerability model.
        """
        return {
            "asset_target": f"{host}:{port}",
            "title": f"Service Exposure / Vulnerability on {service.upper()} ({port})",
            "severity": "MEDIUM",
            "cvss_score": 5.3,
            "cve_id": None,
            "vulnerability_type": "Exposed Port / Service",
            "evidence": script_output[:250],
            "business_impact": f"Potential exploitation of unhardened {service} service on port {port}.",
            "remediation": f"Restrict firewall access or bind {service} only to internal VPN interfaces.",
            "tool_source": "Nmap"
        }
