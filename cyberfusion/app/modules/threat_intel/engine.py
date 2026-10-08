from typing import Dict, List, Any

MOCK_IOC_DATABASE = {
    "185.220.101.5": {"type": "IP", "name": "Tor Exit Node / Brute Force Actor", "confidence": 98.0, "mitre": "T1110"},
    "194.26.29.110": {"type": "IP", "name": "Cobalt Strike C2 Server", "confidence": 95.0, "mitre": "T1071"},
    "auth-secure-update.xyz": {"type": "Domain", "name": "Phishing Credential Harvester", "confidence": 94.0, "mitre": "T1566.002"},
    "CVE-2024-3400": {"type": "CVE", "name": "Palo Alto Networks PAN-OS Command Injection", "cvss": 10.0, "mitre": "T1190"},
    "CVE-2024-6387": {"type": "CVE", "name": "regreSSHion OpenSSH Signal Handler Race Condition", "cvss": 8.1, "mitre": "T1068"}
}

class ThreatIntelligenceEngine:
    def lookup_ioc(self, value: str) -> Dict[str, Any]:
        val = value.strip().lower()
        for k, v in MOCK_IOC_DATABASE.items():
            if k.lower() in val or val in k.lower():
                return {
                    "indicator": value,
                    "matched": True,
                    "details": v
                }
        return {
            "indicator": value,
            "matched": False,
            "details": {"type": "Unknown", "name": "No current reputation flags", "confidence": 10.0}
        }

threat_intel_engine = ThreatIntelligenceEngine()
