from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any
from collections import defaultdict
from cyberfusion.app.modules.siem.rules import SIEM_RULES

class SIEMCorrelationEngine:
    def __init__(self):
        self.failed_logins = defaultdict(list)
        self.brute_force_ips = set()

    def process_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        alerts = []
        now = datetime.now(timezone.utc)
        src_ip = event.get("source_ip") or "unknown_ip"
        user = event.get("user") or "unknown_user"
        host = event.get("host") or "server-01"
        ev_type = event.get("event_type", "")

        # 1. Failed Logins & Brute Force
        if ev_type == "failed_login":
            cutoff = now - timedelta(seconds=300)
            self.failed_logins[src_ip] = [t for t in self.failed_logins[src_ip] if t > cutoff]
            self.failed_logins[src_ip].append(now)

            rule = SIEM_RULES["RULE_BRUTE_FORCE_SSH"]
            if len(self.failed_logins[src_ip]) >= rule["threshold"] and src_ip not in self.brute_force_ips:
                self.brute_force_ips.add(src_ip)
                alerts.append({
                    "title": "Multiple Failed Authentication Attempts (Brute Force)",
                    "severity": "HIGH",
                    "category": "Credential Access",
                    "source_ip": src_ip,
                    "target_host": host,
                    "alert_rule": rule["id"],
                    "description": f"{len(self.failed_logins[src_ip])} failed login attempts from {src_ip} targeting '{user}'.",
                    "raw_events_count": len(self.failed_logins[src_ip]),
                    "mitre_technique": rule["mitre_technique"],
                    "status": "INVESTIGATING"
                })

        # 2. Account Takeover (Success after failure)
        elif ev_type == "successful_login":
            if src_ip in self.brute_force_ips:
                rule = SIEM_RULES["RULE_ACCOUNT_TAKEOVER"]
                alerts.append({
                    "title": "Account Takeover: Successful Login After Brute Force",
                    "severity": "CRITICAL",
                    "category": "Account Compromise",
                    "source_ip": src_ip,
                    "target_host": host,
                    "alert_rule": rule["id"],
                    "description": f"Successful session established for '{user}' from {src_ip} following brute force attacks.",
                    "raw_events_count": len(self.failed_logins[src_ip]) + 1,
                    "mitre_technique": rule["mitre_technique"],
                    "status": "NEW"
                })

        # 3. Privilege Escalation
        elif ev_type == "privilege_escalation":
            rule = SIEM_RULES["RULE_PRIV_ESC"]
            alerts.append({
                "title": "Privilege Escalation to Root/Administrator",
                "severity": "HIGH",
                "category": "Privilege Escalation",
                "source_ip": src_ip,
                "target_host": host,
                "alert_rule": rule["id"],
                "description": f"User '{user}' executed root privilege escalation commands on {host}.",
                "raw_events_count": 1,
                "mitre_technique": rule["mitre_technique"],
                "status": "NEW"
            })

        # 4. Suspicious Command Execution
        elif ev_type == "suspicious_command":
            rule = SIEM_RULES["RULE_SUSPICIOUS_CMD"]
            alerts.append({
                "title": "Suspicious Discovery & Execution Utility Detected",
                "severity": "HIGH",
                "category": "Execution",
                "source_ip": src_ip,
                "target_host": host,
                "alert_rule": rule["id"],
                "description": f"Recon or credential dumper utility executed on {host}.",
                "raw_events_count": 1,
                "mitre_technique": rule["mitre_technique"],
                "status": "NEW"
            })

        # 5. Outbound C2
        elif ev_type == "outbound_connection":
            rule = SIEM_RULES["RULE_C2_OUTBOUND"]
            alerts.append({
                "title": "Outbound Command and Control Beaconing Detected",
                "severity": "HIGH",
                "category": "Command and Control",
                "source_ip": host,
                "target_host": "external_c2",
                "alert_rule": rule["id"],
                "description": f"Host {host} initiated outbound network communication to external C2 node.",
                "raw_events_count": 1,
                "mitre_technique": rule["mitre_technique"],
                "status": "NEW"
            })

        return alerts

siem_correlator = SIEMCorrelationEngine()
