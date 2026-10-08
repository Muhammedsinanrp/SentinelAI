"""
CYBERSHIELD X - Real-time SIEM Correlation & Alert Generation Engine
Correlates incoming logs across time windows, detects attack sequences, and builds incident chains.
"""
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional
from collections import defaultdict
from cybershield.app.modules.siem.rules import SOC_DETECTION_RULES

class SIEMCorrelationEngine:
    def __init__(self):
        # State tracking: IP -> list of timestamps of failed logins
        self.failed_logins_by_ip = defaultdict(list)
        # IP -> timestamp of brute force triggered
        self.brute_force_ips = {}
        # Active incident timelines keyed by source_ip or session
        self.active_chains = defaultdict(list)

    def process_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Evaluates incoming normalized event against detection rules.
        Returns any generated alerts with linked incident timelines.
        """
        alerts = []
        now = datetime.now(timezone.utc)
        src_ip = event.get("source_ip") or "unknown_ip"
        user = event.get("user") or "unknown_user"
        host = event.get("host") or "server-01"
        ev_type = event.get("event_type", "")
        raw = event.get("raw_message", "")

        # Clean old failed login records (> 10 minutes)
        cutoff = now - timedelta(seconds=600)
        self.failed_logins_by_ip[src_ip] = [
            t for t in self.failed_logins_by_ip[src_ip] if t > cutoff
        ]

        # -----------------------------------------------------------------
        # 1. Failed Login Handling & Brute Force Detection
        # -----------------------------------------------------------------
        if ev_type == "failed_login":
            self.failed_logins_by_ip[src_ip].append(now)
            count = len(self.failed_logins_by_ip[src_ip])

            # Record in chain
            self.active_chains[src_ip].append({
                "timestamp": now,
                "event_name": "Failed Authentication",
                "description": f"Failed login for user '{user}' from {src_ip}",
                "actor": src_ip,
                "target": host,
                "mitre_id": "T1110.001",
                "phase": "Credential Access"
            })

            # Check threshold (e.g. >= 4 attempts)
            rule = SOC_DETECTION_RULES["RULE_BRUTE_FORCE_SSH"]
            if count >= rule["threshold"] and src_ip not in self.brute_force_ips:
                self.brute_force_ips[src_ip] = now
                alerts.append({
                    "title": "SSH / Remote Brute Force Attack Detected",
                    "severity": "HIGH",
                    "category": "Credential Access",
                    "source_ip": src_ip,
                    "target_host": host,
                    "alert_rule": rule["id"],
                    "description": f"Detected {count} failed authentication attempts within 5 minutes from {src_ip} targeting user '{user}'.",
                    "raw_events_count": count,
                    "mitre_technique": rule["mitre_technique"],
                    "status": "INVESTIGATING",
                    "timeline_events": list(self.active_chains[src_ip])
                })

        # -----------------------------------------------------------------
        # 2. Successful Login after Brute Force (Account Compromise!)
        # -----------------------------------------------------------------
        elif ev_type == "successful_login":
            self.active_chains[src_ip].append({
                "timestamp": now,
                "event_name": "Successful Authentication",
                "description": f"Interactive session established for user '{user}' from {src_ip}",
                "actor": src_ip,
                "target": host,
                "mitre_id": "T1078",
                "phase": "Initial Access"
            })

            if src_ip in self.brute_force_ips:
                rule = SOC_DETECTION_RULES["RULE_BRUTE_FORCE_SUCCESS"]
                alerts.append({
                    "title": "CRITICAL: Successful Logon Followed by Brute Force",
                    "severity": "CRITICAL",
                    "category": "Account Compromise",
                    "source_ip": src_ip,
                    "target_host": host,
                    "alert_rule": rule["id"],
                    "description": f"Adversary from {src_ip} successfully authenticated as '{user}' after repeated brute-force failures.",
                    "raw_events_count": len(self.active_chains[src_ip]),
                    "mitre_technique": rule["mitre_technique"],
                    "status": "NEW",
                    "timeline_events": list(self.active_chains[src_ip])
                })

        # -----------------------------------------------------------------
        # 3. Privilege Escalation
        # -----------------------------------------------------------------
        elif ev_type == "privilege_escalation":
            self.active_chains[src_ip].append({
                "timestamp": now,
                "event_name": "Privilege Escalation",
                "description": f"Elevation to elevated permissions / root detected for user '{user}': {raw}",
                "actor": user,
                "target": host,
                "mitre_id": "T1548.003",
                "phase": "Privilege Escalation"
            })

            rule = SOC_DETECTION_RULES["RULE_PRIVILEGE_ESCALATION"]
            alerts.append({
                "title": "Suspicious Privilege Escalation to Root/Admin",
                "severity": "HIGH",
                "category": "Privilege Escalation",
                "source_ip": src_ip,
                "target_host": host,
                "alert_rule": rule["id"],
                "description": f"User '{user}' executed root elevation commands on {host}.",
                "raw_events_count": 1,
                "mitre_technique": rule["mitre_technique"],
                "status": "INVESTIGATING",
                "timeline_events": list(self.active_chains[src_ip])
            })

        # -----------------------------------------------------------------
        # 4. Suspicious Command Execution
        # -----------------------------------------------------------------
        elif ev_type == "suspicious_command":
            cmd = event.get("parsed_data", {}).get("detected_keyword", raw)
            self.active_chains[src_ip].append({
                "timestamp": now,
                "event_name": "Suspicious Command Execution",
                "description": f"Suspicious utility executed: {cmd}",
                "actor": user,
                "target": host,
                "mitre_id": "T1059",
                "phase": "Execution"
            })

            rule = SOC_DETECTION_RULES["RULE_SUSPICIOUS_CMD_EXEC"]
            alerts.append({
                "title": f"Suspicious Command Execution ({cmd})",
                "severity": "HIGH",
                "category": "Execution",
                "source_ip": src_ip,
                "target_host": host,
                "alert_rule": rule["id"],
                "description": f"High-risk command '{cmd}' observed on {host}.",
                "raw_events_count": 1,
                "mitre_technique": rule["mitre_technique"],
                "status": "INVESTIGATING",
                "timeline_events": list(self.active_chains[src_ip])
            })

        # -----------------------------------------------------------------
        # 5. Web Exploit Attack
        # -----------------------------------------------------------------
        elif ev_type in ("web_attack_sqli", "web_attack_traversal"):
            vuln_name = "SQL Injection" if "sqli" in ev_type else "Directory Traversal"
            self.active_chains[src_ip].append({
                "timestamp": now,
                "event_name": f"Web Exploit Attempt ({vuln_name})",
                "description": f"HTTP probe with exploit pattern: {raw}",
                "actor": src_ip,
                "target": host,
                "mitre_id": "T1190",
                "phase": "Initial Access"
            })

            rule = SOC_DETECTION_RULES["RULE_WEB_ATTACK_SHELL"]
            alerts.append({
                "title": f"Web Application Attack: {vuln_name} Detected",
                "severity": "HIGH",
                "category": "Initial Access",
                "source_ip": src_ip,
                "target_host": host,
                "alert_rule": rule["id"],
                "description": f"Inbound HTTP exploit payload targeting {host} from {src_ip}.",
                "raw_events_count": 1,
                "mitre_technique": rule["mitre_technique"],
                "status": "NEW",
                "timeline_events": list(self.active_chains[src_ip])
            })

        # -----------------------------------------------------------------
        # 6. Outbound Connection / C2 Beaconing
        # -----------------------------------------------------------------
        elif ev_type == "outbound_connection":
            dst_ip = event.get("destination_ip") or "external_c2"
            self.active_chains[src_ip].append({
                "timestamp": now,
                "event_name": "Outbound Connection Established",
                "description": f"Outbound session initiated to external IP {dst_ip}",
                "actor": host,
                "target": dst_ip,
                "mitre_id": "T1071.001",
                "phase": "Command and Control"
            })

            rule = SOC_DETECTION_RULES["RULE_OUTBOUND_BEACON"]
            alerts.append({
                "title": "Potential C2 Outbound Connection / Beaconing",
                "severity": "CRITICAL" if src_ip in self.brute_force_ips else "HIGH",
                "category": "Command and Control",
                "source_ip": host,
                "target_host": dst_ip,
                "alert_rule": rule["id"],
                "description": f"Host {host} initiated outbound network communication following suspicious activity.",
                "raw_events_count": 1,
                "mitre_technique": rule["mitre_technique"],
                "status": "NEW",
                "timeline_events": list(self.active_chains[src_ip])
            })

        return alerts

siem_correlator = SIEMCorrelationEngine()
