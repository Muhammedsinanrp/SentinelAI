from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any

class UnifiedKillchainCorrelator:
    """
    Correlates disparate events across Phishing, Identity, Endpoint, API, Cloud, and SIEM
    into a cohesive multi-vector attack chain.
    """
    def build_cross_domain_incident(self) -> Dict[str, Any]:
        now = datetime.now(timezone.utc)
        timeline_events = [
            {
                "time": (now - timedelta(minutes=45)).strftime("%H:%M:%S"),
                "module_source": "Phishing Defense",
                "phase": "Initial Access",
                "event_name": "Phishing Email Delivered",
                "description": "Target user clicked credential lure URL 'auth-secure-update.xyz'. SPF/DKIM validation failed.",
                "actor": "External Phishing Campaign",
                "target": "admin@company.com",
                "mitre_id": "T1566.002"
            },
            {
                "time": (now - timedelta(minutes=40)).strftime("%H:%M:%S"),
                "module_source": "Identity Threat",
                "phase": "Initial Access",
                "event_name": "Impossible Travel Authentication",
                "description": "Login detected from Moscow, Russia (speed: 4,900 km/h) 20 mins after normal session in India.",
                "actor": "185.220.101.5",
                "target": "admin@company.com",
                "mitre_id": "T1078.003"
            },
            {
                "time": (now - timedelta(minutes=30)).strftime("%H:%M:%S"),
                "module_source": "SIEM / SOC",
                "phase": "Privilege Escalation",
                "event_name": "Sudo Elevation via Stolen Credentials",
                "description": "User executed sudo session on server-01 without secondary MFA challenge.",
                "actor": "admin",
                "target": "server-01.corp",
                "mitre_id": "T1548.003"
            },
            {
                "time": (now - timedelta(minutes=20)).strftime("%H:%M:%S"),
                "module_source": "API Security",
                "phase": "Credential / Data Access",
                "event_name": "Excessive API Data Query (BOLA)",
                "description": "Adversary queried /api/admin and scraped tenant account records via unthrottled API endpoint.",
                "actor": "185.220.101.5",
                "target": "/api/admin",
                "mitre_id": "T1114"
            },
            {
                "time": (now - timedelta(minutes=10)).strftime("%H:%M:%S"),
                "module_source": "Cloud Security (CSPM)",
                "phase": "Persistence",
                "event_name": "Cloud Security Group Ingress Modified",
                "description": "Adversary attempted creating 0.0.0.0/0 ingress rule on production database security group.",
                "actor": "admin",
                "target": "sg-prod-db-01",
                "mitre_id": "T1562.001"
            },
            {
                "time": (now - timedelta(minutes=2)).strftime("%H:%M:%S"),
                "module_source": "Ransomware Defense",
                "phase": "Impact",
                "event_name": "Mass File Encryption Spike",
                "description": "Process 'cryptolocker.exe' modified 1,284 files in 45 seconds (entropy 7.9). Host isolated.",
                "actor": "cryptolocker.exe (PID 2048)",
                "target": "workstation-09.corp",
                "mitre_id": "T1486"
            }
        ]

        return {
            "title": "CRITICAL: Multi-Vector Compromise & Ransomware Attack Chain",
            "severity": "CRITICAL",
            "risk_score": 98,
            "root_cause": "Phishing credential harvesting (auth-secure-update.xyz) leading to Account Takeover, API scraping, and Ransomware staging.",
            "attack_vector": "Phishing -> Impossible Travel -> PrivEsc -> API Abuse -> Ransomware",
            "containment_status": "CONTAINED (Endpoint Isolated & Session Revoked)",
            "mitre_chain": [
                {"technique": "T1566.002", "name": "Spearphishing Link", "phase": "Initial Access"},
                {"technique": "T1078.003", "name": "Valid Accounts", "phase": "Initial Access"},
                {"technique": "T1548.003", "name": "Sudo Elevation", "phase": "Privilege Escalation"},
                {"technique": "T1114", "name": "Email & API Collection", "phase": "Collection"},
                {"technique": "T1486", "name": "Data Encrypted for Impact", "phase": "Impact"}
            ],
            "timeline": timeline_events
        }

unified_correlator = UnifiedKillchainCorrelator()
