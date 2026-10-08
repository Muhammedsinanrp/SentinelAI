"""
CYBERSHIELD X - SIEM Detection Rules
Sigma-inspired rules with MITRE ATT&CK technique mapping.
"""
from typing import Dict, Any

SOC_DETECTION_RULES: Dict[str, Dict[str, Any]] = {
    "RULE_BRUTE_FORCE_SSH": {
        "id": "CS-RULE-001",
        "name": "Multiple Failed Authentication Attempts (Brute Force)",
        "mitre_technique": "T1110.001",
        "severity": "HIGH",
        "threshold": 4,
        "time_window_seconds": 300,
        "description": "Multiple authentication failures detected originating from the same source IP in a short time frame."
    },
    "RULE_BRUTE_FORCE_SUCCESS": {
        "id": "CS-RULE-002",
        "name": "Brute Force Attack Followed by Successful Logon (Account Compromise)",
        "mitre_technique": "T1078.003",
        "severity": "CRITICAL",
        "threshold": 1,
        "time_window_seconds": 600,
        "description": "A successful logon was recorded from an IP address that previously triggered failed authentication threshold."
    },
    "RULE_PRIVILEGE_ESCALATION": {
        "id": "CS-RULE-003",
        "name": "Suspicious Privilege Escalation Activity",
        "mitre_technique": "T1548.003",
        "severity": "HIGH",
        "threshold": 1,
        "time_window_seconds": 300,
        "description": "User escalated privileges to root or Administrator via sudo, su, or Windows token impersonation."
    },
    "RULE_SUSPICIOUS_CMD_EXEC": {
        "id": "CS-RULE-004",
        "name": "Defense Evasion / Suspicious Command Execution",
        "mitre_technique": "T1059",
        "severity": "HIGH",
        "threshold": 1,
        "time_window_seconds": 120,
        "description": "Execution of suspicious recon or execution utilities (whoami, mimikatz, powershell -enc, bash -i)."
    },
    "RULE_WEB_ATTACK_SHELL": {
        "id": "CS-RULE-005",
        "name": "Web Application Exploit Attempt",
        "mitre_technique": "T1190",
        "severity": "HIGH",
        "threshold": 1,
        "time_window_seconds": 180,
        "description": "SQL Injection, Path Traversal (../), or Remote File Inclusion pattern detected in web request."
    },
    "RULE_OUTBOUND_BEACON": {
        "id": "CS-RULE-006",
        "name": "Potential C2 Outbound Connection / Beaconing",
        "mitre_technique": "T1071.001",
        "severity": "HIGH",
        "threshold": 3,
        "time_window_seconds": 300,
        "description": "Repeated outbound communication from an internal host to an external high-risk IP or non-standard port."
    }
}
