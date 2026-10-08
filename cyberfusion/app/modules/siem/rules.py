from typing import Dict, Any

SIEM_RULES: Dict[str, Dict[str, Any]] = {
    "RULE_BRUTE_FORCE_SSH": {
        "id": "CF-RULE-001",
        "name": "Multiple Failed Authentication Attempts",
        "mitre_technique": "T1110.001",
        "severity": "HIGH",
        "threshold": 3,
        "time_window_seconds": 300,
        "description": "Repeated login failures from the same source IP."
    },
    "RULE_ACCOUNT_TAKEOVER": {
        "id": "CF-RULE-002",
        "name": "Brute Force Followed by Successful Logon (Account Takeover)",
        "mitre_technique": "T1078.003",
        "severity": "CRITICAL",
        "threshold": 1,
        "time_window_seconds": 600,
        "description": "Adversary gained interactive session following brute force failure sequence."
    },
    "RULE_PRIV_ESC": {
        "id": "CF-RULE-003",
        "name": "Privilege Escalation to Root/Administrator",
        "mitre_technique": "T1548.003",
        "severity": "HIGH",
        "threshold": 1,
        "time_window_seconds": 300,
        "description": "Sudo or token elevation executed following remote logon."
    },
    "RULE_SUSPICIOUS_CMD": {
        "id": "CF-RULE-004",
        "name": "Suspicious Discovery & Execution Utility",
        "mitre_technique": "T1059",
        "severity": "HIGH",
        "threshold": 1,
        "time_window_seconds": 120,
        "description": "Recon or execution binaries observed (whoami, mimikatz, powershell -enc)."
    },
    "RULE_C2_OUTBOUND": {
        "id": "CF-RULE-005",
        "name": "Outbound Command and Control Beaconing",
        "mitre_technique": "T1071.001",
        "severity": "HIGH",
        "threshold": 1,
        "time_window_seconds": 300,
        "description": "Internal host established outbound session to suspicious external port."
    }
}
