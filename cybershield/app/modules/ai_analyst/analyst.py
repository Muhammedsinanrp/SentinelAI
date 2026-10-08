"""
CYBERSHIELD X - AI Security Analyst Engine
Acts as an autonomous Tier-3 SOC Analyst providing correlation, risk scoring, and response playbooks.
"""
import json
import httpx
from typing import Dict, Any, List
from cybershield.app.config import settings

SOC_SYSTEM_PROMPT = """You are CYBERSHIELD X, a Tier-3 Senior SOC Analyst and Incident Response Commander.
You receive structured security telemetry, asset surface context, vulnerability intelligence, and SIEM attack timelines.
Your task is to analyze the incident and produce a professional, actionable incident response dossier.

You MUST respond strictly with a valid JSON object with the following schema:
{
  "incident_summary": "High-level executive briefing of what occurred",
  "assessed_severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "potential_attack_type": "Specific attack category (e.g. SSH Brute Force with Compromise, Web Shell Execution)",
  "mitre_att_ck": [
    {"technique_id": "Txxxx", "name": "Technique Name", "phase": "Tactic Phase"}
  ],
  "root_cause_analysis": "How the attacker gained initial access or privilege",
  "attack_timeline_summary": "Step-by-step reconstruction of chronological actions",
  "immediate_containment_actions": [
    "Step 1: Specific containment command or action",
    "Step 2: Specific network or account isolation action"
  ],
  "eradication_and_remediation": [
    "Step 1: Patching or password rotation advice",
    "Step 2: Long term hardening recommendation"
  ]
}
"""

class AIAnalyst:
    def __init__(self):
        self.base_url = settings.ai.base_url
        self.api_key = settings.ai.api_key
        self.model = settings.ai.model

    async def investigate(self, context_text: str, alert: Dict[str, Any], timeline: List[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Conducts deep security analysis using LLM or built-in heuristic reasoning engine.
        """
        # If API key is available, query LLM
        if self.api_key and not self.api_key.startswith("your-"):
            try:
                return await self._query_llm(context_text)
            except Exception as e:
                print(f"[!] AI Analyst API call failed ({e}), switching to Heuristic Reasoning Engine...")

        # Fallback to Autonomous Rule-Based SOC Reasoning Engine
        return self._heuristic_soc_analysis(alert, timeline)

    async def _query_llm(self, context_text: str) -> Dict[str, Any]:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": SOC_SYSTEM_PROMPT},
                {"role": "user", "content": context_text}
            ],
            "temperature": 0.2,
            "max_tokens": 1500
        }
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(f"{self.base_url.rstrip('/')}/chat/completions", headers=headers, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                content = data["choices"][0]["message"]["content"]
                # Parse JSON block
                start = content.find("{")
                end = content.rfind("}")
                if start != -1 and end != -1:
                    return json.loads(content[start:end+1])
            raise RuntimeError(f"API returned status {resp.status_code}: {resp.text}")

    def _heuristic_soc_analysis(self, alert: Dict[str, Any], timeline: List[Dict[str, Any]] = None) -> Dict[str, Any]:
        title = alert.get("title", "")
        src_ip = alert.get("source_ip", "185.220.101.5")
        host = alert.get("target_host", "server-01")
        sev = alert.get("severity", "HIGH")
        mitre = alert.get("mitre_technique", "T1110")

        # Heuristic rules tailored to the attack scenario
        if "Brute Force" in title or "Compromise" in title or "Logon" in title:
            return {
                "incident_summary": f"Target host '{host}' was subjected to an automated credential brute-force campaign originating from untrusted source IP '{src_ip}', followed by anomalous session activity.",
                "assessed_severity": sev,
                "potential_attack_type": "SSH Brute Force with Lateral Movement / Account Takeover",
                "mitre_att_ck": [
                    {"technique_id": "T1110.001", "name": "Password Guessing", "phase": "Credential Access"},
                    {"technique_id": "T1078.003", "name": "Local Accounts", "phase": "Defense Evasion / Initial Access"},
                    {"technique_id": "T1548.003", "name": "Sudo and Sudo Caching", "phase": "Privilege Escalation"},
                    {"technique_id": "T1059", "name": "Command and Scripting Interpreter", "phase": "Execution"},
                    {"technique_id": "T1071.001", "name": "Web Protocols C2", "phase": "Command and Control"}
                ],
                "root_cause_analysis": f"Weak or exposed administrative service (e.g. Port 22 SSH) without multi-factor authentication (MFA) or fail2ban IP rate limiting.",
                "attack_timeline_summary": f"1. Initial reconnaissance and password spraying from {src_ip}.\n2. Account breached following repeated attempts.\n3. Escalation of privileges and interactive shell invocation.\n4. C2 communication attempt.",
                "immediate_containment_actions": [
                    f"1. Immediately block source IP '{src_ip}' on perimeter firewalls and local iptables.",
                    f"2. Terminate all active SSH/RDP sessions originating from '{src_ip}' on {host}.",
                    f"3. Force password reset and revoke active API tokens/SSH keys for compromised users on {host}."
                ],
                "eradication_and_remediation": [
                    "1. Enforce SSH key-based authentication with Ed25519; disable password authentication.",
                    "2. Deploy Fail2Ban / Wazuh active response agents with dynamic blocking.",
                    "3. Restrict administrative management ports (22, 3389) behind an encrypted WireGuard/OpenVPN tunnel.",
                    "4. Audit syslog / auditd logs for unauthorized persistence mechanisms (cron jobs, systemd services)."
                ]
            }

        # Web attack fallback
        return {
            "incident_summary": f"Inbound exploitation attempts observed against {host} triggering SIEM rule '{alert.get('alert_rule', 'Alert')}'.",
            "assessed_severity": sev,
            "potential_attack_type": "Web Application Exploitation / Security Misconfiguration",
            "mitre_att_ck": [
                {"technique_id": mitre, "name": "Exploit Public-Facing Application", "phase": "Initial Access"}
            ],
            "root_cause_analysis": f"Exposed unhardened endpoint on {host} vulnerable to input manipulation or missing security controls.",
            "attack_timeline_summary": "Inbound HTTP probes with malicious payloads detected and flagged by SIEM inspection rules.",
            "immediate_containment_actions": [
                f"1. Enable WAF blocking mode for suspicious IP '{src_ip}'.",
                "2. Rate limit URI requests to vulnerable endpoints."
            ],
            "eradication_and_remediation": [
                "1. Apply input validation and parameterized queries.",
                "2. Enforce strict Content-Security-Policy and HSTS headers.",
                "3. Perform complete SAST/DAST security code review."
            ]
        }

ai_analyst_service = AIAnalyst()
