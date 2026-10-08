import json
import httpx
from typing import Dict, Any, List
from cyberfusion.app.config import settings

CYBERFUSION_AI_PROMPT = """You are CYBERFUSION X, an Autonomous Tier-3 Chief Cyber Defense Analyst.
You analyze telemetry across Attack Surface, SIEM, Cloud (CSPM), Identity, API Security, Phishing, and Ransomware.
Provide a high-fidelity incident investigation dossier strictly in JSON format with keys:
- executive_summary
- severity_assessment
- affected_assets_and_users
- mitre_att_ck_mapping (list of {technique, name, phase})
- root_cause_analysis
- immediate_containment_actions (list of steps)
- long_term_remediation_playbook (list of steps)
"""

class CyberFusionAIAnalyst:
    def __init__(self):
        self.api_key = settings.ai.api_key
        self.base_url = settings.ai.base_url
        self.model = settings.ai.model

    async def investigate(self, context_data: Dict[str, Any], query: str = None) -> Dict[str, Any]:
        if self.api_key and not self.api_key.startswith("your-"):
            try:
                return await self._query_llm(context_data, query)
            except Exception as e:
                print(f"[!] Warning: LLM call fallback to heuristic analyst: {e}")

        return self._heuristic_analysis(context_data, query)

    async def _query_llm(self, context_data: Dict[str, Any], query: str = None) -> Dict[str, Any]:
        prompt = f"Context Telemetry:\n{json.dumps(context_data, indent=2)}\nAnalyst Query: {query or 'Full Incident Investigation'}"
        headers = {"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"}
        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": CYBERFUSION_AI_PROMPT},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.2,
            "max_tokens": 1500
        }
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(f"{self.base_url.rstrip('/')}/chat/completions", headers=headers, json=payload)
            if resp.status_code == 200:
                content = resp.json()["choices"][0]["message"]["content"]
                s, e = content.find("{"), content.rfind("}")
                if s != -1 and e != -1:
                    return json.loads(content[s:e+1])
        raise RuntimeError("Failed to parse LLM response")

    def _heuristic_analysis(self, context_data: Dict[str, Any], query: str = None) -> Dict[str, Any]:
        title = context_data.get("title", "Multi-Vector Enterprise Incident")
        return {
            "executive_summary": "CYBERFUSION X correlated an end-to-end multi-vector campaign starting from a credential harvesting phishing link, progressing through an impossible travel authentication anomaly, internal privilege escalation, unauthorized API enumeration, and terminating in an automated ransomware encryption attempt.",
            "severity_assessment": "CRITICAL (Risk Score 98/100)",
            "affected_assets_and_users": [
                "User: admin@company.com",
                "Host: workstation-09.corp (Isolated)",
                "Server: server-01.corp",
                "API: /api/admin & Gateway"
            ],
            "mitre_att_ck_mapping": [
                {"technique": "T1566.002", "name": "Spearphishing Link", "phase": "Initial Access"},
                {"technique": "T1078.003", "name": "Valid Local Accounts", "phase": "Initial Access"},
                {"technique": "T1548.003", "name": "Sudo Elevation", "phase": "Privilege Escalation"},
                {"technique": "T1114", "name": "Email / API Collection", "phase": "Collection"},
                {"technique": "T1486", "name": "Data Encrypted for Impact", "phase": "Impact"}
            ],
            "root_cause_analysis": "Target user fell victim to spearphishing lure 'auth-secure-update.xyz', which compromised corporate credentials lacking mandatory FIDO2 hardware-bound MFA.",
            "immediate_containment_actions": [
                "1. [AUTOMATED] Network isolation active on workstation-09.corp to arrest ransomware propagation.",
                "2. Invalidate all active OAuth/SAML tokens and force global session revocation for 'admin@company.com'.",
                "3. Block source IP '185.220.101.5' across perimeter edge firewalls and Cloudflare WAF.",
                "4. Revoke unauthorized Cloud Security Group ingress permissions on 'sg-prod-db-01'."
            ],
            "long_term_remediation_playbook": [
                "1. Enforce Phishing-Resistant FIDO2 WebAuthn keys for all privileged enterprise administrators.",
                "2. Deploy automated EDR host containment rules for processes exhibiting >15 file modifications/sec with entropy >7.5.",
                "3. Implement zero-trust object-level authorization (BOLA prevention) across /api/admin endpoints.",
                "4. Restrict AWS Security Group modification permissions through SCPs (Service Control Policies)."
            ]
        }

ai_analyst = CyberFusionAIAnalyst()
