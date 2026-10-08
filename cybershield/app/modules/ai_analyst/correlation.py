"""
CYBERSHIELD X - Multi-Source Context Aggregator for AI
Fuses Asset Discovery, Vulnerability Database, and SIEM Telemetry.
"""
from typing import Dict, Any, List

class IncidentContextAggregator:
    @staticmethod
    def build_security_context(
        alert: Dict[str, Any],
        asset: Dict[str, Any] = None,
        vulns: List[Dict[str, Any]] = None,
        timeline: List[Dict[str, Any]] = None
    ) -> str:
        """
        Creates a structured incident brief for LLM investigation.
        """
        lines = []
        lines.append("=== CYBERSHIELD X SECURITY INCIDENT BRIEF ===")
        lines.append(f"Alert Title : {alert.get('title', 'Unknown Alert')}")
        lines.append(f"Severity    : {alert.get('severity', 'HIGH')}")
        lines.append(f"Category    : {alert.get('category', 'Intrusion')}")
        lines.append(f"Source IP   : {alert.get('source_ip', 'Unknown')}")
        lines.append(f"Target Host : {alert.get('target_host', 'Internal Host')}")
        lines.append(f"MITRE Tactic: {alert.get('mitre_technique', 'T1110')}")
        lines.append(f"Description : {alert.get('description', '')}")

        if asset:
            lines.append("\n--- TARGET ASSET CONTEXT ---")
            lines.append(f"Domain/Host : {asset.get('domain', 'N/A')}")
            lines.append(f"IP Addresses: {', '.join(asset.get('ip_addresses', []))}")
            lines.append(f"Open Ports  : {', '.join(str(p.get('port')) for p in asset.get('open_ports', []))}")
            lines.append(f"Technologies: {', '.join(asset.get('technologies', []))}")

        if vulns:
            lines.append(f"\n--- ACTIVE KNOWN VULNERABILITIES ON TARGET ({len(vulns)}) ---")
            for i, v in enumerate(vulns[:5], 1):
                lines.append(f"{i}. [{v.get('severity')}] {v.get('title')} (CVSS {v.get('cvss_score')})")

        if timeline:
            lines.append(f"\n--- ATTACK TIMELINE SEQUENCE ({len(timeline)} events) ---")
            for t in timeline:
                lines.append(f"[{t.get('time', 'N/A')}] Phase: {t.get('phase')} | Event: {t.get('event_name')} | Actor: {t.get('actor')} -> Target: {t.get('target')}")
                lines.append(f"       Details: {t.get('description')}")

        return "\n".join(lines)
