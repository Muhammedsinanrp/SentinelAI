"""
CYBERSHIELD X - Log Ingestion & Normalizer
Parses raw Linux auth.log, Windows Security Events, Nginx/Apache logs, and Wazuh JSON.
"""
import re
import json
from datetime import datetime, timezone
from typing import Dict, Any, Optional

# Regex Patterns
RE_LINUX_FAILED_SSH = re.compile(
    r"sshd\[\d+\]:\s+Failed\s+password\s+for\s+(?:invalid\s+user\s+)?(\S+)\s+from\s+(\d+\.\d+\.\d+\.\d+)",
    re.IGNORECASE
)
RE_LINUX_ACCEPTED_SSH = re.compile(
    r"sshd\[\d+\]:\s+Accepted\s+(?:password|publickey)\s+for\s+(\S+)\s+from\s+(\d+\.\d+\.\d+\.\d+)",
    re.IGNORECASE
)
RE_LINUX_SUDO_PRIV = re.compile(
    r"sudo:\s+(\S+)\s+:\s+TTY=\S+\s+;\s+PWD=\S+\s+;\s+USER=root\s+;\s+COMMAND=(.*)",
    re.IGNORECASE
)
RE_NGINX_LOG = re.compile(
    r'(\d+\.\d+\.\d+\.\d+)\s+-\s+\S+\s+\[(.*?)\]\s+"([A-Z]+)\s+(.*?)\s+HTTP/\d\.\d"\s+(\d+)',
    re.IGNORECASE
)

SUSPICIOUS_COMMANDS = [
    "whoami", "id", "uname -a", "mimikatz", "powershell -enc",
    "bash -i", "/dev/tcp/", "nc -e", "chmod +s", "cat /etc/shadow"
]

class LogIngestor:
    @staticmethod
    def parse_log(source_type: str, raw_message: str, host: Optional[str] = "server-01") -> Dict[str, Any]:
        """
        Extracts structured security telemetry from unstructured or structured log messages.
        """
        raw = raw_message.strip()
        record = {
            "source_type": source_type.lower(),
            "host": host or "server-01",
            "raw_message": raw,
            "source_ip": None,
            "destination_ip": None,
            "user": None,
            "event_type": "generic_log",
            "severity": "INFO",
            "parsed_data": {}
        }

        # 1. Wazuh JSON
        if raw.startswith("{") and raw.endswith("}"):
            try:
                data = json.loads(raw)
                record["parsed_data"] = data
                record["source_type"] = "wazuh"
                rule = data.get("rule", {})
                record["severity"] = "HIGH" if rule.get("level", 0) >= 10 else "INFO"
                record["event_type"] = rule.get("description", "wazuh_alert")
                agent = data.get("agent", {})
                record["host"] = agent.get("name", record["host"])
                data_obj = data.get("data", {})
                record["source_ip"] = data_obj.get("srcip")
                record["user"] = data_obj.get("dstuser") or data_obj.get("srcuser")
                return record
            except Exception:
                pass

        # 2. Linux Syslog / Auth.log
        m_failed = RE_LINUX_FAILED_SSH.search(raw)
        if m_failed:
            record["event_type"] = "failed_login"
            record["user"] = m_failed.group(1)
            record["source_ip"] = m_failed.group(2)
            record["severity"] = "MEDIUM"
            return record

        m_acc = RE_LINUX_ACCEPTED_SSH.search(raw)
        if m_acc:
            record["event_type"] = "successful_login"
            record["user"] = m_acc.group(1)
            record["source_ip"] = m_acc.group(2)
            record["severity"] = "LOW"
            return record

        m_sudo = RE_LINUX_SUDO_PRIV.search(raw)
        if m_sudo:
            record["event_type"] = "privilege_escalation"
            record["user"] = m_sudo.group(1)
            record["parsed_data"] = {"command": m_sudo.group(2)}
            record["severity"] = "HIGH"
            return record

        # 3. Windows Security Event IDs
        if "EventID: 4625" in raw or "Event ID 4625" in raw or "4625" in raw and "Logon Failure" in raw:
            record["source_type"] = "windows"
            record["event_type"] = "failed_login"
            ip_match = re.search(r"Source Network Address:\s*(\d+\.\d+\.\d+\.\d+)", raw)
            user_match = re.search(r"Account Name:\s*(\S+)", raw)
            if ip_match:
                record["source_ip"] = ip_match.group(1)
            if user_match:
                record["user"] = user_match.group(1)
            record["severity"] = "MEDIUM"
            return record

        if "EventID: 4624" in raw or "Event ID 4624" in raw or "4624" in raw and "An account was successfully logged on" in raw:
            record["source_type"] = "windows"
            record["event_type"] = "successful_login"
            ip_match = re.search(r"Source Network Address:\s*(\d+\.\d+\.\d+\.\d+)", raw)
            user_match = re.search(r"Account Name:\s*(\S+)", raw)
            if ip_match:
                record["source_ip"] = ip_match.group(1)
            if user_match:
                record["user"] = user_match.group(1)
            record["severity"] = "LOW"
            return record

        if "EventID: 4672" in raw or "Special privileges assigned" in raw:
            record["source_type"] = "windows"
            record["event_type"] = "privilege_escalation"
            record["severity"] = "HIGH"
            return record

        # 4. Web Application / Nginx / Apache
        m_web = RE_NGINX_LOG.search(raw)
        if m_web:
            record["source_type"] = "web"
            record["source_ip"] = m_web.group(1)
            path = m_web.group(4)
            record["parsed_data"] = {"method": m_web.group(3), "path": path, "status": m_web.group(5)}

            # Exploit pattern checks
            if any(sqli in path.lower() for sqli in ["' union select", "' or '1'='1", "information_schema", "sleep("]):
                record["event_type"] = "web_attack_sqli"
                record["severity"] = "HIGH"
            elif any(trav in path for trav in ["../", "..%2f", "/etc/passwd", "/windows/win.ini"]):
                record["event_type"] = "web_attack_traversal"
                record["severity"] = "HIGH"
            else:
                record["event_type"] = "web_request"
            return record

        # 5. Check for suspicious commands
        for cmd in SUSPICIOUS_COMMANDS:
            if cmd in raw.lower():
                record["event_type"] = "suspicious_command"
                record["severity"] = "HIGH"
                record["parsed_data"] = {"detected_keyword": cmd}
                return record

        # 6. Check for outbound beaconing
        if "outbound connection" in raw.lower() or "c2" in raw.lower() or "beacon" in raw.lower():
            record["event_type"] = "outbound_connection"
            record["severity"] = "HIGH"
            ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", raw)
            if ip_match:
                record["destination_ip"] = ip_match.group(1)
            return record

        return record
