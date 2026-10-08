import re
import json
from typing import Dict, Any, Optional

RE_LINUX_FAILED = re.compile(r"sshd\[\d+\]:\s+Failed\s+password\s+for\s+(?:invalid\s+user\s+)?(\S+)\s+from\s+(\d+\.\d+\.\d+\.\d+)", re.IGNORECASE)
RE_LINUX_ACCEPTED = re.compile(r"sshd\[\d+\]:\s+Accepted\s+(?:password|publickey)\s+for\s+(\S+)\s+from\s+(\d+\.\d+\.\d+\.\d+)", re.IGNORECASE)
RE_LINUX_SUDO = re.compile(r"sudo:\s+(\S+)\s+:\s+TTY=\S+\s+;\s+PWD=\S+\s+;\s+USER=root\s+;\s+COMMAND=(.*)", re.IGNORECASE)

class LogIngestor:
    @staticmethod
    def parse_log(source_type: str, raw_message: str, host: Optional[str] = "server-01") -> Dict[str, Any]:
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

        if m := RE_LINUX_FAILED.search(raw):
            record["event_type"] = "failed_login"
            record["user"] = m.group(1)
            record["source_ip"] = m.group(2)
            record["severity"] = "MEDIUM"
            return record

        if m := RE_LINUX_ACCEPTED.search(raw):
            record["event_type"] = "successful_login"
            record["user"] = m.group(1)
            record["source_ip"] = m.group(2)
            record["severity"] = "LOW"
            return record

        if m := RE_LINUX_SUDO.search(raw):
            record["event_type"] = "privilege_escalation"
            record["user"] = m.group(1)
            record["severity"] = "HIGH"
            record["parsed_data"] = {"command": m.group(2)}
            return record

        if "whoami" in raw.lower() or "mimikatz" in raw.lower() or "powershell -enc" in raw.lower():
            record["event_type"] = "suspicious_command"
            record["severity"] = "HIGH"
            return record

        if "c2" in raw.lower() or "outbound connection" in raw.lower() or "beacon" in raw.lower():
            record["event_type"] = "outbound_connection"
            record["severity"] = "HIGH"
            return record

        return record
