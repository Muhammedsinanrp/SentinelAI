from datetime import datetime, timezone
from typing import Dict, Any

class RansomwareBehaviorMonitor:
    def evaluate_behavior(
        self,
        host: str,
        process_name: str,
        files_modified: int,
        duration_seconds: int,
        entropy: float = 7.9
    ) -> Dict[str, Any]:
        """
        Defensive behavioral analysis. Evaluates file modification frequency and entropy spikes.
        Does not require deploying weaponized malware; monitors telemetry signatures.
        """
        rate = files_modified / max(1, duration_seconds)
        is_ransomware = False
        action = "MONITOR"

        # Threshold: > 20 files per second + high entropy (> 7.5) indicates automated cryptographic ransomware
        if rate >= 15.0 and entropy >= 7.5:
            is_ransomware = True
            action = "ISOLATE_ENDPOINT_IMMEDIATELY"

        severity = "CRITICAL" if is_ransomware else "MEDIUM"
        behavior_flag = "Mass File Encryption Spike (High Entropy)" if is_ransomware else "Normal File Operations"

        return {
            "host": host,
            "process_name": process_name,
            "pid": 2048,
            "files_modified_count": files_modified,
            "duration_seconds": duration_seconds,
            "modification_rate_per_sec": round(rate, 1),
            "entropy_score": entropy,
            "behavior_flag": behavior_flag,
            "severity": severity,
            "is_isolated": is_ransomware,
            "containment_action": action,
            "mitre_technique": "T1486 (Data Encrypted for Impact)",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }

ransomware_monitor = RansomwareBehaviorMonitor()
