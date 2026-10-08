"""
CYBERSHIELD X - Incident Attack Timeline Generator
Reconstructs multi-stage attack chains in chronological order.
"""
from typing import List, Dict, Any
from datetime import datetime

class TimelineBuilder:
    @staticmethod
    def format_timeline_chain(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Sorts and formats incident events chronologically with MITRE tactic tagging.
        """
        def _get_ts(e):
            val = e.get("timestamp")
            if isinstance(val, str):
                try:
                    return datetime.fromisoformat(val.replace("Z", "+00:00"))
                except Exception:
                    return datetime.min
            elif isinstance(val, datetime):
                return val
            return datetime.min

        sorted_events = sorted(events, key=_get_ts)
        formatted = []
        for ev in sorted_events:
            ts = ev.get("timestamp")
            time_str = ts.strftime("%H:%M:%S") if isinstance(ts, datetime) else str(ts)[:19]
            formatted.append({
                "time": time_str,
                "event_name": ev.get("event_name", "Security Event"),
                "description": ev.get("description", ""),
                "actor": ev.get("actor", "Unknown"),
                "target": ev.get("target", "Internal Host"),
                "phase": ev.get("phase", "Execution"),
                "mitre_id": ev.get("mitre_id", "T1059")
            })
        return formatted
