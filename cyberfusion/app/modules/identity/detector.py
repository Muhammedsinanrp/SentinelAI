from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List

LOCATION_COORDINATES = {
    "india": (20.5937, 78.9629),
    "russia": (61.5240, 105.3188),
    "united states": (37.0902, -95.7129),
    "germany": (51.1657, 10.4515),
    "china": (35.8617, 104.1954),
}

def approx_distance_km(loc1: str, loc2: str) -> float:
    loc1_clean = loc1.strip().lower()
    loc2_clean = loc2.strip().lower()
    if loc1_clean == loc2_clean:
        return 0.0
    if ("india" in loc1_clean and "russia" in loc2_clean) or ("russia" in loc1_clean and "india" in loc2_clean):
        return 4900.0
    return 3500.0

class IdentityThreatDetector:
    def __init__(self):
        # Cache of user last login: user_email -> {"time": datetime, "location": str, "device": str}
        self.user_history = {}

    def analyze_auth_event(self, user_email: str, source_ip: str, location: str, device: str) -> Dict[str, Any]:
        now = datetime.now(timezone.utc)
        reasons = []
        is_impossible = False
        calculated_speed = 0.0
        risk_score = 15

        prev = self.user_history.get(user_email)
        if prev:
            time_delta_hours = max(0.05, (now - prev["time"]).total_seconds() / 3600.0)
            dist_km = approx_distance_km(prev["location"], location)
            calculated_speed = dist_km / time_delta_hours

            # Commercial flights max ~900 km/h
            if calculated_speed > 800.0:
                is_impossible = True
                reasons.append(f"Impossible Travel: {prev['location']} -> {location} ({int(dist_km)} km in {int(time_delta_hours*60)} mins, speed {int(calculated_speed)} km/h)")
                risk_score += 55

            if device.lower() != prev["device"].lower() and "unknown" in device.lower():
                reasons.append(f"Anomalous Device: Authenticated from unfamiliar client fingerprint '{device}'")
                risk_score += 20
        else:
            if "unknown" in device.lower():
                reasons.append("New / Unrecognized Device Fingerprint")
                risk_score += 15

        # Check suspicious time (e.g. 2 AM - 4 AM)
        current_hour = now.hour
        if 2 <= current_hour <= 4:
            reasons.append("Unusual Login Window: Authentication initiated during anomalous off-hours (03:00)")
            risk_score += 15

        # Update cache
        self.user_history[user_email] = {
            "time": now,
            "location": location,
            "device": device
        }

        final_risk = min(100, risk_score)
        verdict = "CRITICAL" if final_risk >= 85 else "HIGH" if final_risk >= 65 else "MEDIUM" if final_risk >= 35 else "LOW"

        return {
            "user_email": user_email,
            "source_ip": source_ip,
            "location": location,
            "device_fingerprint": device,
            "is_impossible_travel": is_impossible,
            "speed_kmh": round(calculated_speed, 1),
            "anomaly_reasons": reasons,
            "risk_score": final_risk,
            "verdict": verdict
        }

identity_detector = IdentityThreatDetector()
