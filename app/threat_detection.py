from dataclasses import dataclass
import math


@dataclass(frozen=True)
class Detection:
    threat_type: str
    severity: str
    description: str
    risk_points: int


RULES = {
    "failed_login_attempts": ("Multiple failed logins", 2, 4, 7, 12, "failed attempts"),
    "repeated_connections": ("Repeated connection attempts", 5, 10, 20, 40, "connection attempts"),
    "port_scan": ("Simulated port-scan activity", 3, 8, 16, 32, "ports probed"),
    "excessive_requests": ("Excessive requests", 120, 300, 600, 1200, "requests per minute"),
    "unusual_traffic": ("Unusual traffic spike", 2, 3, 5, 8, "times baseline traffic"),
}

EVENT_TYPES = frozenset(RULES) | frozenset({
    "unusual_login_time", "suspicious_ip_activity", "abnormal_device_activity",
})


def classify_event(event_type, attributes=None):
    """Classify supplied simulated telemetry; this function performs no network activity."""
    attrs = attributes or {}
    key = str(event_type or "").strip().lower()

    if key == "unusual_login_time" and attrs.get("outside_schedule", True):
        return Detection("Unusual login time", "MEDIUM", "A login occurred outside the configured campus access window.", 12)
    if key == "suspicious_ip_activity" and attrs.get("flagged", True):
        return Detection("Suspicious IP activity", "HIGH", "Simulated telemetry marked the source IP for analyst review.", 22)
    if key == "abnormal_device_activity" and attrs.get("abnormal", True):
        return Detection("Abnormal device activity", "HIGH", "Device behavior deviated from its simulated baseline.", 22)

    rule = RULES.get(key)
    if not rule:
        return None
    threat_type, low_at, medium_at, high_at, critical_at, unit = rule
    try:
        value = float(attrs.get("count", attrs.get("value", 0)))
    except (TypeError, ValueError, OverflowError):
        return None
    if not math.isfinite(value):
        return None
    if value < low_at:
        return None
    if value >= critical_at:
        severity, points = "CRITICAL", 32
    elif value >= high_at:
        severity, points = "HIGH", 22
    elif value >= medium_at:
        severity, points = "MEDIUM", 12
    else:
        severity, points = "LOW", 5
    return Detection(threat_type, severity, f"Observed {value:g} {unit}; review the device activity.", points)


def risk_level(score):
    if score >= 81:
        return "Critical"
    if score >= 61:
        return "High"
    if score >= 31:
        return "Medium"
    return "Low"
