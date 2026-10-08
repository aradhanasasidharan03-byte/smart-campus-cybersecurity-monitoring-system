import ipaddress
import math

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app.models import Device, ThreatEvent
from app.security import minimum_role
from app.threat_detection import RULES
from app.threat_service import record_simulated_event
from extensions import db

bp = Blueprint("threats", __name__, url_prefix="/threats")

EVENTS = {
    "failed_login_attempts": "Multiple failed login attempts",
    "unusual_login_time": "Unusual login time",
    "repeated_connections": "Repeated connection attempts",
    "suspicious_ip_activity": "Suspicious IP activity",
    "port_scan": "Simulated port-scan activity",
    "excessive_requests": "Excessive requests",
    "abnormal_device_activity": "Abnormal device activity",
    "unusual_traffic": "Unusual traffic spike",
}


@bp.get("")
@login_required
def index():
    recent_events = ThreatEvent.query.order_by(ThreatEvent.created_at.desc()).limit(20).all()
    numeric_rules = []
    for event_type, (name, low, medium, high, critical, unit) in RULES.items():
        numeric_rules.append({"event_type": event_type, "name": name, "low": low, "medium": medium,
                              "high": high, "critical": critical, "unit": unit})
    return render_template("threats/index.html", events=EVENTS, rules=numeric_rules,
                           special_rules=[
                               {"name": EVENTS["unusual_login_time"], "condition": "outside_schedule = true", "severity": "MEDIUM"},
                               {"name": EVENTS["suspicious_ip_activity"], "condition": "flagged = true", "severity": "HIGH"},
                               {"name": EVENTS["abnormal_device_activity"], "condition": "abnormal = true", "severity": "HIGH"},
                           ], devices=Device.query.order_by(Device.name).all(), recent_events=recent_events)


@bp.post("/simulate")
@minimum_role("Security Analyst")
def simulate():
    event_type = request.form.get("event_type", "")
    if event_type not in EVENTS:
        flash("Select a supported simulated event type.", "danger")
        return redirect(url_for("threats.index"))
    try:
        device = db.session.get(Device, int(request.form.get("device_id", "")))
    except (TypeError, ValueError):
        device = None
    if not device:
        flash("Select a valid device.", "danger")
        return redirect(url_for("threats.index"))
    source_ip = request.form.get("source_ip", "").strip() or device.ip_address
    try:
        source_ip = str(ipaddress.ip_address(source_ip))
    except ValueError:
        flash("Enter a valid simulated IPv4 or IPv6 source address.", "danger")
        return redirect(url_for("threats.index"))
    try:
        value = float(request.form.get("value", "0"))
    except (TypeError, ValueError):
        value = math.nan
    if not math.isfinite(value) or value < 0 or value > 1000000:
        flash("Event intensity must be a number between 0 and 1,000,000.", "danger")
        return redirect(url_for("threats.index"))
    attributes = {"count": value, "outside_schedule": True, "flagged": True, "abnormal": True}
    detection, alert = record_simulated_event(current_user, device, event_type, source_ip, attributes)
    if detection:
        flash(f"{detection.severity} detection created; device risk is now {device.risk_score}/100.", "success")
    else:
        flash("Telemetry recorded; no detection threshold was met.", "info")
    return redirect(url_for("threats.index"))
