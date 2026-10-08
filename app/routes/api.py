import ipaddress
import json

from flask import Blueprint, jsonify, request
from flask_login import current_user

from app.models import Device
from app.security import minimum_role
from app.threat_detection import EVENT_TYPES
from app.threat_service import record_simulated_event
from extensions import db

bp = Blueprint("api", __name__, url_prefix="/api")


@bp.post("/events")
@minimum_role("Security Analyst")
def ingest_event():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify(error="Expected a JSON event object."), 400
    event_type = str(payload.get("event_type", "")).strip().lower()
    if event_type not in EVENT_TYPES:
        return jsonify(error="Unsupported simulated event type."), 400
    device = None
    try:
        if payload.get("device_id") is not None:
            device = db.session.get(Device, int(payload["device_id"]))
        elif payload.get("asset_tag"):
            device = Device.query.filter_by(asset_tag=str(payload["asset_tag"]).strip()).first()
    except (TypeError, ValueError):
        return jsonify(error="device_id must be an integer."), 400
    if not device:
        return jsonify(error="A valid device_id or asset_tag is required."), 400
    source_ip = str(payload.get("source_ip", device.ip_address)).strip()
    try:
        source_ip = str(ipaddress.ip_address(source_ip))
    except ValueError:
        return jsonify(error="source_ip must be a valid IPv4 or IPv6 address."), 400
    attributes = payload.get("attributes", {})
    if not isinstance(attributes, dict):
        return jsonify(error="attributes must be a JSON object."), 400
    try:
        json.dumps(attributes, allow_nan=False)
    except (TypeError, ValueError):
        return jsonify(error="attributes must contain finite JSON values."), 400
    description = str(payload.get("description", "")).strip()
    if len(description) > 500:
        return jsonify(error="description must be 500 characters or fewer."), 400
    detection, alert = record_simulated_event(current_user, device, event_type, source_ip, attributes, description)
    result = {"detected": bool(detection), "event_type": event_type, "device": device.asset_tag,
              "risk_score": device.risk_score, "risk_level": device.risk_level}
    if detection:
        result.update(alert_id=alert.alert_code, severity=detection.severity,
                      risk_score=device.risk_score, risk_level=device.risk_level)
    return jsonify(result), 201


@bp.get("/health")
def health():
    return jsonify(status="ok", service="smart-campus-security")
