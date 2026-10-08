import secrets

from app.models import SecurityAlert, SecurityLog, ThreatEvent, utcnow
from app.threat_detection import classify_event
from extensions import db


def record_simulated_event(user, device, event_type, source_ip, attributes, description=""):
    detection = classify_event(event_type, attributes)
    now = utcnow()
    db.session.add(SecurityLog(
        user_id=user.id,
        actor=user.name,
        device_id=device.id,
        event_type="Telemetry received",
        description=description or f"Simulated {event_type} event received.",
        ip_address=source_ip,
        severity=detection.severity if detection else "LOW",
        created_at=now,
    ))
    alert = None
    if detection:
        device.risk_score = min(100, device.risk_score + detection.risk_points)
        device.last_seen = now
        alert = SecurityAlert(
            alert_code=f"ALT-{now:%y%m%d}-{secrets.token_hex(3).upper()}",
            threat_type=detection.threat_type,
            device_id=device.id,
            ip_address=source_ip,
            severity=detection.severity,
            description=detection.description,
            status="New",
            created_at=now,
        )
        db.session.add_all([
            alert,
            ThreatEvent(
                device_id=device.id,
                threat_type=detection.threat_type,
                source_ip=source_ip,
                severity=detection.severity,
                description=detection.description,
                event_data={"event_type": event_type, "attributes": attributes},
                created_at=now,
            ),
        ])
    db.session.commit()
    return detection, alert
