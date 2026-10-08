import secrets
from datetime import timedelta

from flask import current_app

from werkzeug.security import generate_password_hash

from app.models import Department, Device, Report, SecurityAlert, SecurityLog, ThreatEvent, User, utcnow
from extensions import db


def seed_demo_data():
    if User.query.first():
        return

    demo_passwords = {}
    for role, email in (("ADMIN", "admin@campus.edu"), ("ANALYST", "analyst@campus.edu"),
                        ("VIEWER", "viewer@campus.edu")):
        password = current_app.config.get(f"DEMO_{role}_PASSWORD")
        if password and not password.startswith("replace-with-"):
            demo_passwords[role] = password
        elif current_app.config.get("APP_ENV") == "production":
            raise RuntimeError(f"DEMO_{role}_PASSWORD is required when production demo seeding is enabled.")
        else:
            demo_passwords[role] = secrets.token_urlsafe(18)
            print(f"Generated local demo credential: {email} / {demo_passwords[role]}")

    users = [
        User(name="Campus Administrator", email="admin@campus.edu", password_hash=generate_password_hash(demo_passwords["ADMIN"]), role="Admin"),
        User(name="Jordan Lee", email="analyst@campus.edu", password_hash=generate_password_hash(demo_passwords["ANALYST"]), role="Security Analyst"),
        User(name="Taylor Morgan", email="viewer@campus.edu", password_hash=generate_password_hash(demo_passwords["VIEWER"]), role="Viewer"),
    ]
    db.session.add_all(users)
    department_rows = [
        Department(name="IT Services", description="Campus infrastructure and support"),
        Department(name="Research Labs", description="Teaching and research environments"),
        Department(name="Library", description="Library workstations and services"),
        Department(name="Student Housing", description="Residence network and IoT"),
        Department(name="Administration", description="Administrative systems"),
    ]
    departments = []
    for department in department_rows:
        existing = Department.query.filter_by(name=department.name).first()
        if existing:
            departments.append(existing)
        else:
            departments.append(department)
            db.session.add(department)
    db.session.flush()
    department_map = {item.name: item.id for item in departments}

    inventory = [
        ("CAM-014", "North Quad Camera 14", "10.24.4.14", "02:4A:8B:10:20:14", "Camera", "Student Housing", "Online", 18),
        ("AP-022", "Engineering Access Point", "10.24.2.22", "02:4A:8B:10:20:22", "Access point", "IT Services", "Online", 67),
        ("WS-108", "Library Workstation 108", "10.24.3.108", "02:4A:8B:10:20:31", "Workstation", "Library", "Online", 9),
        ("LAB-031", "Robotics Lab Controller", "10.24.8.31", "02:4A:8B:10:20:41", "Controller", "Research Labs", "Monitoring", 84),
        ("IOT-067", "Residence HVAC Gateway", "10.24.4.67", "02:4A:8B:10:20:52", "IoT gateway", "Student Housing", "Online", 42),
        ("SRV-003", "Student Portal Node", "10.24.1.13", "02:4A:8B:10:20:63", "Server", "IT Services", "Online", 28),
        ("PRN-019", "Admin Building Printer", "10.24.5.19", "02:4A:8B:10:20:74", "Printer", "Administration", "Offline", 12),
        ("CAM-029", "Science Hall Camera 29", "10.24.8.29", "02:4A:8B:10:20:85", "Camera", "Research Labs", "Online", 73),
        ("WS-214", "Admissions Workstation 214", "10.24.5.214", "02:4A:8B:10:20:96", "Workstation", "Administration", "Online", 4),
        ("AP-041", "Library East Access Point", "10.24.3.41", "02:4A:8B:10:20:A7", "Access point", "Library", "Offline", 31),
        ("IOT-092", "Greenhouse Sensor Hub", "10.24.8.92", "02:4A:8B:10:20:B8", "IoT gateway", "Research Labs", "Monitoring", 56),
        ("SRV-011", "Identity Services Replica", "10.24.1.21", "02:4A:8B:10:20:C9", "Server", "IT Services", "Online", 21),
    ]
    now = utcnow()
    devices = [Device(asset_tag=tag, name=name, ip_address=ip, mac_address=mac, device_type=kind,
                      department_id=department_map[department], status=status, risk_score=score,
                      last_seen=now - timedelta(minutes=index * 7))
               for index, (tag, name, ip, mac, kind, department, status, score) in enumerate(inventory)]
    db.session.add_all(devices)
    db.session.flush()

    alert_rows = [
        ("Multiple failed logins", "WS-108", "MEDIUM", "Six failed sign-in attempts were recorded within five minutes.", "New", 12),
        ("Simulated port-scan activity", "LAB-031", "CRITICAL", "A lab controller reported probes across 22 simulated service ports.", "Investigating", 34),
        ("Unusual login time", "SRV-003", "MEDIUM", "A privileged account signed in outside the campus access window.", "New", 58),
        ("Suspicious IP activity", "AP-022", "HIGH", "Simulated source reputation signal requires analyst review.", "Investigating", 91),
        ("Excessive requests", "CAM-029", "HIGH", "Request volume exceeded the configured device baseline.", "New", 143),
        ("Abnormal device activity", "IOT-067", "HIGH", "Telemetry diverged from the expected HVAC gateway profile.", "Resolved", 210),
        ("Unusual traffic spike", "LAB-031", "CRITICAL", "Traffic reached 5.2 times the simulated baseline.", "New", 275),
        ("Repeated connection attempts", "AP-041", "LOW", "Repeated connection attempts were observed before the access point went offline.", "Resolved", 380),
        ("Multiple failed logins", "SRV-011", "MEDIUM", "Authentication failures were isolated to a single demo account.", "New", 510),
    ]
    device_map = {device.asset_tag: device for device in devices}
    alerts = []
    for index, (kind, tag, severity, description, status, minutes) in enumerate(alert_rows, 1):
        created = now - timedelta(minutes=minutes)
        alert = SecurityAlert(alert_code=f"ALT-2026-{index:04d}", threat_type=kind,
                              device_id=device_map[tag].id, ip_address=device_map[tag].ip_address,
                              severity=severity, description=description, status=status, created_at=created)
        alerts.append(alert)
    db.session.add_all(alerts)
    db.session.flush()

    log_rows = [
        ("Device heartbeat", "Access point heartbeat received; signal quality stable.", "10.24.2.22", "LOW", "AP-022"),
        ("Authentication failure", "Invalid sign-in attempt for a demo account.", "10.24.3.108", "MEDIUM", "WS-108"),
        ("Threat detected", "Simulated port-scan rule matched the lab telemetry batch.", "10.24.8.31", "CRITICAL", "LAB-031"),
        ("Policy check", "Device configuration baseline verified.", "10.24.1.13", "LOW", "SRV-003"),
        ("Traffic anomaly", "Outbound traffic exceeded the demo threshold.", "10.24.8.29", "HIGH", "CAM-029"),
        ("Device offline", "Last heartbeat exceeded the monitoring interval.", "10.24.3.41", "MEDIUM", "AP-041"),
        ("Alert status changed", "Alert moved to investigation by Jordan Lee.", "10.24.2.22", "LOW", "AP-022"),
        ("Threat detected", "Suspicious IP activity was flagged by simulated telemetry.", "10.24.2.22", "HIGH", "AP-022"),
        ("Risk score updated", "Device risk increased after repeated simulated connection attempts.", "10.24.4.67", "MEDIUM", "IOT-067"),
        ("User sign-in", "Security analyst signed in to the monitoring console.", "10.24.1.50", "LOW", None),
        ("Device heartbeat", "Camera telemetry received within normal limits.", "10.24.4.14", "LOW", "CAM-014"),
        ("Threat detected", "Unusual login time rule matched a demonstration event.", "10.24.1.13", "MEDIUM", "SRV-003"),
    ]
    logs = [SecurityLog(actor="Campus Monitor", event_type=kind, description=description,
                        ip_address=ip, severity=severity,
                        device_id=device_map[tag].id if tag else None,
                        created_at=now - timedelta(minutes=18 * index))
            for index, (kind, description, ip, severity, tag) in enumerate(log_rows, 1)]
    db.session.add_all(logs)
    db.session.add_all([
        ThreatEvent(device_id=device_map[tag].id, threat_type=alert.threat_type,
                    source_ip=alert.ip_address, severity=alert.severity,
                    description=alert.description, event_data={"source": "demo_seed"}, created_at=alert.created_at)
        for tag, alert in zip([row[1] for row in alert_rows], alerts)
    ])
    db.session.add(Report(title="Campus security overview", report_type="weekly_summary",
                          created_by=users[0].id, summary={"alerts": len(alerts), "devices": len(devices)}))
    db.session.commit()
