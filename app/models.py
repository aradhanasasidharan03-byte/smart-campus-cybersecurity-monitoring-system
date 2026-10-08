from datetime import datetime, timezone

from flask_login import UserMixin
from sqlalchemy import CheckConstraint

from extensions import db


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(160), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(24), nullable=False, default="Viewer", index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    __table_args__ = (CheckConstraint("role IN ('Admin', 'Security Analyst', 'Viewer')", name="ck_user_role"),)


class Department(db.Model):
    __tablename__ = "departments"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.String(240), nullable=True)
    devices = db.relationship("Device", back_populates="department", cascade="all, delete-orphan")


class Device(db.Model):
    __tablename__ = "devices"

    id = db.Column(db.Integer, primary_key=True)
    asset_tag = db.Column(db.String(32), unique=True, nullable=False, index=True)
    name = db.Column(db.String(120), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False, index=True)
    mac_address = db.Column(db.String(17), nullable=False)
    device_type = db.Column(db.String(48), nullable=False)
    department_id = db.Column(db.Integer, db.ForeignKey("departments.id", ondelete="CASCADE"), nullable=False)
    status = db.Column(db.String(16), nullable=False, default="Online", index=True)
    risk_score = db.Column(db.Integer, nullable=False, default=0)
    last_seen = db.Column(db.DateTime, nullable=False, default=utcnow)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    department = db.relationship("Department", back_populates="devices")
    alerts = db.relationship("SecurityAlert", back_populates="device")
    logs = db.relationship("SecurityLog", back_populates="device")
    threat_events = db.relationship("ThreatEvent", back_populates="device")

    __table_args__ = (
        CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="ck_device_risk_score"),
        CheckConstraint("status IN ('Online', 'Offline', 'Monitoring')", name="ck_device_status"),
    )

    @property
    def risk_level(self):
        if self.risk_score >= 81:
            return "Critical"
        if self.risk_score >= 61:
            return "High"
        if self.risk_score >= 31:
            return "Medium"
        return "Low"


class SecurityAlert(db.Model):
    __tablename__ = "security_alerts"

    id = db.Column(db.Integer, primary_key=True)
    alert_code = db.Column(db.String(24), unique=True, nullable=False, index=True)
    threat_type = db.Column(db.String(64), nullable=False, index=True)
    device_id = db.Column(db.Integer, db.ForeignKey("devices.id", ondelete="SET NULL"), nullable=True)
    ip_address = db.Column(db.String(45), nullable=False)
    severity = db.Column(db.String(16), nullable=False, index=True)
    description = db.Column(db.String(500), nullable=False)
    status = db.Column(db.String(24), nullable=False, default="New", index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)
    resolved_at = db.Column(db.DateTime, nullable=True)

    device = db.relationship("Device", back_populates="alerts")

    __table_args__ = (
        CheckConstraint("severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')", name="ck_alert_severity"),
        CheckConstraint("status IN ('New', 'Investigating', 'Resolved')", name="ck_alert_status"),
    )


class SecurityLog(db.Model):
    __tablename__ = "security_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    device_id = db.Column(db.Integer, db.ForeignKey("devices.id", ondelete="SET NULL"), nullable=True)
    actor = db.Column(db.String(120), nullable=False)
    event_type = db.Column(db.String(64), nullable=False, index=True)
    description = db.Column(db.String(500), nullable=False)
    ip_address = db.Column(db.String(45), nullable=False)
    severity = db.Column(db.String(16), nullable=False, default="LOW", index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)

    device = db.relationship("Device", back_populates="logs")


class ThreatEvent(db.Model):
    __tablename__ = "threat_events"

    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey("devices.id", ondelete="SET NULL"), nullable=True)
    threat_type = db.Column(db.String(64), nullable=False, index=True)
    source_ip = db.Column(db.String(45), nullable=False)
    severity = db.Column(db.String(16), nullable=False, index=True)
    description = db.Column(db.String(500), nullable=False)
    event_data = db.Column(db.JSON, nullable=False, default=dict)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)

    device = db.relationship("Device", back_populates="threat_events")


class Report(db.Model):
    __tablename__ = "reports"

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(160), nullable=False)
    report_type = db.Column(db.String(48), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    summary = db.Column(db.JSON, nullable=False, default=dict)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
