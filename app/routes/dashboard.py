from datetime import timedelta

from flask import Blueprint, render_template
from flask_login import login_required
from sqlalchemy import func

from app.models import Device, SecurityAlert, SecurityLog, utcnow

bp = Blueprint("dashboard", __name__)


@bp.get("/")
@login_required
def index():
    devices = Device.query.order_by(Device.name.asc()).all()
    alerts = SecurityAlert.query.order_by(SecurityAlert.created_at.desc()).limit(7).all()
    recent_logs = SecurityLog.query.order_by(SecurityLog.created_at.desc()).limit(8).all()
    total_devices = len(devices)
    active_devices = sum(device.status == "Online" for device in devices)
    offline_devices = sum(device.status == "Offline" for device in devices)
    suspicious_devices = sum(device.risk_score >= 61 for device in devices)
    total_threats = SecurityAlert.query.count()
    critical_threats = SecurityAlert.query.filter_by(severity="CRITICAL").count()
    unresolved_alerts = SecurityAlert.query.filter(SecurityAlert.status != "Resolved").count()

    severity_rows = (SecurityAlert.query.with_entities(SecurityAlert.severity, func.count(SecurityAlert.id))
                     .group_by(SecurityAlert.severity).all())
    type_rows = (SecurityAlert.query.with_entities(SecurityAlert.threat_type, func.count(SecurityAlert.id))
                 .group_by(SecurityAlert.threat_type).order_by(func.count(SecurityAlert.id).desc()).limit(6).all())
    status_rows = (Device.query.with_entities(Device.status, func.count(Device.id)).group_by(Device.status).all())
    risk_rows = {}
    for device in devices:
        risk_rows[device.risk_level] = risk_rows.get(device.risk_level, 0) + 1

    days = [(utcnow().date() - timedelta(days=offset)) for offset in reversed(range(7))]
    activity = []
    for day in days:
        count = SecurityLog.query.filter(func.date(SecurityLog.created_at) == day).count()
        activity.append(count)

    return render_template("dashboard/index.html", devices=devices, alerts=alerts, recent_logs=recent_logs,
                           total_devices=total_devices, active_devices=active_devices,
                           offline_devices=offline_devices, suspicious_devices=suspicious_devices,
                           total_threats=total_threats, critical_threats=critical_threats,
                           unresolved_alerts=unresolved_alerts,
                           chart_data={"severity": {key: value for key, value in severity_rows},
                                       "types": {key: value for key, value in type_rows},
                                       "status": {key: value for key, value in status_rows},
                                       "risk": risk_rows,
                                       "activity_labels": [day.strftime("%b %d") for day in days],
                                       "activity": activity})
