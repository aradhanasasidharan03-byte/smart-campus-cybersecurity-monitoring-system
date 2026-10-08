from datetime import timedelta

from flask import Blueprint, render_template
from flask_login import login_required
from sqlalchemy import func

from app.models import Device, SecurityAlert, SecurityLog, ThreatEvent, utcnow

bp = Blueprint("reports", __name__, url_prefix="/reports")


@bp.get("")
@login_required
def index():
    severity = dict(SecurityAlert.query.with_entities(SecurityAlert.severity, func.count(SecurityAlert.id)).group_by(SecurityAlert.severity).all())
    types = dict(SecurityAlert.query.with_entities(SecurityAlert.threat_type, func.count(SecurityAlert.id))
                  .group_by(SecurityAlert.threat_type).order_by(func.count(SecurityAlert.id).desc()).limit(8).all())
    status = dict(Device.query.with_entities(Device.status, func.count(Device.id)).group_by(Device.status).all())
    risk = {level: sum(device.risk_level == level for device in Device.query.all()) for level in ("Low", "Medium", "High", "Critical")}
    days = [utcnow().date() - timedelta(days=offset) for offset in reversed(range(14))]
    activity = [SecurityLog.query.filter(func.date(SecurityLog.created_at) == day).count() for day in days]
    return render_template("reports/index.html", threat_count=ThreatEvent.query.count(), alert_count=SecurityAlert.query.count(),
                           chart_data={"severity": severity, "types": types, "status": status, "risk": risk,
                                       "activity_labels": [day.strftime("%b %d") for day in days], "activity": activity})
