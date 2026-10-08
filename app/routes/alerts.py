from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from app.models import SecurityAlert, SecurityLog, utcnow
from app.security import minimum_role
from extensions import db

bp = Blueprint("alerts", __name__, url_prefix="/alerts")


@bp.get("")
@login_required
def index():
    severity = request.args.get("severity", "").upper()
    status = request.args.get("status", "")
    query = request.args.get("q", "").strip()
    alerts = SecurityAlert.query
    if severity in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        alerts = alerts.filter_by(severity=severity)
    if status in {"New", "Investigating", "Resolved"}:
        alerts = alerts.filter_by(status=status)
    if query:
        alerts = alerts.filter(SecurityAlert.description.ilike(f"%{query}%") |
                              SecurityAlert.threat_type.ilike(f"%{query}%") |
                              SecurityAlert.ip_address.ilike(f"%{query}%") |
                              SecurityAlert.alert_code.ilike(f"%{query}%"))
    return render_template("alerts/index.html", alerts=alerts.order_by(SecurityAlert.created_at.desc()).all(),
                           severity=severity, status=status, query=query)


@bp.post("/<int:alert_id>/status")
@minimum_role("Security Analyst")
def update_status(alert_id):
    alert = db.get_or_404(SecurityAlert, alert_id)
    new_status = request.form.get("status", "")
    if new_status not in {"New", "Investigating", "Resolved"}:
        flash("Select a valid alert status.", "danger")
    else:
        alert.status = new_status
        alert.resolved_at = utcnow() if new_status == "Resolved" else None
        db.session.add(SecurityLog(user_id=current_user.id, actor=current_user.name,
                                   event_type="Alert status changed",
                                   description=f"Alert {alert.alert_code} moved to {new_status}.",
                                   ip_address=alert.ip_address, severity="LOW", device_id=alert.device_id))
        db.session.commit()
        flash(f"Alert {alert.alert_code} updated.", "success")
    return redirect(request.referrer if request.referrer and request.referrer.startswith(request.host_url) else url_for("alerts.index"))
