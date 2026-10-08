from flask import Blueprint, render_template, request
from flask_login import login_required

from app.models import SecurityLog

bp = Blueprint("logs", __name__, url_prefix="/logs")


@bp.get("")
@login_required
def index():
    query = request.args.get("q", "").strip()
    severity = request.args.get("severity", "").upper()
    event_type = request.args.get("event", "").strip()
    logs = SecurityLog.query
    if query:
        term = f"%{query}%"
        logs = logs.filter(SecurityLog.actor.ilike(term) | SecurityLog.description.ilike(term) |
                           SecurityLog.ip_address.ilike(term) | SecurityLog.event_type.ilike(term))
    if severity in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        logs = logs.filter_by(severity=severity)
    if event_type:
        logs = logs.filter(SecurityLog.event_type == event_type)
    entries = logs.order_by(SecurityLog.created_at.desc()).limit(250).all()
    event_types = [row[0] for row in SecurityLog.query.with_entities(SecurityLog.event_type).distinct().order_by(SecurityLog.event_type).all()]
    return render_template("logs/index.html", logs=entries, query=query, severity=severity,
                           selected_event=event_type, event_types=event_types)
