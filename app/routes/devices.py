import re
from datetime import datetime

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from sqlalchemy import or_

from app.models import Department, Device, SecurityLog, utcnow
from app.security import minimum_role
from extensions import db

bp = Blueprint("devices", __name__, url_prefix="/devices")


def validate_device(form, device=None):
    fields = {key: form.get(key, "").strip() for key in
              ("asset_tag", "name", "ip_address", "mac_address", "device_type", "department_id", "status")}
    errors = []
    if not re.fullmatch(r"[A-Za-z0-9-]{2,32}", fields["asset_tag"]):
        errors.append("Asset tag must be 2-32 letters, numbers, or hyphens.")
    if not 2 <= len(fields["name"]) <= 120:
        errors.append("Device name must be between 2 and 120 characters.")
    try:
        import ipaddress
        ipaddress.ip_address(fields["ip_address"])
    except ValueError:
        errors.append("Enter a valid IPv4 or IPv6 address.")
    if not re.fullmatch(r"(?i)([0-9a-f]{2}:){5}[0-9a-f]{2}", fields["mac_address"]):
        errors.append("Enter a valid MAC address.")
    if not 2 <= len(fields["device_type"]) <= 48:
        errors.append("Select a device type.")
    try:
        department = db.session.get(Department, int(fields["department_id"]))
    except (TypeError, ValueError):
        department = None
    if not department:
        errors.append("Select a valid department.")
    if fields["status"] not in {"Online", "Offline", "Monitoring"}:
        errors.append("Select a valid device status.")
    duplicate = Device.query.filter_by(asset_tag=fields["asset_tag"]).first()
    if duplicate and (device is None or duplicate.id != device.id):
        errors.append("That asset tag is already in use.")
    return fields, department, errors


def log_device(action, device):
    db.session.add(SecurityLog(user_id=current_user.id, actor=current_user.name, event_type="Device " + action,
                               description=f"{action} device {device.asset_tag}.", ip_address=device.ip_address,
                               severity="LOW", device_id=device.id))


@bp.get("")
@login_required
def index():
    query = request.args.get("q", "").strip()
    status = request.args.get("status", "").strip()
    risk = request.args.get("risk", "").strip().title()
    devices_query = Device.query.join(Department)
    if query:
        like = f"%{query}%"
        devices_query = devices_query.filter(or_(Device.asset_tag.ilike(like), Device.name.ilike(like),
                                                 Device.ip_address.ilike(like), Department.name.ilike(like)))
    if status in {"Online", "Offline", "Monitoring"}:
        devices_query = devices_query.filter(Device.status == status)
    devices = devices_query.order_by(Device.name).all()
    if risk in {"Low", "Medium", "High", "Critical"}:
        devices = [device for device in devices if device.risk_level == risk]
    return render_template("devices/index.html", devices=devices, departments=Department.query.order_by(Department.name).all(),
                           query=query, selected_status=status, selected_risk=risk)


@bp.route("/new", methods=["GET", "POST"])
@minimum_role("Security Analyst")
def create():
    if request.method == "POST":
        fields, department, errors = validate_device(request.form)
        if errors:
            for error in errors:
                flash(error, "danger")
        else:
            device = Device(asset_tag=fields["asset_tag"], name=fields["name"], ip_address=fields["ip_address"],
                            mac_address=fields["mac_address"].upper(), device_type=fields["device_type"],
                            department=department, status=fields["status"], last_seen=utcnow())
            db.session.add(device)
            db.session.flush()
            log_device("added", device)
            db.session.commit()
            flash("Device added to inventory.", "success")
            return redirect(url_for("devices.index"))
    return render_template("devices/form.html", device=None, departments=Department.query.order_by(Department.name).all())


@bp.get("/<int:device_id>")
@login_required
def detail(device_id):
    device = db.get_or_404(Device, device_id)
    return render_template("devices/detail.html", device=device,
                           alerts=device.alerts and sorted(device.alerts, key=lambda item: item.created_at, reverse=True)[:6],
                           logs=sorted(device.logs, key=lambda item: item.created_at, reverse=True)[:8])


@bp.route("/<int:device_id>/edit", methods=["GET", "POST"])
@minimum_role("Security Analyst")
def edit(device_id):
    device = db.get_or_404(Device, device_id)
    if request.method == "POST":
        fields, department, errors = validate_device(request.form, device)
        if errors:
            for error in errors:
                flash(error, "danger")
        else:
            for field in ("asset_tag", "name", "ip_address", "device_type", "status"):
                setattr(device, field, fields[field])
            device.mac_address = fields["mac_address"].upper()
            device.department = department
            log_device("updated", device)
            db.session.commit()
            flash("Device details updated.", "success")
            return redirect(url_for("devices.index"))
    return render_template("devices/form.html", device=device, departments=Department.query.order_by(Department.name).all())


@bp.post("/<int:device_id>/delete")
@minimum_role("Admin")
def delete(device_id):
    device = db.get_or_404(Device, device_id)
    db.session.add(SecurityLog(user_id=current_user.id, actor=current_user.name, event_type="Device deleted",
                               description=f"Deleted device {device.asset_tag} from inventory.",
                               ip_address=device.ip_address, severity="MEDIUM"))
    db.session.delete(device)
    db.session.commit()
    flash("Device removed from inventory.", "success")
    return redirect(url_for("devices.index"))
