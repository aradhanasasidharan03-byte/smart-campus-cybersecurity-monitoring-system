import re

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from werkzeug.security import check_password_hash, generate_password_hash

from app.models import SecurityLog, utcnow
from extensions import db

bp = Blueprint("profile", __name__, url_prefix="/profile")


@bp.route("", methods=["GET", "POST"])
@login_required
def index():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        errors = []
        if not 2 <= len(name) <= 100:
            errors.append("Name must be between 2 and 100 characters.")
        password_changed = bool(current_password or new_password)
        if password_changed:
            if not check_password_hash(current_user.password_hash, current_password):
                errors.append("Current password was not recognized.")
            if (len(new_password) < 12 or not re.search(r"[A-Za-z]", new_password)
                    or not re.search(r"\d", new_password)):
                errors.append("New password must be at least 12 characters and include a letter and a number.")
        if errors:
            for error in errors:
                flash(error, "danger")
            return render_template("profile/index.html")

        current_user.name = name
        if password_changed:
            current_user.password_hash = generate_password_hash(new_password)
        db.session.add(SecurityLog(
            user_id=current_user.id,
            actor=name,
            event_type="Profile updated",
            description="Account profile details updated." + (" Password changed." if password_changed else ""),
            ip_address=request.remote_addr or "127.0.0.1",
            severity="LOW",
            created_at=utcnow(),
        ))
        db.session.commit()
        flash("Profile changes saved.", "success")
        return redirect(url_for("profile.index"))
    return render_template("profile/index.html")
