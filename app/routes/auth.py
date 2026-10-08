import re

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_user, logout_user
from werkzeug.security import check_password_hash, generate_password_hash

from app.models import SecurityLog, User
from extensions import db

bp = Blueprint("auth", __name__)


def log_auth_event(event_type, description, severity="LOW"):
    db.session.add(SecurityLog(actor=current_user.name if current_user.is_authenticated else "Anonymous",
                               user_id=current_user.id if current_user.is_authenticated else None,
                               event_type=event_type, description=description,
                               ip_address=request.remote_addr or "127.0.0.1", severity=severity))


@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user, remember=False, fresh=True)
            log_auth_event("User sign-in", "User signed in to the monitoring console.")
            db.session.commit()
            return redirect(url_for("dashboard.index"))
        flash("Email or password was not recognized.", "danger")
    return render_template("auth/login.html")


@bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        errors = []
        if not 2 <= len(name) <= 100:
            errors.append("Name must be between 2 and 100 characters.")
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email) or len(email) > 160:
            errors.append("Enter a valid email address.")
        if len(password) < 12 or not re.search(r"[A-Za-z]", password) or not re.search(r"\d", password):
            errors.append("Password must be at least 12 characters and include a letter and a number.")
        if User.query.filter_by(email=email).first():
            errors.append("An account with that email already exists.")
        if errors:
            for error in errors:
                flash(error, "danger")
            return render_template("auth/register.html")
        user = User(name=name, email=email, password_hash=generate_password_hash(password), role="Viewer")
        db.session.add(user)
        db.session.flush()
        log_auth_event("Account created", "A new Viewer account was registered.")
        db.session.commit()
        login_user(user, fresh=True)
        flash("Your viewer account is ready.", "success")
        return redirect(url_for("dashboard.index"))
    return render_template("auth/register.html")


@bp.post("/logout")
def logout():
    if current_user.is_authenticated:
        log_auth_event("User sign-out", "User signed out of the monitoring console.")
        db.session.commit()
    logout_user()
    flash("You have been signed out.", "success")
    return redirect(url_for("auth.login"))
