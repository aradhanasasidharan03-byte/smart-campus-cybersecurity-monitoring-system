import secrets
import warnings

from flask import Flask, render_template
from flask_login import LoginManager
from sqlalchemy.engine import make_url

from config import BASE_DIR, Config
from extensions import csrf, db

login_manager = LoginManager()
login_manager.login_view = "auth.login"
login_manager.login_message = "Sign in to access the monitoring console."
login_manager.login_message_category = "warning"


def create_app(test_config=None):
    app = Flask(__name__, template_folder=str(BASE_DIR / "templates"),
                static_folder=str(BASE_DIR / "static"))
    app.config.from_object(Config)
    if test_config:
        app.config.update(test_config)
    secret_key = app.config.get("SECRET_KEY")
    if not secret_key or str(secret_key).startswith("replace-with-"):
        if app.config.get("APP_ENV") == "production":
            raise RuntimeError("Set a private SECRET_KEY before production startup.")
        app.config["SECRET_KEY"] = secrets.token_hex(32)
        warnings.warn("Using a temporary local SECRET_KEY; set SECRET_KEY in .env to preserve sessions.",
                      RuntimeWarning, stacklevel=2)
    if (app.config.get("APP_ENV") == "production"
            and make_url(app.config["SQLALCHEMY_DATABASE_URI"]).get_backend_name() == "sqlite"):
        raise RuntimeError("Set DATABASE_URL to a persistent production database before startup.")

    db.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)

    from app.models import User

    @app.context_processor
    def inject_template_helpers():
        from app.models import Device, SecurityAlert, utcnow

        return {"Device": Device, "SecurityAlert": SecurityAlert, "now": utcnow}

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    from app.routes import alerts, api, auth, dashboard, devices, logs, profile, reports, threats

    app.register_blueprint(auth.bp)
    app.register_blueprint(dashboard.bp)
    app.register_blueprint(devices.bp)
    app.register_blueprint(alerts.bp)
    app.register_blueprint(reports.bp)
    app.register_blueprint(logs.bp)
    app.register_blueprint(profile.bp)
    app.register_blueprint(threats.bp)
    app.register_blueprint(api.bp)

    @app.errorhandler(403)
    def forbidden(_error):
        return render_template("errors/403.html"), 403

    @app.errorhandler(404)
    def not_found(_error):
        return render_template("errors/404.html"), 404

    @app.errorhandler(500)
    def server_error(_error):
        db.session.rollback()
        return render_template("errors/500.html"), 500

    with app.app_context():
        db.create_all()
        if app.config.get("SEED_DEMO"):
            from app.seed import seed_demo_data

            seed_demo_data()

    return app
