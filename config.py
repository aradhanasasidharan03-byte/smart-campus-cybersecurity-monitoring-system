import os
from pathlib import Path

from sqlalchemy.engine import make_url


BASE_DIR = Path(__file__).resolve().parent


def normalize_database_url(database_url):
    url = make_url(database_url)
    if url.drivername in {"postgres", "postgresql"}:
        url = url.set(drivername="postgresql+psycopg")
    return url.render_as_string(hide_password=False)


class Config:
    APP_ENV = os.environ.get("APP_ENV", "development").lower()
    SECRET_KEY = os.environ.get("SECRET_KEY")
    SQLALCHEMY_DATABASE_URI = normalize_database_url(
        os.environ.get("DATABASE_URL") or f"sqlite:///{BASE_DIR / 'campus_security.db'}"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True}
    MAX_CONTENT_LENGTH = 16 * 1024
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get(
        "COOKIE_SECURE", "true" if APP_ENV == "production" else "false"
    ).lower() == "true"
    PERMANENT_SESSION_LIFETIME = 60 * 60 * 8
    WTF_CSRF_TIME_LIMIT = 60 * 60
    SEED_DEMO = os.environ.get(
        "SEED_DEMO", "false" if APP_ENV == "production" else "true"
    ).lower() == "true"
    DEMO_ADMIN_PASSWORD = os.environ.get("DEMO_ADMIN_PASSWORD")
    DEMO_ANALYST_PASSWORD = os.environ.get("DEMO_ANALYST_PASSWORD")
    DEMO_VIEWER_PASSWORD = os.environ.get("DEMO_VIEWER_PASSWORD")
