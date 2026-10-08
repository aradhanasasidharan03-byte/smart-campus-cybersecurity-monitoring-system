import secrets
import string

import pytest

from app import create_app
from extensions import db


def new_test_password():
    return secrets.token_urlsafe(24) + secrets.choice(string.ascii_letters) + secrets.choice(string.digits)


@pytest.fixture
def app():
    demo_passwords = {
        "admin@campus.edu": new_test_password(),
        "analyst@campus.edu": new_test_password(),
        "viewer@campus.edu": new_test_password(),
    }
    application = create_app({
        "TESTING": True,
        "WTF_CSRF_ENABLED": False,
        "SECRET_KEY": secrets.token_hex(32),
        "DEMO_ADMIN_PASSWORD": demo_passwords["admin@campus.edu"],
        "DEMO_ANALYST_PASSWORD": demo_passwords["analyst@campus.edu"],
        "DEMO_VIEWER_PASSWORD": demo_passwords["viewer@campus.edu"],
        "TEST_DEMO_PASSWORDS": demo_passwords,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "SEED_DEMO": True,
    })
    yield application
    with application.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    return app.test_client()


def sign_in(client, email="analyst@campus.edu", password=None):
    if password is None:
        password = client.application.config["TEST_DEMO_PASSWORDS"][email]
    return client.post("/login", data={"email": email, "password": password}, follow_redirects=True)
