from app.models import Device, SecurityAlert, SecurityLog, ThreatEvent, User
from app.threat_detection import classify_event
from config import normalize_database_url
from extensions import db
from tests.conftest import new_test_password, sign_in


def test_application_startup_and_dashboard(client):
    response = client.get("/")
    assert response.status_code == 302
    sign_in(client)
    response = client.get("/")
    assert response.status_code == 200
    assert b"Security overview" in response.data
    assert b"12" in response.data


def test_login_and_logout(client):
    response = client.post("/login", data={"email": "analyst@campus.edu", "password": "wrong"})
    assert response.status_code == 200
    assert b"was not recognized" in response.data
    sign_in(client)
    response = client.post("/logout", follow_redirects=True)
    assert response.status_code == 200
    assert b"Sign in" in response.data


def test_registration_creates_viewer(client, app):
    password = new_test_password()
    response = client.post("/register", data={"name": "Casey Example", "email": "casey@campus.edu",
                                               "password": password}, follow_redirects=True)
    assert response.status_code == 200
    assert b"viewer account is ready" in response.data
    with app.app_context():
        from app.models import User
        user = User.query.filter_by(email="casey@campus.edu").one()
        assert user.role == "Viewer"
        assert user.password_hash != password


def test_device_operations(client, app):
    sign_in(client)
    response = client.post("/devices/new", data={
        "asset_tag": "TEST-100", "name": "Test Campus Sensor", "ip_address": "10.24.9.100",
        "mac_address": "02:4A:8B:10:20:DD", "device_type": "IoT gateway",
        "department_id": "1", "status": "Online",
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b"Test Campus Sensor" in response.data
    with app.app_context():
        device = Device.query.filter_by(asset_tag="TEST-100").one()
        device_id = device.id
    response = client.post(f"/devices/{device_id}/edit", data={
        "asset_tag": "TEST-100", "name": "Updated Campus Sensor", "ip_address": "10.24.9.101",
        "mac_address": "02:4A:8B:10:20:DE", "device_type": "IoT gateway",
        "department_id": "1", "status": "Monitoring",
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b"Updated Campus Sensor" in response.data
    assert client.get(f"/devices/{device_id}").status_code == 200
    assert client.get(f"/devices/{device_id}/edit").status_code == 200
    response = client.post(f"/devices/{device_id}/delete", follow_redirects=True)
    assert response.status_code == 403


def test_admin_can_delete_device(client, app):
    sign_in(client, "admin@campus.edu")
    with app.app_context():
        device_id = Device.query.filter_by(asset_tag="WS-214").one().id
    response = client.post(f"/devices/{device_id}/delete", follow_redirects=True)
    assert response.status_code == 200
    with app.app_context():
        assert db.session.get(Device, device_id) is None


def test_alert_operations(client, app):
    sign_in(client)
    with app.app_context():
        alert_id = SecurityAlert.query.filter_by(alert_code="ALT-2026-0001").one().id
    response = client.post(f"/alerts/{alert_id}/status", data={"status": "Resolved"}, follow_redirects=True)
    assert response.status_code == 200
    with app.app_context():
        alert = db.session.get(SecurityAlert, alert_id)
        assert alert.status == "Resolved"
        assert alert.resolved_at is not None
        assert SecurityLog.query.filter_by(event_type="Alert status changed").count() >= 2


def test_simulated_event_creates_alert_and_increases_risk(client, app):
    sign_in(client)
    with app.app_context():
        device = Device.query.filter_by(asset_tag="WS-108").one()
        before = device.risk_score
        device_id = device.id
    response = client.post("/api/events", json={"event_type": "failed_login_attempts", "device_id": device_id,
                                                "source_ip": "10.24.3.108", "attributes": {"count": 14}})
    assert response.status_code == 201
    payload = response.get_json()
    assert payload["detected"] is True
    assert payload["severity"] == "CRITICAL"
    with app.app_context():
        assert db.session.get(Device, device_id).risk_score == min(100, before + 32)
        assert SecurityAlert.query.filter_by(ip_address="10.24.3.108").count() >= 2


def test_detection_rules_cover_all_severity_bands():
    expected = {2: "LOW", 4: "MEDIUM", 7: "HIGH", 12: "CRITICAL"}
    for count, severity in expected.items():
        assert classify_event("failed_login_attempts", {"count": count}).severity == severity


def test_database_url_normalizes_render_postgres_schemes():
    assert normalize_database_url("postgres://user:password@db.example/campus") == (
        "postgresql+psycopg://user:password@db.example/campus"
    )
    assert normalize_database_url("postgresql://user:password@db.example/campus") == (
        "postgresql+psycopg://user:password@db.example/campus"
    )
    assert normalize_database_url("mysql+pymysql://user:password@db.example/campus") == (
        "mysql+pymysql://user:password@db.example/campus"
    )


def test_api_rejects_unknown_event_type(client):
    sign_in(client)
    response = client.post("/api/events", json={"event_type": "real_network_scan", "device_id": 1})
    assert response.status_code == 400
    assert response.get_json()["error"] == "Unsupported simulated event type."


def test_api_rejects_non_finite_json_attributes(client, app):
    sign_in(client)
    with app.app_context():
        device_id = Device.query.filter_by(asset_tag="WS-108").one().id
    response = client.post("/api/events", json={"event_type": "failed_login_attempts",
                                                "device_id": device_id,
                                                "attributes": {"count": float("nan")}})
    assert response.status_code == 400
    assert "finite JSON values" in response.get_json()["error"]


def test_all_read_only_views_and_public_error_page_render(client):
    sign_in(client)
    for path in ("/devices", "/threats", "/alerts", "/logs", "/reports", "/profile", "/api/health"):
        assert client.get(path).status_code == 200
    response = client.get("/missing-page")
    assert response.status_code == 404
    assert b"We couldn't find that page" in response.data


def test_viewer_cannot_change_inventory_or_alerts(client, app):
    sign_in(client, "viewer@campus.edu")
    with app.app_context():
        device_id = Device.query.filter_by(asset_tag="WS-108").one().id
        alert_id = SecurityAlert.query.first().id
    assert client.get(f"/devices/{device_id}/edit").status_code == 403
    assert client.post(f"/alerts/{alert_id}/status", data={"status": "Resolved"}).status_code == 403
    assert client.post("/api/events", json={"event_type": "port_scan", "device_id": device_id}).status_code == 403
    assert client.post("/threats/simulate", data={"event_type": "port_scan", "device_id": device_id}).status_code == 403


def test_threat_detection_page_simulates_and_audits_event(client, app):
    sign_in(client)
    response = client.get("/threats")
    assert response.status_code == 200
    assert b"Rule thresholds" in response.data
    with app.app_context():
        device = Device.query.filter_by(asset_tag="WS-108").one()
        device_id, before = device.id, device.risk_score
    response = client.post("/threats/simulate", data={
        "event_type": "failed_login_attempts", "device_id": device_id,
        "value": "2", "source_ip": "",
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b"LOW detection created" in response.data
    with app.app_context():
        assert db.session.get(Device, device_id).risk_score == min(100, before + 5)
        assert ThreatEvent.query.filter_by(device_id=device_id, severity="LOW").count() == 1
        assert SecurityAlert.query.filter_by(device_id=device_id, severity="LOW").count() >= 1
        assert SecurityLog.query.filter_by(event_type="Telemetry received").count() == 1


def test_profile_updates_name_and_password(client, app):
    sign_in(client)
    new_password = new_test_password()
    response = client.post("/profile", data={
        "name": "Jordan Updated",
        "current_password": client.application.config["TEST_DEMO_PASSWORDS"]["analyst@campus.edu"],
        "new_password": new_password,
    }, follow_redirects=True)
    assert response.status_code == 200
    assert b"Profile changes saved" in response.data
    with app.app_context():
        user = User.query.filter_by(email="analyst@campus.edu").one()
        assert user.name == "Jordan Updated"
        assert user.password_hash != new_password
        assert SecurityLog.query.filter_by(event_type="Profile updated").count() == 1
    client.post("/logout")
    response = client.post("/login", data={"email": "analyst@campus.edu", "password": new_password})
    assert response.status_code == 302


def test_inventory_and_alert_search_filters(client):
    sign_in(client)
    response = client.get("/devices?q=WS-108&status=Online")
    assert response.status_code == 200
    assert b"Library Workstation 108" in response.data
    assert b"Robotics Lab Controller" not in response.data
    response = client.get("/alerts?severity=CRITICAL&status=New")
    assert response.status_code == 200
    assert b"Unusual traffic spike" in response.data
    assert b"Multiple failed logins" not in response.data


def test_logout_form_requires_csrf_when_enabled(client, app):
    sign_in(client)
    app.config["WTF_CSRF_ENABLED"] = True
    assert client.post("/logout").status_code == 400


def test_production_rejects_missing_secret():
    import pytest
    from app import create_app

    with pytest.raises(RuntimeError, match="private SECRET_KEY"):
        create_app({"APP_ENV": "production", "SECRET_KEY": None, "TESTING": True})


def test_production_rejects_sqlite_database():
    import pytest
    from app import create_app

    with pytest.raises(RuntimeError, match="persistent production database"):
        create_app({"APP_ENV": "production", "SECRET_KEY": "test-production-key",
                    "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:", "TESTING": True})
