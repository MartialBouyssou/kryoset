import pyotp
import pytest
from fastapi.testclient import TestClient

from kryoset.core.audit_logger import AuditLogger
from kryoset.tests.api.conftest import auth_header


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_login_valid(client, admin_user):
    resp = client.post("/auth/login", json={"username": "admin", "password": "adminpass1"})
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"


def test_login_invalid_password(client, admin_user):
    resp = client.post("/auth/login", json={"username": "admin", "password": "wrong"})
    assert resp.status_code == 401


def test_login_unknown_user(client):
    resp = client.post("/auth/login", json={"username": "nobody", "password": "whatever"})
    assert resp.status_code == 401


def test_login_disabled_user(client, user_manager):
    user_manager.add_user("bob", "bobpass12")
    user_manager.set_enabled("bob", enabled=False)
    resp = client.post("/auth/login", json={"username": "bob", "password": "bobpass12"})
    assert resp.status_code == 401


def test_me_endpoint(client, admin_token):
    resp = client.get("/auth/me", headers=auth_header(admin_token))
    assert resp.status_code == 200
    data = resp.json()
    assert data["username"] == "admin"
    assert data["admin"] is True
    assert "totp_enabled" in data
    assert data["initial_path"] == "/"
    assert "quota_bytes" in data
    assert "used_bytes" in data
    assert "recent_logins" in data
    assert "recent_failures" in data


def test_me_endpoint_returns_user_home_as_initial_path(client, user_token, user_manager):
    users = user_manager._get_users()
    users["alice"]["home_path"] = "/home/alice"
    user_manager._save_users(users)

    resp = client.get("/auth/me", headers=auth_header(user_token))
    assert resp.status_code == 200
    data = resp.json()
    assert data["username"] == "alice"
    assert data["initial_path"] == "/home/alice"


def test_me_endpoint_includes_recent_auth_activity(client, admin_token, tmp_path):
    logger = AuditLogger(log_directory=tmp_path / "logs", retention_days=7, max_total_size_mb=None)
    client.app.state.audit_logger = logger
    logger.log_auth_success("admin", "127.0.0.1")
    logger.log_auth_failure("admin", "127.0.0.2")

    resp = client.get("/auth/me", headers=auth_header(admin_token))
    assert resp.status_code == 200
    data = resp.json()
    assert data["recent_logins"]
    assert data["recent_logins"][0]["event"] == "AUTH_SUCCESS"
    assert data["recent_failures"]
    assert data["recent_failures"][0]["event"] == "AUTH_FAILURE"


def test_me_requires_auth(client):
    resp = client.get("/auth/me")
    assert resp.status_code == 401


def test_refresh_token(client, admin_user):
    login = client.post("/auth/login", json={"username": "admin", "password": "adminpass1"})
    refresh_token = login.json()["refresh_token"]
    resp = client.post("/auth/refresh", json={"refresh_token": refresh_token})
    assert resp.status_code == 200
    assert "access_token" in resp.json()


def test_refresh_token_preserves_admin(client, admin_user):
    login = client.post("/auth/login", json={"username": "admin", "password": "adminpass1"})
    refresh_token = login.json()["refresh_token"]
    refreshed = client.post("/auth/refresh", json={"refresh_token": refresh_token})
    assert refreshed.status_code == 200

    access = refreshed.json()["access_token"]
    me = client.get("/auth/me", headers=auth_header(access))
    assert me.status_code == 200
    assert me.json()["admin"] is True


def test_refresh_with_access_token_rejected(client, admin_token):
    resp = client.post("/auth/refresh", json={"refresh_token": admin_token})
    assert resp.status_code == 401


def test_refresh_invalid_token(client):
    resp = client.post("/auth/refresh", json={"refresh_token": "not.a.token"})
    assert resp.status_code == 401


def test_logout_revokes_token(client, admin_user):
    login = client.post("/auth/login", json={"username": "admin", "password": "adminpass1"})
    token = login.json()["access_token"]
    resp = client.post("/auth/logout", headers=auth_header(token))
    assert resp.status_code == 200
    resp2 = client.get("/auth/me", headers=auth_header(token))
    assert resp2.status_code == 401


def test_totp_two_step_flow(client, user_manager):
    user_manager.add_user("totpuser", "totppass1")
    from kryoset.core.totp import TOTPManager
    totp_mgr = TOTPManager(user_manager)
    secret = totp_mgr.generate_secret("totpuser")
    totp_mgr.confirm_setup("totpuser", pyotp.TOTP(secret).now())

    resp = client.post("/auth/login", json={"username": "totpuser", "password": "totppass1"})
    assert resp.status_code == 200
    data = resp.json()
    assert data.get("totp_required") is True
    assert "access_token" not in data

    code = pyotp.TOTP(secret).now()
    resp2 = client.post("/auth/totp", json={"username": "totpuser", "code": code})
    assert resp2.status_code == 200
    assert "access_token" in resp2.json()


def test_totp_invalid_code_rejected(client, user_manager):
    user_manager.add_user("totpuser2", "totppass2")
    from kryoset.core.totp import TOTPManager
    totp_mgr = TOTPManager(user_manager)
    secret = totp_mgr.generate_secret("totpuser2")
    totp_mgr.confirm_setup("totpuser2", pyotp.TOTP(secret).now())

    client.post("/auth/login", json={"username": "totpuser2", "password": "totppass2"})
    resp = client.post("/auth/totp", json={"username": "totpuser2", "code": "000000"})
    assert resp.status_code == 401


def test_totp_retry_after_invalid_code_succeeds(client, user_manager):
    user_manager.add_user("totpuser3", "totppass3")
    from kryoset.core.totp import TOTPManager
    totp_mgr = TOTPManager(user_manager)
    secret = totp_mgr.generate_secret("totpuser3")
    totp_mgr.confirm_setup("totpuser3", pyotp.TOTP(secret).now())

    login = client.post("/auth/login", json={"username": "totpuser3", "password": "totppass3"})
    assert login.status_code == 200
    assert login.json().get("totp_required") is True

    wrong = client.post("/auth/totp", json={"username": "totpuser3", "code": "000000"})
    assert wrong.status_code == 401

    correct_code = pyotp.TOTP(secret).now()
    retry = client.post("/auth/totp", json={"username": "totpuser3", "code": correct_code})
    assert retry.status_code == 200
    assert "access_token" in retry.json()


def test_totp_without_pending_session_rejected(client):
    resp = client.post("/auth/totp", json={"username": "ghost", "code": "123456"})
    assert resp.status_code == 400
