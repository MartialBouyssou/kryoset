import pytest

from kryoset.tests.api.conftest import auth_header


def test_get_logs_admin(client, admin_token):
    resp = client.get("/logs/", headers=auth_header(admin_token))
    assert resp.status_code == 200
    assert "lines" in resp.json()


def test_get_logs_requires_admin(client, user_token):
    resp = client.get("/logs/", headers=auth_header(user_token))
    assert resp.status_code == 403


def test_get_logs_returns_list(client, admin_token):
    resp = client.get("/logs/", headers=auth_header(admin_token))
    assert resp.status_code == 200
    assert isinstance(resp.json()["lines"], list)


def test_list_log_files_admin(client, admin_token):
    resp = client.get("/logs/files", headers=auth_header(admin_token))
    assert resp.status_code == 200
    assert "files" in resp.json()


def test_list_log_files_requires_admin(client, user_token):
    resp = client.get("/logs/files", headers=auth_header(user_token))
    assert resp.status_code == 403


def test_get_logs_with_filter(client, admin_token, app):
    from kryoset.core.audit_logger import AuditLogger, LOG_DIRECTORY
    logger = AuditLogger(log_directory=LOG_DIRECTORY)
    logger.log_auth_success("alice", "127.0.0.1")
    logger.log_auth_failure("eve", "10.0.0.1")
    resp = client.get("/logs/?filter=AUTH_SUCCESS", headers=auth_header(admin_token))
    assert resp.status_code == 200
    for line in resp.json()["lines"]:
        assert "AUTH_SUCCESS" in line


def test_get_logs_lines_limit(client, admin_token, app):
    from kryoset.core.audit_logger import AuditLogger, LOG_DIRECTORY
    logger = AuditLogger(log_directory=LOG_DIRECTORY)
    for i in range(20):
        logger.log_auth_success("alice", "127.0.0.1")
    resp = client.get("/logs/?lines=5", headers=auth_header(admin_token))
    assert resp.status_code == 200
    assert len(resp.json()["lines"]) <= 5
