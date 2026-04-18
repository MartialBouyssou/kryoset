import io

import pytest

from kryoset.core.permissions import Permission, PermissionRule
from kryoset.tests.api.conftest import auth_header


def _grant(permission_store, username, path, perms):
    rule = PermissionRule(
        subject_type="user",
        subject_id=username,
        path=path,
        permissions=perms,
    )
    permission_store.add_rule(rule)


def test_list_directory_admin(client, admin_token, config):
    (config.storage_path / "subdir").mkdir()
    (config.storage_path / "file.txt").write_text("hello")
    resp = client.get("/files/list", headers=auth_header(admin_token))
    assert resp.status_code == 200
    names = [e["name"] for e in resp.json()["entries"]]
    assert "subdir" in names
    assert "file.txt" in names


def test_list_directory_requires_auth(client):
    resp = client.get("/files/list")
    assert resp.status_code == 401


def test_list_directory_permission_denied(client, user_token):
    resp = client.get("/files/list", headers=auth_header(user_token))
    assert resp.status_code == 403
    detail = resp.json()["detail"]
    assert "Access denied for user 'alice'" in detail
    assert "Required permission: LIST" in detail
    assert "Effective permissions: NONE" in detail


def test_list_directory_with_permission(client, user_token, permission_store, config):
    _grant(permission_store, "alice", "/", Permission.LIST)
    resp = client.get("/files/list", headers=auth_header(user_token))
    assert resp.status_code == 200


def test_list_nonexistent_path(client, admin_token):
    resp = client.get("/files/list?path=nonexistent", headers=auth_header(admin_token))
    assert resp.status_code == 404


def test_download_file_admin(client, admin_token, config):
    (config.storage_path / "hello.txt").write_text("world")
    resp = client.get("/files/download?path=hello.txt", headers=auth_header(admin_token))
    assert resp.status_code == 200
    assert resp.content == b"world"


def test_download_file_not_found(client, admin_token):
    resp = client.get("/files/download?path=missing.txt", headers=auth_header(admin_token))
    assert resp.status_code == 404


def test_download_requires_permission(client, user_token):
    resp = client.get("/files/download?path=hello.txt", headers=auth_header(user_token))
    assert resp.status_code == 403


def test_download_with_permission(client, user_token, permission_store, config):
    (config.storage_path / "share.txt").write_text("shared")
    _grant(permission_store, "alice", "/", Permission.DOWNLOAD)
    resp = client.get("/files/download?path=share.txt", headers=auth_header(user_token))
    assert resp.status_code == 200
    assert resp.content == b"shared"


def test_upload_file_admin(client, admin_token):
    resp = client.post(
        "/files/upload?path=uploaded.txt",
        headers=auth_header(admin_token),
        files={"file": ("uploaded.txt", b"content", "text/plain")},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["size"] == 7


def test_upload_requires_auth(client):
    resp = client.post(
        "/files/upload?path=test.txt",
        files={"file": ("test.txt", b"data", "text/plain")},
    )
    assert resp.status_code == 401


def test_upload_quota_exceeded(client, user_token, permission_store, user_manager):
    _grant(permission_store, "alice", "/", Permission.UPLOAD)
    from kryoset.core.quota import QuotaManager
    from kryoset.core.configuration import Configuration
    user_manager.set_quota = lambda u, q: None
    users = user_manager._get_users()
    users["alice"]["storage_quota_bytes"] = 5
    user_manager._save_users(users)

    resp = client.post(
        "/files/upload?path=big.txt",
        headers=auth_header(user_token),
        files={"file": ("big.txt", b"0123456789", "text/plain")},
    )
    assert resp.status_code == 413


def test_mkdir_admin(client, admin_token):
    resp = client.post(
        "/files/mkdir",
        headers=auth_header(admin_token),
        json={"path": "newdir"},
    )
    assert resp.status_code == 201


def test_mkdir_conflict(client, admin_token, config):
    (config.storage_path / "existing").mkdir()
    resp = client.post(
        "/files/mkdir",
        headers=auth_header(admin_token),
        json={"path": "existing"},
    )
    assert resp.status_code == 409


def test_delete_file_admin(client, admin_token, config):
    (config.storage_path / "todelete.txt").write_text("bye")
    resp = client.delete("/files/delete?path=todelete.txt", headers=auth_header(admin_token))
    assert resp.status_code == 200
    assert not (config.storage_path / "todelete.txt").exists()


def test_delete_not_found(client, admin_token):
    resp = client.delete("/files/delete?path=ghost.txt", headers=auth_header(admin_token))
    assert resp.status_code == 404


def test_rename_file_admin(client, admin_token, config):
    (config.storage_path / "old.txt").write_text("data")
    resp = client.post(
        "/files/rename",
        headers=auth_header(admin_token),
        json={"source": "old.txt", "destination": "new.txt"},
    )
    assert resp.status_code == 200
    assert (config.storage_path / "new.txt").exists()
    assert not (config.storage_path / "old.txt").exists()


def test_rename_destination_exists(client, admin_token, config):
    (config.storage_path / "a.txt").write_text("a")
    (config.storage_path / "b.txt").write_text("b")
    resp = client.post(
        "/files/rename",
        headers=auth_header(admin_token),
        json={"source": "a.txt", "destination": "b.txt"},
    )
    assert resp.status_code == 409


def test_path_traversal_blocked(client, admin_token):
    resp = client.get("/files/download?path=../etc/passwd", headers=auth_header(admin_token))
    assert resp.status_code in (400, 403)
