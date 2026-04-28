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


def test_preview_image_admin(client, admin_token, config):
    image_bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
    (config.storage_path / "photo.png").write_bytes(image_bytes)

    resp = client.get("/files/preview?path=photo.png", headers=auth_header(admin_token))

    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("image/png")
    assert "inline" in resp.headers.get("content-disposition", "")
    assert resp.content == image_bytes


def test_preview_mov_admin(client, admin_token, config):
    mov_bytes = b"\x00\x00\x00\x18ftypqt  "
    (config.storage_path / "clip.MOV").write_bytes(mov_bytes)

    resp = client.get("/files/preview?path=clip.MOV", headers=auth_header(admin_token))

    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("video/quicktime")
    assert "inline" in resp.headers.get("content-disposition", "")
    assert resp.content == mov_bytes


def test_preview_unsupported_type_returns_415(client, admin_token, config):
    (config.storage_path / "archive.zip").write_bytes(b"PK\x03\x04")

    resp = client.get("/files/preview?path=archive.zip", headers=auth_header(admin_token))

    assert resp.status_code == 415


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


def test_upload_quota_blocks_cumulative_usage(client, user_token, permission_store, user_manager, config):
    _grant(permission_store, "alice", "/", Permission.UPLOAD)
    users = user_manager._get_users()
    users["alice"]["home_path"] = "/home/alice"
    users["alice"]["storage_quota_bytes"] = 5_000_000
    user_manager._save_users(users)

    (config.storage_path / "home").mkdir(exist_ok=True)
    (config.storage_path / "home" / "alice").mkdir(exist_ok=True)
    (config.storage_path / "home" / "alice" / "existing.bin").write_bytes(b"x" * 4_900_000)

    resp = client.post(
        "/files/upload?path=home/alice/too-big.bin",
        headers=auth_header(user_token),
        files={"file": ("too-big.bin", b"y" * 200_000, "application/octet-stream")},
    )
    assert resp.status_code == 413
    assert not (config.storage_path / "home" / "alice" / "too-big.bin").exists()


def test_upload_quota_blocks_cumulative_usage_on_group_home(client, user_token, permission_store, user_manager, config):
    _grant(permission_store, "alice", "/", Permission.UPLOAD)
    permission_store.create_group("team", home_path="/directory", home_auto_user_subdir=True)
    permission_store.add_group_member("team", "alice")

    users = user_manager._get_users()
    users["alice"]["storage_quota_bytes"] = 5_000_000
    users["alice"].pop("home_path", None)
    user_manager._save_users(users)

    (config.storage_path / "directory").mkdir(exist_ok=True)
    (config.storage_path / "directory" / "alice").mkdir(exist_ok=True)
    (config.storage_path / "directory" / "alice" / "existing.bin").write_bytes(b"x" * 4_900_000)

    resp = client.post(
        "/files/upload?path=directory/alice/too-big.bin",
        headers=auth_header(user_token),
        files={"file": ("too-big.bin", b"y" * 200_000, "application/octet-stream")},
    )
    assert resp.status_code == 413
    assert not (config.storage_path / "directory" / "alice" / "too-big.bin").exists()


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


def test_upload_and_delete_update_persisted_used_cache(
    client,
    user_token,
    permission_store,
    user_manager,
    config,
):
    _grant(permission_store, "alice", "/", Permission.UPLOAD | Permission.DELETE)
    users = user_manager._get_users()
    users["alice"]["home_path"] = "/home/alice"
    user_manager._save_users(users)

    resp_upload = client.post(
        "/files/upload?path=home/alice/a.bin",
        headers=auth_header(user_token),
        files={"file": ("a.bin", b"1234", "application/octet-stream")},
    )
    assert resp_upload.status_code == 201
    assert config._data.get("user_used_bytes_cache", {}).get("alice:/home/alice") == 4

    resp_delete = client.delete(
        "/files/delete?path=home/alice/a.bin",
        headers=auth_header(user_token),
    )
    assert resp_delete.status_code == 200
    assert config._data.get("user_used_bytes_cache", {}).get("alice:/home/alice") == 0


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


def test_user_home_path_restricts_access_outside_home(client, user_manager, user_token, config):
    user_manager.change_password("alice", "alicepass1")
    users = user_manager._get_users()
    users["alice"]["home_path"] = "/home/alice"
    user_manager._save_users(users)

    (config.storage_path / "home").mkdir(exist_ok=True)
    (config.storage_path / "home" / "alice").mkdir(exist_ok=True)
    (config.storage_path / "home" / "alice" / "inside.txt").write_text("ok")
    (config.storage_path / "outside.txt").write_text("blocked")

    inside = client.get("/files/download?path=home/alice/inside.txt", headers=auth_header(user_token))
    assert inside.status_code == 200

    outside = client.get("/files/download?path=outside.txt", headers=auth_header(user_token))
    assert outside.status_code == 403


def test_group_auto_home_allows_generated_path(client, permission_store, regular_user, user_token, config):
    permission_store.create_group("team", home_path="/directory", home_auto_user_subdir=True)
    permission_store.add_group_member("team", "alice")

    (config.storage_path / "directory").mkdir(exist_ok=True)
    (config.storage_path / "directory" / "alice").mkdir(exist_ok=True)
    (config.storage_path / "directory" / "alice" / "data.txt").write_text("ok")

    allowed = client.get(
        "/files/download?path=directory/alice/data.txt",
        headers=auth_header(user_token),
    )
    assert allowed.status_code == 200

    denied = client.get("/files/download?path=directory/other/data.txt", headers=auth_header(user_token))
    assert denied.status_code == 403
