import pytest

from kryoset.core.permissions import Permission, PermissionRule
from kryoset.tests.api.conftest import auth_header


def _grant_share(permission_store, username, path):
    rule = PermissionRule(
        subject_type="user",
        subject_id=username,
        path=path,
        permissions=Permission.SHARE | Permission.DOWNLOAD,
    )
    permission_store.add_rule(rule)


def test_create_share_admin(client, admin_token, config):
    (config.storage_path / "doc.txt").write_text("shared")
    resp = client.post(
        "/shares/",
        headers=auth_header(admin_token),
        json={"path": "doc.txt", "permissions": ["DOWNLOAD"]},
    )
    assert resp.status_code == 201
    data = resp.json()
    assert "token" in data


def test_create_share_requires_share_permission(client, user_token):
    resp = client.post(
        "/shares/",
        headers=auth_header(user_token),
        json={"path": "doc.txt", "permissions": ["DOWNLOAD"]},
    )
    assert resp.status_code == 403


def test_create_share_user_with_permission(client, user_token, permission_store, config):
    (config.storage_path / "shared.txt").write_text("content")
    _grant_share(permission_store, "alice", "/")
    resp = client.post(
        "/shares/",
        headers=auth_header(user_token),
        json={"path": "shared.txt", "permissions": ["DOWNLOAD"]},
    )
    assert resp.status_code == 201


def test_list_shares_admin_sees_all(client, admin_token, config, permission_store, user_token):
    _grant_share(permission_store, "alice", "/")
    (config.storage_path / "f.txt").write_text("x")
    client.post("/shares/", headers=auth_header(user_token), json={"path": "f.txt", "permissions": ["DOWNLOAD"]})
    resp = client.get("/shares/", headers=auth_header(admin_token))
    assert resp.status_code == 200
    assert len(resp.json()) >= 1


def test_list_shares_user_sees_own(client, user_token, admin_token, config, permission_store):
    _grant_share(permission_store, "alice", "/")
    (config.storage_path / "mine.txt").write_text("x")
    client.post("/shares/", headers=auth_header(user_token), json={"path": "mine.txt", "permissions": ["DOWNLOAD"]})
    resp = client.get("/shares/", headers=auth_header(user_token))
    assert resp.status_code == 200
    for share in resp.json():
        assert share["created_by"] == "alice"


def test_revoke_share_creator(client, user_token, permission_store, config):
    _grant_share(permission_store, "alice", "/")
    (config.storage_path / "rev.txt").write_text("x")
    create = client.post("/shares/", headers=auth_header(user_token), json={"path": "rev.txt", "permissions": ["DOWNLOAD"]})
    token = create.json()["token"]
    resp = client.delete(f"/shares/{token}", headers=auth_header(user_token))
    assert resp.status_code == 200


def test_revoke_share_other_user_denied(client, user_token, admin_token, config, permission_store, user_manager):
    _grant_share(permission_store, "alice", "/")
    (config.storage_path / "notmine.txt").write_text("x")
    create = client.post("/shares/", headers=auth_header(user_token), json={"path": "notmine.txt", "permissions": ["DOWNLOAD"]})
    token = create.json()["token"]
    user_manager.add_user("bob", "bobpass12")
    bob_login = client.post("/auth/login", json={"username": "bob", "password": "bobpass12"})
    bob_token = bob_login.json()["access_token"]
    resp = client.delete(f"/shares/{token}", headers=auth_header(bob_token))
    assert resp.status_code == 403


def test_revoke_share_admin_can_revoke_any(client, admin_token, user_token, config, permission_store):
    _grant_share(permission_store, "alice", "/")
    (config.storage_path / "any.txt").write_text("x")
    create = client.post("/shares/", headers=auth_header(user_token), json={"path": "any.txt", "permissions": ["DOWNLOAD"]})
    token = create.json()["token"]
    resp = client.delete(f"/shares/{token}", headers=auth_header(admin_token))
    assert resp.status_code == 200


def test_public_download(client, admin_token, config):
    (config.storage_path / "public.txt").write_text("public content")
    create = client.post(
        "/shares/",
        headers=auth_header(admin_token),
        json={"path": "public.txt", "permissions": ["DOWNLOAD"]},
    )
    token = create.json()["token"]
    resp = client.get(f"/shares/public/{token}")
    assert resp.status_code == 200
    assert resp.content == b"public content"


def test_public_download_increments_counter(client, admin_token, config):
    (config.storage_path / "counted.txt").write_text("x")
    create = client.post(
        "/shares/",
        headers=auth_header(admin_token),
        json={"path": "counted.txt", "permissions": ["DOWNLOAD"], "download_limit": 2},
    )
    token = create.json()["token"]
    client.get(f"/shares/public/{token}")
    resp = client.get("/shares/", headers=auth_header(admin_token))
    share = next(s for s in resp.json() if s["token"] == token)
    assert share["download_count"] == 1


def test_public_download_limit_exhausted(client, admin_token, config):
    (config.storage_path / "limited.txt").write_text("x")
    create = client.post(
        "/shares/",
        headers=auth_header(admin_token),
        json={"path": "limited.txt", "permissions": ["DOWNLOAD"], "download_limit": 1},
    )
    token = create.json()["token"]
    client.get(f"/shares/public/{token}")
    resp = client.get(f"/shares/public/{token}")
    assert resp.status_code == 404


def test_public_download_with_password(client, admin_token, config):
    (config.storage_path / "protected.txt").write_text("secret")
    create = client.post(
        "/shares/",
        headers=auth_header(admin_token),
        json={"path": "protected.txt", "permissions": ["DOWNLOAD"], "password": "mypass"},
    )
    token = create.json()["token"]
    resp_no_pass = client.get(f"/shares/public/{token}")
    assert resp_no_pass.status_code == 401
    resp_wrong = client.get(f"/shares/public/{token}?password=wrong")
    assert resp_wrong.status_code == 401
    resp_ok = client.get(f"/shares/public/{token}?password=mypass")
    assert resp_ok.status_code == 200


def test_public_download_token_not_found(client):
    resp = client.get("/shares/public/nonexistenttoken")
    assert resp.status_code == 404


def test_revoke_not_found(client, admin_token):
    resp = client.delete("/shares/ghosttoken", headers=auth_header(admin_token))
    assert resp.status_code == 404
