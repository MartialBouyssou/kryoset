import pytest

from kryoset.tests.api.conftest import auth_header


def test_list_users_admin(client, admin_token, admin_user):
    resp = client.get("/users/", headers=auth_header(admin_token))
    assert resp.status_code == 200
    users = resp.json()
    usernames = [u["username"] for u in users]
    assert "admin" in usernames
    assert any(u["username"] == "admin" and u["storage_max_bytes"] is None for u in users)


def test_list_users_requires_admin(client, user_token):
    resp = client.get("/users/", headers=auth_header(user_token))
    assert resp.status_code == 403


def test_create_user_admin(client, admin_token):
    resp = client.post(
        "/users/",
        headers=auth_header(admin_token),
        json={"username": "newuser", "password": "newpass12"},
    )
    assert resp.status_code == 201


def test_create_user_admin_assigns_default_home(client, admin_token, app):
    resp = client.post(
        "/users/",
        headers=auth_header(admin_token),
        json={"username": "newuserhome", "password": "newpass12"},
    )
    assert resp.status_code == 201
    assert resp.json()["home_path"] == "/home/newuserhome"
    assert app.state.user_manager.get_home_path("newuserhome") == "/home/newuserhome"


def test_create_user_with_storage_max(client, admin_token, app):
    resp = client.post(
        "/users/",
        headers=auth_header(admin_token),
        json={
            "username": "quotauser",
            "password": "newpass12",
            "storage_max_bytes": 5_000_000,
        },
    )
    assert resp.status_code == 201
    assert resp.json()["storage_max_bytes"] == 5_000_000
    assert app.state.storage_manager.get_allocation("user:quotauser") == 5_000_000


def test_create_user_with_home_path(client, admin_token, app):
    resp = client.post(
        "/users/",
        headers=auth_header(admin_token),
        json={
            "username": "homeduser",
            "password": "newpass12",
            "home_path": "/workspace",
        },
    )
    assert resp.status_code == 201
    assert app.state.user_manager.get_home_path("homeduser") == "/workspace"


def test_create_user_and_add_to_group(client, admin_token, permission_store):
    permission_store.create_group("devs")
    resp = client.post(
        "/users/",
        headers=auth_header(admin_token),
        json={
            "username": "groupeduser",
            "password": "newpass12",
            "group_name": "devs",
        },
    )
    assert resp.status_code == 201
    groups = permission_store.get_user_groups("groupeduser")
    assert "devs" in groups


def test_list_users_shows_storage_max(client, admin_token, app, regular_user):
    app.state.storage_manager.set_allocation("user:alice", 2_500_000)
    resp = client.get("/users/", headers=auth_header(admin_token))
    assert resp.status_code == 200
    assert any(u["username"] == "alice" and u["storage_max_bytes"] == 2_500_000 for u in resp.json())


def test_create_user_duplicate(client, admin_token, admin_user):
    resp = client.post(
        "/users/",
        headers=auth_header(admin_token),
        json={"username": "admin", "password": "adminpass1"},
    )
    assert resp.status_code == 409


def test_delete_user_admin(client, admin_token, user_manager):
    user_manager.add_user("todelete", "pass1234")
    resp = client.delete("/users/todelete", headers=auth_header(admin_token))
    assert resp.status_code == 200


def test_delete_user_not_found(client, admin_token):
    resp = client.delete("/users/ghost", headers=auth_header(admin_token))
    assert resp.status_code == 404


def test_enable_disable_user(client, admin_token, user_manager):
    user_manager.add_user("toggled", "pass1234")
    resp = client.post("/users/toggled/disable", headers=auth_header(admin_token))
    assert resp.status_code == 200
    resp = client.post("/users/toggled/enable", headers=auth_header(admin_token))
    assert resp.status_code == 200


def test_change_password_self(client, user_token):
    resp = client.post(
        "/users/alice/password",
        headers=auth_header(user_token),
        json={"new_password": "newpass99"},
    )
    assert resp.status_code == 200


def test_change_password_other_user_denied(client, user_token):
    resp = client.post(
        "/users/admin/password",
        headers=auth_header(user_token),
        json={"new_password": "hacked123"},
    )
    assert resp.status_code == 403


def test_change_password_admin_can_change_others(client, admin_token, regular_user):
    resp = client.post(
        "/users/alice/password",
        headers=auth_header(admin_token),
        json={"new_password": "adminset1"},
    )
    assert resp.status_code == 200


def test_reset_password_admin(client, admin_token, regular_user):
    resp = client.post("/users/alice/reset-password", headers=auth_header(admin_token))
    assert resp.status_code == 200
    assert "temporary_password" in resp.json()


def test_set_admin_flag(client, admin_token, regular_user):
    import pyotp
    setup = client.post("/users/alice/totp/setup", headers=auth_header(admin_token))
    assert setup.status_code == 200
    code = pyotp.TOTP(setup.json()["secret"]).now()
    confirm = client.post(
        "/users/alice/totp/confirm",
        headers=auth_header(admin_token),
        json={"code": code},
    )
    assert confirm.status_code == 200
    resp = client.post("/users/alice/admin?grant=true", headers=auth_header(admin_token))
    assert resp.status_code == 200


def test_set_admin_requires_totp_enabled(client, admin_token, regular_user):
    resp = client.post("/users/alice/admin?grant=true", headers=auth_header(admin_token))
    assert resp.status_code == 400
    assert "must enable TOTP" in resp.json()["detail"]


def test_totp_status_self(client, user_token):
    resp = client.get("/users/alice/totp/status", headers=auth_header(user_token))
    assert resp.status_code == 200
    assert "enabled" in resp.json()


def test_totp_setup_self(client, user_token):
    resp = client.post("/users/alice/totp/setup", headers=auth_header(user_token))
    assert resp.status_code == 200
    data = resp.json()
    assert "secret" in data
    assert "uri" in data


def test_totp_confirm_self(client, user_token, user_manager):
    import pyotp
    resp = client.post("/users/alice/totp/setup", headers=auth_header(user_token))
    secret = resp.json()["secret"]
    code = pyotp.TOTP(secret).now()
    resp2 = client.post(
        "/users/alice/totp/confirm",
        headers=auth_header(user_token),
        json={"code": code},
    )
    assert resp2.status_code == 200


def test_totp_confirm_invalid_code(client, user_token):
    client.post("/users/alice/totp/setup", headers=auth_header(user_token))
    resp = client.post(
        "/users/alice/totp/confirm",
        headers=auth_header(user_token),
        json={"code": "000000"},
    )
    assert resp.status_code == 400


def test_totp_disable_self(client, user_token, user_manager):
    import pyotp
    setup = client.post("/users/alice/totp/setup", headers=auth_header(user_token))
    secret = setup.json()["secret"]
    code = pyotp.TOTP(secret).now()
    client.post("/users/alice/totp/confirm", headers=auth_header(user_token), json={"code": code})
    resp = client.delete("/users/alice/totp", headers=auth_header(user_token))
    assert resp.status_code == 200


def test_get_quota_self(client, user_token):
    resp = client.get("/users/alice/quota", headers=auth_header(user_token))
    assert resp.status_code == 200
    data = resp.json()
    assert "quota_bytes" in data
    assert "used_bytes" in data


def test_get_quota_other_user_denied(client, user_token, admin_user):
    resp = client.get("/users/admin/quota", headers=auth_header(user_token))
    assert resp.status_code == 403


def test_set_quota_admin(client, admin_token, regular_user):
    resp = client.put(
        "/users/alice/quota",
        headers=auth_header(admin_token),
        json={"quota_bytes": 1073741824},
    )
    assert resp.status_code == 200


def test_set_quota_requires_admin(client, user_token):
    resp = client.put(
        "/users/alice/quota",
        headers=auth_header(user_token),
        json={"quota_bytes": 1073741824},
    )
    assert resp.status_code == 403
