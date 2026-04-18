import pytest

from kryoset.core.permissions import Permission, PermissionRule
from kryoset.tests.api.conftest import auth_header


def test_list_rules_admin(client, admin_token):
    resp = client.get("/permissions/rules", headers=auth_header(admin_token))
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_list_rules_requires_admin(client, user_token):
    resp = client.get("/permissions/rules", headers=auth_header(user_token))
    assert resp.status_code == 403


def test_add_rule_admin(client, admin_token):
    resp = client.post(
        "/permissions/rules",
        headers=auth_header(admin_token),
        json={
            "subject_type": "user",
            "subject_id": "alice",
            "path": "/photos",
            "permissions": ["LIST", "DOWNLOAD"],
        },
    )
    assert resp.status_code == 201
    assert "rule_id" in resp.json()


def test_add_rule_invalid_permission(client, admin_token):
    resp = client.post(
        "/permissions/rules",
        headers=auth_header(admin_token),
        json={
            "subject_type": "user",
            "subject_id": "alice",
            "path": "/photos",
            "permissions": ["INVALID_FLAG"],
        },
    )
    assert resp.status_code == 400


def test_add_rule_invalid_subject_type(client, admin_token):
    resp = client.post(
        "/permissions/rules",
        headers=auth_header(admin_token),
        json={
            "subject_type": "robot",
            "subject_id": "alice",
            "path": "/",
            "permissions": ["LIST"],
        },
    )
    assert resp.status_code == 400


def test_remove_rule_admin(client, admin_token, permission_store):
    rule = PermissionRule(
        subject_type="user", subject_id="alice", path="/tmp", permissions=Permission.LIST
    )
    rule_id = permission_store.add_rule(rule)
    resp = client.delete(f"/permissions/rules/{rule_id}", headers=auth_header(admin_token))
    assert resp.status_code == 200


def test_remove_rule_not_found(client, admin_token):
    resp = client.delete("/permissions/rules/9999", headers=auth_header(admin_token))
    assert resp.status_code == 404


def test_check_permission_own_user(client, user_token, permission_store):
    rule = PermissionRule(
        subject_type="user", subject_id="alice", path="/docs", permissions=Permission.LIST | Permission.DOWNLOAD
    )
    permission_store.add_rule(rule)
    resp = client.get("/permissions/check?path=/docs", headers=auth_header(user_token))
    assert resp.status_code == 200
    data = resp.json()
    assert "LIST" in data["permissions"]
    assert "DOWNLOAD" in data["permissions"]


def test_check_permission_no_rules(client, user_token):
    resp = client.get("/permissions/check?path=/secret", headers=auth_header(user_token))
    assert resp.status_code == 200
    assert resp.json()["permissions"] == []


def test_list_groups_admin(client, admin_token):
    resp = client.get("/permissions/groups", headers=auth_header(admin_token))
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)


def test_list_groups_requires_admin(client, user_token):
    resp = client.get("/permissions/groups", headers=auth_header(user_token))
    assert resp.status_code == 403


def test_create_group_admin(client, admin_token):
    resp = client.post("/permissions/groups/engineers", headers=auth_header(admin_token))
    assert resp.status_code == 201


def test_create_group_duplicate(client, admin_token, permission_store):
    permission_store.create_group("devs")
    resp = client.post("/permissions/groups/devs", headers=auth_header(admin_token))
    assert resp.status_code == 409


def test_delete_group_admin(client, admin_token, permission_store):
    permission_store.create_group("todelete")
    resp = client.delete("/permissions/groups/todelete", headers=auth_header(admin_token))
    assert resp.status_code == 200


def test_delete_group_not_found(client, admin_token):
    resp = client.delete("/permissions/groups/ghost", headers=auth_header(admin_token))
    assert resp.status_code == 404


def test_add_member_to_group(client, admin_token, permission_store, regular_user):
    permission_store.create_group("team")
    resp = client.post(
        "/permissions/groups/team/members",
        headers=auth_header(admin_token),
        json={"username": "alice"},
    )
    assert resp.status_code == 201


def test_add_member_group_not_found(client, admin_token):
    resp = client.post(
        "/permissions/groups/ghost/members",
        headers=auth_header(admin_token),
        json={"username": "alice"},
    )
    assert resp.status_code == 400


def test_remove_member_from_group(client, admin_token, permission_store, regular_user):
    permission_store.create_group("squad")
    permission_store.add_group_member("squad", "alice")
    resp = client.delete(
        "/permissions/groups/squad/members/alice",
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 200


def test_remove_member_not_in_group(client, admin_token, permission_store, regular_user):
    permission_store.create_group("empty")
    resp = client.delete(
        "/permissions/groups/empty/members/alice",
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 404


def test_add_rule_with_manage_perms(client, user_token, permission_store):
    rule = PermissionRule(
        subject_type="user",
        subject_id="alice",
        path="/",
        permissions=Permission.MANAGE_PERMS,
    )
    permission_store.add_rule(rule)
    resp = client.post(
        "/permissions/rules",
        headers=auth_header(user_token),
        json={
            "subject_type": "user",
            "subject_id": "alice",
            "path": "/shared",
            "permissions": ["LIST"],
        },
    )
    assert resp.status_code == 201


def test_update_rule_admin(client, admin_token, user_token, permission_store):
    rule = PermissionRule(
        subject_type="user",
        subject_id="alice",
        path="/docs",
        permissions=Permission.LIST,
    )
    rule_id = permission_store.add_rule(rule)

    resp = client.put(
        f"/permissions/rules/{rule_id}",
        headers=auth_header(admin_token),
        json={
            "subject_type": "user",
            "subject_id": "alice",
            "path": "/docs",
            "permissions": ["LIST", "DOWNLOAD"],
            "can_delegate": True,
        },
    )
    assert resp.status_code == 200

    check = client.get("/permissions/check?path=/docs", headers=auth_header(user_token))
    assert check.status_code == 200
    assert "DOWNLOAD" in check.json()["permissions"]


def test_update_rule_not_found(client, admin_token):
    resp = client.put(
        "/permissions/rules/999999",
        headers=auth_header(admin_token),
        json={
            "subject_type": "user",
            "subject_id": "alice",
            "path": "/docs",
            "permissions": ["LIST"],
            "can_delegate": False,
        },
    )
    assert resp.status_code == 404


def test_add_rule_relative_path_is_effective_immediately(client, admin_token, user_token):
    resp = client.post(
        "/permissions/rules",
        headers=auth_header(admin_token),
        json={
            "subject_type": "user",
            "subject_id": "alice",
            "path": "docs",
            "permissions": ["LIST"],
        },
    )
    assert resp.status_code == 201

    check = client.get("/permissions/check?path=/docs", headers=auth_header(user_token))
    assert check.status_code == 200
    assert "LIST" in check.json()["permissions"]
