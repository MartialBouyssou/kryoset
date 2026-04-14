import json
from pathlib import Path

import pytest

from kryoset.core.control_channel import ControlChannel, ControlChannelError
from kryoset.core.permission_store import PermissionStore
from kryoset.core.permissions import Permission, PermissionRule


@pytest.fixture()
def store(tmp_path: Path) -> PermissionStore:
    db = PermissionStore(db_path=tmp_path / "perms.db")
    db.initialize()
    return db


@pytest.fixture()
def admin_channel(store) -> ControlChannel:
    return ControlChannel(store, username="admin", is_admin=True)


@pytest.fixture()
def alice_channel(store) -> ControlChannel:
    store.add_rule(PermissionRule(
        subject_type="user", subject_id="alice",
        path="/alice", permissions=Permission.SHARE | Permission.MANAGE_PERMS,
        can_delegate=True,
    ))
    return ControlChannel(store, username="alice", is_admin=False)


class TestIsVirtualPath:
    def test_control_root(self, store):
        ch = ControlChannel(store, "alice")
        assert ch.is_virtual_path("/.kryoset")

    def test_commands_subpath(self, store):
        ch = ControlChannel(store, "alice")
        assert ch.is_virtual_path("/.kryoset/commands/cmd.json")

    def test_real_path(self, store):
        ch = ControlChannel(store, "alice")
        assert not ch.is_virtual_path("/photos")


class TestListVirtualDirectory:
    def test_root_shows_three_dirs(self, admin_channel):
        entries = admin_channel.list_virtual_directory("/.kryoset")
        names = {e["name"] for e in entries}
        assert names == {"commands", "shares", "permissions"}

    def test_shares_empty_initially(self, admin_channel):
        entries = admin_channel.list_virtual_directory("/.kryoset/shares")
        assert entries == []

    def test_shares_shows_created_links(self, admin_channel, store):
        store.create_share_link("admin", "/report.pdf", Permission.DOWNLOAD)
        entries = admin_channel.list_virtual_directory("/.kryoset/shares")
        assert len(entries) == 1
        assert entries[0]["name"].endswith(".json")


class TestCreateShare:
    def test_admin_can_create_share_on_any_path(self, admin_channel):
        cmd = json.dumps({
            "action": "create_share",
            "path": "/any/path.pdf",
            "expires_in_hours": 24,
            "download_limit": 5,
        }).encode()
        result = admin_channel.process_command(cmd)
        assert result["status"] == "ok"
        assert "token" in result

    def test_alice_can_share_her_zone(self, alice_channel):
        cmd = json.dumps({
            "action": "create_share",
            "path": "/alice/report.pdf",
            "expires_in_hours": 2,
        }).encode()
        result = alice_channel.process_command(cmd)
        assert result["status"] == "ok"

    def test_alice_cannot_share_outside_her_zone(self, alice_channel):
        cmd = json.dumps({
            "action": "create_share",
            "path": "/other/file.pdf",
        }).encode()
        with pytest.raises(ControlChannelError, match="SHARE permission"):
            alice_channel.process_command(cmd)

    def test_create_share_missing_path_raises(self, admin_channel):
        cmd = json.dumps({"action": "create_share"}).encode()
        with pytest.raises(ControlChannelError, match="path"):
            admin_channel.process_command(cmd)


class TestRevokeShare:
    def test_admin_can_revoke_any_share(self, admin_channel, store):
        link = store.create_share_link("alice", "/f.pdf", Permission.DOWNLOAD)
        cmd = json.dumps({"action": "revoke_share", "token": link.token}).encode()
        result = admin_channel.process_command(cmd)
        assert result["status"] == "ok"
        assert store.get_share_link(link.token) is None

    def test_user_cannot_revoke_others_share(self, alice_channel, store):
        link = store.create_share_link("bob", "/bob.pdf", Permission.DOWNLOAD)
        cmd = json.dumps({"action": "revoke_share", "token": link.token}).encode()
        with pytest.raises(ControlChannelError, match="Access denied"):
            alice_channel.process_command(cmd)

    def test_revoke_nonexistent_raises(self, admin_channel):
        cmd = json.dumps({"action": "revoke_share", "token": "nonexistent"}).encode()
        with pytest.raises(ControlChannelError, match="not found"):
            admin_channel.process_command(cmd)


class TestAddRemovePermission:
    def test_admin_can_add_rule(self, admin_channel):
        cmd = json.dumps({
            "action": "add_permission",
            "subject_type": "user",
            "subject_id": "bob",
            "path": "/shared",
            "permissions": ["DOWNLOAD"],
        }).encode()
        result = admin_channel.process_command(cmd)
        assert result["status"] == "ok"
        assert "rule_id" in result

    def test_alice_can_add_rule_in_her_zone(self, alice_channel):
        cmd = json.dumps({
            "action": "add_permission",
            "subject_type": "user",
            "subject_id": "carol",
            "path": "/alice/subdir",
            "permissions": ["DOWNLOAD"],
        }).encode()
        result = alice_channel.process_command(cmd)
        assert result["status"] == "ok"

    def test_invalid_subject_type_raises(self, admin_channel):
        cmd = json.dumps({
            "action": "add_permission",
            "subject_type": "robot",
            "subject_id": "r2d2",
            "path": "/x",
            "permissions": ["DOWNLOAD"],
        }).encode()
        with pytest.raises(ControlChannelError, match="subject_type"):
            admin_channel.process_command(cmd)

    def test_admin_can_remove_rule(self, admin_channel, store):
        rule_id = store.add_rule(PermissionRule(
            subject_type="user", subject_id="bob",
            path="/x", permissions=Permission.DOWNLOAD,
        ))
        cmd = json.dumps({"action": "remove_permission", "rule_id": rule_id}).encode()
        result = admin_channel.process_command(cmd)
        assert result["status"] == "ok"


class TestMalformedCommands:
    def test_invalid_json_raises(self, admin_channel):
        with pytest.raises(ControlChannelError, match="Malformed"):
            admin_channel.process_command(b"{ not valid json }")

    def test_unknown_action_raises(self, admin_channel):
        cmd = json.dumps({"action": "explode"}).encode()
        with pytest.raises(ControlChannelError, match="Unknown action"):
            admin_channel.process_command(cmd)
