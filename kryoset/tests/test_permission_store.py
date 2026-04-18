from datetime import datetime, timedelta
from pathlib import Path

import pytest

from kryoset.core.permission_store import PermissionStore, PermissionStoreError
from kryoset.core.permissions import Permission, PermissionRule


@pytest.fixture()
def store(tmp_path: Path) -> PermissionStore:
    db = PermissionStore(db_path=tmp_path / "perms.db")
    db.initialize()
    return db


class TestGroups:
    def test_create_and_list(self, store):
        store.create_group("editors")
        groups = store.list_groups()
        assert any(g["name"] == "editors" for g in groups)

    def test_duplicate_raises(self, store):
        store.create_group("editors")
        with pytest.raises(PermissionStoreError, match="already exists"):
            store.create_group("editors")

    def test_delete_group(self, store):
        store.create_group("editors")
        store.delete_group("editors")
        assert not any(g["name"] == "editors" for g in store.list_groups())

    def test_delete_nonexistent_raises(self, store):
        with pytest.raises(PermissionStoreError, match="does not exist"):
            store.delete_group("ghost")

    def test_add_and_remove_member(self, store):
        store.create_group("editors")
        store.add_group_member("editors", "alice")
        groups = {g["name"]: g for g in store.list_groups()}
        assert "alice" in groups["editors"]["members"]
        store.remove_group_member("editors", "alice")
        groups = {g["name"]: g for g in store.list_groups()}
        assert "alice" not in groups["editors"]["members"]

    def test_add_member_to_nonexistent_group_raises(self, store):
        with pytest.raises(PermissionStoreError):
            store.add_group_member("ghost_group", "alice")

    def test_remove_nonmember_raises(self, store):
        store.create_group("editors")
        with pytest.raises(PermissionStoreError, match="not a member"):
            store.remove_group_member("editors", "nobody")

    def test_get_user_groups(self, store):
        store.create_group("editors")
        store.create_group("viewers")
        store.add_group_member("editors", "alice")
        store.add_group_member("viewers", "alice")
        groups = store.get_user_groups("alice")
        assert set(groups) == {"editors", "viewers"}


class TestRules:
    def _rule(self, **kwargs) -> PermissionRule:
        defaults = dict(
            subject_type="user",
            subject_id="alice",
            path="/photos",
            permissions=Permission.DOWNLOAD,
        )
        defaults.update(kwargs)
        return PermissionRule(**defaults)

    def test_add_and_list_rule(self, store):
        rule_id = store.add_rule(self._rule())
        rules = store.list_rules()
        assert any(r.rule_id == rule_id for r in rules)

    def test_remove_rule(self, store):
        rule_id = store.add_rule(self._rule())
        store.remove_rule(rule_id)
        assert not any(r.rule_id == rule_id for r in store.list_rules())

    def test_remove_nonexistent_raises(self, store):
        with pytest.raises(PermissionStoreError, match="does not exist"):
            store.remove_rule(9999)

    def test_list_rules_by_path_prefix(self, store):
        store.add_rule(self._rule(path="/photos"))
        store.add_rule(self._rule(path="/docs"))
        rules = store.list_rules(path_prefix="/photos")
        assert all(r.path.startswith("/photos") for r in rules)
        assert len(rules) == 1

    def test_rule_persists_all_fields(self, store):
        future = datetime.utcnow() + timedelta(hours=24)
        rule = self._rule(
            expires_at=future,
            upload_quota_bytes=1024 * 1024,
            download_limit=5,
            ip_whitelist=["192.168.0.0/16"],
            can_delegate=True,
        )
        rule_id = store.add_rule(rule)
        loaded = next(r for r in store.list_rules() if r.rule_id == rule_id)
        assert loaded.upload_quota_bytes == 1024 * 1024
        assert loaded.download_limit == 5
        assert "192.168.0.0/16" in loaded.ip_whitelist
        assert loaded.can_delegate is True


class TestResolvePermissions:
    def test_no_rules_returns_none(self, store):
        perms, pwd = store.resolve_permissions("alice", "/photos")
        assert perms == Permission.NONE
        assert pwd is None

    def test_direct_user_rule_applies(self, store):
        store.add_rule(PermissionRule(
            subject_type="user", subject_id="alice",
            path="/photos", permissions=Permission.DOWNLOAD,
        ))
        perms, _ = store.resolve_permissions("alice", "/photos")
        assert Permission.DOWNLOAD in perms

    def test_group_rule_applies_to_member(self, store):
        store.create_group("editors")
        store.add_group_member("editors", "alice")
        store.add_rule(PermissionRule(
            subject_type="group", subject_id="editors",
            path="/docs", permissions=Permission.UPLOAD,
        ))
        perms, _ = store.resolve_permissions("alice", "/docs")
        assert Permission.UPLOAD in perms

    def test_user_rule_overrides_group_rule(self, store):
        store.create_group("editors")
        store.add_group_member("editors", "alice")
        store.add_rule(PermissionRule(
            subject_type="group", subject_id="editors",
            path="/docs", permissions=Permission.DOWNLOAD | Permission.UPLOAD | Permission.DELETE,
        ))
        store.add_rule(PermissionRule(
            subject_type="user", subject_id="alice",
            path="/docs", permissions=Permission.NONE,
        ))
        perms, _ = store.resolve_permissions("alice", "/docs")
        assert perms == Permission.NONE

    def test_child_path_inherits_from_parent(self, store):
        store.add_rule(PermissionRule(
            subject_type="user", subject_id="alice",
            path="/", permissions=Permission.DOWNLOAD,
        ))
        perms, _ = store.resolve_permissions("alice", "/photos/holiday")
        assert Permission.DOWNLOAD in perms

    def test_more_specific_path_overrides_parent(self, store):
        store.add_rule(PermissionRule(
            subject_type="user", subject_id="alice",
            path="/", permissions=Permission.DOWNLOAD | Permission.UPLOAD,
        ))
        store.add_rule(PermissionRule(
            subject_type="user", subject_id="alice",
            path="/private", permissions=Permission.NONE,
        ))
        perms, _ = store.resolve_permissions("alice", "/private/secret.txt")
        assert perms == Permission.NONE

    def test_expired_rule_is_ignored(self, store):
        past = datetime.utcnow() - timedelta(hours=1)
        store.add_rule(PermissionRule(
            subject_type="user", subject_id="alice",
            path="/photos", permissions=Permission.DOWNLOAD,
            expires_at=past,
        ))
        perms, _ = store.resolve_permissions("alice", "/photos")
        assert perms == Permission.NONE

    def test_password_hash_is_returned(self, store):
        import bcrypt
        pwd_hash = bcrypt.hashpw(b"secret", bcrypt.gensalt()).decode()
        store.add_rule(PermissionRule(
            subject_type="user", subject_id="alice",
            path="/vip", permissions=Permission.DOWNLOAD,
            password_hash=pwd_hash,
        ))
        _, returned_hash = store.resolve_permissions("alice", "/vip")
        assert returned_hash == pwd_hash


class TestShareLinks:
    def test_create_and_retrieve(self, store):
        link = store.create_share_link(
            created_by="alice",
            path="/report.pdf",
            permissions=Permission.DOWNLOAD,
            download_limit=3,
        )
        retrieved = store.get_share_link(link.token)
        assert retrieved is not None
        assert retrieved.path == "/report.pdf"
        assert retrieved.download_limit == 3

    def test_revoke_removes_link(self, store):
        link = store.create_share_link("alice", "/x.pdf", Permission.DOWNLOAD)
        store.revoke_share_link(link.token)
        assert store.get_share_link(link.token) is None

    def test_revoke_nonexistent_raises(self, store):
        with pytest.raises(PermissionStoreError, match="not found"):
            store.revoke_share_link("ghost_token")

    def test_list_by_creator(self, store):
        store.create_share_link("alice", "/a.pdf", Permission.DOWNLOAD)
        store.create_share_link("bob", "/b.pdf", Permission.DOWNLOAD)
        alice_links = store.list_share_links(created_by="alice")
        assert all(l.created_by == "alice" for l in alice_links)
        assert len(alice_links) == 1

    def test_increment_download_count(self, store):
        link = store.create_share_link("alice", "/f.pdf", Permission.DOWNLOAD, download_limit=2)
        store.increment_share_download(link.token)
        store.increment_share_download(link.token)
        updated = store.get_share_link(link.token)
        assert updated.download_count == 2
        assert not updated.is_valid()


class TestUploadQuota:
    def test_record_and_retrieve_usage(self, store):
        rule_id = store.add_rule(PermissionRule(
            subject_type="user", subject_id="alice",
            path="/uploads", permissions=Permission.UPLOAD,
            upload_quota_bytes=10 * 1024 * 1024,
        ))
        store.record_upload(rule_id, "alice", 500_000)
        store.record_upload(rule_id, "alice", 200_000)
        assert store.get_upload_usage(rule_id, "alice") == 700_000

    def test_usage_is_per_user(self, store):
        rule_id = store.add_rule(PermissionRule(
            subject_type="group", subject_id="team",
            path="/shared", permissions=Permission.UPLOAD,
        ))
        store.record_upload(rule_id, "alice", 100)
        store.record_upload(rule_id, "bob", 200)
        assert store.get_upload_usage(rule_id, "alice") == 100
        assert store.get_upload_usage(rule_id, "bob") == 200
