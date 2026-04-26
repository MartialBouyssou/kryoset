import json
import tempfile
from pathlib import Path

import pytest

from kryoset.core.configuration import Configuration
from kryoset.core.storage_manager import StorageError, StorageManager
from kryoset.core.user_manager import UserManager


@pytest.fixture()
def tmp_storage(tmp_path):
    storage = tmp_path / "storage"
    storage.mkdir()
    return storage


@pytest.fixture()
def config(tmp_path, tmp_storage):
    cfg_path = tmp_path / "config.json"
    cfg_path.write_text(json.dumps({
        "storage_path": str(tmp_storage),
        "host": "0.0.0.0", "port": 2222,
        "host_key_path": str(tmp_path / "hk"), "users": {},
    }))
    cfg = Configuration(cfg_path)
    cfg.load()
    return cfg


@pytest.fixture()
def user_manager(config):
    um = UserManager(config)
    um.add_user("alice", "alicepass1")
    um.add_user("admin", "adminpass1")
    um.set_admin("admin", admin=True)
    return um


@pytest.fixture()
def sm(config, user_manager):
    return StorageManager(config, user_manager)


def test_get_used_bytes_empty(sm):
    assert sm.get_used_bytes() == 0


def test_get_used_bytes_with_file(sm, tmp_storage):
    (tmp_storage / "file.txt").write_bytes(b"hello world")
    assert sm.get_used_bytes() == 11


def test_set_global_max(sm):
    sm.set_global_max(1_000_000)
    assert sm.get_global_max() == 1_000_000


def test_remove_global_max(sm):
    sm.set_global_max(1_000_000)
    sm.set_global_max(None)
    assert sm.get_global_max() is None


def test_set_global_max_below_usage_raises(sm, tmp_storage):
    (tmp_storage / "big.bin").write_bytes(b"x" * 1000)
    with pytest.raises(StorageError, match="smaller than current usage"):
        sm.set_global_max(500)


def test_set_global_max_below_allocations_raises(sm):
    sm.set_global_max(10_000)
    sm.set_allocation("user:alice", 8_000)
    with pytest.raises(StorageError, match="sum of existing allocations"):
        sm.set_global_max(5_000)


def test_set_allocation_user(sm):
    sm.set_allocation("user:alice", 5_000_000)
    assert sm.get_allocation("user:alice") == 5_000_000


def test_set_allocation_group(sm):
    sm.set_allocation("group:editors", 2_000_000)
    assert sm.get_allocation("group:editors") == 2_000_000


def test_remove_allocation(sm):
    sm.set_allocation("user:alice", 5_000_000)
    sm.set_allocation("user:alice", None)
    assert sm.get_allocation("user:alice") is None


def test_allocation_exceeds_global_budget_raises(sm):
    sm.set_global_max(1_000_000)
    with pytest.raises(StorageError, match="exceed the global budget"):
        sm.set_allocation("user:alice", 2_000_000)


def test_effective_quota_user_wins_over_group(sm):
    sm.set_allocation("user:alice", 5_000_000)
    sm.set_allocation("group:editors", 1_000_000)
    assert sm.get_effective_quota("alice") == 5_000_000


def test_effective_quota_group_fallback(sm, config):
    from kryoset.core.permission_store import PermissionStore
    db_path = Path(config.config_path).parent / "perms.db"
    ps = PermissionStore(db_path)
    ps.initialize()
    ps.create_group("editors")
    ps.add_group_member("editors", "alice")
    sm_with_ps = StorageManager(config, sm._user_manager, ps)
    sm_with_ps.set_allocation("group:editors", 3_000_000)
    assert sm_with_ps.get_effective_quota("alice") == 3_000_000


def test_effective_quota_min_of_groups(sm, config):
    from kryoset.core.permission_store import PermissionStore
    db_path = Path(config.config_path).parent / "perms2.db"
    ps = PermissionStore(db_path)
    ps.initialize()
    ps.create_group("g1")
    ps.create_group("g2")
    ps.add_group_member("g1", "alice")
    ps.add_group_member("g2", "alice")
    sm2 = StorageManager(config, sm._user_manager, ps)
    sm2.set_allocation("group:g1", 8_000_000)
    sm2.set_allocation("group:g2", 3_000_000)
    assert sm2.get_effective_quota("alice") == 3_000_000


def test_effective_quota_admin_unlimited(sm):
    sm.set_global_max(100)
    sm.set_allocation("user:admin", 50)
    assert sm.get_effective_quota("admin") is None


def test_effective_quota_no_allocation(sm):
    assert sm.get_effective_quota("alice") is None


def test_check_upload_allowed_no_limit(sm):
    sm.check_upload_allowed("alice", 999_999_999)


def test_check_upload_global_limit(sm, tmp_storage):
    sm.set_global_max(100)
    (tmp_storage / "existing.bin").write_bytes(b"x" * 80)
    with pytest.raises(StorageError, match="global NAS storage is full"):
        sm.check_upload_allowed("alice", 30)


def test_check_upload_user_quota(sm, tmp_storage):
    sm.set_allocation("user:alice", 50)
    (tmp_storage / "alice").mkdir()
    (tmp_storage / "alice" / "file.bin").write_bytes(b"x" * 40)
    with pytest.raises(StorageError, match="quota exceeded"):
        sm.check_upload_allowed("alice", 20)


def test_check_upload_admin_exempt_from_global(sm, tmp_storage):
    sm.set_global_max(10)
    (tmp_storage / "x.bin").write_bytes(b"x" * 9)
    sm.check_upload_allowed("admin", 999_999)


def test_validate_on_startup_usage_exceeds_budget(sm, tmp_storage, config):
    (tmp_storage / "large.bin").write_bytes(b"x" * 1000)
    config._data["storage_max_bytes"] = 500
    config.save()
    warnings = sm.validate_on_startup()
    assert any("updated" in w for w in warnings)
    assert sm.get_global_max() >= 1000


def test_summary_keys(sm):
    s = sm.summary()
    assert "global_max_bytes" in s
    assert "used_bytes" in s
    assert "disk_total_bytes" in s
    assert "allocated_bytes" in s


def test_get_unallocated_bytes(sm):
    sm.set_global_max(10_000_000)
    sm.set_allocation("user:alice", 3_000_000)
    assert sm.get_unallocated_bytes() == 7_000_000
