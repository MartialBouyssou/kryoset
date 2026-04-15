from pathlib import Path

import pytest

from kryoset.core.configuration import Configuration
from kryoset.core.quota import QuotaError, QuotaManager
from kryoset.core.user_manager import UserManager


@pytest.fixture()
def storage(tmp_path: Path) -> Path:
    storage = tmp_path / "storage"
    storage.mkdir()
    return storage


@pytest.fixture()
def user_manager(tmp_path: Path, storage: Path) -> UserManager:
    cfg = Configuration(tmp_path / "config.json")
    cfg.initialize(storage_path=str(storage))
    um = UserManager(cfg)
    um.add_user("alice", "securepassword1")
    um.add_user("admin", "adminpassword1")
    um.set_admin("admin", admin=True)
    return um


@pytest.fixture()
def quota_manager(user_manager: UserManager, storage: Path) -> QuotaManager:
    return QuotaManager(user_manager, storage)


class TestSetAndGetQuota:
    def test_no_quota_by_default(self, quota_manager):
        assert quota_manager.get_quota("alice") is None

    def test_set_quota_in_bytes(self, quota_manager):
        quota_manager.set_quota("alice", 1024 * 1024 * 1024)
        assert quota_manager.get_quota("alice") == 1024 * 1024 * 1024

    def test_remove_quota_with_none(self, quota_manager):
        quota_manager.set_quota("alice", 1000)
        quota_manager.set_quota("alice", None)
        assert quota_manager.get_quota("alice") is None

    def test_set_quota_for_nonexistent_user_raises(self, quota_manager):
        with pytest.raises(ValueError, match="does not exist"):
            quota_manager.set_quota("ghost", 1000)

    def test_set_negative_quota_raises(self, quota_manager):
        with pytest.raises(ValueError, match="positive"):
            quota_manager.set_quota("alice", -100)


class TestGetUsedBytes:
    def test_zero_when_no_files(self, quota_manager):
        assert quota_manager.get_used_bytes("alice") == 0

    def test_counts_files_in_user_directory(self, quota_manager, storage: Path):
        user_dir = storage / "alice"
        user_dir.mkdir()
        (user_dir / "file.txt").write_bytes(b"x" * 1000)
        assert quota_manager.get_used_bytes("alice") == 1000

    def test_counts_files_recursively(self, quota_manager, storage: Path):
        user_dir = storage / "alice"
        subdir = user_dir / "sub"
        subdir.mkdir(parents=True)
        (user_dir / "a.txt").write_bytes(b"x" * 500)
        (subdir / "b.txt").write_bytes(b"x" * 300)
        assert quota_manager.get_used_bytes("alice") == 800


class TestCheckUploadAllowed:
    def test_allowed_when_no_quota(self, quota_manager):
        quota_manager.check_upload_allowed("alice", 999_999_999)

    def test_allowed_when_within_quota(self, quota_manager, storage: Path):
        quota_manager.set_quota("alice", 10_000)
        quota_manager.check_upload_allowed("alice", 5_000)

    def test_denied_when_quota_exceeded(self, quota_manager, storage: Path):
        quota_manager.set_quota("alice", 1_000)
        user_dir = storage / "alice"
        user_dir.mkdir()
        (user_dir / "existing.txt").write_bytes(b"x" * 900)
        with pytest.raises(QuotaError, match="quota exceeded"):
            quota_manager.check_upload_allowed("alice", 200)

    def test_admin_exempt_from_quota(self, quota_manager):
        quota_manager.set_quota("admin", 1)
        quota_manager.check_upload_allowed("admin", 999_999_999)


class TestFormatQuotaSummary:
    def test_shows_no_quota_when_unlimited(self, quota_manager):
        summary = quota_manager.format_quota_summary("alice")
        assert "no quota" in summary

    def test_shows_percentage_when_quota_set(self, quota_manager, storage: Path):
        quota_manager.set_quota("alice", 1024 * 1024 * 10)
        user_dir = storage / "alice"
        user_dir.mkdir()
        (user_dir / "file.txt").write_bytes(b"x" * 1024 * 1024 * 5)
        summary = quota_manager.format_quota_summary("alice")
        assert "50%" in summary

    def test_shows_used_and_total(self, quota_manager):
        quota_manager.set_quota("alice", 1024 * 1024 * 100)
        summary = quota_manager.format_quota_summary("alice")
        assert "GB" in summary or "MB" in summary
