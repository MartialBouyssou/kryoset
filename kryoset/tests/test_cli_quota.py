from pathlib import Path

from click.testing import CliRunner

from kryoset.cli import cli
from kryoset.core.configuration import Configuration
from kryoset.core.user_manager import UserManager


def _create_config_with_user(tmp_path: Path) -> Path:
    storage = tmp_path / "storage"
    storage.mkdir()
    config_path = tmp_path / "config.json"

    config = Configuration(config_path)
    config.initialize(storage_path=str(storage))

    user_manager = UserManager(config)
    user_manager.add_user("alice", "securepassword1")
    return config_path


def test_user_set_max_storage_sets_quota(tmp_path: Path):
    config_path = _create_config_with_user(tmp_path)
    runner = CliRunner()

    result = runner.invoke(
        cli,
        ["user", "set-max-storage", "alice", "2GB", "--config", str(config_path)],
    )

    assert result.exit_code == 0
    assert "[ok] Quota for 'alice' set to 2GB." in result.output

    config = Configuration(config_path)
    config.load()
    assert config.users["alice"]["storage_quota_bytes"] == 2 * 1024**3


def test_user_set_max_storage_removes_quota_with_none(tmp_path: Path):
    config_path = _create_config_with_user(tmp_path)
    runner = CliRunner()

    runner.invoke(
        cli,
        ["user", "set-max-storage", "alice", "1GB", "--config", str(config_path)],
    )
    result = runner.invoke(
        cli,
        ["user", "set-max-storage", "alice", "none", "--config", str(config_path)],
    )

    assert result.exit_code == 0
    assert "[ok] Quota removed for 'alice' (unlimited)." in result.output

    config = Configuration(config_path)
    config.load()
    assert "storage_quota_bytes" not in config.users["alice"]


def test_user_set_max_storage_rejects_invalid_size(tmp_path: Path):
    config_path = _create_config_with_user(tmp_path)
    runner = CliRunner()

    result = runner.invoke(
        cli,
        ["user", "set-max-storage", "alice", "abc", "--config", str(config_path)],
    )

    assert result.exit_code == 1
    assert "[error] Invalid size." in result.output
