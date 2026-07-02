import json
from pathlib import Path

from click.testing import CliRunner

from kryoset.cli import cli
from kryoset.core.configuration import Configuration
from kryoset.core.permission_store import PermissionStore
from kryoset.core.permissions import Permission, PermissionRule
from kryoset.core.user_manager import UserManager


def _create_user_config(tmp_path: Path) -> tuple[Path, Path, Path]:
    storage = tmp_path / "storage"
    storage.mkdir()
    config_path = tmp_path / "config.json"
    config = Configuration(config_path)
    config.initialize(storage_path=str(storage))
    user_manager = UserManager(config)
    user_manager.add_user("alice", "alicepass1", home_path="/home/alice")
    (storage / "home" / "alice").mkdir(parents=True, exist_ok=True)
    (storage / "home" / "alice" / "file.txt").write_text("secret", encoding="utf-8")
    permission_db = tmp_path / "permissions.db"
    store = PermissionStore(permission_db)
    store.initialize()
    store.create_group("staff")
    store.add_group_member("staff", "alice", storage_path=storage)
    store.add_rule(PermissionRule(subject_type="user", subject_id="alice", path="/home/alice", permissions=Permission.LIST | Permission.DOWNLOAD))
    store.create_share_link(created_by="alice", path="/home/alice/file.txt", permissions=Permission.DOWNLOAD, password="goodpass1")
    return config_path, permission_db, storage


def test_cli_user_export_excludes_secrets(tmp_path: Path):
    config_path, permission_db, _ = _create_user_config(tmp_path)
    runner = CliRunner()

    result = runner.invoke(cli, ["user", "export", "alice", "--config", str(config_path), "--permission-db", str(permission_db)])

    assert result.exit_code == 0, result.output
    data = json.loads(result.output)
    assert data["username"] == "alice"
    assert data["groups"] == ["staff"]
    assert data["share_links"][0]["password_protected"] is True
    serialized = json.dumps(data)
    assert "password_hash" not in serialized
    assert "totp_secret" not in serialized
    assert "goodpass1" not in serialized


def test_cli_user_purge_removes_metadata_and_optionally_files(tmp_path: Path):
    config_path, permission_db, storage = _create_user_config(tmp_path)
    runner = CliRunner()

    result = runner.invoke(
        cli,
        [
            "user",
            "purge",
            "alice",
            "--delete-files",
            "--yes",
            "--config",
            str(config_path),
            "--permission-db",
            str(permission_db),
        ],
    )

    assert result.exit_code == 0, result.output
    config = Configuration(config_path)
    config.load()
    assert "alice" not in config.users
    assert not (storage / "home" / "alice").exists()

    store = PermissionStore(permission_db)
    store.initialize()
    assert store.get_user_groups("alice") == []
    assert store.get_rules_for_user("alice") == []
    assert store.list_share_links(created_by="alice") == []
