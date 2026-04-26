from pathlib import Path

from click.testing import CliRunner

from kryoset.cli import cli
from kryoset.core.configuration import Configuration


def _create_config(tmp_path: Path) -> Path:
    storage = tmp_path / "storage"
    storage.mkdir()
    config_path = tmp_path / "config.json"
    config = Configuration(config_path)
    config.initialize(storage_path=str(storage))
    return config_path


def test_storage_set_max_updates_config(tmp_path: Path):
    config_path = _create_config(tmp_path)
    runner = CliRunner()

    result = runner.invoke(
        cli,
        ["storage", "set-max", "100GB", "--config", str(config_path)],
    )

    assert result.exit_code == 0
    assert "[ok] Global storage budget set to 100GB." in result.output

    config = Configuration(config_path)
    config.load()
    assert config._data["storage_max_bytes"] == 100 * 1024**3


def test_storage_set_max_none_removes_limit(tmp_path: Path):
    config_path = _create_config(tmp_path)
    runner = CliRunner()

    runner.invoke(
        cli,
        ["storage", "set-max", "100GB", "--config", str(config_path)],
    )
    result = runner.invoke(
        cli,
        ["storage", "set-max", "none", "--config", str(config_path)],
    )

    assert result.exit_code == 0
    assert "[ok] Global storage budget removed (unlimited)." in result.output

    config = Configuration(config_path)
    config.load()
    assert "storage_max_bytes" not in config._data


def test_storage_set_max_rejects_invalid_size(tmp_path: Path):
    config_path = _create_config(tmp_path)
    runner = CliRunner()

    result = runner.invoke(
        cli,
        ["storage", "set-max", "abc", "--config", str(config_path)],
    )

    assert result.exit_code == 1
    assert "[error] Invalid size." in result.output
