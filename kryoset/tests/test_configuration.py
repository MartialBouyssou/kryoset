import json
from pathlib import Path

import pytest

from kryoset.core.configuration import Configuration, ConfigurationError


class TestConfigurationInitialise:
    def test_creates_file_on_disk(self, config_path: Path, temp_storage: Path):
        cfg = Configuration(config_path)
        cfg.initialize(storage_path=str(temp_storage))
        assert config_path.exists()

    def test_file_is_readable_json(self, config_path: Path, temp_storage: Path):
        cfg = Configuration(config_path)
        cfg.initialize(storage_path=str(temp_storage))
        with open(config_path) as f:
            data = json.load(f)
        assert data["storage_path"] == str(temp_storage)

    def test_default_port_is_2222(self, config_path: Path, temp_storage: Path):
        cfg = Configuration(config_path)
        cfg.initialize(storage_path=str(temp_storage))
        assert cfg.port == 2222

    def test_custom_port_is_saved(self, config_path: Path, temp_storage: Path):
        cfg = Configuration(config_path)
        cfg.initialize(storage_path=str(temp_storage), port=3333)
        assert cfg.port == 3333

    def test_file_permissions_are_restrictive(
        self, config_path: Path, temp_storage: Path
    ):
        cfg = Configuration(config_path)
        cfg.initialize(storage_path=str(temp_storage))
        mode = oct(config_path.stat().st_mode)[-3:]
        assert mode == "600"


class TestConfigurationLoad:
    def test_load_existing_config(self, configuration: Configuration, config_path: Path):
        loaded = Configuration(config_path)
        loaded.load()
        assert str(loaded.storage_path) == str(configuration.storage_path)

    def test_load_missing_file_raises(self, tmp_path: Path):
        cfg = Configuration(tmp_path / "nonexistent.json")
        with pytest.raises(ConfigurationError, match="not found"):
            cfg.load()

    def test_load_malformed_json_raises(self, config_path: Path):
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text("{ this is not valid json }")
        cfg = Configuration(config_path)
        with pytest.raises(ConfigurationError, match="malformed"):
            cfg.load()


class TestConfigurationValidate:
    def test_valid_config_passes(self, configuration: Configuration):
        configuration.validate()  # should not raise

    def test_missing_storage_path_raises(self, config_path: Path):
        cfg = Configuration(config_path)
        cfg._data = {"storage_path": "", "port": 2222}
        with pytest.raises(ConfigurationError, match="storage_path"):
            cfg.validate()

    def test_nonexistent_storage_path_raises(self, config_path: Path):
        cfg = Configuration(config_path)
        cfg._data = {"storage_path": "/this/does/not/exist", "port": 2222}
        with pytest.raises(ConfigurationError, match="does not exist"):
            cfg.validate()

    def test_invalid_port_raises(self, configuration: Configuration, temp_storage: Path):
        configuration._data["port"] = 99999
        with pytest.raises(ConfigurationError, match="port"):
            configuration.validate()

    def test_port_zero_raises(self, configuration: Configuration):
        configuration._data["port"] = 0
        with pytest.raises(ConfigurationError, match="port"):
            configuration.validate()


class TestConfigurationProperties:
    def test_storage_path_is_path_object(self, configuration: Configuration):
        assert isinstance(configuration.storage_path, Path)

    def test_host_defaults_to_all_interfaces(self, configuration: Configuration):
        assert configuration.host == "0.0.0.0"

    def test_users_starts_empty(self, configuration: Configuration):
        assert configuration.users == {}

    def test_set_users_persists(self, configuration: Configuration, config_path: Path):
        configuration.set_users({"bob": {"password_hash": "x", "enabled": True}})
        reloaded = Configuration(config_path)
        reloaded.load()
        assert "bob" in reloaded.users
