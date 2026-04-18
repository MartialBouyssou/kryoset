from pathlib import Path

import pytest

from kryoset.core.configuration import Configuration
from kryoset.core.user_manager import UserManager


@pytest.fixture()
def temp_storage(tmp_path: Path) -> Path:
    """Return a temporary directory that acts as the NAS storage root."""
    storage = tmp_path / "storage"
    storage.mkdir()
    return storage


@pytest.fixture()
def config_path(tmp_path: Path) -> Path:
    """Return a path inside a temporary directory for the config file."""
    return tmp_path / "config.json"


@pytest.fixture()
def configuration(config_path: Path, temp_storage: Path) -> Configuration:
    """Return a fully initialised Configuration pointing at temp_storage."""
    cfg = Configuration(config_path)
    cfg.initialize(storage_path=str(temp_storage), port=2222)
    return cfg


@pytest.fixture()
def user_manager(configuration: Configuration) -> UserManager:
    """Return a UserManager bound to the test configuration."""
    return UserManager(configuration)


@pytest.fixture()
def user_manager_with_alice(user_manager: UserManager) -> UserManager:
    """Return a UserManager that already contains a user 'alice'."""
    user_manager.add_user("alice", "securepassword123")
    return user_manager
