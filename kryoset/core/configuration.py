"""
Configuration management for Kryoset.

Handles loading, saving and validating the server configuration stored
in a JSON file. The configuration holds the storage path, network
settings and the registered user list.
"""

import json
import os
from pathlib import Path
from typing import Any

DEFAULT_CONFIG_PATH = Path.home() / ".kryoset" / "config.json"

DEFAULT_CONFIG: dict[str, Any] = {
    "storage_path": "",
    "host": "0.0.0.0",
    "port": 2222,
    "host_key_path": str(Path.home() / ".kryoset" / "host_key"),
    "users": {},
}


class ConfigurationError(Exception):
    """Raised when the configuration is invalid or cannot be loaded."""


class Configuration:
    """
    Reads and writes the Kryoset JSON configuration file.

    All server settings (storage path, host, port, users) are stored in a
    single JSON file so that the server can be fully reproduced from it.
    """

    def __init__(self, config_path: Path = DEFAULT_CONFIG_PATH) -> None:
        self.config_path = config_path
        self._data: dict[str, Any] = {}

    def load(self) -> None:
        """
        Load the configuration from disk.

        Raises:
            ConfigurationError: If the file does not exist or is malformed.
        """
        if not self.config_path.exists():
            raise ConfigurationError(
                f"Configuration file not found: {self.config_path}\n"
                "Run 'kryoset init' to create a new configuration."
            )
        try:
            with open(self.config_path, "r", encoding="utf-8") as config_file:
                self._data = json.load(config_file)
        except json.JSONDecodeError as error:
            raise ConfigurationError(
                f"Configuration file is malformed: {error}"
            ) from error

    def save(self) -> None:
        """
        Persist the current configuration to disk.

        The parent directory is created automatically if it does not exist.
        """
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.config_path, "w", encoding="utf-8") as config_file:
            json.dump(self._data, config_file, indent=2)
        os.chmod(self.config_path, 0o600)

    def initialize(self, storage_path: str, port: int = 2222) -> None:
        """
        Create a fresh configuration with sensible defaults.

        Args:
            storage_path: Absolute path to the disk or partition to share.
            port: TCP port the SFTP server will listen on (default 2222).
        """
        self._data = dict(DEFAULT_CONFIG)
        self._data["storage_path"] = str(storage_path)
        self._data["port"] = port
        self.save()

    def validate(self) -> None:
        """
        Check that all required fields are present and coherent.

        Raises:
            ConfigurationError: If a required field is missing or invalid.
        """
        if not self._data.get("storage_path"):
            raise ConfigurationError("'storage_path' is not set in configuration.")
        storage = Path(self._data["storage_path"])
        if not storage.exists():
            raise ConfigurationError(
                f"Storage path does not exist: {storage}"
            )
        if not storage.is_dir():
            raise ConfigurationError(
                f"Storage path is not a directory: {storage}"
            )
        port = self._data.get("port", 0)
        if not isinstance(port, int) or not (1 <= port <= 65535):
            raise ConfigurationError(
                f"Invalid port number: {port}. Must be between 1 and 65535."
            )

    @property
    def storage_path(self) -> Path:
        """Absolute path to the shared storage directory."""
        return Path(self._data["storage_path"])

    @property
    def host(self) -> str:
        """IP address the server binds to."""
        return self._data.get("host", "0.0.0.0")

    @property
    def port(self) -> int:
        """TCP port the server listens on."""
        return self._data.get("port", 2222)

    @property
    def host_key_path(self) -> Path:
        """Path to the RSA host private key file."""
        return Path(self._data.get("host_key_path", DEFAULT_CONFIG["host_key_path"]))

    @property
    def users(self) -> dict[str, Any]:
        """Dictionary of registered users keyed by username."""
        return self._data.get("users", {})

    def set_users(self, users: dict[str, Any]) -> None:
        """
        Replace the entire users dictionary and persist to disk.

        Args:
            users: New users dictionary to store.
        """
        self._data["users"] = users
        self.save()
