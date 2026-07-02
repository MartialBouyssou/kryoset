import json
import os
import tempfile
from pathlib import Path
from threading import RLock
from typing import Any, Optional

DEFAULT_CONFIG_PATH = Path.home() / ".kryoset" / "config.json"

DEFAULT_CONFIG: dict[str, Any] = {
    "storage_path": "",
    "host": "0.0.0.0",
    "port": 2222,
    "host_key_path": str(Path.home() / ".kryoset" / "host_key"),
    "storage_max_bytes": None,
    "storage_allocations": {},
    "users": {},
}


class ConfigurationError(Exception):
    """Raised when the configuration is invalid or cannot be loaded."""


class Configuration:
    """
    Reads and writes the Kryoset JSON configuration file.

    The configuration can be modified by several Kryoset entry points (API,
    CLI, SFTP process).  Reads therefore perform a cheap mtime check and reload
    when another process has changed the file.  Writes are atomic to avoid a
    half-written config if the process crashes mid-save.
    """

    def __init__(self, config_path: Path = DEFAULT_CONFIG_PATH) -> None:
        self.config_path = config_path
        self._data: dict[str, Any] = {}
        self._last_loaded_mtime_ns: int | None = None
        self._lock = RLock()

    def _update_loaded_mtime(self) -> None:
        try:
            self._last_loaded_mtime_ns = self.config_path.stat().st_mtime_ns
        except FileNotFoundError:
            self._last_loaded_mtime_ns = None

    def _load_unlocked(self) -> None:
        if not self.config_path.exists():
            raise ConfigurationError(
                f"Configuration file not found: {self.config_path}\n"
                "Run 'kryoset init' to create a new configuration."
            )
        try:
            try:
                os.chmod(self.config_path.parent, 0o700)
                os.chmod(self.config_path, 0o600)
            except OSError:
                pass
            with open(self.config_path, "r", encoding="utf-8") as config_file:
                data = json.load(config_file)
        except json.JSONDecodeError as error:
            raise ConfigurationError(
                f"Configuration file is malformed: {error}"
            ) from error
        if not isinstance(data, dict):
            raise ConfigurationError("Configuration root must be a JSON object.")
        self._data = data
        self._update_loaded_mtime()

    def load(self) -> None:
        """
        Load the configuration from disk.

        Raises:
            ConfigurationError: If the file does not exist or is malformed.
        """
        with self._lock:
            self._load_unlocked()

    def reload_if_changed(self) -> None:
        """Reload the config if another process changed it on disk."""
        with self._lock:
            if not self.config_path.exists():
                return
            try:
                current_mtime = self.config_path.stat().st_mtime_ns
            except OSError:
                return
            if self._last_loaded_mtime_ns is None or current_mtime != self._last_loaded_mtime_ns:
                self._load_unlocked()

    def save(self) -> None:
        """
        Persist the current configuration to disk atomically.

        The parent directory is created automatically if it does not exist.
        """
        with self._lock:
            self.config_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(self.config_path.parent, 0o700)
            except OSError:
                pass
            fd, tmp_name = tempfile.mkstemp(
                prefix=f".{self.config_path.name}.",
                suffix=".tmp",
                dir=self.config_path.parent,
                text=True,
            )
            tmp_path = Path(tmp_name)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as config_file:
                    json.dump(self._data, config_file, indent=2)
                    config_file.write("\n")
                    config_file.flush()
                    os.fsync(config_file.fileno())
                os.chmod(tmp_path, 0o600)
                os.replace(tmp_path, self.config_path)
                try:
                    dir_fd = os.open(self.config_path.parent, os.O_DIRECTORY)
                    try:
                        os.fsync(dir_fd)
                    finally:
                        os.close(dir_fd)
                except OSError:
                    pass
                self._update_loaded_mtime()
            finally:
                try:
                    if tmp_path.exists():
                        tmp_path.unlink()
                except OSError:
                    pass

    def initialize(
        self,
        storage_path: str,
        port: int = 2222,
        storage_max_bytes: Optional[int] = None,
    ) -> None:
        """
        Create a fresh configuration with sensible defaults.
        """
        with self._lock:
            self._data = dict(DEFAULT_CONFIG)
            self._data["storage_path"] = str(storage_path)
            self._data["port"] = port
            if storage_max_bytes is not None:
                self._data["storage_max_bytes"] = storage_max_bytes
            self.save()

    def validate(self) -> None:
        """Check that all required fields are present and coherent."""
        self.reload_if_changed()
        if not self._data.get("storage_path"):
            raise ConfigurationError("'storage_path' is not set in configuration.")
        storage = Path(self._data["storage_path"])
        if not storage.exists():
            raise ConfigurationError(f"Storage path does not exist: {storage}")
        if not storage.is_dir():
            raise ConfigurationError(f"Storage path is not a directory: {storage}")
        port = self._data.get("port", 0)
        if not isinstance(port, int) or not (1 <= port <= 65535):
            raise ConfigurationError(
                f"Invalid port number: {port}. Must be between 1 and 65535."
            )

    @property
    def storage_path(self) -> Path:
        """Absolute path to the shared storage directory."""
        self.reload_if_changed()
        return Path(self._data["storage_path"])

    @property
    def host(self) -> str:
        """IP address the server binds to."""
        self.reload_if_changed()
        return self._data.get("host", "0.0.0.0")

    @property
    def port(self) -> int:
        """TCP port the server listens on."""
        self.reload_if_changed()
        return self._data.get("port", 2222)

    @property
    def host_key_path(self) -> Path:
        """Path to the RSA host private key file."""
        self.reload_if_changed()
        return Path(self._data.get("host_key_path", DEFAULT_CONFIG["host_key_path"]))

    @property
    def users(self) -> dict[str, Any]:
        """Dictionary of registered users keyed by username."""
        self.reload_if_changed()
        users = self._data.get("users", {})
        return users if isinstance(users, dict) else {}

    def set_users(self, users: dict[str, Any]) -> None:
        """Replace the entire users dictionary and persist to disk."""
        with self._lock:
            self._data["users"] = users
            self.save()
