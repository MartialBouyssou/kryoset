import secrets
from pathlib import Path
from typing import Optional

import bcrypt

_DUMMY_PASSWORD_HASH = bcrypt.hashpw(b"kryoset-dummy-password", bcrypt.gensalt())

from kryoset.core.configuration import Configuration
from kryoset.core.home_paths import normalize_home_path


class UserError(Exception):
    """Raised when a user operation fails (duplicate, not found, etc.)."""


class UserManager:
    """
    Manages Kryoset user accounts.

    User records are stored inside the configuration file under the 'users'
    key. Each record holds the bcrypt password hash and a flag indicating
    whether the account is enabled.

    Args:
        configuration: A loaded :class:`Configuration` instance.
    """

    def __init__(self, configuration: Configuration) -> None:
        self._configuration = configuration

    def _get_users(self) -> dict:
        # Pick up user changes made by another Kryoset process without requiring
        # the running SFTP/API process to restart.
        if hasattr(self._configuration, "reload_if_changed"):
            self._configuration.reload_if_changed()
        return dict(self._configuration.users)

    def _save_users(self, users: dict) -> None:
        self._configuration.set_users(users)

    @staticmethod
    def _validate_username(username: str) -> None:
        if not username or len(username) > 64 or not username.replace("_", "").isalnum():
            raise UserError(
                f"Invalid username '{username}'. "
                "Use 1-64 letters, digits or underscores."
            )

    def user_exists(self, username: str) -> bool:
        return username in self._get_users()

    def is_enabled(self, username: str) -> bool:
        return self._get_users().get(username, {}).get("enabled", False)

    def get_token_version(self, username: str) -> int:
        return int(self._get_users().get(username, {}).get("token_version", 0))

    def bump_token_version(self, username: str) -> None:
        users = self._get_users()
        if username not in users:
            raise UserError(f"User '{username}' does not exist.")
        users[username]["token_version"] = int(users[username].get("token_version", 0)) + 1
        self._save_users(users)

    def add_user(self, username: str, password: str, home_path: Optional[str] = None) -> None:
        """
        Create a new user with a bcrypt-hashed password.

        Args:
            username: Unique login name (letters, digits, underscores only).
            password: Plain-text password (minimum 8 characters).
            home_path: Optional virtual home root for this user.

        Raises:
            UserError: If the username already exists, is invalid, or the
                password is too short.
        """
        self._validate_username(username)
        if len(password) < 8:
            raise UserError("Password must be at least 8 characters long.")

        users = self._get_users()
        if username in users:
            raise UserError(f"User '{username}' already exists.")

        password_hash = bcrypt.hashpw(
            password.encode("utf-8"), bcrypt.gensalt()
        ).decode("utf-8")

        users[username] = {
            "password_hash": password_hash,
            "enabled": True,
            "token_version": 0,
        }
        if home_path is not None:
            normalized = normalize_home_path(home_path)
            users[username]["home_path"] = normalized
            # Create the home directory immediately inside the storage root.
            home_real = (
                Path(self._configuration.storage_path) / normalized.lstrip("/")
            )
            try:
                home_real.mkdir(parents=True, exist_ok=True)
            except PermissionError:
                # Skip permission errors - directory may be created later or by system
                pass
        self._save_users(users)

    def remove_user(self, username: str) -> None:
        """
        Delete a user from the configuration.

        Args:
            username: Login name of the user to remove.

        Raises:
            UserError: If the user does not exist.
        """
        users = self._get_users()
        if username not in users:
            raise UserError(f"User '{username}' does not exist.")
        del users[username]
        self._save_users(users)

    def authenticate(self, username: str, password: str) -> bool:
        """
        Verify a username and password pair.

        Args:
            username: Login name to check.
            password: Plain-text password to verify.

        Returns:
            True if credentials are valid and the account is enabled,
            False otherwise.
        """
        users = self._get_users()
        user_record = users.get(username)
        if user_record is None:
            # Perform a fixed-cost dummy verification to reduce username timing
            # leaks without generating a new bcrypt salt on every failed login.
            bcrypt.checkpw(password.encode("utf-8"), _DUMMY_PASSWORD_HASH)
            return False
        if not user_record.get("enabled", True):
            return False
        stored_hash = user_record["password_hash"].encode("utf-8")
        return bcrypt.checkpw(password.encode("utf-8"), stored_hash)

    def set_enabled(self, username: str, *, enabled: bool) -> None:
        """
        Enable or disable a user account without deleting it.

        Args:
            username: Login name of the user to update.
            enabled: True to enable the account, False to disable it.

        Raises:
            UserError: If the user does not exist.
        """
        users = self._get_users()
        if username not in users:
            raise UserError(f"User '{username}' does not exist.")
        users[username]["enabled"] = enabled
        if not enabled:
            users[username]["token_version"] = int(users[username].get("token_version", 0)) + 1
        self._save_users(users)

    def change_password(self, username: str, new_password: str) -> None:
        """
        Replace the password of an existing user.

        Args:
            username: Login name of the user.
            new_password: New plain-text password (minimum 8 characters).

        Raises:
            UserError: If the user does not exist or the password is too short.
        """
        if len(new_password) < 8:
            raise UserError("Password must be at least 8 characters long.")
        users = self._get_users()
        if username not in users:
            raise UserError(f"User '{username}' does not exist.")
        password_hash = bcrypt.hashpw(
            new_password.encode("utf-8"), bcrypt.gensalt()
        ).decode("utf-8")
        users[username]["password_hash"] = password_hash
        users[username]["token_version"] = int(users[username].get("token_version", 0)) + 1
        self._save_users(users)

    def list_users(self) -> list[dict]:
        """
        Return a list of user summaries (no password hashes exposed).

        Returns:
            A list of dicts with keys 'username' and 'enabled'.
        """
        return [
            {
                "username": name,
                "enabled": record.get("enabled", True),
                "home_path": record.get("home_path"),
            }
            for name, record in self._get_users().items()
        ]

    def get_home_path(self, username: str) -> Optional[str]:
        """Return a user's configured home path, or None if not set."""
        users = self._get_users()
        return users.get(username, {}).get("home_path")

    def generate_temporary_password(self, username: str) -> str:
        """
        Generate a cryptographically random password and assign it to the user.

        Useful for password resets. The caller is responsible for transmitting
        this password securely to the user.

        Args:
            username: Login name of the user.

        Returns:
            The newly generated plain-text password.

        Raises:
            UserError: If the user does not exist.
        """
        temporary_password = secrets.token_urlsafe(16)
        self.change_password(username, temporary_password)
        return temporary_password

    def is_admin(self, username: str) -> bool:
        """
        Return True if *username* holds the admin role.

        Args:
            username: Login name to check.
        """
        users = self._get_users()
        return users.get(username, {}).get("admin", False)

    def set_admin(self, username: str, *, admin: bool) -> None:
        """
        Grant or revoke the admin role for a user.

        Args:
            username: Login name of the user.
            admin: True to grant admin, False to revoke.

        Raises:
            UserError: If the user does not exist.
        """
        users = self._get_users()
        if username not in users:
            raise UserError(f"User '{username}' does not exist.")
        has_existing_admin = any(record.get("admin", False) for record in users.values())
        if admin and has_existing_admin and not users[username].get("totp_enabled", False):
            raise UserError(
                f"User '{username}' must enable TOTP (A2F) before admin role can be granted."
            )
        users[username]["admin"] = admin
        users[username]["token_version"] = int(users[username].get("token_version", 0)) + 1
        self._save_users(users)
