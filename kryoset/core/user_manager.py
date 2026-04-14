import secrets

import bcrypt

from kryoset.core.configuration import Configuration


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
        return dict(self._configuration.users)

    def _save_users(self, users: dict) -> None:
        self._configuration.set_users(users)

    def add_user(self, username: str, password: str) -> None:
        """
        Create a new user with a bcrypt-hashed password.

        Args:
            username: Unique login name (letters, digits, underscores only).
            password: Plain-text password (minimum 8 characters).

        Raises:
            UserError: If the username already exists, is invalid, or the
                password is too short.
        """
        if not username or not username.replace("_", "").isalnum():
            raise UserError(
                f"Invalid username '{username}'. "
                "Use only letters, digits and underscores."
            )
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
        }
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
            # Perform a dummy hash to prevent timing attacks.
            bcrypt.checkpw(b"dummy", bcrypt.hashpw(b"dummy", bcrypt.gensalt()))
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
        self._save_users(users)

    def list_users(self) -> list[dict]:
        """
        Return a list of user summaries (no password hashes exposed).

        Returns:
            A list of dicts with keys 'username' and 'enabled'.
        """
        return [
            {"username": name, "enabled": record.get("enabled", True)}
            for name, record in self._get_users().items()
        ]

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
        users[username]["admin"] = admin
        self._save_users(users)
