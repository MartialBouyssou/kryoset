import base64
import io
import secrets
from typing import Optional

import pyotp
import qrcode


class TOTPError(Exception):
    """Raised when a TOTP operation fails."""


class TOTPManager:
    """
    Manages TOTP (Time-based One-Time Password) secrets for users.

    Secrets are stored as base32 strings inside the user record in the
    configuration file. This class is stateless — it reads and writes
    through the :class:`UserManager` it is given.

    Args:
        user_manager: A loaded :class:`UserManager` instance.
        issuer_name: Application name shown in the authenticator app.
    """

    ISSUER_NAME = "Kryoset"

    def __init__(self, user_manager, issuer_name: str = ISSUER_NAME) -> None:
        self._user_manager = user_manager
        self._issuer_name = issuer_name

    def generate_secret(self, username: str) -> str:
        """
        Generate a new TOTP secret for *username* and store it (unconfirmed).

        The secret is stored but TOTP is not yet enforced until the user
        confirms it with :meth:`confirm_setup`. This prevents locking out a
        user who started but did not finish the setup.

        Args:
            username: Login name of the user.

        Returns:
            The plain-text base32 secret to display to the user.

        Raises:
            TOTPError: If the user does not exist.
        """
        from kryoset.core.user_manager import UserError
        users = self._user_manager._get_users()
        if username not in users:
            raise TOTPError(f"User '{username}' does not exist.")

        secret = pyotp.random_base32()
        users[username]["totp_secret_pending"] = secret
        users[username].pop("totp_secret", None)
        users[username]["totp_enabled"] = False
        self._user_manager._save_users(users)
        return secret

    def get_provisioning_uri(self, username: str) -> str:
        """
        Return the otpauth:// URI for QR code generation.

        This URI encodes the pending (unconfirmed) secret and can be
        scanned directly by Google Authenticator, Authy, etc.

        Args:
            username: Login name of the user.

        Returns:
            otpauth:// URI string.

        Raises:
            TOTPError: If no pending secret exists for the user.
        """
        users = self._user_manager._get_users()
        user = users.get(username, {})
        secret = user.get("totp_secret_pending") or user.get("totp_secret")
        if not secret:
            raise TOTPError(
                f"No TOTP secret found for '{username}'. "
                "Run 'kryoset user totp setup' first."
            )
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(name=username, issuer_name=self._issuer_name)

    def get_qr_code_png(self, username: str) -> bytes:
        """
        Generate a QR code PNG for the user's provisioning URI.

        Args:
            username: Login name of the user.

        Returns:
            Raw PNG bytes of the QR code image.
        """
        uri = self.get_provisioning_uri(username)
        image = qrcode.make(uri)
        buffer = io.BytesIO()
        image.save(buffer, format="PNG")
        return buffer.getvalue()

    def confirm_setup(self, username: str, code: str) -> None:
        """
        Validate *code* against the pending secret and activate TOTP.

        The pending secret becomes the active secret only if the code is valid.

        Args:
            username: Login name of the user.
            code: 6-digit TOTP code from the authenticator app.

        Raises:
            TOTPError: If the code is invalid or no pending secret exists.
        """
        users = self._user_manager._get_users()
        user = users.get(username, {})
        pending_secret = user.get("totp_secret_pending")
        if not pending_secret:
            raise TOTPError(
                f"No pending TOTP setup found for '{username}'. "
                "Run 'kryoset user totp setup' first."
            )

        totp = pyotp.TOTP(pending_secret)
        if not totp.verify(code, valid_window=1):
            raise TOTPError("Invalid TOTP code. Please try again.")

        users[username]["totp_secret"] = pending_secret
        del users[username]["totp_secret_pending"]
        users[username]["totp_enabled"] = True
        self._user_manager._save_users(users)

    def verify(self, username: str, code: str) -> bool:
        """
        Verify a TOTP code for *username* during authentication.

        Args:
            username: Login name of the user.
            code: 6-digit TOTP code from the authenticator app.

        Returns:
            True if the code is valid, False otherwise.
        """
        users = self._user_manager._get_users()
        user = users.get(username, {})
        if not user.get("totp_enabled", False):
            return True
        secret = user.get("totp_secret")
        if not secret:
            return True
        totp = pyotp.TOTP(secret)
        return totp.verify(code, valid_window=1)

    def is_enabled(self, username: str) -> bool:
        """
        Return True if TOTP is active for *username*.

        Args:
            username: Login name of the user.
        """
        users = self._user_manager._get_users()
        return users.get(username, {}).get("totp_enabled", False)

    def disable(self, username: str) -> None:
        """
        Disable TOTP for *username* and remove the stored secret.

        Args:
            username: Login name of the user.

        Raises:
            TOTPError: If the user does not exist.
        """
        from kryoset.core.user_manager import UserError
        users = self._user_manager._get_users()
        if username not in users:
            raise TOTPError(f"User '{username}' does not exist.")
        users[username].pop("totp_secret", None)
        users[username].pop("totp_secret_pending", None)
        users[username]["totp_enabled"] = False
        self._user_manager._save_users(users)
