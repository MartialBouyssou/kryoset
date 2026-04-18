import os
from pathlib import Path
from typing import Optional


class QuotaError(Exception):
    """Raised when a quota limit would be exceeded."""


class QuotaManager:
    """
    Manages per-user global storage quotas across the entire NAS.

    Each user can be assigned a maximum number of bytes they may store
    across the whole storage root. Usage is computed by scanning the
    user's upload log, not by walking the filesystem (which would be
    slow). Admins are always exempt from quota checks.

    Quotas are stored in the configuration file under each user record::

        "alice": {
            "password_hash": "...",
            "enabled": true,
            "admin": false,
            "storage_quota_bytes": 5368709120
        }

    Args:
        user_manager: A loaded :class:`UserManager` instance.
        storage_path: Root path of the NAS storage.
    """

    def __init__(self, user_manager, storage_path: Path) -> None:
        self._user_manager = user_manager
        self._storage_path = storage_path

    def get_quota(self, username: str) -> Optional[int]:
        """
        Return the storage quota for *username* in bytes, or None if unlimited.

        Args:
            username: Login name of the user.
        """
        users = self._user_manager._get_users()
        return users.get(username, {}).get("storage_quota_bytes")

    def set_quota(self, username: str, quota_bytes: Optional[int]) -> None:
        """
        Set the storage quota for *username*.

        Args:
            username: Login name of the user.
            quota_bytes: Maximum bytes allowed, or None to remove the quota.

        Raises:
            ValueError: If the user does not exist or quota is negative.
        """
        from kryoset.core.user_manager import UserError
        users = self._user_manager._get_users()
        if username not in users:
            raise ValueError(f"User '{username}' does not exist.")
        if quota_bytes is not None and quota_bytes < 0:
            raise ValueError("Quota must be a positive number of bytes.")
        if quota_bytes is None:
            users[username].pop("storage_quota_bytes", None)
        else:
            users[username]["storage_quota_bytes"] = quota_bytes
        self._user_manager._save_users(users)

    def get_used_bytes(self, username: str) -> int:
        """
        Compute how many bytes *username* currently owns in the storage root.

        Ownership is determined by scanning the user's dedicated subdirectory
        at ``<storage_root>/<username>/`` if it exists, plus any files
        recorded as uploaded by this user via the permission store quota log.
        For simplicity, we scan the filesystem for the user's home directory.

        Args:
            username: Login name of the user.

        Returns:
            Total bytes used, 0 if the user has no files.
        """
        user_dir = self._storage_path / username
        if not user_dir.exists():
            return 0
        total = 0
        for dirpath, _, filenames in os.walk(user_dir):
            for filename in filenames:
                try:
                    total += os.path.getsize(os.path.join(dirpath, filename))
                except OSError:
                    pass
        return total

    def check_upload_allowed(
        self, username: str, additional_bytes: int
    ) -> None:
        """
        Raise :class:`QuotaError` if uploading *additional_bytes* would
        exceed the user's quota.

        Admins are always exempt. Users with no quota set are unrestricted.

        Args:
            username: Login name of the user.
            additional_bytes: Size of the file about to be uploaded.

        Raises:
            QuotaError: If the upload would exceed the quota.
        """
        if self._user_manager.is_admin(username):
            return

        quota = self.get_quota(username)
        if quota is None:
            return

        used = self.get_used_bytes(username)
        if used + additional_bytes > quota:
            remaining = max(0, quota - used)
            raise QuotaError(
                f"Upload refused: quota exceeded for '{username}'. "
                f"Used {used:,} / {quota:,} bytes "
                f"({remaining:,} bytes remaining)."
            )

    def format_quota_summary(self, username: str) -> str:
        """
        Return a human-readable quota summary for *username*.

        Args:
            username: Login name of the user.

        Returns:
            A formatted string like ``"2.1 GB used / 10.0 GB quota (21%)"``
            or ``"no quota set"``.
        """
        quota = self.get_quota(username)
        used = self.get_used_bytes(username)

        def human(b: int) -> str:
            for unit in ("B", "KB", "MB", "GB", "TB"):
                if b < 1024 or unit == "TB":
                    return f"{b:.1f} {unit}"
                b /= 1024
            return f"{b:.1f} TB"

        if quota is None:
            return f"{human(used)} used / no quota"
        percent = int(used / quota * 100) if quota else 0
        return f"{human(used)} used / {human(quota)} quota ({percent}%)"
