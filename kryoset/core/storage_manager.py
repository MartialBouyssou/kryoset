import os
import shutil
from pathlib import Path
from typing import Any, Optional

from kryoset.core.configuration import Configuration


class StorageError(Exception):
    """Raised when a storage quota operation fails."""


class StorageManager:
    """
    Manages the global NAS storage budget and per-entity allocation.

    The global budget caps how much disk space Kryoset is allowed to use
    in total.  Individual users and groups can be allocated slices of that
    budget, but the sum of allocations may never exceed the global maximum.

    Storage resolution follows the same override chain as permissions:
    - A user-specific allocation always wins over any group allocation.
    - If a user has no individual allocation, their effective quota is the
      *minimum* of all their group allocations (most restrictive wins).
    - Admins are always exempt from quota checks.

    Allocations are stored in ``config.json`` under two keys::

        "storage_max_bytes": 107374182400,   # global NAS budget
        "storage_allocations": {
            "user:alice": 10737418240,
            "group:editors": 5368709120
        }

    Args:
        configuration: A loaded :class:`Configuration` instance.
        user_manager: The active :class:`UserManager`.
        permission_store: The active :class:`PermissionStore` (for group
            membership lookups).
    """

    def __init__(self, configuration: Configuration, user_manager, permission_store=None) -> None:
        self._configuration = configuration
        self._user_manager = user_manager
        self._permission_store = permission_store

    @staticmethod
    def _format_bytes(b: int) -> str:
        """Convert bytes to human-readable format (B, KB, MB, GB, TB)."""
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if b < 1024 or unit == "TB":
                return f"{int(b)} {unit}" if unit == "B" else f"{b:.1f} {unit}"
            b /= 1024
        return f"{b:.1f} TB"


    def _get_raw(self) -> dict[str, Any]:
        return dict(self._configuration._data)

    def _save_field(self, key: str, value: Any) -> None:
        self._configuration._data[key] = value
        self._configuration.save()

    def _allocations(self) -> dict[str, int]:
        return dict(self._configuration._data.get("storage_allocations", {}))

    def _save_allocations(self, alloc: dict[str, int]) -> None:
        self._save_field("storage_allocations", alloc)


    def get_global_max(self) -> Optional[int]:
        """Return the global NAS storage budget in bytes, or None if unlimited."""
        return self._configuration._data.get("storage_max_bytes")

    def set_global_max(self, max_bytes: Optional[int]) -> None:
        """
        Set the global NAS storage budget.

        The value must not be less than the space already used by Kryoset,
        and the sum of all existing allocations must not exceed the new budget.

        Args:
            max_bytes: Maximum bytes Kryoset may use in total, or None to remove the limit.

        Raises:
            StorageError: If the budget would be smaller than current usage or
                          smaller than the sum of existing allocations.
        """
        if max_bytes is not None:
            if max_bytes < 0:
                raise StorageError("Storage budget must be a positive number of bytes.")
            used = self.get_used_bytes()
            if max_bytes < used:
                raise StorageError(
                    f"Budget {max_bytes:,} B is smaller than current usage {used:,} B."
                )
            alloc_total = sum(self._allocations().values())
            if max_bytes < alloc_total:
                raise StorageError(
                    f"Budget {max_bytes:,} B is smaller than the sum of existing allocations "
                    f"({alloc_total:,} B). Reduce allocations first."
                )
        if max_bytes is None:
            self._configuration._data.pop("storage_max_bytes", None)
            self._configuration.save()
        else:
            self._save_field("storage_max_bytes", max_bytes)

    def get_used_bytes(self) -> int:
        """Return the total bytes currently stored under the storage root."""
        storage_root = self._configuration.storage_path
        if not storage_root.exists():
            return 0
        total = 0
        for dirpath, _, filenames in os.walk(storage_root):
            for filename in filenames:
                try:
                    total += os.path.getsize(os.path.join(dirpath, filename))
                except OSError:
                    pass
        return total

    def get_free_bytes(self) -> Optional[int]:
        """
        Return how many bytes are still available within the global budget.

        Returns None if no global budget is configured.
        """
        global_max = self.get_global_max()
        if global_max is None:
            return None
        return max(0, global_max - self.get_used_bytes())

    def get_allocated_bytes(self) -> int:
        """Return the sum of all individual allocations (users + groups)."""
        return sum(self._allocations().values())

    def get_unallocated_bytes(self) -> Optional[int]:
        """
        Return the bytes in the global budget not yet assigned to anyone.

        Returns None if no global budget is configured.
        """
        global_max = self.get_global_max()
        if global_max is None:
            return None
        return max(0, global_max - self.get_allocated_bytes())

    def validate_on_startup(self) -> list[str]:
        """
        Check storage constraints and return a list of warning messages.

        Called at server startup. Does not raise — issues are returned as
        strings so the caller can log or display them.
        """
        warnings = []
        global_max = self.get_global_max()
        if global_max is None:
            return warnings

        disk = shutil.disk_usage(self._configuration.storage_path)
        if global_max > disk.total:
            warnings.append(
                f"Global storage budget ({global_max:,} B) exceeds disk size "
                f"({disk.total:,} B). Capping to disk size."
            )
            self._save_field("storage_max_bytes", disk.total)
            global_max = disk.total

        used = self.get_used_bytes()
        if used > global_max:
            warnings.append(
                f"Current usage ({used:,} B) exceeds global budget ({global_max:,} B). "
                "The budget has been updated to match actual usage."
            )
            self._save_field("storage_max_bytes", used)

        return warnings


    def set_allocation(self, entity_key: str, bytes_allocated: Optional[int]) -> None:
        """
        Set the storage allocation for a user or group.

        The allocation must not cause the total assigned bytes to exceed the
        global budget.

        Args:
            entity_key: ``"user:<name>"`` or ``"group:<name>"``.
            bytes_allocated: Bytes to assign, or None to remove the allocation.

        Raises:
            StorageError: If the allocation would exceed the global budget.
        """
        alloc = self._allocations()
        old_value = alloc.get(entity_key, 0)

        if bytes_allocated is None:
            alloc.pop(entity_key, None)
        else:
            if bytes_allocated < 0:
                raise StorageError("Allocation must be a positive number of bytes.")
            global_max = self.get_global_max()
            if global_max is not None:
                new_total = sum(alloc.values()) - old_value + bytes_allocated
                if new_total > global_max:
                    remaining = max(0, global_max - (sum(alloc.values()) - old_value))
                    raise StorageError(
                        f"Allocation of {bytes_allocated:,} B would exceed the global budget. "
                        f"At most {remaining:,} B can be allocated."
                    )
            alloc[entity_key] = bytes_allocated

        self._save_allocations(alloc)

    def get_allocation(self, entity_key: str) -> Optional[int]:
        """Return the allocation for a user or group key, or None."""
        return self._allocations().get(entity_key)

    def list_allocations(self) -> dict[str, int]:
        """Return all entity allocations."""
        return self._allocations()


    def get_effective_quota(self, username: str) -> Optional[int]:
        """
        Compute the effective storage quota for a user.

        Resolution:
        1. If the user has an individual allocation → use it.
        2. Otherwise take the minimum of all their group allocations.
        3. If no allocation exists → return None (unlimited within global budget).

        Admins always return None (unlimited).

        Args:
            username: The username to resolve.

        Returns:
            Bytes, or None for unlimited.
        """
        if self._user_manager.is_admin(username):
            return None

        alloc = self._allocations()
        user_key = f"user:{username}"
        if user_key in alloc:
            return alloc[user_key]

        if self._permission_store is None:
            return None

        groups = self._permission_store.get_user_groups(username)
        group_allocs = [alloc[f"group:{g}"] for g in groups if f"group:{g}" in alloc]
        if group_allocs:
            return min(group_allocs)

        return None

    def check_upload_allowed(
        self,
        username: str,
        additional_bytes: int,
        current_user_used_bytes: Optional[int] = None,
    ) -> None:
        """
        Raise :class:`StorageError` if uploading *additional_bytes* would
        exceed the user's effective quota or the global budget.

        Args:
            username: The authenticated username.
            additional_bytes: Size of the file being uploaded.
            current_user_used_bytes: Optional precomputed usage for the user
                home directory. When provided, avoids a filesystem rescan.

        Raises:
            StorageError: If the upload would exceed any limit.
        """
        if self._user_manager.is_admin(username):
            return

        global_max = self.get_global_max()
        if global_max is not None:
            used = self.get_used_bytes()
            if used + additional_bytes > global_max:
                raise StorageError(
                    f"Upload refused: global NAS storage is full. "
                    f"Used {self._format_bytes(used)} / {self._format_bytes(global_max)}."
                )

        quota = self.get_effective_quota(username)
        if quota is not None:
            user_home = None
            if hasattr(self._user_manager, "get_home_path"):
                user_home = self._user_manager.get_home_path(username)
            if user_home is not None:
                from kryoset.core.home_paths import normalize_home_path
                user_dir = self._configuration.storage_path / normalize_home_path(user_home).lstrip("/")
            else:
                user_dir = self._configuration.storage_path / username

            if current_user_used_bytes is not None:
                user_used = max(0, int(current_user_used_bytes))
            else:
                user_used = 0
                if user_dir.exists():
                    for dirpath, _, filenames in os.walk(user_dir):
                        for filename in filenames:
                            try:
                                user_used += os.path.getsize(os.path.join(dirpath, filename))
                            except OSError:
                                pass
            if user_used + additional_bytes > quota:
                remaining = max(0, quota - user_used)
                raise StorageError(
                    f"Upload refused: quota exceeded for '{username}'. "
                    f"Used {self._format_bytes(user_used)} / {self._format_bytes(quota)} "
                    f"({self._format_bytes(remaining)} remaining)."
                )

    def summary(self) -> dict:
        """Return a dict suitable for the /storage/status API endpoint."""
        global_max = self.get_global_max()
        used = self.get_used_bytes()
        disk = shutil.disk_usage(self._configuration.storage_path)
        return {
            "global_max_bytes": global_max,
            "used_bytes": used,
            "free_bytes": max(0, global_max - used) if global_max is not None else disk.free,
            "disk_total_bytes": disk.total,
            "disk_free_bytes": disk.free,
            "allocated_bytes": self.get_allocated_bytes(),
            "unallocated_bytes": self.get_unallocated_bytes(),
        }
