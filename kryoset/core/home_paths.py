from __future__ import annotations

from typing import Optional


def normalize_home_path(path: str) -> str:
    """Normalize a configured home path to an absolute POSIX-like path."""
    stripped = path.strip()
    if not stripped:
        raise ValueError("Home path cannot be empty.")
    if not stripped.startswith("/"):
        stripped = "/" + stripped
    parts = [p for p in stripped.split("/") if p and p != "."]
    return "/" + "/".join(parts) if parts else "/"


def normalize_virtual_path(path: str) -> str:
    """Normalize a user-requested path to an absolute virtual path."""
    stripped = path.strip()
    if not stripped:
        return "/"
    if not stripped.startswith("/"):
        stripped = "/" + stripped
    parts = [p for p in stripped.split("/") if p and p != "."]
    return "/" + "/".join(parts) if parts else "/"


def is_within_home(path: str, home_root: str) -> bool:
    """Return True if *path* is equal to or nested under *home_root*."""
    normalized_path = normalize_virtual_path(path)
    normalized_home = normalize_home_path(home_root)
    return (
        normalized_path == normalized_home
        or normalized_path.startswith(normalized_home.rstrip("/") + "/")
    )


def resolve_user_home_roots(username: str, user_manager, permission_store) -> list[str]:
    """
    Return effective home roots for a user.

    Resolution order:
    1. Explicit user home path (if set) wins and is exclusive.
    2. Otherwise, derive roots from all groups with home settings.
    3. If none, return an empty list (no home restriction).
    """
    user_home = None
    if hasattr(user_manager, "get_home_path"):
        user_home = user_manager.get_home_path(username)
    if user_home:
        return [normalize_home_path(user_home)]

    if permission_store is None or not hasattr(permission_store, "get_user_group_home_paths"):
        return []

    homes = permission_store.get_user_group_home_paths(username)
    unique: list[str] = []
    for home in homes:
        normalized = normalize_home_path(home)
        if normalized not in unique:
            unique.append(normalized)
    return unique
