from pathlib import Path
from typing import Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError

from kryoset.api.auth import decode_token
from kryoset.core.home_paths import is_within_home, resolve_user_home_roots
from kryoset.core.permissions import Permission, PRESET_OWNER

_bearer = HTTPBearer(auto_error=False)


def _resolve_token(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_bearer),
) -> dict:
    """
    Extract and decode the Bearer token from the Authorization header.

    Raises:
        HTTPException 401: If the token is missing or invalid.
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authorization token.",
        )
    try:
        payload = decode_token(credentials.credentials)
    except JWTError as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(error),
        )
    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Expected an access token.",
        )
    return payload


def get_current_user(payload: dict = Depends(_resolve_token)) -> dict:
    """
    FastAPI dependency that returns the current authenticated user payload.

    Returns:
        Dictionary with keys 'sub' (username) and 'admin' (bool).
    """
    return payload


def require_admin(payload: dict = Depends(_resolve_token)) -> dict:
    """
    FastAPI dependency that enforces admin-only access.

    Raises:
        HTTPException 403: If the token does not carry admin privileges.
    """
    if not payload.get("admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required.",
        )
    return payload


def _resolve_storage_path(request: Request, path: str) -> Path:
    """
    Resolve a user-supplied relative path against the storage root.

    Raises:
        HTTPException 400: If the path is absolute.
        HTTPException 403: If the resolved path escapes the storage root (traversal).
    """
    if Path(path).is_absolute():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Path must be relative.",
        )
    storage_root: Path = request.app.state.configuration.storage_path
    try:
        resolved = (storage_root / path).resolve()
        resolved.relative_to(storage_root.resolve())
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Path traversal detected.",
        )
    return resolved


def check_path_permission(
    request: Request,
    path: str,
    required: Permission,
    username: str,
) -> None:
    """
    Verify that *username* holds *required* permission on *path*.

    Admin users always pass. Other users are checked against the permission
    store and receive HTTP 403 if the check fails.

    Args:
        request: The current FastAPI request (used to access app.state).
        path: Relative storage path to check.
        required: Permission flag(s) that must be present.
        username: The authenticated username.

    Raises:
        HTTPException 403: If the user lacks the required permission.
    """
    user_manager = request.app.state.user_manager
    if user_manager.is_admin(username):
        return

    normalized_path = "/" + path.strip("/")
    permission_store = request.app.state.permission_store
    home_roots = resolve_user_home_roots(username, user_manager, permission_store)
    if home_roots:
        if any(is_within_home(normalized_path, root) for root in home_roots):
            return
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Access denied for user '{username}' on '{normalized_path}'. "
                f"Outside configured home path(s): {', '.join(home_roots)}."
            ),
        )

    if permission_store is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission store not configured.",
        )

    effective, _ = permission_store.resolve_permissions(username, normalized_path)
    if not (effective & required):
        required_names = required.to_names() or ["NONE"]
        effective_names = effective.to_names() or ["NONE"]
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Access denied for user '{username}' on '{normalized_path}'. "
                f"Required permission: {', '.join(required_names)}. "
                f"Effective permissions: {', '.join(effective_names)}."
            ),
        )
