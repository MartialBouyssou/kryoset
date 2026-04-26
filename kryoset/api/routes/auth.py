import gzip
import re
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from pydantic import BaseModel

from kryoset.api.auth import (
    create_access_token,
    create_refresh_token,
    decode_token,
    revoke_token,
)
from kryoset.api.dependencies import get_current_user
from kryoset.core.audit_logger import LOG_DIRECTORY
from kryoset.core.home_paths import resolve_user_home_roots

router = APIRouter(prefix="/auth", tags=["auth"])

_bearer = HTTPBearer(auto_error=False)

_pending_totp: dict[str, str] = {}
_AUDIT_LINE_RE = re.compile(r"^\[(?P<timestamp>[^\]]+)\]\s+\[(?P<event>[^\]]+)\]\s+(?P<details>.*)$")


class LoginRequest(BaseModel):
    username: str
    password: str


class TOTPRequest(BaseModel):
    username: str
    code: str


class RefreshRequest(BaseModel):
    refresh_token: str


class ChangePasswordRequest(BaseModel):
    new_password: str


def _parse_audit_details(details: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for token in details.split():
        if "=" not in token:
            continue
        key, value = token.split("=", 1)
        fields[key] = value
    return fields


def _read_audit_lines(path):
    if path.suffix == ".gz":
        with gzip.open(path, "rt", encoding="utf-8") as handle:
            return handle.read().splitlines()
    return path.read_text(encoding="utf-8").splitlines()


def _collect_auth_activity(log_directory: Path, username: str, limit: int = 5) -> tuple[list[dict], list[dict]]:
    recent_logins: list[dict] = []
    recent_failures: list[dict] = []

    if not log_directory.exists():
        return recent_logins, recent_failures

    audit_paths = sorted(
        log_directory.glob("kryoset.log*"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )

    for path in audit_paths:
        try:
            lines = _read_audit_lines(path)
        except OSError:
            continue

        for line in reversed(lines):
            match = _AUDIT_LINE_RE.match(line)
            if not match:
                continue
            event = match.group("event").strip()
            if event not in {"AUTH_SUCCESS", "AUTH_FAILURE", "TOTP_SUCCESS", "TOTP_FAILURE"}:
                continue

            details = _parse_audit_details(match.group("details"))
            if details.get("user") != username:
                continue

            entry = {
                "timestamp": match.group("timestamp"),
                "event": event,
                "ip": details.get("ip", "unknown"),
            }

            if event in {"AUTH_SUCCESS", "TOTP_SUCCESS"}:
                if len(recent_logins) < limit:
                    recent_logins.append(entry)
            else:
                if len(recent_failures) < limit:
                    recent_failures.append(entry)

            if len(recent_logins) >= limit and len(recent_failures) >= limit:
                return recent_logins, recent_failures

    return recent_logins, recent_failures


@router.post("/login")
def login(body: LoginRequest, request: Request) -> dict:
    """
    Authenticate with username and password.

    If TOTP is enabled for the account the response contains a 'totp_required'
    flag and the caller must complete the flow via POST /auth/totp.  Otherwise
    a full token pair is returned immediately.
    """
    user_manager = request.app.state.user_manager
    audit = request.app.state.audit_logger
    client_ip = request.client.host if request.client else "unknown"

    if not user_manager.authenticate(body.username, body.password):
        if audit:
            audit.log_auth_failure(body.username, client_ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials.",
        )

    if audit:
        audit.log_auth_success(body.username, client_ip)

    totp_manager = request.app.state.totp_manager
    if totp_manager and totp_manager.is_enabled(body.username):
        _pending_totp[body.username] = body.password
        return {"totp_required": True, "username": body.username}

    is_admin = user_manager.is_admin(body.username)
    return {
        "access_token": create_access_token(body.username, is_admin),
        "refresh_token": create_refresh_token(body.username),
        "token_type": "bearer",
    }


@router.post("/totp")
def totp_verify(body: TOTPRequest, request: Request) -> dict:
    """
    Complete the two-step TOTP authentication flow.

    The username must have successfully passed the password step (POST /auth/login)
    before this endpoint can be called.
    """
    user_manager = request.app.state.user_manager
    totp_manager = request.app.state.totp_manager
    audit = request.app.state.audit_logger
    client_ip = request.client.host if request.client else "unknown"

    if body.username not in _pending_totp:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No pending TOTP session for this user.",
        )

    if totp_manager is None or not totp_manager.verify(body.username, body.code):
        if audit:
            audit.log_totp_failure(body.username, client_ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid TOTP code.",
        )

    _pending_totp.pop(body.username, None)
    if audit:
        audit.log_totp_success(body.username, client_ip)

    is_admin = user_manager.is_admin(body.username)
    return {
        "access_token": create_access_token(body.username, is_admin),
        "refresh_token": create_refresh_token(body.username),
        "token_type": "bearer",
    }


@router.post("/refresh")
def refresh(body: RefreshRequest, request: Request) -> dict:
    """
    Exchange a refresh token for a new access token.

    The refresh token must be valid and not revoked.
    """
    try:
        payload = decode_token(body.refresh_token)
    except JWTError as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(error),
        )
    if payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Expected a refresh token.",
        )
    username = payload["sub"]
    user_manager = request.app.state.user_manager
    is_admin = user_manager.is_admin(username)
    return {
        "access_token": create_access_token(username, is_admin),
        "token_type": "bearer",
    }


@router.post("/logout")
def logout(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
) -> dict:
    """
    Revoke the current access token immediately.
    """
    if credentials:
        revoke_token(credentials.credentials)
    return {"detail": "Logged out."}


@router.get("/me")
def me(request: Request, payload: dict = Depends(get_current_user)) -> dict:
    """
    Return information about the currently authenticated user.
    """
    username = payload["sub"]
    user_manager = request.app.state.user_manager
    permission_store = request.app.state.permission_store
    quota_manager = request.app.state.quota_manager
    storage_manager = request.app.state.storage_manager
    totp_manager = request.app.state.totp_manager
    audit_logger = request.app.state.audit_logger
    log_directory = getattr(audit_logger, "_log_directory", LOG_DIRECTORY) if audit_logger else LOG_DIRECTORY
    recent_logins, recent_failures = _collect_auth_activity(log_directory, username)
    home_roots = resolve_user_home_roots(username, user_manager, permission_store)
    initial_path = home_roots[0] if home_roots else "/"

    # Use effective quota (from storage_allocations) if available, otherwise per-user quota
    quota_bytes = None
    if storage_manager:
        quota_bytes = storage_manager.get_effective_quota(username)
    elif quota_manager:
        quota_bytes = quota_manager.get_quota(username)

    return {
        "username": username,
        "admin": payload.get("admin", False),
        "totp_enabled": totp_manager.is_enabled(username) if totp_manager else False,
        "initial_path": initial_path,
        "quota_bytes": quota_bytes,
        "used_bytes": quota_manager.get_used_bytes(username, home_path=initial_path) if quota_manager else None,
        "recent_logins": recent_logins,
        "recent_failures": recent_failures,
    }


@router.get("/quota")
def get_quota(request: Request, payload: dict = Depends(get_current_user)) -> dict:
    """
    Return current quota info for the authenticated user (for live updates).
    """
    username = payload["sub"]
    user_manager = request.app.state.user_manager
    permission_store = request.app.state.permission_store
    quota_manager = request.app.state.quota_manager
    storage_manager = request.app.state.storage_manager
    
    home_roots = resolve_user_home_roots(username, user_manager, permission_store)
    initial_path = home_roots[0] if home_roots else "/"

    # Use effective quota (from storage_allocations) if available, otherwise per-user quota
    quota_bytes = None
    if storage_manager:
        quota_bytes = storage_manager.get_effective_quota(username)
    elif quota_manager:
        quota_bytes = quota_manager.get_quota(username)

    # Calculate used bytes from the user's actual home directory
    used_bytes = None
    if quota_manager:
        used_bytes = quota_manager.get_used_bytes(username, home_path=initial_path)

    return {
        "quota_bytes": quota_bytes,
        "used_bytes": used_bytes,
    }
