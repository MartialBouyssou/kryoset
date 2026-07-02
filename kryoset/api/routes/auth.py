import gzip
import os
import re
import secrets
from datetime import timedelta
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import InvalidTokenError as JWTError
from pydantic import BaseModel

from kryoset.api.auth import (
    ACCESS_TOKEN_EXPIRE_MINUTES,
    REFRESH_TOKEN_EXPIRE_DAYS,
    create_access_token,
    create_refresh_token,
    decode_token,
    revoke_token,
)
from kryoset.api.dependencies import get_current_user
from kryoset.api.rate_limit import RateLimitExceeded, login_limiter, totp_limiter
from kryoset.core.audit_logger import LOG_DIRECTORY
from kryoset.core.home_paths import resolve_user_home_roots
from kryoset.core.timezone import now_utc

router = APIRouter(prefix="/auth", tags=["auth"])

_bearer = HTTPBearer(auto_error=False)

_pending_totp: dict[str, dict] = {}
_TOTP_PENDING_TTL_MINUTES = 5
_AUDIT_LINE_RE = re.compile(r"^\[(?P<timestamp>[^\]]+)\]\s+\[(?P<event>[^\]]+)\]\s+(?P<details>.*)$")

ACCESS_COOKIE_NAME = "kryoset_access"
REFRESH_COOKIE_NAME = "kryoset_refresh"
CSRF_COOKIE_NAME = "kryoset_csrf"
CSRF_HEADER_NAME = "X-Kryoset-CSRF"
COOKIE_SECURE = os.getenv("KRYOSET_COOKIE_SECURE", "0").strip().lower() in {"1", "true", "yes", "on"}
COOKIE_SAMESITE = os.getenv("KRYOSET_COOKIE_SAMESITE", "strict").strip().lower()
if COOKIE_SAMESITE not in {"strict", "lax", "none"}:
    COOKIE_SAMESITE = "strict"


def _set_auth_cookies(response: Response, access_token: str, refresh_token: str) -> str:
    csrf_token = secrets.token_urlsafe(32)
    cookie_common = {
        "httponly": True,
        "secure": COOKIE_SECURE,
        "samesite": COOKIE_SAMESITE,
        "path": "/",
    }
    response.set_cookie(
        ACCESS_COOKIE_NAME,
        access_token,
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        **cookie_common,
    )
    response.set_cookie(
        REFRESH_COOKIE_NAME,
        refresh_token,
        max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
        **cookie_common,
    )
    response.set_cookie(
        CSRF_COOKIE_NAME,
        csrf_token,
        max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
        httponly=False,
        secure=COOKIE_SECURE,
        samesite=COOKIE_SAMESITE,
        path="/",
    )
    return csrf_token


def _clear_auth_cookies(response: Response) -> None:
    for name in (ACCESS_COOKIE_NAME, REFRESH_COOKIE_NAME, CSRF_COOKIE_NAME):
        response.delete_cookie(name, path="/", secure=COOKIE_SECURE, samesite=COOKIE_SAMESITE)



class LoginRequest(BaseModel):
    username: str
    password: str


class TOTPRequest(BaseModel):
    username: str
    code: str
    totp_token: str


class RefreshRequest(BaseModel):
    refresh_token: str | None = None


class LogoutRequest(BaseModel):
    refresh_token: str | None = None


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


def _read_audit_tail_lines(path: Path, *, max_bytes: int = 512 * 1024) -> list[str]:
    # /auth/me must stay fast even when audit logs are large.  Read only a
    # bounded tail from the current/plain rotated log.  Compressed older logs
    # are intentionally skipped for this UX-only summary.
    if path.suffix == ".gz":
        return []
    try:
        size = path.stat().st_size
        with path.open("rb") as handle:
            if size > max_bytes:
                handle.seek(-max_bytes, 2)
                handle.readline()  # drop partial first line
            data = handle.read()
        return data.decode("utf-8", errors="replace").splitlines()
    except OSError:
        return []



def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _auth_key(prefix: str, username: str, client_ip: str) -> str:
    return f"{prefix}:{client_ip}:{username.lower()}"


def _rate_limit_response(error: RateLimitExceeded) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail=str(error),
        headers={"Retry-After": str(error.retry_after)},
    )


def _primary_home_path(username: str, request: Request) -> str:
    user_manager = request.app.state.user_manager
    permission_store = request.app.state.permission_store
    home_roots = resolve_user_home_roots(username, user_manager, permission_store)
    return home_roots[0] if home_roots else "/"


def _quota_payload(username: str, request: Request, *, refresh: bool = False) -> dict:
    """Return quota data without forcing an expensive filesystem scan by default."""
    quota_manager = request.app.state.quota_manager
    storage_manager = request.app.state.storage_manager

    initial_path = _primary_home_path(username, request)

    quota_bytes = None
    if storage_manager:
        quota_bytes = storage_manager.get_effective_quota(username)
    elif quota_manager:
        quota_bytes = quota_manager.get_quota(username)

    used_bytes = None
    usage_stale = True
    if quota_manager:
        if refresh:
            used_bytes = quota_manager.refresh_used_bytes(username, home_path=initial_path)
            usage_stale = False
        else:
            used_bytes = quota_manager.get_cached_used_bytes(username, home_path=initial_path)
            usage_stale = used_bytes is None

    return {
        "quota_bytes": quota_bytes,
        "used_bytes": used_bytes,
        "usage_stale": usage_stale,
        "initial_path": initial_path,
    }


def _collect_auth_activity(log_directory: Path, username: str, limit: int = 5) -> tuple[list[dict], list[dict]]:
    recent_logins: list[dict] = []
    recent_failures: list[dict] = []

    if not log_directory.exists():
        return recent_logins, recent_failures

    audit_paths = sorted(
        log_directory.glob("kryoset.log*"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    )[:3]

    for path in audit_paths:
        for line in reversed(_read_audit_tail_lines(path)):
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
def login(body: LoginRequest, request: Request, response: Response) -> dict:
    """
    Authenticate with username and password.

    If TOTP is enabled for the account the response contains a 'totp_required'
    flag and a short-lived 'totp_token'. The caller must complete the flow via
    POST /auth/totp. Passwords are never stored in the pending TOTP state.
    """
    user_manager = request.app.state.user_manager
    audit = request.app.state.audit_logger
    client_ip = _client_ip(request)
    key = _auth_key("login", body.username, client_ip)

    try:
        login_limiter.check(key)
    except RateLimitExceeded as error:
        raise _rate_limit_response(error)

    if not user_manager.authenticate(body.username, body.password):
        if audit:
            audit.log_auth_failure(body.username, client_ip)
        try:
            login_limiter.record_failure(
                key,
                limit=5,
                window_seconds=15 * 60,
                block_seconds=15 * 60,
            )
        except RateLimitExceeded as error:
            raise _rate_limit_response(error)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials.",
        )

    login_limiter.reset(key)

    if audit:
        audit.log_auth_success(body.username, client_ip)

    totp_manager = request.app.state.totp_manager
    if totp_manager and totp_manager.is_enabled(body.username):
        pending_token = secrets.token_urlsafe(32)
        _pending_totp[pending_token] = {
            "username": body.username,
            "client_ip": client_ip,
            "expires_at": now_utc() + timedelta(minutes=_TOTP_PENDING_TTL_MINUTES),
        }
        return {"totp_required": True, "username": body.username, "totp_token": pending_token}

    is_admin = user_manager.is_admin(body.username)
    token_version = user_manager.get_token_version(body.username)
    access_token = create_access_token(body.username, is_admin, token_version)
    refresh_token = create_refresh_token(body.username, token_version)
    csrf_token = _set_auth_cookies(response, access_token, refresh_token)
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "csrf_token": csrf_token,
        "token_type": "bearer",
    }


@router.post("/totp")
def totp_verify(body: TOTPRequest, request: Request, response: Response) -> dict:
    """
    Complete the two-step TOTP authentication flow.
    """
    user_manager = request.app.state.user_manager
    totp_manager = request.app.state.totp_manager
    audit = request.app.state.audit_logger
    client_ip = _client_ip(request)
    key = _auth_key("totp", body.username, client_ip)

    try:
        totp_limiter.check(key)
    except RateLimitExceeded as error:
        raise _rate_limit_response(error)

    pending = _pending_totp.get(body.totp_token)
    if (
        pending is None
        or pending.get("username") != body.username
        or pending.get("client_ip") != client_ip
        or pending.get("expires_at") < now_utc()
    ):
        _pending_totp.pop(body.totp_token, None)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No valid pending TOTP session for this user.",
        )

    if totp_manager is None or not totp_manager.verify(body.username, body.code):
        if audit:
            audit.log_totp_failure(body.username, client_ip)
        try:
            totp_limiter.record_failure(
                key,
                limit=5,
                window_seconds=10 * 60,
                block_seconds=10 * 60,
            )
        except RateLimitExceeded as error:
            _pending_totp.pop(body.totp_token, None)
            raise _rate_limit_response(error)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid TOTP code.",
        )

    _pending_totp.pop(body.totp_token, None)
    totp_limiter.reset(key)
    if audit:
        audit.log_totp_success(body.username, client_ip)

    is_admin = user_manager.is_admin(body.username)
    token_version = user_manager.get_token_version(body.username)
    access_token = create_access_token(body.username, is_admin, token_version)
    refresh_token = create_refresh_token(body.username, token_version)
    csrf_token = _set_auth_cookies(response, access_token, refresh_token)
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "csrf_token": csrf_token,
        "token_type": "bearer",
    }


@router.post("/refresh")
def refresh(request: Request, response: Response, body: RefreshRequest | None = None) -> dict:
    """
    Exchange a refresh token for a fresh token pair.
    """
    refresh_token = body.refresh_token if body and body.refresh_token else request.cookies.get(REFRESH_COOKIE_NAME)
    token_from_cookie = not (body and body.refresh_token) and bool(refresh_token)
    if token_from_cookie:
        cookie_csrf = request.cookies.get(CSRF_COOKIE_NAME)
        header_csrf = request.headers.get(CSRF_HEADER_NAME)
        if not cookie_csrf or not header_csrf or cookie_csrf != header_csrf:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Missing or invalid CSRF token.",
            )
    if not refresh_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing refresh token.",
        )
    try:
        payload = decode_token(refresh_token)
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token.",
        )
    if payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Expected a refresh token.",
        )
    username = payload.get("sub")
    user_manager = request.app.state.user_manager
    if not username or not user_manager.user_exists(username) or not user_manager.is_enabled(username):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is disabled or no longer exists.",
        )
    token_version = user_manager.get_token_version(username)
    if int(payload.get("ver", 0)) != token_version:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session is no longer valid.",
        )
    is_admin = user_manager.is_admin(username)
    revoke_token(refresh_token)
    access_token = create_access_token(username, is_admin, token_version)
    new_refresh_token = create_refresh_token(username, token_version)
    csrf_token = _set_auth_cookies(response, access_token, new_refresh_token)
    return {
        "access_token": access_token,
        "refresh_token": new_refresh_token,
        "csrf_token": csrf_token,
        "token_type": "bearer",
    }


@router.post("/logout")
def logout(
    request: Request,
    response: Response,
    body: LogoutRequest | None = None,
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
) -> dict:
    """
    Revoke the current access token and, when provided, the refresh token.
    """
    cookie_access = request.cookies.get(ACCESS_COOKIE_NAME)
    cookie_refresh = request.cookies.get(REFRESH_COOKIE_NAME)
    if (cookie_access or cookie_refresh) and credentials is None:
        cookie_csrf = request.cookies.get(CSRF_COOKIE_NAME)
        header_csrf = request.headers.get(CSRF_HEADER_NAME)
        if not cookie_csrf or not header_csrf or cookie_csrf != header_csrf:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Missing or invalid CSRF token.",
            )
    if credentials:
        revoke_token(credentials.credentials)
    if cookie_access:
        revoke_token(cookie_access)
    if body and body.refresh_token:
        revoke_token(body.refresh_token)
    if cookie_refresh:
        revoke_token(cookie_refresh)
    _clear_auth_cookies(response)
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
    quota = _quota_payload(username, request, refresh=False)

    return {
        "username": username,
        "admin": payload.get("admin", False),
        "totp_enabled": totp_manager.is_enabled(username) if totp_manager else False,
        "initial_path": quota["initial_path"],
        "quota_bytes": quota["quota_bytes"],
        "used_bytes": quota["used_bytes"],
        "usage_stale": quota["usage_stale"],
        "recent_logins": recent_logins,
        "recent_failures": recent_failures,
    }


@router.get("/quota")
def get_quota(
    request: Request,
    refresh: bool = Query(default=False),
    payload: dict = Depends(get_current_user),
) -> dict:
    """
    Return current quota info for the authenticated user.

    By default this endpoint returns the cached usage value so the UI does not
    freeze while scanning very large home directories. Pass refresh=true only
    when the caller explicitly wants to rescan the filesystem.
    """
    username = payload["sub"]
    quota = _quota_payload(username, request, refresh=refresh)
    return {
        "quota_bytes": quota["quota_bytes"],
        "used_bytes": quota["used_bytes"],
        "usage_stale": quota["usage_stale"],
    }
