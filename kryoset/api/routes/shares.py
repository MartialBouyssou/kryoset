from pathlib import PurePosixPath
from typing import Optional
from urllib.parse import quote

import bcrypt
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import FileResponse
from pydantic import BaseModel

from kryoset.api.dependencies import get_current_user
from kryoset.api.rate_limit import RateLimitExceeded, share_limiter
from kryoset.core.permission_store import PermissionStoreError
from kryoset.core.permissions import Permission

router = APIRouter(prefix="/shares", tags=["shares"])


class ShareCreateRequest(BaseModel):
    path: str
    permissions: list[str] = ["DOWNLOAD"]
    expires_at: Optional[str] = None
    download_limit: Optional[int] = None
    password: Optional[str] = None


class PublicDownloadRequest(BaseModel):
    password: Optional[str] = None


def _get_store(request: Request):
    """Return the permission store or raise 503 if not configured."""
    store = request.app.state.permission_store
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Permission store not configured.",
        )
    return store


def _client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _content_disposition(filename: str) -> dict[str, str]:
    safe_name = filename.replace("\r", "_").replace("\n", "_").replace('"', "_") or "download"
    return {"Content-Disposition": f"attachment; filename*=UTF-8''{quote(safe_name)}"}

def _normalize_share_path(path: str) -> str:
    raw = str(path or "").strip()
    if not raw:
        raise PermissionStoreError("Share path cannot be empty.")
    parts = []
    for part in raw.replace("\\", "/").split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            raise PermissionStoreError("Share path traversal is not allowed.")
        parts.append(part)
    return "/" + "/".join(parts)


def _public_filename(path: str) -> str:
    name = PurePosixPath(path).name
    return name or "download"


def _rate_limit_response(error: RateLimitExceeded) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        detail=str(error),
        headers={"Retry-After": str(error.retry_after)},
    )


def _verify_share_password(token: str, request: Request, password_hash: str, password: Optional[str]) -> None:
    if password is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="This share link requires a password.",
        )

    key = f"share:{_client_ip(request)}:{token}"
    try:
        share_limiter.check(key)
    except RateLimitExceeded as error:
        raise _rate_limit_response(error)

    if not bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8")):
        try:
            share_limiter.record_failure(
                key,
                limit=8,
                window_seconds=10 * 60,
                block_seconds=10 * 60,
            )
        except RateLimitExceeded as error:
            raise _rate_limit_response(error)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid share link password.",
        )
    share_limiter.reset(key)


def _public_download_impl(token: str, request: Request, password: Optional[str]) -> FileResponse:
    store = _get_store(request)
    link = store.get_share_link(token)

    if link is None or not link.is_valid():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Share link not found or expired.")

    if link.password_hash:
        _verify_share_password(token, request, link.password_hash, password)

    if Permission.DOWNLOAD not in link.permissions:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This share link does not grant download access.",
        )

    storage_root = request.app.state.configuration.storage_path
    target = (storage_root / link.path.lstrip("/")).resolve()

    try:
        target.relative_to(storage_root.resolve())
    except ValueError:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid path.")

    if not target.exists() or not target.is_file():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found.")

    try:
        store.reserve_share_download(token)
    except PermissionStoreError as error:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(error))

    audit = request.app.state.audit_logger
    if audit:
        audit.log_share_accessed(token, _client_ip(request))

    return FileResponse(
        path=target,
        media_type="application/octet-stream",
        headers=_content_disposition(target.name),
    )


@router.post("/", status_code=status.HTTP_201_CREATED)
def create_share(
    body: ShareCreateRequest,
    request: Request,
    payload: dict = Depends(get_current_user),
) -> dict:
    """
    Create a share link for a path. Requires SHARE permission on that path.
    """
    username = payload["sub"]
    from kryoset.api.dependencies import check_path_permission
    store = _get_store(request)
    try:
        normalized_path = _normalize_share_path(body.path)
    except PermissionStoreError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))
    check_path_permission(request, normalized_path.lstrip("/"), Permission.SHARE, username)


    try:
        perms = Permission.from_names(body.permissions)
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))

    expires_at = None
    if body.expires_at:
        from kryoset.core.timezone import parse_iso
        expires_at = parse_iso(body.expires_at)

    try:
        if body.password is not None and len(body.password) < 8:
            raise PermissionStoreError("Share password must be at least 8 characters long.")
        link = store.create_share_link(
            created_by=username,
            path=normalized_path,
            permissions=perms,
            expires_at=expires_at,
            download_limit=body.download_limit,
            password=body.password,
        )
    except PermissionStoreError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))

    audit = request.app.state.audit_logger
    if audit:
        audit.log_share_created(username, body.path, link.token)
    return {
        "token": link.token,
        "path": link.path,
        "permissions": link.permissions.to_names(),
        "expires_at": link.expires_at.isoformat() if link.expires_at else None,
        "download_limit": link.download_limit,
        "created_by": link.created_by,
    }


@router.get("/")
def list_shares(
    request: Request,
    payload: dict = Depends(get_current_user),
) -> list:
    """
    List share links.

    Admins see all links; regular users see only their own.
    """
    store = _get_store(request)
    username = payload["sub"]
    if payload.get("admin"):
        links = store.list_share_links()
    else:
        links = store.list_share_links(created_by=username)

    return [
        {
            "token": link.token,
            "path": link.path,
            "permissions": link.permissions.to_names(),
            "expires_at": link.expires_at.isoformat() if link.expires_at else None,
            "download_limit": link.download_limit,
            "download_count": link.download_count,
            "created_by": link.created_by,
            "valid": link.is_valid(),
        }
        for link in links
    ]


@router.delete("/{token}")
def revoke_share(
    token: str,
    request: Request,
    payload: dict = Depends(get_current_user),
) -> dict:
    """
    Revoke a share link by token. The caller must be the creator or an admin.
    """
    store = _get_store(request)
    link = store.get_share_link(token)
    if link is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Share link not found.")

    username = payload["sub"]
    if not payload.get("admin") and link.created_by != username:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only revoke your own share links.",
        )

    try:
        store.revoke_share_link(token)
    except PermissionStoreError as error:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(error))

    audit = request.app.state.audit_logger
    if audit:
        audit.log_share_revoked(username, token)
    return {"detail": "Share link revoked."}


@router.get("/public/{token}")
def public_download(
    token: str,
    request: Request,
    password: Optional[str] = None,
) -> FileResponse:
    """
    Download a file via a public share link.

    For password-protected links, prefer POST /shares/public/{token} with a JSON
    body so the password is not stored in URLs, browser history or access logs.
    """
    return _public_download_impl(token, request, password)


@router.post("/public/{token}")
def public_download_post(
    token: str,
    request: Request,
    body: PublicDownloadRequest | None = None,
) -> FileResponse:
    """Download a public share using a JSON body for the optional password."""
    return _public_download_impl(token, request, body.password if body else None)
