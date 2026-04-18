from typing import Optional

import bcrypt
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel

from kryoset.api.dependencies import get_current_user
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
    check_path_permission(request, body.path, Permission.SHARE, username)

    store = _get_store(request)

    try:
        perms = Permission.from_names(body.permissions)
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))

    expires_at = None
    if body.expires_at:
        from kryoset.core.timezone import parse_iso
        expires_at = parse_iso(body.expires_at)

    link = store.create_share_link(
        created_by=username,
        path=body.path,
        permissions=perms,
        expires_at=expires_at,
        download_limit=body.download_limit,
        password=body.password,
    )
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
    return {"detail": "Share link revoked."}


@router.get("/public/{token}")
def public_download(
    token: str,
    request: Request,
    password: Optional[str] = None,
) -> StreamingResponse:
    """
    Download a file via a public share link. No authentication required.

    If the share link is password-protected, supply the password as a
    query parameter.
    """
    store = _get_store(request)
    link = store.get_share_link(token)

    if link is None or not link.is_valid():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Share link not found or expired.")

    if link.password_hash:
        if password is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="This share link requires a password.",
            )
        if not bcrypt.checkpw(password.encode("utf-8"), link.password_hash.encode("utf-8")):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid share link password.",
            )

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

    file_size = target.stat().st_size

    async def _iter_file():
        bytes_sent = 0
        chunk_size = 64 * 1024
        with open(target, "rb") as handle:
            while True:
                if await request.is_disconnected():
                    break
                chunk = handle.read(chunk_size)
                if not chunk:
                    break
                bytes_sent += len(chunk)
                yield chunk

        if bytes_sent == file_size:
            store.increment_share_download(token)

    headers = {"Content-Disposition": f'attachment; filename="{target.name}"'}
    return StreamingResponse(_iter_file(), media_type="application/octet-stream", headers=headers)
