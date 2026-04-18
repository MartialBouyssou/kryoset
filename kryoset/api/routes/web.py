from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import FileResponse, HTMLResponse

from kryoset.core.permissions import Permission

router = APIRouter(tags=["web"])

_STATIC = Path(__file__).parent.parent.parent / "web" / "static"


@router.get("/", response_class=HTMLResponse)
def index() -> HTMLResponse:
    """Serve the main application SPA."""
    return HTMLResponse((_STATIC / "app.html").read_text(encoding="utf-8"))


@router.get("/share/{token}", response_class=HTMLResponse)
def share_page(token: str) -> HTMLResponse:
    """Serve the public share download page."""
    return HTMLResponse((_STATIC / "share.html").read_text(encoding="utf-8"))


@router.get("/api/shares/info/{token}")
def share_info(token: str, request: Request) -> dict:
    """
    Return metadata about a share link without triggering a download.

    This endpoint is used by the public share page to display file
    information before the user initiates the download. No authentication
    is required.
    """
    store = request.app.state.permission_store
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Permission store not configured.",
        )

    link = store.get_share_link(token)
    if link is None or not link.is_valid():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Share link not found or expired.",
        )

    return {
        "token": link.token,
        "path": link.path,
        "permissions": link.permissions.to_names(),
        "expires_at": link.expires_at.isoformat() if link.expires_at else None,
        "download_limit": link.download_limit,
        "download_count": link.download_count,
        "password_protected": link.password_hash is not None,
        "valid": link.is_valid(),
    }