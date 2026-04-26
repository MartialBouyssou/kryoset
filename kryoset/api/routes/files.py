import mimetypes
import shutil
from threading import Lock
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, UploadFile, status
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel

from kryoset.api.dependencies import check_path_permission, get_current_user
from kryoset.core.home_paths import resolve_user_home_roots
from kryoset.core.permissions import Permission

router = APIRouter(prefix="/files", tags=["files"])

_UPLOAD_LOCKS: dict[str, Lock] = {}
_UPLOAD_LOCKS_GUARD = Lock()

_PREVIEWABLE_MIME = {
    "image/jpeg", "image/png", "image/gif", "image/webp", "image/svg+xml",
    "image/bmp", "image/x-icon", "image/vnd.microsoft.icon", "image/tiff", "image/avif",
    "image/heic", "image/heif",
    "video/mp4", "video/webm",
    "audio/mpeg", "audio/ogg", "audio/wav",
    "text/plain", "text/markdown", "text/csv",
    "application/pdf",
}

_PREVIEWABLE_EXT = {
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg",
    ".bmp", ".ico", ".tif", ".tiff", ".avif", ".jfif", ".heic", ".heif",
    ".mp4", ".webm",
    ".mp3", ".ogg", ".wav",
    ".txt", ".md", ".csv", ".log", ".json", ".xml", ".py", ".js", ".ts", ".html", ".css",
    ".pdf",
}


def _safe_resolve(storage_root: Path, rel_path: str) -> Path:
    """
    Resolve a user-supplied relative path against the storage root.

    Raises:
        HTTPException 400: If the path is absolute.
        HTTPException 403: If the resolved path escapes the storage root.
    """
    if Path(rel_path).is_absolute():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Path must be relative.")
    try:
        resolved = (storage_root / rel_path).resolve()
        resolved.relative_to(storage_root.resolve())
    except ValueError:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Path traversal detected.")
    return resolved


def _upload_lock_for(username: str) -> Lock:
    with _UPLOAD_LOCKS_GUARD:
        lock = _UPLOAD_LOCKS.get(username)
        if lock is None:
            lock = Lock()
            _UPLOAD_LOCKS[username] = lock
        return lock


def _human_bytes(value: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    amount = float(value)
    unit_index = 0
    while amount >= 1024 and unit_index < len(units) - 1:
        amount /= 1024
        unit_index += 1
    if unit_index == 0:
        return f"{int(amount)} {units[unit_index]}"
    return f"{amount:.1f} {units[unit_index]}"


def _path_size_bytes(target: Path) -> int:
    """Return total file size for a file or directory tree."""
    if not target.exists():
        return 0
    if target.is_file():
        try:
            return target.stat().st_size
        except OSError:
            return 0

    total = 0
    for child in target.rglob("*"):
        if child.is_file():
            try:
                total += child.stat().st_size
            except OSError:
                pass
    return total


@router.get("/list")
def list_directory(
    path: str = Query(default=""),
    show_hidden: bool = Query(default=False),
    sort_by: str = Query(default="name"),
    sort_desc: bool = Query(default=False),
    request: Request = None,
    payload: dict = Depends(get_current_user),
) -> dict:
    """
    List the contents of a directory in the storage root.

    Requires LIST permission. Hidden files (starting with '.') are excluded
    by default unless show_hidden is set.
    """
    username = payload["sub"]
    storage_root: Path = request.app.state.configuration.storage_path
    check_path_permission(request, path, Permission.LIST, username)
    target = _safe_resolve(storage_root, path)

    if not target.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Path not found.")
    if not target.is_dir():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Path is not a directory.")

    entries = []
    for item in target.iterdir():
        if not show_hidden and item.name.startswith("."):
            continue
        stat = item.stat()
        mime = None
        previewable = False
        if item.is_file():
            mime, _ = mimetypes.guess_type(item.name)
            previewable = (
                item.suffix.lower() in _PREVIEWABLE_EXT
                or (mime and mime in _PREVIEWABLE_MIME)
            )
        entries.append({
            "name": item.name,
            "type": "directory" if item.is_dir() else "file",
            "size": stat.st_size if item.is_file() else None,
            "modified": stat.st_mtime,
            "mime": mime,
            "previewable": previewable,
        })

    reverse = sort_desc
    if sort_by == "size":
        entries.sort(key=lambda e: (e["type"] == "directory", e["size"] or 0), reverse=reverse)
    elif sort_by == "modified":
        entries.sort(key=lambda e: (e["type"] == "directory", e["modified"]), reverse=reverse)
    else:
        entries.sort(key=lambda e: (e["type"] == "directory", e["name"].lower()), reverse=reverse)

    return {"path": path or "/", "entries": entries}


@router.get("/download")
def download_file(
    path: str = Query(...),
    request: Request = None,
    payload: dict = Depends(get_current_user),
) -> FileResponse:
    """
    Download a file from the storage root. Requires DOWNLOAD permission.
    """
    username = payload["sub"]
    storage_root: Path = request.app.state.configuration.storage_path
    check_path_permission(request, path, Permission.DOWNLOAD, username)
    target = _safe_resolve(storage_root, path)

    if not target.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found.")
    if not target.is_file():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Path is not a file.")

    audit = request.app.state.audit_logger
    if audit:
        audit.log_file_download(username, path)

    return FileResponse(path=target, filename=target.name)


@router.get("/preview")
def preview_file(
    path: str = Query(...),
    request: Request = None,
    payload: dict = Depends(get_current_user),
) -> Response:
    """
    Return a file for inline preview in the browser.

    Unlike /download, this sets Content-Disposition: inline and limits
    access to file types that are safe to preview. Requires DOWNLOAD permission.
    """
    username = payload["sub"]
    storage_root: Path = request.app.state.configuration.storage_path
    check_path_permission(request, path, Permission.DOWNLOAD, username)
    target = _safe_resolve(storage_root, path)

    if not target.exists() or not target.is_file():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found.")

    suffix = target.suffix.lower()
    mime, _ = mimetypes.guess_type(target.name)
    is_previewable = suffix in _PREVIEWABLE_EXT or (mime in _PREVIEWABLE_MIME if mime else False)

    if not is_previewable:
        raise HTTPException(status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, detail="File type not previewable.")

    content = target.read_bytes()

    if not mime:
        mime = "application/octet-stream"

    return Response(
        content=content,
        media_type=mime,
        headers={"Content-Disposition": f'inline; filename="{target.name}"'},
    )


@router.post("/upload", status_code=status.HTTP_201_CREATED)
async def upload_file(
    path: str = Query(...),
    file: UploadFile = None,
    request: Request = None,
    payload: dict = Depends(get_current_user),
) -> dict:
    """
    Upload a file to the given path. Requires UPLOAD permission on the parent directory.
    """
    username = payload["sub"]
    storage_root: Path = request.app.state.configuration.storage_path
    parent = str(Path(path).parent)
    check_path_permission(request, parent, Permission.UPLOAD, username)
    target = _safe_resolve(storage_root, path)

    content = await file.read()
    file_size = len(content)

    storage_manager = request.app.state.storage_manager
    quota_manager = request.app.state.quota_manager
    user_manager = request.app.state.user_manager
    permission_store = request.app.state.permission_store

    with _upload_lock_for(username):
        # Resolve quota limit (b): allocation-based quota first, then legacy per-user quota.
        quota_bytes = None
        if storage_manager is not None:
            quota_bytes = storage_manager.get_effective_quota(username)
        if quota_bytes is None and quota_manager is not None:
            quota_bytes = quota_manager.get_quota(username)

        # Resolve used space (a) from the effective home path currently enforced for the user.
        home_roots = resolve_user_home_roots(username, user_manager, permission_store)
        home_path = home_roots[0] if home_roots else user_manager.get_home_path(username)
        used_bytes = (
            quota_manager.get_used_bytes(username, home_path=home_path)
            if quota_manager is not None
            else 0
        )

        # Enforce exactly: if a + c > b, block upload.
        if quota_bytes is not None and used_bytes + file_size > quota_bytes:
            remaining = max(0, quota_bytes - used_bytes)
            detail = (
                f"Upload refused: quota exceeded for '{username}'. "
                f"Used {_human_bytes(used_bytes)} / {_human_bytes(quota_bytes)} "
                f"({_human_bytes(remaining)} remaining)."
            )
            audit = request.app.state.audit_logger
            if audit:
                audit.log_quota_exceeded(username, path)
            raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail=detail)

        # Keep global budget check from storage manager.
        if storage_manager is not None:
            from kryoset.core.storage_manager import StorageError as StorageError_

            try:
                storage_manager.check_upload_allowed(
                    username,
                    file_size,
                    current_user_used_bytes=used_bytes,
                )
            except StorageError_ as error:
                audit = request.app.state.audit_logger
                if audit:
                    audit.log_quota_exceeded(username, path)
                raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail=str(error))

        existing_size = _path_size_bytes(target) if target.exists() else 0
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)

        if quota_manager is not None:
            quota_manager.update_used_bytes(
                username,
                file_size - existing_size,
                home_path=home_path,
            )

    audit = request.app.state.audit_logger
    if audit:
        audit.log_file_upload(username, path, file_size)

    return {"detail": "File uploaded.", "path": path, "size": file_size}


class MkdirRequest(BaseModel):
    path: str


@router.post("/mkdir", status_code=status.HTTP_201_CREATED)
def make_directory(
    body: MkdirRequest,
    request: Request = None,
    payload: dict = Depends(get_current_user),
) -> dict:
    """
    Create a new directory. Requires UPLOAD permission on the parent directory.
    """
    username = payload["sub"]
    storage_root: Path = request.app.state.configuration.storage_path
    parent = str(Path(body.path).parent)
    check_path_permission(request, parent, Permission.UPLOAD, username)
    target = _safe_resolve(storage_root, body.path)

    if target.exists():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Path already exists.")

    target.mkdir(parents=True)

    audit = request.app.state.audit_logger
    if audit:
        audit.log_mkdir(username, body.path)

    return {"detail": "Directory created.", "path": body.path}


@router.delete("/delete")
def delete_path(
    path: str = Query(...),
    request: Request = None,
    payload: dict = Depends(get_current_user),
) -> dict:
    """
    Delete a file or directory. Requires DELETE permission.
    """
    username = payload["sub"]
    storage_root: Path = request.app.state.configuration.storage_path
    check_path_permission(request, path, Permission.DELETE, username)
    target = _safe_resolve(storage_root, path)

    if not target.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Path not found.")

    deleted_size = _path_size_bytes(target)

    user_manager = request.app.state.user_manager
    permission_store = request.app.state.permission_store
    quota_manager = request.app.state.quota_manager
    home_roots = resolve_user_home_roots(username, user_manager, permission_store)
    home_path = home_roots[0] if home_roots else user_manager.get_home_path(username)

    if target.is_dir():
        shutil.rmtree(target)
        audit = request.app.state.audit_logger
        if audit:
            audit.log_rmdir(username, path)
    else:
        target.unlink()
        audit = request.app.state.audit_logger
        if audit:
            audit.log_file_delete(username, path)

    if quota_manager is not None and deleted_size > 0:
        quota_manager.update_used_bytes(username, -deleted_size, home_path=home_path)

    return {"detail": "Deleted.", "path": path}


class RenameRequest(BaseModel):
    source: str
    destination: str


@router.post("/rename")
def rename_path(
    body: RenameRequest,
    request: Request = None,
    payload: dict = Depends(get_current_user),
) -> dict:
    """
    Rename or move a file or directory. Requires RENAME (and MOVE if parent changes).
    """
    username = payload["sub"]
    storage_root: Path = request.app.state.configuration.storage_path

    check_path_permission(request, body.source, Permission.RENAME, username)
    src = _safe_resolve(storage_root, body.source)
    dst = _safe_resolve(storage_root, body.destination)

    if not src.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Source path not found.")
    if dst.exists():
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Destination already exists.")

    if src.parent != dst.parent:
        check_path_permission(request, body.source, Permission.MOVE, username)

    src.rename(dst)

    audit = request.app.state.audit_logger
    if audit:
        audit.log_file_rename(username, body.source, body.destination)

    return {"detail": "Renamed.", "source": body.source, "destination": body.destination}
