import shutil
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, UploadFile, status
from fastapi.responses import FileResponse
from pydantic import BaseModel

from kryoset.api.dependencies import check_path_permission, get_current_user
from kryoset.core.permissions import Permission

router = APIRouter(prefix="/files", tags=["files"])


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


@router.get("/list")
def list_directory(
    path: str = Query(default=""),
    request: Request = None,
    payload: dict = Depends(get_current_user),
) -> dict:
    """
    List the contents of a directory in the storage root.

    Requires LIST permission on the target path.
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
    for item in sorted(target.iterdir()):
        entries.append({
            "name": item.name,
            "type": "directory" if item.is_dir() else "file",
            "size": item.stat().st_size if item.is_file() else None,
        })
    return {"path": path or "/", "entries": entries}


@router.get("/download")
def download_file(
    path: str = Query(...),
    request: Request = None,
    payload: dict = Depends(get_current_user),
) -> FileResponse:
    """
    Download a file from the storage root.

    Requires DOWNLOAD permission on the target path.
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
        audit.log_file_read(username, path)

    return FileResponse(path=target, filename=target.name)


@router.post("/upload", status_code=status.HTTP_201_CREATED)
async def upload_file(
    path: str = Query(...),
    file: UploadFile = None,
    request: Request = None,
    payload: dict = Depends(get_current_user),
) -> dict:
    """
    Upload a file to the given path in the storage root.

    Requires UPLOAD permission on the parent directory. Quota is checked
    before writing.
    """
    username = payload["sub"]
    storage_root: Path = request.app.state.configuration.storage_path
    parent = str(Path(path).parent)
    check_path_permission(request, parent, Permission.UPLOAD, username)
    target = _safe_resolve(storage_root, path)

    content = await file.read()
    file_size = len(content)

    quota_manager = request.app.state.quota_manager
    if quota_manager:
        from kryoset.core.quota import QuotaError
        try:
            quota_manager.check_upload_allowed(username, file_size)
        except QuotaError as error:
            audit = request.app.state.audit_logger
            if audit:
                audit.log_quota_exceeded(username, path)
            raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail=str(error))

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)

    audit = request.app.state.audit_logger
    if audit:
        audit.log_file_write(username, path)

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
    Create a new directory at the given path.

    Requires UPLOAD permission on the parent directory.
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
    Delete a file or directory from the storage root.

    Requires DELETE permission on the target path.
    """
    username = payload["sub"]
    storage_root: Path = request.app.state.configuration.storage_path
    check_path_permission(request, path, Permission.DELETE, username)
    target = _safe_resolve(storage_root, path)

    if not target.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Path not found.")

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
    Rename or move a file or directory.

    Requires RENAME permission on the source path and MOVE permission if the
    parent directory changes.
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
