from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from kryoset.api.dependencies import require_admin

router = APIRouter(prefix="/logs", tags=["logs"])


@router.get("/")
def get_logs(
    lines: int = Query(default=100, ge=1, le=10000),
    filter: Optional[str] = Query(default=None),
    request: Request = None,
    payload: dict = Depends(require_admin),
) -> dict:
    """
    Return recent audit log lines. Admin only.

    Args:
        lines: Maximum number of lines to return.
        filter: Optional substring to filter log lines (case-insensitive).
    """
    from kryoset.core.audit_logger import LOG_DIRECTORY
    log_file = LOG_DIRECTORY / "kryoset.log"

    if not log_file.exists():
        return {"lines": []}

    all_lines = log_file.read_text(encoding="utf-8").splitlines()

    if filter:
        all_lines = [line for line in all_lines if filter.upper() in line.upper()]

    return {"lines": all_lines[-lines:]}


@router.get("/files")
def list_log_files(
    request: Request,
    payload: dict = Depends(require_admin),
) -> dict:
    """
    Return a list of available log files (current and rotated). Admin only.
    """
    from kryoset.core.audit_logger import LOG_DIRECTORY
    if not LOG_DIRECTORY.exists():
        return {"files": []}

    log_files = []
    for path in sorted(LOG_DIRECTORY.glob("kryoset.log*")):
        stat = path.stat()
        log_files.append({
            "name": path.name,
            "size_bytes": stat.st_size,
        })

    return {"files": log_files}
