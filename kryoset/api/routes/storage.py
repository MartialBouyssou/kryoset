from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel

from kryoset.api.dependencies import get_current_user, require_admin
from kryoset.core.storage_manager import StorageError

router = APIRouter(prefix="/storage", tags=["storage"])


def _get_sm(request: Request):
    """Return the storage manager or raise 503."""
    sm = request.app.state.storage_manager
    if sm is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Storage manager not configured.")
    return sm


class GlobalMaxRequest(BaseModel):
    max_bytes: Optional[int]


class AllocationRequest(BaseModel):
    bytes_allocated: Optional[int]


@router.get("/status")
def storage_status(request: Request, payload: dict = Depends(require_admin)) -> dict:
    """Return global storage usage and budget. Admin only."""
    return _get_sm(request).summary()


@router.put("/max")
def set_global_max(body: GlobalMaxRequest, request: Request, payload: dict = Depends(require_admin)) -> dict:
    """Set or remove the global NAS storage budget. Admin only."""
    try:
        _get_sm(request).set_global_max(body.max_bytes)
    except StorageError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))
    return {"detail": "Global budget updated.", "max_bytes": body.max_bytes}


@router.get("/allocations")
def list_allocations(request: Request, payload: dict = Depends(require_admin)) -> dict:
    """List all per-user and per-group storage allocations. Admin only."""
    return _get_sm(request).list_allocations()


@router.put("/allocations/user/{username}")
def set_user_allocation(
    username: str,
    body: AllocationRequest,
    request: Request,
    payload: dict = Depends(require_admin),
) -> dict:
    """
    Set or remove a storage allocation for a specific user.

    This overrides any group allocation for that user. Admin only.
    """
    try:
        _get_sm(request).set_allocation(f"user:{username}", body.bytes_allocated)
    except StorageError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))
    return {"detail": f"Allocation updated for user '{username}'.", "bytes_allocated": body.bytes_allocated}


@router.delete("/allocations/user/{username}")
def remove_user_allocation(
    username: str,
    request: Request,
    payload: dict = Depends(require_admin),
) -> dict:
    """Remove a user's individual storage allocation (falls back to group). Admin only."""
    _get_sm(request).set_allocation(f"user:{username}", None)
    return {"detail": f"Allocation removed for user '{username}'."}


@router.put("/allocations/group/{name}")
def set_group_allocation(
    name: str,
    body: AllocationRequest,
    request: Request,
    payload: dict = Depends(require_admin),
) -> dict:
    """Set or remove a storage allocation for a group. Admin only."""
    try:
        _get_sm(request).set_allocation(f"group:{name}", body.bytes_allocated)
    except StorageError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))
    return {"detail": f"Allocation updated for group '{name}'.", "bytes_allocated": body.bytes_allocated}


@router.delete("/allocations/group/{name}")
def remove_group_allocation(
    name: str,
    request: Request,
    payload: dict = Depends(require_admin),
) -> dict:
    """Remove a group's storage allocation. Admin only."""
    _get_sm(request).set_allocation(f"group:{name}", None)
    return {"detail": f"Allocation removed for group '{name}'."}


@router.get("/quota/me")
def my_quota(request: Request, payload: dict = Depends(get_current_user)) -> dict:
    """Return the effective storage quota for the current user."""
    username = payload["sub"]
    sm = _get_sm(request)
    quota = sm.get_effective_quota(username)
    return {
        "username": username,
        "effective_quota_bytes": quota,
        "unlimited": quota is None,
    }


@router.get("/quota/{username}")
def user_quota(username: str, request: Request, payload: dict = Depends(require_admin)) -> dict:
    """Return the effective storage quota for any user. Admin only."""
    sm = _get_sm(request)
    quota = sm.get_effective_quota(username)
    return {
        "username": username,
        "effective_quota_bytes": quota,
        "unlimited": quota is None,
        "user_allocation": sm.get_allocation(f"user:{username}"),
    }
