from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel

from kryoset.api.dependencies import get_current_user, require_admin
from kryoset.core.user_manager import UserError

router = APIRouter(prefix="/users", tags=["users"])


class CreateUserRequest(BaseModel):
    username: str
    password: str


class PasswordRequest(BaseModel):
    new_password: str


class QuotaRequest(BaseModel):
    quota_bytes: Optional[int]


class TOTPConfirmRequest(BaseModel):
    code: str


def _assert_self_or_admin(payload: dict, username: str) -> None:
    """
    Raise HTTP 403 unless the caller is the target user or an admin.

    Args:
        payload: JWT payload of the caller.
        username: Username of the target resource.
    """
    if not payload.get("admin") and payload["sub"] != username:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied. You can only manage your own account.",
        )


@router.get("/")
def list_users(
    request: Request,
    payload: dict = Depends(require_admin),
) -> list:
    """
    Return a list of all registered users. Admin only.
    """
    return request.app.state.user_manager.list_users()


@router.post("/", status_code=status.HTTP_201_CREATED)
def create_user(
    body: CreateUserRequest,
    request: Request,
    payload: dict = Depends(require_admin),
) -> dict:
    """
    Create a new user account. Admin only.
    """
    try:
        request.app.state.user_manager.add_user(body.username, body.password)
    except UserError as error:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(error))
    return {"detail": f"User '{body.username}' created."}


@router.delete("/{username}")
def delete_user(
    username: str,
    request: Request,
    payload: dict = Depends(require_admin),
) -> dict:
    """
    Delete a user account. Admin only.
    """
    try:
        request.app.state.user_manager.remove_user(username)
    except UserError as error:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(error))
    return {"detail": f"User '{username}' deleted."}


@router.post("/{username}/enable")
def enable_user(
    username: str,
    request: Request,
    payload: dict = Depends(require_admin),
) -> dict:
    """
    Enable a user account. Admin only.
    """
    try:
        request.app.state.user_manager.set_enabled(username, enabled=True)
    except UserError as error:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(error))
    return {"detail": f"User '{username}' enabled."}


@router.post("/{username}/disable")
def disable_user(
    username: str,
    request: Request,
    payload: dict = Depends(require_admin),
) -> dict:
    """
    Disable a user account. Admin only.
    """
    try:
        request.app.state.user_manager.set_enabled(username, enabled=False)
    except UserError as error:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(error))
    return {"detail": f"User '{username}' disabled."}


@router.post("/{username}/password")
def change_password(
    username: str,
    body: PasswordRequest,
    request: Request,
    payload: dict = Depends(get_current_user),
) -> dict:
    """
    Change a user's password. The caller must be the user themselves or an admin.
    """
    _assert_self_or_admin(payload, username)
    try:
        request.app.state.user_manager.change_password(username, body.new_password)
    except UserError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))
    return {"detail": "Password updated."}


@router.post("/{username}/reset-password")
def reset_password(
    username: str,
    request: Request,
    payload: dict = Depends(require_admin),
) -> dict:
    """
    Generate and set a random temporary password for a user. Admin only.
    """
    try:
        temp_password = request.app.state.user_manager.generate_temporary_password(username)
    except UserError as error:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(error))
    return {"detail": "Password reset.", "temporary_password": temp_password}


@router.post("/{username}/admin")
def set_admin(
    username: str,
    request: Request,
    grant: bool = True,
    payload: dict = Depends(require_admin),
) -> dict:
    """
    Grant or revoke admin privileges for a user. Admin only.
    """
    try:
        request.app.state.user_manager.set_admin(username, admin=grant)
    except UserError as error:
        detail = str(error)
        if "does not exist" in detail:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=detail)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=detail)
    action = "granted" if grant else "revoked"
    return {"detail": f"Admin {action} for '{username}'."}


@router.get("/{username}/totp/status")
def totp_status(
    username: str,
    request: Request,
    payload: dict = Depends(get_current_user),
) -> dict:
    """
    Return TOTP status for a user. Caller must be the user or an admin.
    """
    _assert_self_or_admin(payload, username)
    totp_manager = request.app.state.totp_manager
    if totp_manager is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="TOTP not configured.")
    return {"username": username, "enabled": totp_manager.is_enabled(username)}


@router.post("/{username}/totp/setup")
def totp_setup(
    username: str,
    request: Request,
    payload: dict = Depends(get_current_user),
) -> dict:
    """
    Generate a TOTP secret for a user and return the provisioning URI.

    The caller must be the user themselves or an admin.
    """
    _assert_self_or_admin(payload, username)
    totp_manager = request.app.state.totp_manager
    if totp_manager is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="TOTP not configured.")
    from kryoset.core.totp import TOTPError
    try:
        secret = totp_manager.generate_secret(username)
        uri = totp_manager.get_provisioning_uri(username)
    except TOTPError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))
    return {"secret": secret, "uri": uri}


@router.post("/{username}/totp/confirm")
def totp_confirm(
    username: str,
    body: TOTPConfirmRequest,
    request: Request,
    payload: dict = Depends(get_current_user),
) -> dict:
    """
    Confirm TOTP setup by verifying a code from the authenticator app.

    The caller must be the user themselves or an admin.
    """
    _assert_self_or_admin(payload, username)
    totp_manager = request.app.state.totp_manager
    if totp_manager is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="TOTP not configured.")
    from kryoset.core.totp import TOTPError
    try:
        totp_manager.confirm_setup(username, body.code)
    except TOTPError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))
    return {"detail": "TOTP enabled."}


@router.delete("/{username}/totp")
def totp_disable(
    username: str,
    request: Request,
    payload: dict = Depends(get_current_user),
) -> dict:
    """
    Disable TOTP for a user. The caller must be the user themselves or an admin.
    """
    _assert_self_or_admin(payload, username)
    totp_manager = request.app.state.totp_manager
    if totp_manager is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="TOTP not configured.")
    from kryoset.core.totp import TOTPError
    try:
        totp_manager.disable(username)
    except TOTPError as error:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(error))
    return {"detail": "TOTP disabled."}


@router.get("/{username}/quota")
def get_quota(
    username: str,
    request: Request,
    payload: dict = Depends(get_current_user),
) -> dict:
    """
    Return quota information for a user. The caller must be the user or an admin.
    """
    _assert_self_or_admin(payload, username)
    quota_manager = request.app.state.quota_manager
    if quota_manager is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Quota manager not configured.")
    return {
        "username": username,
        "quota_bytes": quota_manager.get_quota(username),
        "used_bytes": quota_manager.get_used_bytes(username),
    }


@router.put("/{username}/quota")
def set_quota(
    username: str,
    body: QuotaRequest,
    request: Request,
    payload: dict = Depends(require_admin),
) -> dict:
    """
    Set storage quota for a user. Admin only.
    """
    quota_manager = request.app.state.quota_manager
    if quota_manager is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Quota manager not configured.")
    try:
        quota_manager.set_quota(username, body.quota_bytes)
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))
    return {"detail": "Quota updated.", "quota_bytes": body.quota_bytes}
