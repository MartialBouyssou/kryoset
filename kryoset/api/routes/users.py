import base64
import io
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import Response
from pydantic import BaseModel

from kryoset.api.dependencies import get_current_user, require_admin
from kryoset.core.user_manager import UserError

router = APIRouter(prefix="/users", tags=["users"])


class CreateUserRequest(BaseModel):
    username: str
    password: str
    storage_max_bytes: Optional[int] = None
    home_path: Optional[str] = None
    group_name: Optional[str] = None


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
    """Return a list of all registered users. Admin only."""
    users = request.app.state.user_manager.list_users()
    storage_manager = request.app.state.storage_manager
    totp_manager = request.app.state.totp_manager
    result = []
    for u in users:
        u["totp_enabled"] = totp_manager.is_enabled(u["username"]) if totp_manager else False
        u["admin"] = request.app.state.user_manager.is_admin(u["username"])
        u["home_path"] = request.app.state.user_manager.get_home_path(u["username"])
        u["storage_max_bytes"] = (
            storage_manager.get_allocation(f"user:{u['username']}")
            if storage_manager is not None
            else None
        )
        result.append(u)
    return result


@router.post("/", status_code=status.HTTP_201_CREATED)
def create_user(
    body: CreateUserRequest,
    request: Request,
    payload: dict = Depends(require_admin),
) -> dict:
    """Create a new user account. Admin only."""
    storage_manager = request.app.state.storage_manager
    permission_store = request.app.state.permission_store
    # If no explicit home is provided (and no group is selected), give the
    # user a personal default home so first login starts in an accessible path.
    effective_home_path = (
        body.home_path
        if body.home_path is not None
        else (None if body.group_name else f"/home/{body.username}")
    )
    user_created = False
    try:
        request.app.state.user_manager.add_user(
            body.username,
            body.password,
            home_path=effective_home_path,
        )
        user_created = True
        if permission_store is not None and body.group_name:
            permission_store.add_group_member(body.group_name, body.username, storage_path=request.app.state.configuration.storage_path)
    except UserError as error:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(error))
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))
    except Exception as error:
        if user_created:
            request.app.state.user_manager.remove_user(body.username)
        from kryoset.core.permission_store import PermissionStoreError
        if isinstance(error, PermissionStoreError):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))
        raise

    if storage_manager is not None and body.storage_max_bytes is not None:
        from kryoset.core.storage_manager import StorageError

        try:
            storage_manager.set_allocation(f"user:{body.username}", body.storage_max_bytes)
        except StorageError as error:
            request.app.state.user_manager.remove_user(body.username)
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))

    audit = request.app.state.audit_logger
    if audit:
        audit.log_user_created(payload["sub"], body.username)
    response = {"detail": f"User '{body.username}' created."}
    if body.storage_max_bytes is not None:
        response["storage_max_bytes"] = body.storage_max_bytes
    if effective_home_path is not None:
        response["home_path"] = effective_home_path
    if body.group_name is not None:
        response["group_name"] = body.group_name
    return response


@router.delete("/{username}")
def delete_user(
    username: str,
    request: Request,
    payload: dict = Depends(require_admin),
) -> dict:
    """Delete a user account. Admin only."""
    try:
        request.app.state.user_manager.remove_user(username)
    except UserError as error:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(error))
    audit = request.app.state.audit_logger
    if audit:
        audit.log_user_deleted(payload["sub"], username)
    return {"detail": f"User '{username}' deleted."}


@router.post("/{username}/enable")
def enable_user(username: str, request: Request, payload: dict = Depends(require_admin)) -> dict:
    """Enable a user account. Admin only."""
    try:
        request.app.state.user_manager.set_enabled(username, enabled=True)
    except UserError as error:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(error))
    return {"detail": f"User '{username}' enabled."}


@router.post("/{username}/disable")
def disable_user(username: str, request: Request, payload: dict = Depends(require_admin)) -> dict:
    """Disable a user account. Admin only."""
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
    """Change a user's password. The caller must be the user or an admin."""
    _assert_self_or_admin(payload, username)
    try:
        request.app.state.user_manager.change_password(username, body.new_password)
    except UserError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))
    return {"detail": "Password updated."}


@router.post("/{username}/reset-password")
def reset_password(username: str, request: Request, payload: dict = Depends(require_admin)) -> dict:
    """Generate and set a random temporary password. Admin only."""
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
    """Grant or revoke admin privileges. Admin only."""
    if grant:
        totp_manager = request.app.state.totp_manager
        if totp_manager and not totp_manager.is_enabled(username):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"User '{username}' must enable TOTP before being granted admin.",
            )
    try:
        request.app.state.user_manager.set_admin(username, admin=grant)
    except UserError as error:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(error))
    action = "granted" if grant else "revoked"
    return {"detail": f"Admin {action} for '{username}'."}


@router.post("/{username}/totp/setup")
def totp_setup(username: str, request: Request, payload: dict = Depends(get_current_user)) -> dict:
    """
    Generate a TOTP secret and return the provisioning URI and QR code.

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
        qr_png = totp_manager.get_qr_code_png(username)
        qr_b64 = base64.b64encode(qr_png).decode("ascii")
    except TOTPError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))
    return {"secret": secret, "uri": uri, "qr_code_png_b64": qr_b64}


@router.get("/{username}/totp/qr.png")
def totp_qr_image(username: str, request: Request, payload: dict = Depends(get_current_user)) -> Response:
    """
    Return the TOTP QR code as a PNG image for direct embedding.

    The caller must be the user themselves or an admin.
    """
    _assert_self_or_admin(payload, username)
    totp_manager = request.app.state.totp_manager
    if totp_manager is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="TOTP not configured.")
    from kryoset.core.totp import TOTPError
    try:
        png = totp_manager.get_qr_code_png(username)
    except TOTPError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))
    return Response(content=png, media_type="image/png")


@router.post("/{username}/totp/confirm")
def totp_confirm(
    username: str,
    body: TOTPConfirmRequest,
    request: Request,
    payload: dict = Depends(get_current_user),
) -> dict:
    """Confirm TOTP setup by verifying a code from the authenticator app."""
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
def totp_disable(username: str, request: Request, payload: dict = Depends(get_current_user)) -> dict:
    """Disable TOTP for a user. The caller must be the user or an admin."""
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
def get_quota(username: str, request: Request, payload: dict = Depends(get_current_user)) -> dict:
    """Return quota information. The caller must be the user or an admin."""
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
    """Set storage quota for a user. Admin only."""
    quota_manager = request.app.state.quota_manager
    if quota_manager is None:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Quota manager not configured.")
    try:
        quota_manager.set_quota(username, body.quota_bytes)
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))
    return {"detail": "Quota updated.", "quota_bytes": body.quota_bytes}


@router.get("/{username}/totp/status")
def totp_status(username: str, request: Request, payload: dict = Depends(get_current_user)) -> dict:
    """Return TOTP status for a user. The caller must be the user or an admin."""
    _assert_self_or_admin(payload, username)
    totp_manager = request.app.state.totp_manager
    enabled = totp_manager.is_enabled(username) if totp_manager else False
    return {"username": username, "enabled": enabled}
