from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from pydantic import BaseModel

from kryoset.api.auth import (
    create_access_token,
    create_refresh_token,
    decode_token,
    revoke_token,
)
from kryoset.api.dependencies import get_current_user

router = APIRouter(prefix="/auth", tags=["auth"])

_bearer = HTTPBearer(auto_error=False)

_pending_totp: dict[str, str] = {}


class LoginRequest(BaseModel):
    username: str
    password: str


class TOTPRequest(BaseModel):
    username: str
    code: str


class RefreshRequest(BaseModel):
    refresh_token: str


class ChangePasswordRequest(BaseModel):
    new_password: str


@router.post("/login")
def login(body: LoginRequest, request: Request) -> dict:
    """
    Authenticate with username and password.

    If TOTP is enabled for the account the response contains a 'totp_required'
    flag and the caller must complete the flow via POST /auth/totp.  Otherwise
    a full token pair is returned immediately.
    """
    user_manager = request.app.state.user_manager
    audit = request.app.state.audit_logger
    client_ip = request.client.host if request.client else "unknown"

    if not user_manager.authenticate(body.username, body.password):
        if audit:
            audit.log_auth_failure(body.username, client_ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials.",
        )

    if audit:
        audit.log_auth_success(body.username, client_ip)

    totp_manager = request.app.state.totp_manager
    if totp_manager and totp_manager.is_enabled(body.username):
        _pending_totp[body.username] = body.password
        return {"totp_required": True, "username": body.username}

    is_admin = user_manager.is_admin(body.username)
    return {
        "access_token": create_access_token(body.username, is_admin),
        "refresh_token": create_refresh_token(body.username),
        "token_type": "bearer",
    }


@router.post("/totp")
def totp_verify(body: TOTPRequest, request: Request) -> dict:
    """
    Complete the two-step TOTP authentication flow.

    The username must have successfully passed the password step (POST /auth/login)
    before this endpoint can be called.
    """
    user_manager = request.app.state.user_manager
    totp_manager = request.app.state.totp_manager
    audit = request.app.state.audit_logger
    client_ip = request.client.host if request.client else "unknown"

    if body.username not in _pending_totp:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No pending TOTP session for this user.",
        )

    if totp_manager is None or not totp_manager.verify(body.username, body.code):
        if audit:
            audit.log_totp_failure(body.username, client_ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid TOTP code.",
        )

    _pending_totp.pop(body.username, None)
    if audit:
        audit.log_totp_success(body.username, client_ip)

    is_admin = user_manager.is_admin(body.username)
    return {
        "access_token": create_access_token(body.username, is_admin),
        "refresh_token": create_refresh_token(body.username),
        "token_type": "bearer",
    }


@router.post("/refresh")
def refresh(body: RefreshRequest, request: Request) -> dict:
    """
    Exchange a refresh token for a new access token.

    The refresh token must be valid and not revoked.
    """
    try:
        payload = decode_token(body.refresh_token)
    except JWTError as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(error),
        )
    if payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Expected a refresh token.",
        )
    username = payload["sub"]
    user_manager = request.app.state.user_manager
    is_admin = user_manager.is_admin(username)
    return {
        "access_token": create_access_token(username, is_admin),
        "token_type": "bearer",
    }


@router.post("/logout")
def logout(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
) -> dict:
    """
    Revoke the current access token immediately.
    """
    if credentials:
        revoke_token(credentials.credentials)
    return {"detail": "Logged out."}


@router.get("/me")
def me(payload: dict = Depends(get_current_user)) -> dict:
    """
    Return information about the currently authenticated user.
    """
    return {"username": payload["sub"], "admin": payload.get("admin", False)}
