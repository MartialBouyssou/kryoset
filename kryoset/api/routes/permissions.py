from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel

from kryoset.api.dependencies import get_current_user, require_admin
from kryoset.core.permission_store import PermissionStoreError
from kryoset.core.permissions import Permission, PermissionRule

router = APIRouter(prefix="/permissions", tags=["permissions"])


class RuleCreateRequest(BaseModel):
    subject_type: str
    subject_id: str
    path: str
    permissions: list[str]
    expires_at: Optional[str] = None
    can_delegate: bool = False


class GroupCreateRequest(BaseModel):
    pass


class MemberRequest(BaseModel):
    username: str


def _get_store(request: Request):
    """Return the permission store or raise 503 if not configured."""
    store = request.app.state.permission_store
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Permission store not configured.",
        )
    return store


def _can_manage_permissions(payload: dict, request: Request) -> bool:
    """Return True if the user is admin or holds MANAGE_PERMS on at least one path."""
    if payload.get("admin"):
        return True
    store = request.app.state.permission_store
    if store is None:
        return False
    rules = store.get_rules_for_user(payload["sub"])
    for rule in rules:
        if Permission.MANAGE_PERMS in rule.permissions:
            return True
    return False


@router.get("/rules")
def list_rules(
    path: Optional[str] = Query(default=None),
    request: Request = None,
    payload: dict = Depends(require_admin),
) -> list:
    """
    List all permission rules. Admin only.
    """
    store = _get_store(request)
    rules = store.list_rules(path_prefix=path)
    return [
        {
            "rule_id": rule.rule_id,
            "subject_type": rule.subject_type,
            "subject_id": rule.subject_id,
            "path": rule.path,
            "permissions": rule.permissions.to_names(),
            "expires_at": rule.expires_at.isoformat() if rule.expires_at else None,
            "can_delegate": rule.can_delegate,
        }
        for rule in rules
    ]


@router.post("/rules", status_code=status.HTTP_201_CREATED)
def add_rule(
    body: RuleCreateRequest,
    request: Request,
    payload: dict = Depends(get_current_user),
) -> dict:
    """
    Add a permission rule. Requires admin or MANAGE_PERMS permission.
    """
    if not _can_manage_permissions(payload, request):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin or MANAGE_PERMS permission required.",
        )
    store = _get_store(request)
    try:
        perms = Permission.from_names(body.permissions)
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))

    if body.subject_type not in ("user", "group"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="subject_type must be 'user' or 'group'.",
        )

    normalized_path = "/" + body.path.strip("/") if body.path.strip("/") else "/"

    expires_at = None
    if body.expires_at:
        from kryoset.core.timezone import parse_iso
        expires_at = parse_iso(body.expires_at)

    rule = PermissionRule(
        subject_type=body.subject_type,
        subject_id=body.subject_id,
        path=normalized_path,
        permissions=perms,
        expires_at=expires_at,
        can_delegate=body.can_delegate,
    )
    rule_id = store.add_rule(rule)
    return {"detail": "Rule added.", "rule_id": rule_id}


@router.put("/rules/{rule_id}")
def update_rule(
    rule_id: int,
    body: RuleCreateRequest,
    request: Request,
    payload: dict = Depends(get_current_user),
) -> dict:
    """
    Update a permission rule by ID. Requires admin or MANAGE_PERMS permission.
    """
    if not _can_manage_permissions(payload, request):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin or MANAGE_PERMS permission required.",
        )
    store = _get_store(request)

    try:
        perms = Permission.from_names(body.permissions)
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))

    if body.subject_type not in ("user", "group"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="subject_type must be 'user' or 'group'.",
        )

    normalized_path = "/" + body.path.strip("/") if body.path.strip("/") else "/"

    expires_at = None
    if body.expires_at:
        from kryoset.core.timezone import parse_iso
        expires_at = parse_iso(body.expires_at)

    rule = PermissionRule(
        subject_type=body.subject_type,
        subject_id=body.subject_id,
        path=normalized_path,
        permissions=perms,
        expires_at=expires_at,
        can_delegate=body.can_delegate,
    )
    try:
        store.update_rule(rule_id, rule)
    except PermissionStoreError as error:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(error))
    return {"detail": f"Rule #{rule_id} updated."}


@router.delete("/rules/{rule_id}")
def remove_rule(
    rule_id: int,
    request: Request,
    payload: dict = Depends(get_current_user),
) -> dict:
    """
    Remove a permission rule by ID. Requires admin or MANAGE_PERMS permission.
    """
    if not _can_manage_permissions(payload, request):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin or MANAGE_PERMS permission required.",
        )
    store = _get_store(request)
    try:
        store.remove_rule(rule_id)
    except PermissionStoreError as error:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(error))
    return {"detail": f"Rule #{rule_id} removed."}


@router.get("/check")
def check_permission(
    path: str = Query(...),
    request: Request = None,
    payload: dict = Depends(get_current_user),
) -> dict:
    """
    Return the effective permissions for the current user on a given path.
    """
    store = _get_store(request)
    effective, password_required = store.resolve_permissions(payload["sub"], path)
    return {
        "username": payload["sub"],
        "path": path,
        "permissions": effective.to_names(),
        "password_required": password_required is not None,
    }


@router.get("/groups")
def list_groups(
    request: Request,
    payload: dict = Depends(require_admin),
) -> list:
    """
    List all groups and their members. Admin only.
    """
    store = _get_store(request)
    return store.list_groups()


@router.post("/groups/{name}", status_code=status.HTTP_201_CREATED)
def create_group(
    name: str,
    request: Request,
    payload: dict = Depends(require_admin),
) -> dict:
    """
    Create a new empty group. Admin only.
    """
    store = _get_store(request)
    try:
        store.create_group(name)
    except PermissionStoreError as error:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(error))
    return {"detail": f"Group '{name}' created."}


@router.delete("/groups/{name}")
def delete_group(
    name: str,
    request: Request,
    payload: dict = Depends(require_admin),
) -> dict:
    """
    Delete a group. Admin only.
    """
    store = _get_store(request)
    try:
        store.delete_group(name)
    except PermissionStoreError as error:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(error))
    return {"detail": f"Group '{name}' deleted."}


@router.post("/groups/{name}/members", status_code=status.HTTP_201_CREATED)
def add_member(
    name: str,
    body: MemberRequest,
    request: Request,
    payload: dict = Depends(require_admin),
) -> dict:
    """
    Add a user to a group. Admin only.
    """
    store = _get_store(request)
    try:
        store.add_group_member(name, body.username)
    except PermissionStoreError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))
    return {"detail": f"'{body.username}' added to '{name}'."}


@router.delete("/groups/{name}/members/{username}")
def remove_member(
    name: str,
    username: str,
    request: Request,
    payload: dict = Depends(require_admin),
) -> dict:
    """
    Remove a user from a group. Admin only.
    """
    store = _get_store(request)
    try:
        store.remove_group_member(name, username)
    except PermissionStoreError as error:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(error))
    return {"detail": f"'{username}' removed from '{name}'."}
