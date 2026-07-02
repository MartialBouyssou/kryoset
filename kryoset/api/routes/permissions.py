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
    storage_max_bytes: Optional[int] = None
    home_path: Optional[str] = None
    auto_generate_user_home: bool = False


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


def _normalize_path(path: str) -> str:
    stripped = path.strip("/")
    return "/" + stripped if stripped else "/"


def _path_contains(parent: str, child: str) -> bool:
    parent = _normalize_path(parent)
    child = _normalize_path(child)
    if parent == "/":
        return True
    return child == parent or child.startswith(parent.rstrip("/") + "/")


def _permissions_subset(requested: Permission, allowed: Permission) -> bool:
    for flag in Permission:
        if flag is Permission.NONE:
            continue
        if flag in requested and flag not in allowed:
            return False
    return True


def _can_delegate_permissions(
    payload: dict,
    request: Request,
    target_path: str,
    requested_permissions: Permission | None = None,
    requested_can_delegate: bool = False,
) -> bool:
    """Return True when user can manage permissions for this exact subtree."""
    if payload.get("admin"):
        return True
    if requested_can_delegate:
        return False
    if requested_permissions and Permission.MANAGE_PERMS in requested_permissions:
        return False

    store = request.app.state.permission_store
    if store is None:
        return False

    for rule in store.get_rules_for_user(payload["sub"]):
        if (
            rule.can_delegate
            and Permission.MANAGE_PERMS in rule.permissions
            and _path_contains(rule.path, target_path)
            and (requested_permissions is None or _permissions_subset(requested_permissions, rule.permissions))
        ):
            return True
    return False


def _ensure_can_delegate(
    payload: dict,
    request: Request,
    target_path: str,
    requested_permissions: Permission | None = None,
    requested_can_delegate: bool = False,
) -> None:
    if not _can_delegate_permissions(
        payload,
        request,
        target_path,
        requested_permissions=requested_permissions,
        requested_can_delegate=requested_can_delegate,
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin or delegated MANAGE_PERMS permission required for this path.",
        )


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

    normalized_path = _normalize_path(body.path)
    _ensure_can_delegate(
        payload,
        request,
        normalized_path,
        requested_permissions=perms,
        requested_can_delegate=body.can_delegate,
    )

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
    store = _get_store(request)

    existing_rule = store.get_rule(rule_id)
    if existing_rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Rule #{rule_id} does not exist.")

    try:
        perms = Permission.from_names(body.permissions)
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))

    if body.subject_type not in ("user", "group"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="subject_type must be 'user' or 'group'.",
        )

    normalized_path = _normalize_path(body.path)
    _ensure_can_delegate(payload, request, existing_rule.path)
    _ensure_can_delegate(
        payload,
        request,
        normalized_path,
        requested_permissions=perms,
        requested_can_delegate=body.can_delegate,
    )

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
    store = _get_store(request)
    existing_rule = store.get_rule(rule_id)
    if existing_rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Rule #{rule_id} does not exist.")
    _ensure_can_delegate(payload, request, existing_rule.path)
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
    groups = store.list_groups()
    storage_manager = request.app.state.storage_manager
    for group in groups:
        group["storage_max_bytes"] = (
            storage_manager.get_allocation(f"group:{group['name']}")
            if storage_manager is not None
            else None
        )
    return groups


@router.post("/groups/{name}", status_code=status.HTTP_201_CREATED)
def create_group(
    name: str,
    request: Request,
    body: GroupCreateRequest | None = None,
    payload: dict = Depends(require_admin),
) -> dict:
    """
    Create a new empty group. Admin only.
    """
    store = _get_store(request)
    storage_manager = request.app.state.storage_manager
    try:
        store.create_group(
            name,
            home_path=body.home_path if body is not None else None,
            home_auto_user_subdir=(
                body.auto_generate_user_home if body is not None else False
            ),
        )
    except PermissionStoreError as error:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(error))
    except ValueError as error:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))

    storage_max_bytes = body.storage_max_bytes if body is not None else None

    if storage_manager is not None and storage_max_bytes is not None:
        from kryoset.core.storage_manager import StorageError

        try:
            storage_manager.set_allocation(f"group:{name}", storage_max_bytes)
        except StorageError as error:
            store.delete_group(name)
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(error))

    response = {"detail": f"Group '{name}' created."}
    if storage_max_bytes is not None:
        response["storage_max_bytes"] = storage_max_bytes
    if body is not None and body.home_path is not None:
        response["home_path"] = body.home_path
        response["auto_generate_user_home"] = body.auto_generate_user_home
    return response


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
    storage_path = request.app.state.configuration.storage_path
    try:
        store.add_group_member(name, body.username, storage_path=storage_path)
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
