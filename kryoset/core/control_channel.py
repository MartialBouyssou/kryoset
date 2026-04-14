import json
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Optional

import bcrypt

from kryoset.core.permission_store import PermissionStore, PermissionStoreError
from kryoset.core.permissions import Permission, PermissionRule

logger = logging.getLogger(__name__)

CONTROL_ROOT = "/.kryoset"
COMMANDS_PATH = f"{CONTROL_ROOT}/commands"
SHARES_PATH = f"{CONTROL_ROOT}/shares"
PERMISSIONS_PATH = f"{CONTROL_ROOT}/permissions"


class ControlChannelError(Exception):
    """Raised when a client-submitted command is malformed or unauthorised."""


class ControlChannel:
    """
    Virtual filesystem channel that lets remote users manage their own
    share links and delegated permissions without server-side shell access.

    The channel intercepts reads and writes on the ``/.kryoset/`` virtual
    directory tree and translates them into :class:`PermissionStore` calls.

    This design makes it straightforward to replace the SFTP channel with
    an HTTP/REST API later: the ``process_command`` and ``read_virtual``
    methods map directly to ``POST /api/commands`` and ``GET /api/*``.

    Args:
        permission_store: The application permission store.
        username: The authenticated user making the request.
        is_admin: Whether the user holds the ``admin`` role.
    """

    def __init__(
        self,
        permission_store: PermissionStore,
        username: str,
        is_admin: bool = False,
    ) -> None:
        self._store = permission_store
        self._username = username
        self._is_admin = is_admin

    def is_virtual_path(self, path: str) -> bool:
        """Return True if *path* lives inside the ``/.kryoset/`` tree."""
        normalized = "/" + path.strip("/")
        return normalized == CONTROL_ROOT or normalized.startswith(CONTROL_ROOT + "/")

    def list_virtual_directory(self, path: str) -> list[dict]:
        """
        Return a listing of virtual entries for a control-channel path.

        Each entry is a dict with ``name``, ``is_dir``, and ``size`` keys,
        matching what the SFTP layer needs to build SFTPAttributes.

        Args:
            path: Virtual path to list (must be inside ``/.kryoset/``).

        Returns:
            List of virtual file/directory descriptors.
        """
        normalized = "/" + path.strip("/")

        if normalized == CONTROL_ROOT:
            return [
                {"name": "commands", "is_dir": True, "size": 0},
                {"name": "shares", "is_dir": True, "size": 0},
                {"name": "permissions", "is_dir": True, "size": 0},
            ]

        if normalized == SHARES_PATH:
            links = self._store.list_share_links(
                created_by=None if self._is_admin else self._username
            )
            return [
                {
                    "name": f"{link.token}.json",
                    "is_dir": False,
                    "size": len(self._share_to_json(link)),
                }
                for link in links
            ]

        if normalized == PERMISSIONS_PATH:
            rules = self._get_delegated_rules()
            return [
                {
                    "name": f"rule_{rule.rule_id}.json",
                    "is_dir": False,
                    "size": len(self._rule_to_json(rule)),
                }
                for rule in rules
            ]

        if normalized == COMMANDS_PATH:
            return []

        return []

    def read_virtual_file(self, path: str) -> bytes:
        """
        Return the content of a virtual read-only file.

        Args:
            path: Virtual path to read.

        Returns:
            UTF-8 encoded JSON bytes.

        Raises:
            ControlChannelError: If the path does not correspond to a readable virtual file.
        """
        normalized = "/" + path.strip("/")

        if normalized.startswith(SHARES_PATH + "/") and normalized.endswith(".json"):
            token = Path(normalized).stem
            link = self._store.get_share_link(token)
            if link is None:
                raise ControlChannelError("Share link not found.")
            if not self._is_admin and link.created_by != self._username:
                raise ControlChannelError("Access denied.")
            return self._share_to_json(link).encode("utf-8")

        if normalized.startswith(PERMISSIONS_PATH + "/") and normalized.endswith(".json"):
            try:
                rule_id = int(Path(normalized).stem.split("_")[1])
            except (IndexError, ValueError):
                raise ControlChannelError("Invalid permission file name.")
            rules = {r.rule_id: r for r in self._get_delegated_rules()}
            if rule_id not in rules:
                raise ControlChannelError("Permission rule not found or access denied.")
            return self._rule_to_json(rules[rule_id]).encode("utf-8")

        raise ControlChannelError(f"No readable virtual file at '{path}'.")

    def process_command(self, raw_json: bytes) -> dict[str, Any]:
        """
        Execute a JSON command uploaded by the client.

        Supported actions (``"action"`` field):
        - ``create_share`` — create a share link
        - ``revoke_share`` — revoke a share link by token
        - ``add_permission`` — add a permission rule (owners and admins only)
        - ``remove_permission`` — remove a rule by ID (owners and admins only)

        Args:
            raw_json: Raw bytes of the uploaded JSON command file.

        Returns:
            A result dict with at least a ``"status"`` key
            (``"ok"`` or ``"error"``) and action-specific fields.

        Raises:
            ControlChannelError: If the JSON is malformed or the action is unknown.
        """
        try:
            command = json.loads(raw_json.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise ControlChannelError(f"Malformed JSON command: {error}")

        action = command.get("action", "").strip()
        logger.info(
            "Control command '%s' from user '%s'.", action, self._username
        )

        handlers = {
            "create_share": self._handle_create_share,
            "revoke_share": self._handle_revoke_share,
            "add_permission": self._handle_add_permission,
            "remove_permission": self._handle_remove_permission,
        }

        handler = handlers.get(action)
        if handler is None:
            raise ControlChannelError(
                f"Unknown action '{action}'. Valid actions: {list(handlers)}"
            )

        return handler(command)

    def _handle_create_share(self, command: dict) -> dict:
        path = command.get("path", "").strip()
        if not path:
            raise ControlChannelError("'path' is required for create_share.")

        self._assert_share_permission(path)

        expires_at = None
        if "expires_in_hours" in command:
            expires_at = datetime.utcnow() + timedelta(hours=float(command["expires_in_hours"]))
        elif "expires_at" in command:
            expires_at = datetime.fromisoformat(command["expires_at"])

        perm_names = command.get("permissions", ["DOWNLOAD"])
        try:
            permissions = Permission.from_names(perm_names)
        except ValueError as error:
            raise ControlChannelError(str(error))

        download_limit = command.get("download_limit")
        password = command.get("password")

        link = self._store.create_share_link(
            created_by=self._username,
            path=path,
            permissions=permissions,
            expires_at=expires_at,
            download_limit=download_limit,
            password=password,
        )

        return {
            "status": "ok",
            "token": link.token,
            "path": link.path,
            "expires_at": link.expires_at.isoformat() if link.expires_at else None,
            "download_limit": link.download_limit,
        }

    def _handle_revoke_share(self, command: dict) -> dict:
        token = command.get("token", "").strip()
        if not token:
            raise ControlChannelError("'token' is required for revoke_share.")

        link = self._store.get_share_link(token)
        if link is None:
            raise ControlChannelError("Share link not found.")
        if not self._is_admin and link.created_by != self._username:
            raise ControlChannelError("Access denied: you did not create this share.")

        self._store.revoke_share_link(token)
        return {"status": "ok", "revoked_token": token}

    def _handle_add_permission(self, command: dict) -> dict:
        if not self._is_admin:
            path = command.get("path", "").strip()
            self._assert_delegate_permission(path)

        subject_type = command.get("subject_type", "").strip()
        subject_id = command.get("subject_id", "").strip()
        path = command.get("path", "").strip()
        perm_names = command.get("permissions", [])

        if subject_type not in ("user", "group"):
            raise ControlChannelError("'subject_type' must be 'user' or 'group'.")
        if not subject_id or not path or not perm_names:
            raise ControlChannelError("'subject_id', 'path' and 'permissions' are required.")

        try:
            permissions = Permission.from_names(perm_names)
        except ValueError as error:
            raise ControlChannelError(str(error))

        expires_at = None
        if "expires_in_hours" in command:
            expires_at = datetime.utcnow() + timedelta(hours=float(command["expires_in_hours"]))
        elif "expires_at" in command:
            expires_at = datetime.fromisoformat(command["expires_at"])

        password = command.get("password")
        password_hash = None
        if password:
            password_hash = bcrypt.hashpw(
                password.encode("utf-8"), bcrypt.gensalt()
            ).decode("utf-8")

        rule = PermissionRule(
            subject_type=subject_type,
            subject_id=subject_id,
            path=path,
            permissions=permissions,
            password_hash=password_hash,
            expires_at=expires_at,
            can_delegate=bool(command.get("can_delegate", False)),
            upload_quota_bytes=command.get("upload_quota_bytes"),
            download_limit=command.get("download_limit"),
            ip_whitelist=command.get("ip_whitelist", []),
            ip_blacklist=command.get("ip_blacklist", []),
        )

        rule_id = self._store.add_rule(rule)
        return {"status": "ok", "rule_id": rule_id}

    def _handle_remove_permission(self, command: dict) -> dict:
        rule_id = command.get("rule_id")
        if rule_id is None:
            raise ControlChannelError("'rule_id' is required for remove_permission.")

        if not self._is_admin:
            delegated_ids = {r.rule_id for r in self._get_delegated_rules()}
            if rule_id not in delegated_ids:
                raise ControlChannelError("Access denied: rule is outside your delegated zone.")

        try:
            self._store.remove_rule(rule_id)
        except PermissionStoreError as error:
            raise ControlChannelError(str(error))

        return {"status": "ok", "removed_rule_id": rule_id}

    def _assert_share_permission(self, path: str) -> None:
        """Raise ControlChannelError if the user cannot share *path*."""
        if self._is_admin:
            return
        effective, _ = self._store.resolve_permissions(self._username, path)
        if Permission.SHARE not in effective:
            raise ControlChannelError(
                f"You do not have SHARE permission on '{path}'."
            )

    def _assert_delegate_permission(self, path: str) -> None:
        """Raise ControlChannelError if the user cannot manage perms on *path*."""
        if self._is_admin:
            return
        effective, _ = self._store.resolve_permissions(self._username, path)
        if Permission.MANAGE_PERMS not in effective:
            raise ControlChannelError(
                f"You do not have MANAGE_PERMS permission on '{path}'."
            )

    def _get_delegated_rules(self) -> list[PermissionRule]:
        """Return rules the current user is allowed to manage."""
        if self._is_admin:
            return self._store.list_rules()
        all_rules = self._store.list_rules()
        return [r for r in all_rules if r.can_delegate and r.subject_id == self._username]

    def _share_to_json(self, link) -> str:
        return json.dumps(
            {
                "token": link.token,
                "path": link.path,
                "permissions": link.permissions.to_names(),
                "expires_at": link.expires_at.isoformat() if link.expires_at else None,
                "download_limit": link.download_limit,
                "download_count": link.download_count,
                "created_by": link.created_by,
                "created_at": link.created_at.isoformat() if link.created_at else None,
            },
            indent=2,
        )

    def _rule_to_json(self, rule: PermissionRule) -> str:
        return json.dumps(
            {
                "rule_id": rule.rule_id,
                "subject_type": rule.subject_type,
                "subject_id": rule.subject_id,
                "path": rule.path,
                "permissions": rule.permissions.to_names(),
                "expires_at": rule.expires_at.isoformat() if rule.expires_at else None,
                "can_delegate": rule.can_delegate,
                "upload_quota_bytes": rule.upload_quota_bytes,
                "download_limit": rule.download_limit,
            },
            indent=2,
        )
