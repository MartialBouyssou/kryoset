import json
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from kryoset.core.timezone import now_utc, parse_iso, UTC_TZ
from pathlib import Path
from typing import Generator, Optional

import bcrypt

from kryoset.core.permissions import (
    Permission,
    PermissionRule,
    ShareLink,
    TimeWindow,
)

DEFAULT_DB_PATH = Path.home() / ".kryoset" / "permissions.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS groups (
    name        TEXT PRIMARY KEY,
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS group_members (
    group_name  TEXT NOT NULL REFERENCES groups(name) ON DELETE CASCADE,
    username    TEXT NOT NULL,
    PRIMARY KEY (group_name, username)
);

CREATE TABLE IF NOT EXISTS permission_rules (
    rule_id             INTEGER PRIMARY KEY AUTOINCREMENT,
    subject_type        TEXT NOT NULL CHECK (subject_type IN ('user', 'group')),
    subject_id          TEXT NOT NULL,
    path                TEXT NOT NULL,
    permissions         TEXT NOT NULL,
    password_hash       TEXT,
    expires_at          TEXT,
    time_windows        TEXT NOT NULL DEFAULT '[]',
    upload_quota_bytes  INTEGER,
    download_limit      INTEGER,
    ip_whitelist        TEXT NOT NULL DEFAULT '[]',
    ip_blacklist        TEXT NOT NULL DEFAULT '[]',
    can_delegate        INTEGER NOT NULL DEFAULT 0,
    created_at          TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS upload_usage (
    rule_id     INTEGER NOT NULL REFERENCES permission_rules(rule_id) ON DELETE CASCADE,
    username    TEXT NOT NULL,
    bytes_used  INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (rule_id, username)
);

CREATE TABLE IF NOT EXISTS share_links (
    link_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    token           TEXT UNIQUE NOT NULL,
    created_by      TEXT NOT NULL,
    path            TEXT NOT NULL,
    permissions     TEXT NOT NULL,
    expires_at      TEXT,
    download_limit  INTEGER,
    download_count  INTEGER NOT NULL DEFAULT 0,
    password_hash   TEXT,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);
"""


class PermissionStoreError(Exception):
    """Raised when a permission store operation fails."""


class PermissionStore:
    """
    SQLite-backed store for permission rules, groups and share links.

    All datetime values are stored as ISO-8601 UTC strings. Permission
    flags are stored as JSON arrays of flag names.

    Args:
        db_path: Path to the SQLite database file.
    """

    def __init__(self, db_path: Path = DEFAULT_DB_PATH) -> None:
        self._db_path = db_path

    def initialize(self) -> None:
        """Create the database file and apply the schema if needed."""
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(_SCHEMA)

    @contextmanager
    def _connect(self) -> Generator[sqlite3.Connection, None, None]:
        connection = sqlite3.connect(self._db_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _rule_from_row(self, row: sqlite3.Row) -> PermissionRule:
        return PermissionRule(
            rule_id=row["rule_id"],
            subject_type=row["subject_type"],
            subject_id=row["subject_id"],
            path=row["path"],
            permissions=Permission.from_names(json.loads(row["permissions"])),
            password_hash=row["password_hash"],
            expires_at=parse_iso(row["expires_at"]) if row["expires_at"] else None,
            time_windows=[TimeWindow.from_dict(w) for w in json.loads(row["time_windows"])],
            upload_quota_bytes=row["upload_quota_bytes"],
            download_limit=row["download_limit"],
            ip_whitelist=json.loads(row["ip_whitelist"]),
            ip_blacklist=json.loads(row["ip_blacklist"]),
            can_delegate=bool(row["can_delegate"]),
            created_at=parse_iso(row["created_at"]) if row["created_at"] else None,
        )

    def _share_from_row(self, row: sqlite3.Row) -> ShareLink:
        return ShareLink(
            link_id=row["link_id"],
            token=row["token"],
            created_by=row["created_by"],
            path=row["path"],
            permissions=Permission.from_names(json.loads(row["permissions"])),
            expires_at=parse_iso(row["expires_at"]) if row["expires_at"] else None,
            download_limit=row["download_limit"],
            download_count=row["download_count"],
            password_hash=row["password_hash"],
            created_at=parse_iso(row["created_at"]) if row["created_at"] else None,
        )

    def create_group(self, group_name: str) -> None:
        """
        Create a new empty group.

        Args:
            group_name: Unique name for the group.

        Raises:
            PermissionStoreError: If the group already exists.
        """
        try:
            with self._connect() as conn:
                conn.execute("INSERT INTO groups (name) VALUES (?)", (group_name,))
        except sqlite3.IntegrityError:
            raise PermissionStoreError(f"Group '{group_name}' already exists.")

    def delete_group(self, group_name: str) -> None:
        """
        Delete a group and all its members and rules.

        Args:
            group_name: Name of the group to delete.

        Raises:
            PermissionStoreError: If the group does not exist.
        """
        with self._connect() as conn:
            cursor = conn.execute("DELETE FROM groups WHERE name = ?", (group_name,))
            if cursor.rowcount == 0:
                raise PermissionStoreError(f"Group '{group_name}' does not exist.")

    def list_groups(self) -> list[dict]:
        """Return all groups with their member lists."""
        with self._connect() as conn:
            groups = conn.execute("SELECT name FROM groups ORDER BY name").fetchall()
            result = []
            for group in groups:
                members = conn.execute(
                    "SELECT username FROM group_members WHERE group_name = ? ORDER BY username",
                    (group["name"],),
                ).fetchall()
                result.append({
                    "name": group["name"],
                    "members": [m["username"] for m in members],
                })
            return result

    def add_group_member(self, group_name: str, username: str) -> None:
        """
        Add a user to a group.

        Args:
            group_name: Target group.
            username: User to add.

        Raises:
            PermissionStoreError: If the group does not exist or the user is already a member.
        """
        try:
            with self._connect() as conn:
                conn.execute(
                    "INSERT INTO group_members (group_name, username) VALUES (?, ?)",
                    (group_name, username),
                )

                group_rules = conn.execute(
                    """
                    SELECT * FROM permission_rules
                    WHERE subject_type = 'group' AND subject_id = ?
                    """,
                    (group_name,),
                ).fetchall()
                for row in group_rules:
                    self._upsert_user_rule_from_group(conn, username, self._rule_from_row(row))
        except sqlite3.IntegrityError as error:
            if "FOREIGN KEY" in str(error):
                raise PermissionStoreError(f"Group '{group_name}' does not exist.")
            raise PermissionStoreError(
                f"User '{username}' is already a member of '{group_name}'."
            )

    def remove_group_member(self, group_name: str, username: str) -> None:
        """
        Remove a user from a group.

        Args:
            group_name: Target group.
            username: User to remove.

        Raises:
            PermissionStoreError: If the user is not a member of the group.
        """
        with self._connect() as conn:
            cursor = conn.execute(
                "DELETE FROM group_members WHERE group_name = ? AND username = ?",
                (group_name, username),
            )
            if cursor.rowcount == 0:
                raise PermissionStoreError(
                    f"User '{username}' is not a member of '{group_name}'."
                )

    def get_user_groups(self, username: str) -> list[str]:
        """Return the names of all groups the user belongs to."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT group_name FROM group_members WHERE username = ?", (username,)
            ).fetchall()
            return [row["group_name"] for row in rows]

    def add_rule(self, rule: PermissionRule) -> int:
        """
        Insert a new permission rule and return its generated ID.

        Args:
            rule: The rule to insert (``rule_id`` is ignored).

        Returns:
            The new ``rule_id`` assigned by the database.
        """
        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO permission_rules (
                    subject_type, subject_id, path, permissions,
                    password_hash, expires_at, time_windows,
                    upload_quota_bytes, download_limit,
                    ip_whitelist, ip_blacklist, can_delegate
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    rule.subject_type,
                    rule.subject_id,
                    rule.path,
                    json.dumps(rule.permissions.to_names()),
                    rule.password_hash,
                    rule.expires_at.isoformat() if rule.expires_at else None,
                    json.dumps([w.to_dict() for w in rule.time_windows]),
                    rule.upload_quota_bytes,
                    rule.download_limit,
                    json.dumps(rule.ip_whitelist),
                    json.dumps(rule.ip_blacklist),
                    int(rule.can_delegate),
                ),
            )
            rule_id = cursor.lastrowid

            if rule.subject_type == "group":
                members = conn.execute(
                    "SELECT username FROM group_members WHERE group_name = ?",
                    (rule.subject_id,),
                ).fetchall()
                for member in members:
                    self._upsert_user_rule_from_group(conn, member["username"], rule)

            return rule_id

    def _upsert_user_rule_from_group(
        self,
        conn: sqlite3.Connection,
        username: str,
        group_rule: PermissionRule,
    ) -> None:
        """
        Merge a group's rule into the user's direct rules on the same path.

        This materializes group permissions onto users so the user keeps the
        same permissions as the group by default, while still allowing
        user-specific edits later.
        """
        existing = conn.execute(
            """
            SELECT * FROM permission_rules
            WHERE subject_type = 'user' AND subject_id = ? AND path = ?
            ORDER BY rule_id DESC
            LIMIT 1
            """,
            (username, group_rule.path),
        ).fetchone()

        if existing is None:
            conn.execute(
                """
                INSERT INTO permission_rules (
                    subject_type, subject_id, path, permissions,
                    password_hash, expires_at, time_windows,
                    upload_quota_bytes, download_limit,
                    ip_whitelist, ip_blacklist, can_delegate
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "user",
                    username,
                    group_rule.path,
                    json.dumps(group_rule.permissions.to_names()),
                    group_rule.password_hash,
                    group_rule.expires_at.isoformat() if group_rule.expires_at else None,
                    json.dumps([w.to_dict() for w in group_rule.time_windows]),
                    group_rule.upload_quota_bytes,
                    group_rule.download_limit,
                    json.dumps(group_rule.ip_whitelist),
                    json.dumps(group_rule.ip_blacklist),
                    int(group_rule.can_delegate),
                ),
            )
            return

        existing_rule = self._rule_from_row(existing)
        merged_permissions = existing_rule.permissions | group_rule.permissions
        conn.execute(
            "UPDATE permission_rules SET permissions = ? WHERE rule_id = ?",
            (json.dumps(merged_permissions.to_names()), existing_rule.rule_id),
        )

    def remove_rule(self, rule_id: int) -> None:
        """
        Delete a permission rule by ID.

        Raises:
            PermissionStoreError: If the rule does not exist.
        """
        with self._connect() as conn:
            cursor = conn.execute(
                "DELETE FROM permission_rules WHERE rule_id = ?", (rule_id,)
            )
            if cursor.rowcount == 0:
                raise PermissionStoreError(f"Rule #{rule_id} does not exist.")

    def update_rule(self, rule_id: int, rule: PermissionRule) -> None:
        """
        Update an existing permission rule.

        Args:
            rule_id: ID of the rule to update.
            rule: New rule values (its own ``rule_id`` is ignored).

        Raises:
            PermissionStoreError: If the rule does not exist.
        """
        with self._connect() as conn:
            cursor = conn.execute(
                """
                UPDATE permission_rules
                SET subject_type = ?,
                    subject_id = ?,
                    path = ?,
                    permissions = ?,
                    password_hash = ?,
                    expires_at = ?,
                    time_windows = ?,
                    upload_quota_bytes = ?,
                    download_limit = ?,
                    ip_whitelist = ?,
                    ip_blacklist = ?,
                    can_delegate = ?
                WHERE rule_id = ?
                """,
                (
                    rule.subject_type,
                    rule.subject_id,
                    rule.path,
                    json.dumps(rule.permissions.to_names()),
                    rule.password_hash,
                    rule.expires_at.isoformat() if rule.expires_at else None,
                    json.dumps([w.to_dict() for w in rule.time_windows]),
                    rule.upload_quota_bytes,
                    rule.download_limit,
                    json.dumps(rule.ip_whitelist),
                    json.dumps(rule.ip_blacklist),
                    int(rule.can_delegate),
                    rule_id,
                ),
            )
            if cursor.rowcount == 0:
                raise PermissionStoreError(f"Rule #{rule_id} does not exist.")

    def list_rules(self, path_prefix: Optional[str] = None) -> list[PermissionRule]:
        """
        Return all rules, optionally filtered by path prefix.

        Args:
            path_prefix: Only return rules whose path starts with this prefix.
        """
        with self._connect() as conn:
            if path_prefix:
                rows = conn.execute(
                    "SELECT * FROM permission_rules WHERE path LIKE ? ORDER BY rule_id",
                    (path_prefix.rstrip("/") + "%",),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM permission_rules ORDER BY rule_id"
                ).fetchall()
            return [self._rule_from_row(row) for row in rows]

    def get_rules_for_user(self, username: str) -> list[PermissionRule]:
        """
        Return all rules that directly apply to *username* or any of their groups.

        Args:
            username: The authenticated username.
        """
        groups = self.get_user_groups(username)
        with self._connect() as conn:
            placeholders = ",".join("?" * (1 + len(groups)))
            values = [username] + groups
            rows = conn.execute(
                f"""
                SELECT * FROM permission_rules
                WHERE (subject_type = 'user' AND subject_id = ?)
                   OR (subject_type = 'group' AND subject_id IN ({",".join(["?"] * len(groups))}))
                ORDER BY rule_id
                """,
                values,
            ).fetchall()
            return [self._rule_from_row(row) for row in rows]

    def resolve_permissions(
        self,
        username: str,
        path: str,
        ip_address: Optional[str] = None,
        when: Optional[datetime] = None,
    ) -> tuple[Permission, Optional[str]]:
        """
        Compute the effective permissions for *username* on *path*.

        Resolution algorithm:
        1. Collect all rules that match a prefix of *path* (ancestry chain).
        2. For each ancestor path, keep only the most specific rule
           (user rule beats group rule; deeper path beats shallower).
        3. Merge permissions across the ancestry chain — a more specific
           path can only restrict, not expand, what a shallower path grants.
        4. A direct user rule on a path overrides all group rules on the
           same path regardless of depth.

        Args:
            username: Authenticated username.
            path: Absolute path to resolve (e.g. ``"/photos/holiday"``).
            ip_address: Client IP for whitelist/blacklist checks.
            when: Datetime for expiry and time-window checks.

        Returns:
            A tuple of (effective Permission flags, password_hash or None).
            If a password is required, the caller must verify it before
            granting access.
        """
        path = "/" + path.strip("/")
        all_rules = self.get_rules_for_user(username)

        ancestors = self._ancestor_paths(path)
        effective = None
        required_password: Optional[str] = None

        for ancestor in ancestors:
            matching = [
                rule for rule in all_rules
                if rule.path.rstrip("/") == ancestor.rstrip("/")
                and rule.is_currently_effective(ip_address, when)
            ]
            if not matching:
                continue

            best = sorted(
                matching,
                key=lambda r: (r.specificity(), r.rule_id or 0),
                reverse=True,
            )[0]

            if effective is None:
                effective = best.permissions
            elif ancestor == path:
                effective = best.permissions
            else:
                effective = effective & best.permissions

            if best.password_hash:
                required_password = best.password_hash

        return effective if effective is not None else Permission.NONE, required_password

    def _ancestor_paths(self, path: str) -> list[str]:
        """
        Return the chain of ancestor paths from root to *path* (inclusive).

        Example: ``"/a/b/c"`` → ``["/", "/a", "/a/b", "/a/b/c"]``
        """
        parts = path.strip("/").split("/")
        ancestors = ["/"]
        accumulated = ""
        for part in parts:
            if part:
                accumulated += "/" + part
                ancestors.append(accumulated)
        return ancestors

    def get_upload_usage(self, rule_id: int, username: str) -> int:
        """Return the cumulative bytes uploaded by *username* under *rule_id*."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT bytes_used FROM upload_usage WHERE rule_id = ? AND username = ?",
                (rule_id, username),
            ).fetchone()
            return row["bytes_used"] if row else 0

    def record_upload(self, rule_id: int, username: str, bytes_uploaded: int) -> None:
        """
        Add *bytes_uploaded* to the quota counter for *username* under *rule_id*.

        Args:
            rule_id: The permission rule that governs this upload.
            username: The uploader.
            bytes_uploaded: Number of bytes to add.
        """
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO upload_usage (rule_id, username, bytes_used)
                VALUES (?, ?, ?)
                ON CONFLICT (rule_id, username)
                DO UPDATE SET bytes_used = bytes_used + excluded.bytes_used
                """,
                (rule_id, username, bytes_uploaded),
            )

    def create_share_link(
        self,
        created_by: str,
        path: str,
        permissions: Permission,
        expires_at: Optional[datetime] = None,
        download_limit: Optional[int] = None,
        password: Optional[str] = None,
    ) -> ShareLink:
        """
        Generate and persist a new share link.

        Args:
            created_by: Username of the creator.
            path: Path to share.
            permissions: Allowed operations on the shared path.
            expires_at: UTC expiry datetime, or None for no expiry.
            download_limit: Maximum downloads before auto-revocation, or None.
            password: Plain-text password to protect the link, or None.

        Returns:
            The newly created :class:`ShareLink` with its token and ID.
        """
        token = secrets.token_urlsafe(32)
        password_hash = None
        if password:
            password_hash = bcrypt.hashpw(
                password.encode("utf-8"), bcrypt.gensalt()
            ).decode("utf-8")

        with self._connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO share_links (
                    token, created_by, path, permissions,
                    expires_at, download_limit, password_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    token,
                    created_by,
                    path,
                    json.dumps(permissions.to_names()),
                    expires_at.isoformat() if expires_at else None,
                    download_limit,
                    password_hash,
                ),
            )
            link_id = cursor.lastrowid

        return ShareLink(
            link_id=link_id,
            token=token,
            created_by=created_by,
            path=path,
            permissions=permissions,
            expires_at=expires_at,
            download_limit=download_limit,
            password_hash=password_hash,
        )

    def get_share_link(self, token: str) -> Optional[ShareLink]:
        """
        Look up a share link by token.

        Returns:
            The :class:`ShareLink` or None if the token is unknown.
        """
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM share_links WHERE token = ?", (token,)
            ).fetchone()
            return self._share_from_row(row) if row else None

    def list_share_links(self, created_by: Optional[str] = None) -> list[ShareLink]:
        """
        Return share links, optionally filtered by creator.

        Args:
            created_by: If given, return only links created by this user.
        """
        with self._connect() as conn:
            if created_by:
                rows = conn.execute(
                    "SELECT * FROM share_links WHERE created_by = ? ORDER BY link_id",
                    (created_by,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM share_links ORDER BY link_id"
                ).fetchall()
            return [self._share_from_row(row) for row in rows]

    def revoke_share_link(self, token: str) -> None:
        """
        Delete a share link by token.

        Raises:
            PermissionStoreError: If the token is not found.
        """
        with self._connect() as conn:
            cursor = conn.execute(
                "DELETE FROM share_links WHERE token = ?", (token,)
            )
            if cursor.rowcount == 0:
                raise PermissionStoreError(f"Share link '{token}' not found.")

    def increment_share_download(self, token: str) -> None:
        """
        Increment the download counter for a share link.

        Args:
            token: The share link token.
        """
        with self._connect() as conn:
            conn.execute(
                "UPDATE share_links SET download_count = download_count + 1 WHERE token = ?",
                (token,),
            )
