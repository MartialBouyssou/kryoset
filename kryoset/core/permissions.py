import enum
import ipaddress
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


class Permission(enum.Flag):
    """
    Individual permission flags that can be combined freely.

    Each flag controls one specific action. Combine them with the pipe
    operator: ``Permission.DOWNLOAD | Permission.UPLOAD``.
    """

    NONE = 0
    LIST = enum.auto()
    PREVIEW = enum.auto()
    DOWNLOAD = enum.auto()
    UPLOAD = enum.auto()
    COPY = enum.auto()
    RENAME = enum.auto()
    MOVE = enum.auto()
    DELETE = enum.auto()
    MANAGE_PERMS = enum.auto()
    SHARE = enum.auto()

    @classmethod
    def from_names(cls, names: list[str]) -> "Permission":
        """
        Build a combined Permission from a list of flag name strings.

        Args:
            names: List of flag names, e.g. ``["DOWNLOAD", "UPLOAD"]``.

        Returns:
            Combined :class:`Permission` flag value.

        Raises:
            ValueError: If any name is not a valid Permission flag.
        """
        result = cls.NONE
        for name in names:
            try:
                result |= cls[name.upper()]
            except KeyError:
                raise ValueError(
                    f"Unknown permission '{name}'. "
                    f"Valid values: {[f.name for f in cls if f != cls.NONE]}"
                )
        return result

    def to_names(self) -> list[str]:
        """Return the list of active flag names for this value."""
        return [flag.name for flag in Permission if flag in self and flag != Permission.NONE]


PRESET_READ_ONLY = Permission.LIST | Permission.PREVIEW | Permission.DOWNLOAD
PRESET_CONTRIBUTOR = PRESET_READ_ONLY | Permission.UPLOAD | Permission.COPY
PRESET_EDITOR = PRESET_CONTRIBUTOR | Permission.RENAME | Permission.MOVE
PRESET_FULL = PRESET_EDITOR | Permission.DELETE | Permission.SHARE
PRESET_OWNER = PRESET_FULL | Permission.MANAGE_PERMS


@dataclass
class TimeWindow:
    """
    A recurring weekly time window during which a rule is active.

    Args:
        days: List of ISO weekday numbers (1=Monday … 7=Sunday).
        hour_from: Start hour (0–23, inclusive).
        hour_to: End hour (0–23, inclusive).
    """

    days: list[int]
    hour_from: int
    hour_to: int

    def is_active_now(self, when: Optional[datetime] = None) -> bool:
        """
        Return True if *when* (default: now) falls inside this window.

        Args:
            when: Datetime to check. Defaults to the current local time.
        """
        now = when or datetime.now()
        return now.isoweekday() in self.days and self.hour_from <= now.hour <= self.hour_to

    def to_dict(self) -> dict:
        return {"days": self.days, "hour_from": self.hour_from, "hour_to": self.hour_to}

    @classmethod
    def from_dict(cls, data: dict) -> "TimeWindow":
        return cls(
            days=data["days"],
            hour_from=data["hour_from"],
            hour_to=data["hour_to"],
        )


@dataclass
class PermissionRule:
    """
    A single access-control rule stored in the database.

    A rule grants a set of :class:`Permission` flags to one subject
    (a user or a group) on one storage path. Optional constraints
    (expiry, time windows, IP filters, quota, download limit, password)
    can further restrict when the rule is effective.

    Args:
        rule_id: Database primary key (None before first save).
        subject_type: ``"user"`` or ``"group"``.
        subject_id: Username or group name.
        path: Absolute storage path the rule applies to (e.g. ``"/photos"``).
        permissions: Combined permission flags.
        password_hash: bcrypt hash required before access, or None.
        expires_at: UTC datetime after which the rule is inactive, or None.
        time_windows: List of recurring windows during which the rule is active.
            Empty list means always active.
        upload_quota_bytes: Maximum cumulative upload in bytes, or None.
        download_limit: Maximum number of individual downloads, or None.
        ip_whitelist: If non-empty, only these IPs/CIDRs may use this rule.
        ip_blacklist: IPs/CIDRs that are always denied, regardless of whitelist.
        can_delegate: Whether the subject may grant sub-permissions inside *path*.
        created_at: Creation timestamp.
    """

    subject_type: str
    subject_id: str
    path: str
    permissions: Permission
    rule_id: Optional[int] = None
    password_hash: Optional[str] = None
    expires_at: Optional[datetime] = None
    time_windows: list[TimeWindow] = field(default_factory=list)
    upload_quota_bytes: Optional[int] = None
    download_limit: Optional[int] = None
    ip_whitelist: list[str] = field(default_factory=list)
    ip_blacklist: list[str] = field(default_factory=list)
    can_delegate: bool = False
    created_at: Optional[datetime] = None

    def is_expired(self, when: Optional[datetime] = None) -> bool:
        """Return True if the rule has passed its expiry date."""
        if self.expires_at is None:
            return False
        return (when or datetime.utcnow()) > self.expires_at

    def is_time_window_active(self, when: Optional[datetime] = None) -> bool:
        """Return True if no time windows are set or at least one is currently active."""
        if not self.time_windows:
            return True
        return any(window.is_active_now(when) for window in self.time_windows)

    def is_ip_allowed(self, ip_address: str) -> bool:
        """
        Return True if the given IP is permitted by the white/blacklists.

        Args:
            ip_address: Dotted-decimal IPv4 or IPv6 address string.
        """
        try:
            client_ip = ipaddress.ip_address(ip_address)
        except ValueError:
            return False

        for blacklisted in self.ip_blacklist:
            if client_ip in ipaddress.ip_network(blacklisted, strict=False):
                return False

        if not self.ip_whitelist:
            return True

        for whitelisted in self.ip_whitelist:
            if client_ip in ipaddress.ip_network(whitelisted, strict=False):
                return True

        return False

    def is_currently_effective(
        self, ip_address: Optional[str] = None, when: Optional[datetime] = None
    ) -> bool:
        """
        Return True if this rule is currently active (not expired, in time
        window, and IP is allowed).

        Args:
            ip_address: Client IP to check against white/blacklists.
            when: Datetime to use for expiry and time-window checks.
        """
        if self.is_expired(when):
            return False
        if not self.is_time_window_active(when):
            return False
        if ip_address and not self.is_ip_allowed(ip_address):
            return False
        return True

    def specificity(self) -> tuple:
        """
        Return a sort key: user rules beat group rules; deeper paths beat
        shallower ones.

        Higher tuple values are resolved first.
        """
        subject_priority = 1 if self.subject_type == "user" else 0
        path_depth = self.path.rstrip("/").count("/")
        return (subject_priority, path_depth)


@dataclass
class ShareLink:
    """
    A time-limited, token-based access grant for one path.

    Share links allow unauthenticated (or differently-authenticated) access
    to a specific file or directory without requiring a Kryoset account.

    Args:
        token: Cryptographically random URL-safe token.
        created_by: Username of the share creator.
        path: Absolute storage path this link grants access to.
        permissions: Allowed operations (typically DOWNLOAD only).
        expires_at: UTC datetime after which the link is invalid, or None.
        download_limit: Max number of downloads before auto-revocation, or None.
        download_count: Current download counter.
        password_hash: bcrypt hash required to use the link, or None.
        link_id: Database primary key (None before first save).
        created_at: Creation timestamp.
    """

    token: str
    created_by: str
    path: str
    permissions: Permission
    expires_at: Optional[datetime] = None
    download_limit: Optional[int] = None
    download_count: int = 0
    password_hash: Optional[str] = None
    link_id: Optional[int] = None
    created_at: Optional[datetime] = None

    def is_valid(self, when: Optional[datetime] = None) -> bool:
        """Return True if the link has not expired and the download limit is not reached."""
        if self.expires_at and (when or datetime.utcnow()) > self.expires_at:
            return False
        if self.download_limit is not None and self.download_count >= self.download_limit:
            return False
        return True
