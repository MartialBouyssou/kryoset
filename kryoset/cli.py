"""
Command-line interface for Kryoset.

Provides subcommands to initialise the server, manage users and start or
stop the SFTP daemon. All commands read from (and write to) the
configuration file located at ``~/.kryoset/config.json`` by default.

Usage examples::

    kryoset init /mnt/my_disk
    kryoset user add alice
    kryoset user list
    kryoset user remove alice
    kryoset user disable alice
    kryoset user enable alice
    kryoset user reset-password alice
    kryoset start
"""

import getpass
import logging
import sys
from pathlib import Path

import click

from kryoset import __version__
from kryoset.core.configuration import Configuration, ConfigurationError
from kryoset.core.sftp_server import SFTPServer
from kryoset.core.user_manager import UserError, UserManager

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)


def _load_config(config_path: str | None = None) -> Configuration:
    """Load and return a validated configuration, exiting on error."""
    path = Path(config_path) if config_path else None
    configuration = Configuration(path) if path else Configuration()
    try:
        configuration.load()
        configuration.validate()
    except ConfigurationError as error:
        click.echo(f"[error] {error}", err=True)
        sys.exit(1)
    return configuration


@click.group()
@click.version_option(__version__, prog_name="kryoset")
def cli() -> None:
    """Kryoset — secure self-hosted NAS over SFTP."""


@cli.command()
@click.argument("storage_path", type=click.Path(exists=True, file_okay=False))
@click.option("--port", default=2222, show_default=True, help="SFTP listening port.")
@click.option(
    "--config",
    default=None,
    help="Custom path for the configuration file.",
)
def init(storage_path: str, port: int, config: str | None) -> None:
    """
    Initialise a new Kryoset server.

    STORAGE_PATH is the directory (disk or partition mount point) whose
    contents will be shared over SFTP.
    """
    path = Path(config) if config else None
    configuration = Configuration(path) if path else Configuration()
    configuration.initialize(storage_path=storage_path, port=port)
    click.echo(f"[ok] Configuration created at {configuration.config_path}")
    click.echo(f"     Storage : {storage_path}")
    click.echo(f"     Port    : {port}")
    click.echo("Run 'kryoset user add <username>' to create the first user.")


@cli.command()
@click.option("--config", default=None, help="Path to the configuration file.")
def start(config: str | None) -> None:
    """Start the Kryoset SFTP server (blocking)."""
    configuration = _load_config(config)
    user_manager = UserManager(configuration)
    if not user_manager.list_users():
        click.echo(
            "[warning] No users configured. Add one with 'kryoset user add <name>'.",
            err=True,
        )
    server = SFTPServer(configuration, user_manager)
    try:
        server.start()
    except KeyboardInterrupt:
        click.echo("\n[info] Server stopped by user.")


@cli.group()
def user() -> None:
    """Manage Kryoset user accounts."""


@user.command("add")
@click.argument("username")
@click.option("--config", default=None, help="Path to the configuration file.")
def user_add(username: str, config: str | None) -> None:
    """Add a new user USERNAME to the server."""
    configuration = _load_config(config)
    user_manager = UserManager(configuration)
    password = getpass.getpass(f"Password for '{username}': ")
    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        click.echo("[error] Passwords do not match.", err=True)
        sys.exit(1)
    try:
        user_manager.add_user(username, password)
        click.echo(f"[ok] User '{username}' created.")
    except UserError as error:
        click.echo(f"[error] {error}", err=True)
        sys.exit(1)


@user.command("remove")
@click.argument("username")
@click.option("--config", default=None, help="Path to the configuration file.")
def user_remove(username: str, config: str | None) -> None:
    """Remove user USERNAME from the server."""
    configuration = _load_config(config)
    user_manager = UserManager(configuration)
    try:
        user_manager.remove_user(username)
        click.echo(f"[ok] User '{username}' removed.")
    except UserError as error:
        click.echo(f"[error] {error}", err=True)
        sys.exit(1)


@user.command("list")
@click.option("--config", default=None, help="Path to the configuration file.")
def user_list(config: str | None) -> None:
    """List all registered users."""
    configuration = _load_config(config)
    user_manager = UserManager(configuration)
    users = user_manager.list_users()
    if not users:
        click.echo("No users registered.")
        return
    click.echo(f"{'Username':<20} {'Status'}")
    click.echo("-" * 30)
    for entry in users:
        status = "enabled" if entry["enabled"] else "disabled"
        click.echo(f"{entry['username']:<20} {status}")


@user.command("enable")
@click.argument("username")
@click.option("--config", default=None, help="Path to the configuration file.")
def user_enable(username: str, config: str | None) -> None:
    """Enable a previously disabled user account."""
    configuration = _load_config(config)
    user_manager = UserManager(configuration)
    try:
        user_manager.set_enabled(username, enabled=True)
        click.echo(f"[ok] User '{username}' enabled.")
    except UserError as error:
        click.echo(f"[error] {error}", err=True)
        sys.exit(1)


@user.command("disable")
@click.argument("username")
@click.option("--config", default=None, help="Path to the configuration file.")
def user_disable(username: str, config: str | None) -> None:
    """Disable a user account without deleting it."""
    configuration = _load_config(config)
    user_manager = UserManager(configuration)
    try:
        user_manager.set_enabled(username, enabled=False)
        click.echo(f"[ok] User '{username}' disabled.")
    except UserError as error:
        click.echo(f"[error] {error}", err=True)
        sys.exit(1)


@user.command("reset-password")
@click.argument("username")
@click.option("--config", default=None, help="Path to the configuration file.")
def user_reset_password(username: str, config: str | None) -> None:
    """Generate a new random password for USERNAME."""
    configuration = _load_config(config)
    user_manager = UserManager(configuration)
    try:
        temporary_password = user_manager.generate_temporary_password(username)
        click.echo(f"[ok] New password for '{username}': {temporary_password}")
        click.echo("[warning] Share this password securely and ask the user to change it.")
    except UserError as error:
        click.echo(f"[error] {error}", err=True)
        sys.exit(1)


@user.command("change-password")
@click.argument("username")
@click.option("--config", default=None, help="Path to the configuration file.")
def user_change_password(username: str, config: str | None) -> None:
    """Change the password of an existing user."""
    configuration = _load_config(config)
    user_manager = UserManager(configuration)
    password = getpass.getpass(f"New password for '{username}': ")
    confirm = getpass.getpass("Confirm new password: ")
    if password != confirm:
        click.echo("[error] Passwords do not match.", err=True)
        sys.exit(1)
    try:
        user_manager.change_password(username, password)
        click.echo(f"[ok] Password for '{username}' updated.")
    except UserError as error:
        click.echo(f"[error] {error}", err=True)
        sys.exit(1)


@cli.command()
@click.option("--lines", "-n", default=50, show_default=True, help="Number of lines to show.")
@click.option("--follow", "-f", is_flag=True, help="Follow the log in real time (like tail -f).")
@click.option("--filter", "event_filter", default=None, help="Show only lines containing this text (e.g. AUTH_FAILURE).")
def logs(lines: int, follow: bool, event_filter: str | None) -> None:
    """Display the Kryoset audit log."""
    from kryoset.core.audit_logger import LOG_DIRECTORY
    import time

    log_file = LOG_DIRECTORY / "kryoset.log"
    if not log_file.exists():
        click.echo("[info] No audit log found yet. Start the server and connect to generate logs.")
        return

    def _matches(line: str) -> bool:
        if event_filter is None:
            return True
        return event_filter.upper() in line.upper()

    if not follow:
        all_lines = log_file.read_text(encoding="utf-8").splitlines()
        filtered = [line for line in all_lines if _matches(line)]
        for line in filtered[-lines:]:
            click.echo(line)
        return

    with open(log_file, "r", encoding="utf-8") as log_handle:
        log_handle.seek(0, 2)
        click.echo("[info] Following audit log — press Ctrl-C to stop.")
        try:
            while True:
                line = log_handle.readline()
                if line:
                    if _matches(line):
                        click.echo(line, nl=False)
                else:
                    time.sleep(0.25)
        except KeyboardInterrupt:
            click.echo("\n[info] Stopped.")


def main() -> None:
    """Entry point registered in pyproject.toml."""
    cli()


if __name__ == "__main__":
    main()


@cli.group()
def group() -> None:
    """Manage Kryoset groups."""


@group.command("create")
@click.argument("group_name")
@click.option("--config", default=None)
def group_create(group_name: str, config: str | None) -> None:
    """Create a new empty group GROUP_NAME."""
    from kryoset.core.permission_store import PermissionStore, PermissionStoreError
    store = PermissionStore()
    store.initialize()
    try:
        store.create_group(group_name)
        click.echo(f"[ok] Group '{group_name}' created.")
    except PermissionStoreError as error:
        click.echo(f"[error] {error}", err=True)
        raise SystemExit(1)


@group.command("delete")
@click.argument("group_name")
def group_delete(group_name: str) -> None:
    """Delete group GROUP_NAME and all its rules."""
    from kryoset.core.permission_store import PermissionStore, PermissionStoreError
    store = PermissionStore()
    store.initialize()
    try:
        store.delete_group(group_name)
        click.echo(f"[ok] Group '{group_name}' deleted.")
    except PermissionStoreError as error:
        click.echo(f"[error] {error}", err=True)
        raise SystemExit(1)


@group.command("list")
def group_list() -> None:
    """List all groups and their members."""
    from kryoset.core.permission_store import PermissionStore
    store = PermissionStore()
    store.initialize()
    groups = store.list_groups()
    if not groups:
        click.echo("No groups.")
        return
    for grp in groups:
        members = ", ".join(grp["members"]) if grp["members"] else "(empty)"
        click.echo(f"  {grp['name']}: {members}")


@group.command("add-member")
@click.argument("group_name")
@click.argument("username")
def group_add_member(group_name: str, username: str) -> None:
    """Add USERNAME to GROUP_NAME."""
    from kryoset.core.permission_store import PermissionStore, PermissionStoreError
    store = PermissionStore()
    store.initialize()
    try:
        store.add_group_member(group_name, username)
        click.echo(f"[ok] '{username}' added to '{group_name}'.")
    except PermissionStoreError as error:
        click.echo(f"[error] {error}", err=True)
        raise SystemExit(1)


@group.command("remove-member")
@click.argument("group_name")
@click.argument("username")
def group_remove_member(group_name: str, username: str) -> None:
    """Remove USERNAME from GROUP_NAME."""
    from kryoset.core.permission_store import PermissionStore, PermissionStoreError
    store = PermissionStore()
    store.initialize()
    try:
        store.remove_group_member(group_name, username)
        click.echo(f"[ok] '{username}' removed from '{group_name}'.")
    except PermissionStoreError as error:
        click.echo(f"[error] {error}", err=True)
        raise SystemExit(1)


@cli.group()
def perm() -> None:
    """Manage path permissions."""


@perm.command("add")
@click.option("--path", required=True, help="Storage path (e.g. /photos).")
@click.option("--user", "subject_user", default=None, help="Grant to this user.")
@click.option("--group", "subject_group", default=None, help="Grant to this group.")
@click.option("--permissions", "-p", required=True, multiple=True,
              help="Permission flags: LIST, PREVIEW, DOWNLOAD, UPLOAD, COPY, RENAME, MOVE, DELETE, MANAGE_PERMS, SHARE.")
@click.option("--expires", default=None, help="Expiry: ISO date or e.g. '24h', '7d'.")
@click.option("--password", is_flag=True, default=False, help="Prompt for a path password.")
@click.option("--quota", default=None, help="Upload quota, e.g. 500MB, 2GB.")
@click.option("--download-limit", default=None, type=int, help="Max downloads.")
@click.option("--ip-whitelist", default=None, help="Comma-separated allowed IPs/CIDRs.")
@click.option("--ip-blacklist", default=None, help="Comma-separated denied IPs/CIDRs.")
@click.option("--can-delegate", is_flag=True, default=False, help="Allow subject to manage sub-perms.")
@click.option("--hours", default=None, help="Active hours, e.g. 'mon-fri:09-18'.")
def perm_add(path, subject_user, subject_group, permissions, expires, password,
             quota, download_limit, ip_whitelist, ip_blacklist, can_delegate, hours) -> None:
    """Add a permission rule on PATH."""
    import re
    from datetime import datetime, timedelta
    import bcrypt as _bcrypt
    from kryoset.core.permission_store import PermissionStore
    from kryoset.core.permissions import Permission, PermissionRule, TimeWindow

    if not subject_user and not subject_group:
        click.echo("[error] Specify --user or --group.", err=True)
        raise SystemExit(1)
    if subject_user and subject_group:
        click.echo("[error] Specify only one of --user or --group.", err=True)
        raise SystemExit(1)

    subject_type = "user" if subject_user else "group"
    subject_id = subject_user or subject_group

    try:
        perm_flags = Permission.from_names(list(permissions))
    except ValueError as error:
        click.echo(f"[error] {error}", err=True)
        raise SystemExit(1)

    expires_at = None
    if expires:
        match = re.fullmatch(r"(\d+)([hd])", expires.strip())
        if match:
            amount, unit = int(match.group(1)), match.group(2)
            delta = timedelta(hours=amount) if unit == "h" else timedelta(days=amount)
            expires_at = datetime.utcnow() + delta
        else:
            expires_at = datetime.fromisoformat(expires)

    password_hash = None
    if password:
        pwd = getpass.getpass("Path password: ")
        confirm = getpass.getpass("Confirm: ")
        if pwd != confirm:
            click.echo("[error] Passwords do not match.", err=True)
            raise SystemExit(1)
        password_hash = _bcrypt.hashpw(pwd.encode(), _bcrypt.gensalt()).decode()

    quota_bytes = None
    if quota:
        match = re.fullmatch(r"(\d+(?:\.\d+)?)\s*(MB|GB|KB|B)", quota.upper())
        if not match:
            click.echo("[error] Invalid quota format. Use e.g. 500MB or 2GB.", err=True)
            raise SystemExit(1)
        amount = float(match.group(1))
        unit_map = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3}
        quota_bytes = int(amount * unit_map[match.group(2)])

    time_windows = []
    if hours:
        day_map = {"mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6, "sun": 7}
        try:
            days_part, hours_part = hours.lower().split(":")
            if "-" in days_part:
                start_day, end_day = days_part.split("-")
                start_n, end_n = day_map[start_day], day_map[end_day]
                days = list(range(start_n, end_n + 1))
            else:
                days = [day_map[days_part]]
            hour_from, hour_to = map(int, hours_part.split("-"))
            time_windows = [TimeWindow(days=days, hour_from=hour_from, hour_to=hour_to)]
        except (KeyError, ValueError):
            click.echo("[error] Invalid --hours format. Use e.g. 'mon-fri:09-18'.", err=True)
            raise SystemExit(1)

    rule = PermissionRule(
        subject_type=subject_type,
        subject_id=subject_id,
        path=path,
        permissions=perm_flags,
        password_hash=password_hash,
        expires_at=expires_at,
        time_windows=time_windows,
        upload_quota_bytes=quota_bytes,
        download_limit=download_limit,
        ip_whitelist=[ip.strip() for ip in ip_whitelist.split(",")] if ip_whitelist else [],
        ip_blacklist=[ip.strip() for ip in ip_blacklist.split(",")] if ip_blacklist else [],
        can_delegate=can_delegate,
    )

    store = PermissionStore()
    store.initialize()
    rule_id = store.add_rule(rule)
    click.echo(f"[ok] Rule #{rule_id} added: {subject_type} '{subject_id}' → {path} [{', '.join(perm_flags.to_names())}]")


@perm.command("list")
@click.option("--path", default=None, help="Filter by path prefix.")
def perm_list(path: str | None) -> None:
    """List permission rules."""
    from kryoset.core.permission_store import PermissionStore
    store = PermissionStore()
    store.initialize()
    rules = store.list_rules(path_prefix=path)
    if not rules:
        click.echo("No rules found.")
        return
    click.echo(f"{'#':<5} {'Type':<6} {'Subject':<15} {'Path':<20} {'Permissions':<40} {'Expires'}")
    click.echo("-" * 100)
    for rule in rules:
        expires = rule.expires_at.strftime("%Y-%m-%d") if rule.expires_at else "never"
        perms = ", ".join(rule.permissions.to_names()) or "NONE"
        click.echo(
            f"{rule.rule_id:<5} {rule.subject_type:<6} {rule.subject_id:<15} "
            f"{rule.path:<20} {perms:<40} {expires}"
        )


@perm.command("remove")
@click.argument("rule_id", type=int)
def perm_remove(rule_id: int) -> None:
    """Remove permission rule RULE_ID."""
    from kryoset.core.permission_store import PermissionStore, PermissionStoreError
    store = PermissionStore()
    store.initialize()
    try:
        store.remove_rule(rule_id)
        click.echo(f"[ok] Rule #{rule_id} removed.")
    except PermissionStoreError as error:
        click.echo(f"[error] {error}", err=True)
        raise SystemExit(1)


@perm.command("check")
@click.argument("username")
@click.argument("path")
def perm_check(username: str, path: str) -> None:
    """Show effective permissions for USERNAME on PATH."""
    from kryoset.core.permission_store import PermissionStore
    store = PermissionStore()
    store.initialize()
    effective, password_required = store.resolve_permissions(username, path)
    perms = ", ".join(effective.to_names()) or "NONE"
    click.echo(f"User '{username}' on '{path}': [{perms}]")
    if password_required:
        click.echo("  ⚠ A path password is required.")


@cli.group()
def share() -> None:
    """Manage share links (server-side admin)."""


@share.command("create")
@click.option("--path", required=True, help="Path to share.")
@click.option("--user", "created_by", required=True, help="Creator username.")
@click.option("--expires", default=None, help="e.g. '24h', '7d' or ISO datetime.")
@click.option("--download-limit", default=None, type=int, help="Max downloads.")
@click.option("--permissions", "-p", multiple=True, default=["DOWNLOAD"])
@click.option("--password", is_flag=True, default=False, help="Prompt for link password.")
def share_create(path, created_by, expires, download_limit, permissions, password) -> None:
    """Create a share link for PATH (admin, server-side)."""
    import re
    from datetime import datetime, timedelta
    import bcrypt as _bcrypt
    from kryoset.core.permission_store import PermissionStore
    from kryoset.core.permissions import Permission

    try:
        perm_flags = Permission.from_names(list(permissions))
    except ValueError as error:
        click.echo(f"[error] {error}", err=True)
        raise SystemExit(1)

    expires_at = None
    if expires:
        match = re.fullmatch(r"(\d+)([hd])", expires.strip())
        if match:
            amount, unit = int(match.group(1)), match.group(2)
            delta = timedelta(hours=amount) if unit == "h" else timedelta(days=amount)
            expires_at = datetime.utcnow() + delta
        else:
            expires_at = datetime.fromisoformat(expires)

    plain_password = None
    if password:
        plain_password = getpass.getpass("Link password: ")

    store = PermissionStore()
    store.initialize()
    link = store.create_share_link(
        created_by=created_by,
        path=path,
        permissions=perm_flags,
        expires_at=expires_at,
        download_limit=download_limit,
        password=plain_password,
    )
    click.echo(f"[ok] Share created.")
    click.echo(f"     Token   : {link.token}")
    click.echo(f"     Path    : {link.path}")
    click.echo(f"     Expires : {link.expires_at or 'never'}")
    click.echo(f"     DL limit: {link.download_limit or 'unlimited'}")


@share.command("list")
@click.option("--user", "created_by", default=None, help="Filter by creator.")
def share_list(created_by: str | None) -> None:
    """List active share links."""
    from kryoset.core.permission_store import PermissionStore
    store = PermissionStore()
    store.initialize()
    links = store.list_share_links(created_by=created_by)
    if not links:
        click.echo("No share links.")
        return
    for link in links:
        status = "valid" if link.is_valid() else "expired/exhausted"
        click.echo(
            f"  [{status}] {link.token[:16]}… → {link.path} "
            f"(by {link.created_by}, {link.download_count}/{link.download_limit or '∞'} DL)"
        )


@share.command("revoke")
@click.argument("token")
def share_revoke(token: str) -> None:
    """Revoke a share link by TOKEN."""
    from kryoset.core.permission_store import PermissionStore, PermissionStoreError
    store = PermissionStore()
    store.initialize()
    try:
        store.revoke_share_link(token)
        click.echo(f"[ok] Share link '{token}' revoked.")
    except PermissionStoreError as error:
        click.echo(f"[error] {error}", err=True)
        raise SystemExit(1)


@user.command("set-admin")
@click.argument("username")
@click.option("--revoke", is_flag=True, default=False, help="Revoke admin instead of granting.")
@click.option("--config", default=None)
def user_set_admin(username: str, revoke: bool, config: str | None) -> None:
    """Grant or revoke admin role for USERNAME."""
    configuration = _load_config(config)
    user_manager = UserManager(configuration)
    try:
        user_manager.set_admin(username, admin=not revoke)
        action = "revoked from" if revoke else "granted to"
        click.echo(f"[ok] Admin role {action} '{username}'.")
    except UserError as error:
        click.echo(f"[error] {error}", err=True)
        raise SystemExit(1)


@user.group("totp")
def user_totp() -> None:
    """Manage TOTP two-factor authentication for a user."""


@user_totp.command("setup")
@click.argument("username")
@click.option("--config", default=None)
def totp_setup(username: str, config: str | None) -> None:
    """Generate a TOTP secret for USERNAME and display the QR code URI."""
    from kryoset.core.totp import TOTPManager, TOTPError
    configuration = _load_config(config)
    user_manager = UserManager(configuration)
    totp = TOTPManager(user_manager)
    try:
        secret = totp.generate_secret(username)
        uri = totp.get_provisioning_uri(username)
        click.echo(f"[ok] TOTP secret generated for '{username}'.")
        click.echo(f"     Secret : {secret}")
        click.echo(f"     URI    : {uri}")
        click.echo("")
        click.echo("Scan the URI with your authenticator app, then run:")
        click.echo(f"  kryoset user totp confirm {username} <code>")
    except TOTPError as error:
        click.echo(f"[error] {error}", err=True)
        raise SystemExit(1)


@user_totp.command("confirm")
@click.argument("username")
@click.argument("code")
@click.option("--config", default=None)
def totp_confirm(username: str, code: str, config: str | None) -> None:
    """Confirm TOTP setup for USERNAME with a 6-digit CODE from the app."""
    from kryoset.core.totp import TOTPManager, TOTPError
    configuration = _load_config(config)
    user_manager = UserManager(configuration)
    totp = TOTPManager(user_manager)
    try:
        totp.confirm_setup(username, code)
        click.echo(f"[ok] TOTP enabled for '{username}'. Two-factor auth is now active.")
    except TOTPError as error:
        click.echo(f"[error] {error}", err=True)
        raise SystemExit(1)


@user_totp.command("disable")
@click.argument("username")
@click.option("--config", default=None)
def totp_disable(username: str, config: str | None) -> None:
    """Disable TOTP for USERNAME."""
    from kryoset.core.totp import TOTPManager, TOTPError
    configuration = _load_config(config)
    user_manager = UserManager(configuration)
    totp = TOTPManager(user_manager)
    try:
        totp.disable(username)
        click.echo(f"[ok] TOTP disabled for '{username}'.")
    except TOTPError as error:
        click.echo(f"[error] {error}", err=True)
        raise SystemExit(1)


@user_totp.command("status")
@click.argument("username")
@click.option("--config", default=None)
def totp_status(username: str, config: str | None) -> None:
    """Show TOTP status for USERNAME."""
    from kryoset.core.totp import TOTPManager
    configuration = _load_config(config)
    user_manager = UserManager(configuration)
    totp = TOTPManager(user_manager)
    enabled = totp.is_enabled(username)
    status = "enabled" if enabled else "disabled"
    click.echo(f"TOTP for '{username}': {status}")


@user.group("quota")
def user_quota() -> None:
    """Manage per-user storage quotas."""


@user_quota.command("set")
@click.argument("username")
@click.argument("size")
@click.option("--config", default=None)
def quota_set(username: str, size: str, config: str | None) -> None:
    """Set storage quota for USERNAME. SIZE: e.g. 10GB, 500MB, none."""
    import re
    from kryoset.core.quota import QuotaManager
    configuration = _load_config(config)
    user_manager = UserManager(configuration)
    quota_manager = QuotaManager(user_manager, configuration.storage_path)

    if size.lower() == "none":
        quota_bytes = None
    else:
        match = re.fullmatch(r"(\d+(?:\.\d+)?)\s*(B|KB|MB|GB|TB)", size.upper())
        if not match:
            click.echo("[error] Invalid size. Use e.g. 10GB, 500MB or 'none'.", err=True)
            raise SystemExit(1)
        amount = float(match.group(1))
        unit_map = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3, "TB": 1024**4}
        quota_bytes = int(amount * unit_map[match.group(2)])

    try:
        quota_manager.set_quota(username, quota_bytes)
        if quota_bytes is None:
            click.echo(f"[ok] Quota removed for '{username}' (unlimited).")
        else:
            click.echo(f"[ok] Quota for '{username}' set to {size}.")
    except ValueError as error:
        click.echo(f"[error] {error}", err=True)
        raise SystemExit(1)


@user_quota.command("status")
@click.argument("username")
@click.option("--config", default=None)
def quota_status(username: str, config: str | None) -> None:
    """Show storage quota usage for USERNAME."""
    from kryoset.core.quota import QuotaManager
    configuration = _load_config(config)
    user_manager = UserManager(configuration)
    quota_manager = QuotaManager(user_manager, configuration.storage_path)
    click.echo(f"'{username}': {quota_manager.format_quota_summary(username)}")


@user_quota.command("list")
@click.option("--config", default=None)
def quota_list(config: str | None) -> None:
    """List storage quotas for all users."""
    from kryoset.core.quota import QuotaManager
    configuration = _load_config(config)
    user_manager = UserManager(configuration)
    quota_manager = QuotaManager(user_manager, configuration.storage_path)
    users = user_manager.list_users()
    if not users:
        click.echo("No users.")
        return
    click.echo(f"{'Username':<20} {'Quota summary'}")
    click.echo("-" * 55)
    for entry in users:
        name = entry["username"]
        click.echo(f"{name:<20} {quota_manager.format_quota_summary(name)}")


@cli.command()
@click.option("--host", default="0.0.0.0", show_default=True, help="IP address to bind to.")
@click.option("--port", default=8443, show_default=True, help="HTTPS port to listen on.")
@click.option("--cert", default=None, help="Path to TLS certificate (PEM). Auto-generated if omitted.")
@click.option("--key", default=None, help="Path to TLS private key (PEM). Auto-generated if omitted.")
@click.option("--config", default=None, help="Path to the configuration file.")
@click.option("--reload", is_flag=True, default=False, help="Enable auto-reload (development only).")
def api(host: str, port: int, cert: str | None, key: str | None, config: str | None, reload: bool) -> None:
    """Start the Kryoset REST API server over HTTPS."""
    import uvicorn
    from kryoset.api.app import create_app
    from kryoset.api.tls import generate_self_signed_cert
    from kryoset.core.audit_logger import AuditLogger
    from kryoset.core.permission_store import PermissionStore
    import kryoset.api._runner as _runner

    configuration = _load_config(config)
    user_manager = UserManager(configuration)

    if cert and key:
        cert_path = Path(cert)
        key_path = Path(key)
    else:
        cert_path, key_path = generate_self_signed_cert()
        click.echo(f"[tls] Using certificate: {cert_path}")
        click.echo(f"[tls] Key: {key_path}")

    audit_logger = AuditLogger()
    permission_store = PermissionStore()
    permission_store.initialize()

    _runner._app = create_app(
        configuration=configuration,
        user_manager=user_manager,
        audit_logger=audit_logger,
        permission_store=permission_store,
    )

    click.echo(f"[api] Starting Kryoset API on https://{host}:{port}")
    uvicorn.run(
        "kryoset.api._runner:_app",
        host=host,
        port=port,
        ssl_certfile=str(cert_path),
        ssl_keyfile=str(key_path),
        reload=False,
    )

    """
    uvicorn.run(
        app, 
        host='127.0.0.1', 
        port=8444, 
        ssl_certfile='/home/martial/.kryoset/api_cert.pem', 
        ssl_keyfile='/home/martial/.kryoset/api_key.pem'
    )
    """
