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
