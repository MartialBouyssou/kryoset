import logging
import os
import socket
import threading
from pathlib import Path
from typing import Optional

import paramiko

from kryoset.core.audit_logger import AuditLogger
from kryoset.core.home_paths import is_within_home, resolve_user_home_roots
from kryoset.core.quota import QuotaError, QuotaManager
from kryoset.core.storage_manager import StorageError, StorageManager
from kryoset.core.totp import TOTPManager
from kryoset.core.configuration import Configuration
from kryoset.core.control_channel import ControlChannel, ControlChannelError
from kryoset.core.permission_store import PermissionStore
from kryoset.core.permissions import Permission, PRESET_OWNER
from kryoset.core.user_manager import UserManager

logger = logging.getLogger(__name__)


class KryosetSFTPHandle(paramiko.SFTPHandle):
    """
    File handle for open-file operations.

    Wraps a standard Python file object. On close, upload events are
    forwarded to the audit logger.

    Args:
        file_object: Open Python file object.
        flags: Paramiko open flags.
        audit_logger: Server-wide audit logger.
        username: Authenticated user.
        remote_path: Client-visible path.
        is_write: True when opened for writing.
    """

    def __init__(
        self,
        file_object,
        flags: int = 0,
        audit_logger: Optional[AuditLogger] = None,
        username: str = "",
        remote_path: str = "",
        is_write: bool = False,
        storage_manager: Optional["StorageManager"] = None,
        quota_manager: Optional[QuotaManager] = None,
        local_path: Optional[Path] = None,
        initial_size: int = 0,
        home_path: Optional[str] = None,
    ) -> None:
        super().__init__(flags)
        self._file = file_object
        self._audit_logger = audit_logger
        self._username = username
        self._remote_path = remote_path
        self._is_write = is_write
        self._storage_manager = storage_manager
        self._quota_manager = quota_manager
        self._local_path = local_path
        self._initial_size = max(0, int(initial_size))
        self._home_path = home_path

    def read(self, offset: int, length: int) -> bytes:
        self._file.seek(offset)
        return self._file.read(length)

    def write(self, offset: int, data: bytes) -> int:
        """Write a chunk, enforcing per-user and global storage quotas."""
        if self._storage_manager is not None:
            try:
                self._storage_manager.check_upload_allowed(self._username, len(data))
            except StorageError as quota_error:
                logger.warning(
                    "Write blocked mid-transfer for %s: %s", self._username, quota_error
                )
                return paramiko.SFTP_PERMISSION_DENIED
        self._file.seek(offset)
        self._file.write(data)
        return paramiko.SFTP_OK

    def close(self) -> None:
        self._file.close()
        if self._is_write and self._quota_manager is not None and self._local_path is not None:
            final_size = 0
            try:
                if self._local_path.exists():
                    final_size = self._local_path.stat().st_size
            except OSError:
                final_size = 0
            delta = final_size - self._initial_size
            if delta != 0:
                self._quota_manager.update_used_bytes(
                    self._username,
                    delta,
                    home_path=self._home_path,
                )
        if self._audit_logger and self._is_write:
            self._audit_logger.log_file_write(self._username, self._remote_path)

    def stat(self) -> paramiko.SFTPAttributes:
        return paramiko.SFTPAttributes.from_stat(os.fstat(self._file.fileno()))


class KryosetSFTPServerInterface(paramiko.SFTPServerInterface):
    """
    SFTP subsystem with permission enforcement and virtual control channel.

    Every path is first checked against the :class:`PermissionStore`.
    Paths the user cannot see are silently hidden. The ``/.kryoset/``
    subtree is served virtually and never touches the real filesystem.

    Args:
        server: The parent :class:`KryosetServerInterface`.
        storage_path: Absolute path to the shared storage root.
        audit_logger: Server-wide audit logger.
        permission_store: Application permission store.
    """

    def __init__(
        self,
        server,
        storage_path: Path,
        audit_logger: AuditLogger,
        permission_store: PermissionStore,
        user_manager: Optional[UserManager] = None,
        storage_manager: Optional["StorageManager"] = None,
        quota_manager: Optional[QuotaManager] = None,
        *args,
        **kwargs,
    ) -> None:
        self._storage_path = storage_path
        self._audit_logger = audit_logger
        self._permission_store = permission_store
        self._user_manager = user_manager
        self._storage_manager = storage_manager
        self._quota_manager = quota_manager
        self._username: str = getattr(server, "authenticated_username", "")
        self._is_admin: bool = getattr(server, "is_admin", False)
        self._client_ip: str = getattr(server, "client_ip", "")
        self._control = ControlChannel(
            permission_store, self._username, self._is_admin
        )
        self._pending_command: Optional[bytes] = None
        self._pending_command_path: Optional[str] = None
        super().__init__(server, *args, **kwargs)

    def _resolve(self, client_path: str) -> Path:
        """Translate a client path to an absolute local path safely."""
        resolved = (self._storage_path / client_path.lstrip("/")).resolve()
        try:
            resolved.relative_to(self._storage_path.resolve())
        except ValueError:
            logger.warning("Directory traversal blocked: %s", client_path)
            return self._storage_path
        return resolved

    def _to_remote_path(self, local_path: Path) -> str:
        """Return the client-visible path string for a resolved local path."""
        try:
            relative = local_path.relative_to(self._storage_path.resolve())
            return "/" + str(relative) if str(relative) != "." else "/"
        except ValueError:
            return "/"

    def _effective_permissions(self, remote_path: str) -> Permission:
        """Return the effective permissions for the current user on *remote_path*.

        Admins always receive full permissions regardless of stored rules.
        """
        if self._is_admin:
            return PRESET_OWNER
        home_roots = []
        if self._user_manager is not None:
            home_roots = resolve_user_home_roots(
                self._username,
                self._user_manager,
                self._permission_store,
            )
        if home_roots:
            return PRESET_OWNER if any(is_within_home(remote_path, root) for root in home_roots) else Permission.NONE
        perms, _ = self._permission_store.resolve_permissions(
            self._username, remote_path, self._client_ip
        )
        return perms

    def _can(self, remote_path: str, flag: Permission) -> bool:
        """Return True if the user holds *flag* on *remote_path*."""
        return flag in self._effective_permissions(remote_path)

    def _deny_silently(self) -> int:
        """Return the SFTP 'no such file' code — our silent refusal."""
        return paramiko.SFTP_NO_SUCH_FILE

    def _primary_home_path(self) -> Optional[str]:
        if self._user_manager is None:
            return None
        home_roots = resolve_user_home_roots(
            self._username,
            self._user_manager,
            self._permission_store,
        )
        if home_roots:
            return home_roots[0]
        return self._user_manager.get_home_path(self._username)

    def list_folder(self, path: str):
        if self._control.is_virtual_path(path):
            entries = self._control.list_virtual_directory(path)
            result = []
            for entry in entries:
                attr = paramiko.SFTPAttributes()
                attr.filename = entry["name"]
                attr.st_size = entry["size"]
                attr.st_mode = 0o040755 if entry["is_dir"] else 0o100644
                result.append(attr)
            return result

        real_path = self._resolve(path)
        if not real_path.is_dir():
            return paramiko.SFTP_NO_SUCH_FILE

        entries = []
        for item in real_path.iterdir():
            item_remote = self._to_remote_path(item)
            if not self._can(item_remote, Permission.LIST):
                continue
            attributes = paramiko.SFTPAttributes.from_stat(item.stat())
            attributes.filename = item.name
            entries.append(attributes)

        control_attr = paramiko.SFTPAttributes()
        control_attr.filename = ".kryoset"
        control_attr.st_mode = 0o040755
        control_attr.st_size = 0
        entries.append(control_attr)

        return entries

    def stat(self, path: str):
        if self._control.is_virtual_path(path):
            attr = paramiko.SFTPAttributes()
            attr.st_mode = 0o040755
            attr.st_size = 0
            return attr

        real_path = self._resolve(path)
        if not real_path.exists():
            return paramiko.SFTP_NO_SUCH_FILE
        remote_path = self._to_remote_path(real_path)
        if not self._can(remote_path, Permission.LIST):
            return self._deny_silently()
        return paramiko.SFTPAttributes.from_stat(real_path.stat())

    def lstat(self, path: str):
        return self.stat(path)

    def open(self, path: str, flags: int, attributes):
        if self._control.is_virtual_path(path):
            return self._open_virtual(path, flags)

        real_path = self._resolve(path)
        remote_path = self._to_remote_path(real_path)
        is_write = bool(flags & (os.O_WRONLY | os.O_RDWR))

        required_flag = Permission.UPLOAD if is_write else Permission.DOWNLOAD
        if not self._can(remote_path, required_flag):
            if not self._can(remote_path, Permission.LIST):
                return self._deny_silently()
            return paramiko.SFTP_PERMISSION_DENIED

        try:
            existing_size = real_path.stat().st_size if real_path.exists() else 0
            mode = "rb"
            if flags & os.O_RDWR:
                mode = "r+b"
            elif flags & os.O_WRONLY:
                mode = "wb"

            if is_write and self._storage_manager is not None:
                # For new files we don't yet know the size; we enforce the quota
                # in KryosetSFTPHandle.write() on every chunk.  For overwrites we
                # check the *current* file size so the user can at least replace
                # their own data without being blocked immediately.
                existing_size = real_path.stat().st_size if real_path.exists() else 0
                try:
                    self._storage_manager.check_upload_allowed(self._username, existing_size)
                except StorageError as quota_error:
                    logger.warning("Upload blocked for %s: %s", self._username, quota_error)
                    return paramiko.SFTP_PERMISSION_DENIED

            if (flags & os.O_CREAT) and not real_path.exists():
                real_path.touch()

            file_object = open(real_path, mode)
            if not is_write and self._audit_logger:
                self._audit_logger.log_file_read(self._username, remote_path)

            return KryosetSFTPHandle(
                file_object,
                flags,
                audit_logger=self._audit_logger,
                username=self._username,
                remote_path=remote_path,
                is_write=is_write,
                storage_manager=self._storage_manager,
                quota_manager=self._quota_manager,
                local_path=real_path,
                initial_size=existing_size,
                home_path=self._primary_home_path(),
            )
        except OSError as error:
            logger.error("Cannot open %s: %s", real_path, error)
            return paramiko.SFTP_FAILURE

    def _open_virtual(self, path: str, flags: int):
        """Handle open calls on the virtual /.kryoset/ tree."""
        is_write = bool(flags & (os.O_WRONLY | os.O_RDWR))

        normalized = "/" + path.strip("/")
        if normalized.startswith("/.kryoset/commands/"):
            if is_write:
                import io
                buffer = io.BytesIO()

                class _CommandHandle(paramiko.SFTPHandle):
                    def __init__(inner_self):
                        super().__init__(flags)
                        inner_self._buf = buffer

                    def write(inner_self, offset: int, data: bytes) -> int:
                        inner_self._buf.seek(offset)
                        inner_self._buf.write(data)
                        return paramiko.SFTP_OK

                    def close(inner_self) -> None:
                        raw = inner_self._buf.getvalue()
                        try:
                            result = self._control.process_command(raw)
                            logger.info(
                                "Command result for '%s': %s",
                                self._username, result
                            )
                        except ControlChannelError as error:
                            logger.warning(
                                "Command error for '%s': %s",
                                self._username, error
                            )

                return _CommandHandle()

        if not is_write:
            try:
                content = self._control.read_virtual_file(path)
                import io
                buf = io.BytesIO(content)

                class _ReadHandle(paramiko.SFTPHandle):
                    def __init__(inner_self):
                        super().__init__(flags)

                    def read(inner_self, offset: int, length: int) -> bytes:
                        buf.seek(offset)
                        return buf.read(length)

                    def close(inner_self) -> None:
                        pass

                return _ReadHandle()
            except ControlChannelError:
                return paramiko.SFTP_NO_SUCH_FILE

        return paramiko.SFTP_PERMISSION_DENIED

    def remove(self, path: str) -> int:
        if self._control.is_virtual_path(path):
            return paramiko.SFTP_PERMISSION_DENIED
        real_path = self._resolve(path)
        remote_path = self._to_remote_path(real_path)
        if not self._can(remote_path, Permission.DELETE):
            return self._deny_silently()
        try:
            removed_size = real_path.stat().st_size if real_path.exists() else 0
            real_path.unlink()
            if self._quota_manager is not None and removed_size > 0:
                self._quota_manager.update_used_bytes(
                    self._username,
                    -removed_size,
                    home_path=self._primary_home_path(),
                )
            self._audit_logger.log_file_delete(self._username, remote_path)
            return paramiko.SFTP_OK
        except OSError as error:
            logger.error("Cannot remove %s: %s", real_path, error)
            return paramiko.SFTP_FAILURE

    def rename(self, old_path: str, new_path: str) -> int:
        if self._control.is_virtual_path(old_path):
            return paramiko.SFTP_PERMISSION_DENIED
        real_old = self._resolve(old_path)
        real_new = self._resolve(new_path)
        old_remote = self._to_remote_path(real_old)
        new_remote = self._to_remote_path(real_new)

        if not self._can(old_remote, Permission.RENAME):
            return self._deny_silently()
        if not self._can(new_remote, Permission.MOVE):
            return paramiko.SFTP_PERMISSION_DENIED

        try:
            real_old.rename(real_new)
            self._audit_logger.log_file_rename(
                self._username, old_remote, new_remote
            )
            return paramiko.SFTP_OK
        except OSError as error:
            logger.error("Cannot rename %s: %s", real_old, error)
            return paramiko.SFTP_FAILURE

    def mkdir(self, path: str, attributes) -> int:
        if self._control.is_virtual_path(path):
            return paramiko.SFTP_PERMISSION_DENIED
        real_path = self._resolve(path)
        remote_path = self._to_remote_path(real_path)
        if not self._can(remote_path, Permission.UPLOAD):
            return self._deny_silently()
        try:
            real_path.mkdir(parents=False, exist_ok=False)
            self._audit_logger.log_mkdir(self._username, remote_path)
            return paramiko.SFTP_OK
        except FileExistsError:
            return paramiko.SFTP_FAILURE
        except OSError as error:
            logger.error("Cannot mkdir %s: %s", real_path, error)
            return paramiko.SFTP_FAILURE

    def rmdir(self, path: str) -> int:
        if self._control.is_virtual_path(path):
            return paramiko.SFTP_PERMISSION_DENIED
        real_path = self._resolve(path)
        remote_path = self._to_remote_path(real_path)
        if not self._can(remote_path, Permission.DELETE):
            return self._deny_silently()
        try:
            real_path.rmdir()
            self._audit_logger.log_rmdir(self._username, remote_path)
            return paramiko.SFTP_OK
        except OSError as error:
            logger.error("Cannot rmdir %s: %s", real_path, error)
            return paramiko.SFTP_FAILURE

    def _ensure_home_exists(self, home_remote: str) -> Path:
        """
        Resolve *home_remote* to its physical path and create it if absent.

        Returns the resolved Path so callers can use it directly.
        """
        home_real = self._resolve(home_remote)
        home_real.mkdir(parents=True, exist_ok=True)
        return home_real

    def canonicalize(self, path: str) -> str:
        """
        Resolve *path* to the canonical remote path, enforcing home confinement.

        Rules for non-admin users that have a home configured:
        - On session start (path is '' / '.' / '/') → land inside home root
          and create the directory if it does not exist yet.
        - For any other path that falls *outside* the home root → redirect to
          home root.  This covers clients that send an absolute initial cwd
          (e.g. "/") as well as any subsequent path that escapes the home.
        - Paths that are already inside the home root are kept as-is.

        Admins bypass all home restrictions.
        """
        if self._control.is_virtual_path(path):
            return "/" + path.strip("/")

        if not self._is_admin and self._user_manager is not None:
            home_roots = resolve_user_home_roots(
                self._username,
                self._user_manager,
                self._permission_store,
            )
            if home_roots:
                home_remote = home_roots[0]

                # Always ensure the home directory exists on disk.
                self._ensure_home_exists(home_remote)

                normalized = path.strip("/")
                is_root_or_dot = normalized in ("", ".")
                outside_home = not is_within_home(path, home_remote)

                if is_root_or_dot or outside_home:
                    return home_remote

        real_path = self._resolve(path)
        return self._to_remote_path(real_path)


class KryosetServerInterface(paramiko.ServerInterface):
    """
    SSH server interface — handles authentication and passes session
    context to the SFTP subsystem.

    Args:
        user_manager: For password verification.
        storage_path: Shared storage root.
        audit_logger: Server-wide audit logger.
        permission_store: Application permission store.
        client_address: Remote (host, port) tuple.
    """

    def __init__(
        self,
        user_manager: UserManager,
        storage_path: Path,
        audit_logger: AuditLogger,
        permission_store: PermissionStore,
        client_address: tuple,
        totp_manager: Optional[TOTPManager] = None,
    ) -> None:
        self._user_manager = user_manager
        self._storage_path = storage_path
        self._audit_logger = audit_logger
        self._permission_store = permission_store
        self._totp_manager = totp_manager
        self.client_ip: str = client_address[0]
        self.authenticated_username: str = ""
        self.is_admin: bool = False
        self._password_authenticated: bool = False

    def check_channel_request(self, kind: str, channel_id: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username: str, password: str) -> int:
        if self._user_manager.authenticate(username, password):
            self.authenticated_username = username
            self.is_admin = self._user_manager.is_admin(username)
            self._password_authenticated = True
            logger.info("User '%s' authenticated (admin=%s).", username, self.is_admin)
            self._audit_logger.log_auth_success(username, self.client_ip)
            if self._totp_manager and self._totp_manager.is_enabled(username):
                return paramiko.AUTH_PARTIALLY_SUCCESSFUL
            return paramiko.AUTH_SUCCESSFUL
        logger.warning("Failed auth for '%s'.", username)
        self._audit_logger.log_auth_failure(username, self.client_ip)
        return paramiko.AUTH_FAILED

    def check_auth_interactive(self, username: str, submethods: str) -> int:
        """
        Entry point for keyboard-interactive authentication (second factor).

        Called by Paramiko when the client requests keyboard-interactive auth.
        The actual TOTP code verification happens in
        :meth:`check_auth_interactive_response` which Paramiko calls with the
        user's typed response to our prompt.
        """
        if not self._totp_manager or not self._totp_manager.is_enabled(username):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_SUCCESSFUL

    def get_auth_interactive_prompt(
        self, username: str, instruction: str, lang: str, prompts: list
    ) -> list:
        """
        Return the challenge prompt shown to the client in their terminal.

        OpenSSH displays the prompt string and waits for the user to type
        their 6-digit TOTP code. The second element (False) means the
        response is not echoed (behaves like a password field).
        """
        return [("TOTP code (6 digits): ", False)]

    def check_auth_interactive_response(self, responses: list) -> int:
        """
        Verify the TOTP code submitted by the client.

        Called by Paramiko once per keyboard-interactive exchange with the
        list of strings the user typed in response to our prompts.

        Args:
            responses: List of user-typed strings (one per prompt).

        Returns:
            AUTH_SUCCESSFUL if the code is valid, AUTH_FAILED otherwise.
        """
        username = self.authenticated_username
        if not username:
            return paramiko.AUTH_FAILED

        if not self._totp_manager or not self._totp_manager.is_enabled(username):
            return paramiko.AUTH_SUCCESSFUL

        if not responses:
            self._audit_logger.log_totp_failure(username, self.client_ip)
            return paramiko.AUTH_FAILED

        code = responses[0].strip()
        if self._totp_manager.verify(username, code):
            self._audit_logger.log_totp_success(username, self.client_ip)
            logger.info("TOTP verified for user '%s'.", username)
            return paramiko.AUTH_SUCCESSFUL

        self._audit_logger.log_totp_failure(username, self.client_ip)
        logger.warning("TOTP failure for user '%s'.", username)
        return paramiko.AUTH_FAILED

    def check_auth_gssapi_with_mic(self, username: str, gss_authenticated: int, cc_file: str) -> int:
        return paramiko.AUTH_FAILED

    def check_auth_gssapi_keyex(self, username: str, gss_authenticated: int, cc_file: str) -> int:
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username: str, key) -> int:
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username: str) -> str:
        """
        Advertise accepted authentication methods to the client.

        When TOTP is active for this user, the SSH client is told it must
        perform both password and keyboard-interactive (TOTP) steps.
        When TOTP is disabled, password alone is sufficient.
        """
        if self._totp_manager and self._totp_manager.is_enabled(username):
            return "password,keyboard-interactive"
        return "password"


    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes) -> bool:
        return False

    def check_channel_shell_request(self, channel) -> bool:
        return False

    def check_channel_exec_request(self, channel, command: bytes) -> bool:
        return False


def _make_sftp_interface(
    storage_path: Path,
    audit_logger: AuditLogger,
    permission_store: PermissionStore,
    user_manager: UserManager,
    storage_manager: "StorageManager",
    quota_manager: Optional[QuotaManager],
):
    """Build a bound SFTP interface class for paramiko, closing over server-wide singletons."""
    class _BoundInterface(KryosetSFTPServerInterface):
        def __init__(self, server, *args, **kwargs):
            super().__init__(
                server,
                storage_path,
                audit_logger,
                permission_store,
                user_manager,
                storage_manager,
                quota_manager,
                *args,
                **kwargs,
            )
    return _BoundInterface


def generate_host_key(key_path: Path) -> paramiko.RSAKey:
    """Generate or load the RSA host key."""
    key_path.parent.mkdir(parents=True, exist_ok=True)
    if key_path.exists():
        return paramiko.RSAKey(filename=str(key_path))
    host_key = paramiko.RSAKey.generate(bits=2048)
    host_key.write_private_key_file(str(key_path))
    os.chmod(key_path, 0o600)
    logger.info("Generated new host key at %s", key_path)
    return host_key


class SFTPServer:
    """
    Main Kryoset SFTP server with permission enforcement.

    Args:
        configuration: Validated server configuration.
        user_manager: User account manager.
        audit_logger: Audit logger (created automatically if None).
        permission_store: Permission store (created automatically if None).
    """

    def __init__(
        self,
        configuration: Configuration,
        user_manager: UserManager,
        audit_logger: Optional[AuditLogger] = None,
        permission_store: Optional[PermissionStore] = None,
    ) -> None:
        self._configuration = configuration
        self._user_manager = user_manager
        self._audit_logger = audit_logger or AuditLogger()
        self._permission_store = permission_store or PermissionStore()
        self._storage_manager = StorageManager(configuration, user_manager, permission_store or PermissionStore())
        self._quota_manager = QuotaManager(user_manager, configuration.storage_path)
        self._totp_manager = TOTPManager(user_manager)
        self._host_key = generate_host_key(configuration.host_key_path)
        self._server_socket = None
        self._running = False

    def start(self) -> None:
        """Start listening for connections (blocking)."""
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        self._server_socket.bind((self._configuration.host, self._configuration.port))
        self._server_socket.listen(10)
        self._running = True
        logger.info(
            "Kryoset SFTP server listening on %s:%s",
            self._configuration.host,
            self._configuration.port,
        )
        try:
            while self._running:
                try:
                    client_socket, client_address = self._server_socket.accept()
                except OSError:
                    break
                logger.info("Connection from %s", client_address)
                threading.Thread(
                    target=self._handle_client,
                    args=(client_socket, client_address),
                    daemon=True,
                ).start()
        finally:
            self.stop()

    def stop(self) -> None:
        """Shut down the server socket gracefully."""
        self._running = False
        if self._server_socket:
            try:
                self._server_socket.close()
            except OSError:
                pass
            self._server_socket = None
        logger.info("Kryoset SFTP server stopped.")

    def _handle_client(self, client_socket, client_address) -> None:
        transport = paramiko.Transport(client_socket)
        transport.add_server_key(self._host_key)
        sftp_interface = _make_sftp_interface(
            self._configuration.storage_path,
            self._audit_logger,
            self._permission_store,
            self._user_manager,
            self._storage_manager,
            self._quota_manager,
        )
        transport.set_subsystem_handler("sftp", paramiko.SFTPServer, sftp_interface)
        server_interface = KryosetServerInterface(
            self._user_manager,
            self._configuration.storage_path,
            self._audit_logger,
            self._permission_store,
            client_address,
            totp_manager=self._totp_manager,
        )
        try:
            transport.start_server(server=server_interface)
            while transport.is_active():
                threading.Event().wait(timeout=1)
            username = server_interface.authenticated_username
            if username:
                self._audit_logger.log_disconnection(username, client_address[0])
        except Exception as error:
            logger.error("Error with client %s: %s", client_address, error)
        finally:
            transport.close()
