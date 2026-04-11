import logging
import os
import socket
import threading
from pathlib import Path

import paramiko

from kryoset.core.audit_logger import AuditLogger
from kryoset.core.configuration import Configuration
from kryoset.core.user_manager import UserManager

logger = logging.getLogger(__name__)


class KryosetSFTPHandle(paramiko.SFTPHandle):
    """
    File handle returned by the SFTP server for open-file operations.

    Wraps a standard Python file object and delegates read/write calls to it.
    Notifies the audit logger when the file is closed after a write (upload).

    Args:
        file_object: Open Python file object backing this handle.
        flags: Paramiko flags describing how the file was opened.
        audit_logger: Server-wide audit logger instance.
        username: Authenticated user who opened the file.
        remote_path: Client-visible path of the file.
        is_write: True when the file was opened for writing (upload).
    """

    def __init__(
        self,
        file_object,
        flags: int = 0,
        audit_logger: AuditLogger | None = None,
        username: str = "",
        remote_path: str = "",
        is_write: bool = False,
    ) -> None:
        super().__init__(flags)
        self._file = file_object
        self._audit_logger = audit_logger
        self._username = username
        self._remote_path = remote_path
        self._is_write = is_write

    def read(self, offset: int, length: int) -> bytes:
        self._file.seek(offset)
        return self._file.read(length)

    def write(self, offset: int, data: bytes) -> int:
        self._file.seek(offset)
        self._file.write(data)
        return paramiko.SFTP_OK

    def close(self) -> None:
        self._file.close()
        if self._audit_logger and self._is_write:
            self._audit_logger.log_file_write(self._username, self._remote_path)

    def stat(self) -> paramiko.SFTPAttributes:
        return paramiko.SFTPAttributes.from_stat(os.fstat(self._file.fileno()))


class KryosetSFTPServerInterface(paramiko.SFTPServerInterface):
    """
    SFTP subsystem handler chrooted to the Kryoset storage path.

    Every path received from the client is resolved relative to
    ``storage_path``, preventing directory-traversal attacks. All file
    operations are forwarded to the audit logger.

    Args:
        server: The :class:`KryosetServerInterface` for this session.
        storage_path: Absolute path to the shared storage directory.
        audit_logger: Server-wide audit logger instance.
    """

    def __init__(
        self,
        server,
        storage_path: Path,
        audit_logger: AuditLogger,
        *args,
        **kwargs,
    ) -> None:
        self._storage_path = storage_path
        self._audit_logger = audit_logger
        self._username: str = getattr(server, "authenticated_username", "")
        super().__init__(server, *args, **kwargs)

    def _resolve(self, client_path: str) -> Path:
        """
        Translate a client-supplied path to an absolute local path.

        Ensures the result is inside the storage directory.
        """
        resolved = (self._storage_path / client_path.lstrip("/")).resolve()
        try:
            resolved.relative_to(self._storage_path.resolve())
        except ValueError:
            logger.warning("Directory traversal attempt blocked: %s", client_path)
            return self._storage_path
        return resolved

    def _to_remote_path(self, local_path: Path) -> str:
        """Return the client-visible path string for a resolved local path."""
        try:
            relative = local_path.relative_to(self._storage_path.resolve())
            return "/" + str(relative) if str(relative) != "." else "/"
        except ValueError:
            return "/"

    def list_folder(self, path: str):
        real_path = self._resolve(path)
        if not real_path.is_dir():
            return paramiko.SFTP_NO_SUCH_FILE
        entries = []
        for item in real_path.iterdir():
            attributes = paramiko.SFTPAttributes.from_stat(item.stat())
            attributes.filename = item.name
            entries.append(attributes)
        return entries

    def stat(self, path: str):
        real_path = self._resolve(path)
        if not real_path.exists():
            return paramiko.SFTP_NO_SUCH_FILE
        return paramiko.SFTPAttributes.from_stat(real_path.stat())

    def lstat(self, path: str):
        real_path = self._resolve(path)
        if not real_path.exists():
            return paramiko.SFTP_NO_SUCH_FILE
        return paramiko.SFTPAttributes.from_stat(real_path.lstat())

    def open(self, path: str, flags: int, attributes):
        real_path = self._resolve(path)
        remote_path = self._to_remote_path(real_path)
        try:
            is_write = bool(flags & (os.O_WRONLY | os.O_RDWR))

            mode = "rb"
            if flags & os.O_RDWR:
                mode = "r+b"
            elif flags & os.O_WRONLY:
                mode = "wb"

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
            )
        except OSError as error:
            logger.error("Cannot open %s: %s", real_path, error)
            return paramiko.SFTP_FAILURE

    def remove(self, path: str) -> int:
        real_path = self._resolve(path)
        remote_path = self._to_remote_path(real_path)
        try:
            real_path.unlink()
            self._audit_logger.log_file_delete(self._username, remote_path)
            return paramiko.SFTP_OK
        except OSError as error:
            logger.error("Cannot remove %s: %s", real_path, error)
            return paramiko.SFTP_FAILURE

    def rename(self, old_path: str, new_path: str) -> int:
        real_old = self._resolve(old_path)
        real_new = self._resolve(new_path)
        try:
            real_old.rename(real_new)
            self._audit_logger.log_file_rename(
                self._username,
                self._to_remote_path(real_old),
                self._to_remote_path(real_new),
            )
            return paramiko.SFTP_OK
        except OSError as error:
            logger.error("Cannot rename %s -> %s: %s", real_old, real_new, error)
            return paramiko.SFTP_FAILURE

    def mkdir(self, path: str, attributes) -> int:
        real_path = self._resolve(path)
        remote_path = self._to_remote_path(real_path)
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
        real_path = self._resolve(path)
        remote_path = self._to_remote_path(real_path)
        try:
            real_path.rmdir()
            self._audit_logger.log_rmdir(self._username, remote_path)
            return paramiko.SFTP_OK
        except OSError as error:
            logger.error("Cannot rmdir %s: %s", real_path, error)
            return paramiko.SFTP_FAILURE

    def canonicalize(self, path: str) -> str:
        real_path = self._resolve(path)
        return self._to_remote_path(real_path)


class KryosetServerInterface(paramiko.ServerInterface):
    """
    SSH server interface that handles authentication for Kryoset.

    Accepts password authentication only. Successful and failed attempts
    are forwarded to the audit logger. The authenticated username is stored
    so that the SFTP interface can retrieve it.

    Args:
        user_manager: A :class:`UserManager` instance for credential checks.
        storage_path: Shared storage directory.
        audit_logger: Server-wide audit logger instance.
        client_address: (host, port) tuple of the remote client.
    """

    def __init__(
        self,
        user_manager: UserManager,
        storage_path: Path,
        audit_logger: AuditLogger,
        client_address: tuple,
    ) -> None:
        self._user_manager = user_manager
        self._storage_path = storage_path
        self._audit_logger = audit_logger
        self._client_ip: str = client_address[0]
        self.authenticated_username: str = ""

    def check_channel_request(self, kind: str, channel_id: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username: str, password: str) -> int:
        if self._user_manager.authenticate(username, password):
            self.authenticated_username = username
            logger.info("User '%s' authenticated successfully.", username)
            self._audit_logger.log_auth_success(username, self._client_ip)
            return paramiko.AUTH_SUCCESSFUL
        logger.warning("Failed authentication attempt for user '%s'.", username)
        self._audit_logger.log_auth_failure(username, self._client_ip)
        return paramiko.AUTH_FAILED

    def check_auth_publickey(self, username: str, key) -> int:
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username: str) -> str:
        return "password"

    def check_channel_pty_request(
        self, channel, term, width, height, pixelwidth, pixelheight, modes
    ) -> bool:
        return False

    def check_channel_shell_request(self, channel) -> bool:
        return False

    def check_channel_exec_request(self, channel, command: bytes) -> bool:
        return False


def _make_sftp_interface(storage_path: Path, audit_logger: AuditLogger):
    """
    Return a factory class that creates a :class:`KryosetSFTPServerInterface`.

    Paramiko's ``set_subsystem_handler`` expects a class, not an instance, so
    we return a subclass with the storage path and audit logger baked in.

    Args:
        storage_path: The shared storage directory to chroot into.
        audit_logger: Server-wide audit logger instance.
    """

    class _BoundInterface(KryosetSFTPServerInterface):
        def __init__(self, server, *args, **kwargs):
            super().__init__(server, storage_path, audit_logger, *args, **kwargs)

    return _BoundInterface


def generate_host_key(key_path: Path) -> paramiko.RSAKey:
    """
    Generate and save a 2048-bit RSA host key if it does not already exist.

    Args:
        key_path: File path where the private key will be stored.

    Returns:
        The loaded or newly generated :class:`paramiko.RSAKey`.
    """
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
    The main Kryoset SFTP server.

    Listens for incoming SSH connections and spawns one handler thread per
    client. Each connection is independently authenticated and all events
    are recorded by the shared :class:`AuditLogger`.

    Args:
        configuration: A validated :class:`Configuration` instance.
        user_manager: A :class:`UserManager` bound to the same configuration.
        audit_logger: Audit logger instance (created automatically if omitted).
    """

    def __init__(
        self,
        configuration: Configuration,
        user_manager: UserManager,
        audit_logger: AuditLogger | None = None,
    ) -> None:
        self._configuration = configuration
        self._user_manager = user_manager
        self._audit_logger = audit_logger or AuditLogger()
        self._host_key = generate_host_key(configuration.host_key_path)
        self._server_socket: socket.socket | None = None
        self._running = False

    def start(self) -> None:
        """
        Start listening for connections (blocking call).

        Spawns a daemon thread per client so that the main thread can be
        interrupted with Ctrl-C.
        """
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
                handler = threading.Thread(
                    target=self._handle_client,
                    args=(client_socket, client_address),
                    daemon=True,
                )
                handler.start()
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

    def _handle_client(
        self, client_socket: socket.socket, client_address: tuple
    ) -> None:
        """
        Manage a single client connection in its own thread.

        Args:
            client_socket: The accepted client socket.
            client_address: (host, port) tuple of the remote client.
        """
        transport = paramiko.Transport(client_socket)
        transport.add_server_key(self._host_key)

        sftp_interface = _make_sftp_interface(
            self._configuration.storage_path, self._audit_logger
        )
        transport.set_subsystem_handler("sftp", paramiko.SFTPServer, sftp_interface)

        server_interface = KryosetServerInterface(
            self._user_manager,
            self._configuration.storage_path,
            self._audit_logger,
            client_address,
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
