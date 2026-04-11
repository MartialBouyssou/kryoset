import logging
import os
import socket
import threading
from pathlib import Path

import paramiko

from kryoset.core.configuration import Configuration
from kryoset.core.user_manager import UserManager

logger = logging.getLogger(__name__)


class KryosetSFTPHandle(paramiko.SFTPHandle):
    """
    File handle returned by the SFTP server for open-file operations.

    Wraps a standard Python file object and delegates read/write calls to it.
    """

    def __init__(self, file_object, flags: int = 0) -> None:
        super().__init__(flags)
        self._file = file_object

    def read(self, offset: int, length: int) -> bytes:
        self._file.seek(offset)
        return self._file.read(length)

    def write(self, offset: int, data: bytes) -> int:
        self._file.seek(offset)
        self._file.write(data)
        return paramiko.SFTP_OK

    def close(self) -> None:
        self._file.close()

    def stat(self) -> paramiko.SFTPAttributes:
        return paramiko.SFTPAttributes.from_stat(os.fstat(self._file.fileno()))


class KryosetSFTPServerInterface(paramiko.SFTPServerInterface):
    """
    SFTP subsystem handler chrooted to the Kryoset storage path.

    Every path received from the client is resolved relative to
    ``storage_path``, preventing directory-traversal attacks.

    Args:
        server: The :class:`paramiko.ServerInterface` for this session.
        storage_path: Absolute path to the shared storage directory.
    """

    def __init__(self, server, storage_path: Path, *args, **kwargs) -> None:
        self._storage_path = storage_path
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
        try:
            binary_flags = os.O_RDONLY
            if flags & os.O_WRONLY:
                binary_flags = os.O_WRONLY | os.O_CREAT
            if flags & os.O_RDWR:
                binary_flags = os.O_RDWR | os.O_CREAT
            if flags & os.O_APPEND:
                binary_flags |= os.O_APPEND
            if flags & os.O_TRUNC:
                binary_flags |= os.O_TRUNC

            mode = "rb"
            if binary_flags & os.O_RDWR:
                mode = "r+b"
            elif binary_flags & os.O_WRONLY:
                mode = "wb"

            if (binary_flags & os.O_CREAT) and not real_path.exists():
                real_path.touch()

            file_object = open(real_path, mode)
            handle = KryosetSFTPHandle(file_object, flags)
            return handle
        except OSError as error:
            logger.error("Cannot open %s: %s", real_path, error)
            return paramiko.SFTP_FAILURE

    def remove(self, path: str) -> int:
        real_path = self._resolve(path)
        try:
            real_path.unlink()
            return paramiko.SFTP_OK
        except OSError as error:
            logger.error("Cannot remove %s: %s", real_path, error)
            return paramiko.SFTP_FAILURE

    def rename(self, old_path: str, new_path: str) -> int:
        real_old = self._resolve(old_path)
        real_new = self._resolve(new_path)
        try:
            real_old.rename(real_new)
            return paramiko.SFTP_OK
        except OSError as error:
            logger.error("Cannot rename %s -> %s: %s", real_old, real_new, error)
            return paramiko.SFTP_FAILURE

    def mkdir(self, path: str, attributes) -> int:
        real_path = self._resolve(path)
        try:
            real_path.mkdir(parents=False, exist_ok=False)
            return paramiko.SFTP_OK
        except FileExistsError:
            return paramiko.SFTP_FAILURE
        except OSError as error:
            logger.error("Cannot mkdir %s: %s", real_path, error)
            return paramiko.SFTP_FAILURE

    def rmdir(self, path: str) -> int:
        real_path = self._resolve(path)
        try:
            real_path.rmdir()
            return paramiko.SFTP_OK
        except OSError as error:
            logger.error("Cannot rmdir %s: %s", real_path, error)
            return paramiko.SFTP_FAILURE

    def canonicalize(self, path: str) -> str:
        real_path = self._resolve(path)
        try:
            relative = real_path.relative_to(self._storage_path.resolve())
            return "/" + str(relative) if str(relative) != "." else "/"
        except ValueError:
            return "/"


class KryosetServerInterface(paramiko.ServerInterface):
    """
    SSH server interface that handles authentication for Kryoset.

    Accepts password authentication only; public-key authentication is
    rejected so that all access goes through the user database.

    Args:
        user_manager: A :class:`UserManager` instance for credential checks.
        storage_path: Shared storage directory (passed to the SFTP subsystem).
    """

    def __init__(self, user_manager: UserManager, storage_path: Path) -> None:
        self._user_manager = user_manager
        self._storage_path = storage_path

    def check_channel_request(self, kind: str, channel_id: int) -> int:
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username: str, password: str) -> int:
        if self._user_manager.authenticate(username, password):
            logger.info("User '%s' authenticated successfully.", username)
            return paramiko.AUTH_SUCCESSFUL
        logger.warning("Failed authentication attempt for user '%s'.", username)
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


def _make_sftp_interface(storage_path: Path):
    """
    Return a factory function that creates a :class:`KryosetSFTPServerInterface`.

    Paramiko's ``set_subsystem_handler`` expects a class, not an instance, so
    we return a subclass with the storage path baked in.

    Args:
        storage_path: The shared storage directory to chroot into.
    """

    class _BoundInterface(KryosetSFTPServerInterface):
        def __init__(self, server, *args, **kwargs):
            super().__init__(server, storage_path, *args, **kwargs)

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
    client. Each connection is independently authenticated.

    Args:
        configuration: A validated :class:`Configuration` instance.
        user_manager: A :class:`UserManager` bound to the same configuration.
    """

    def __init__(
        self, configuration: Configuration, user_manager: UserManager
    ) -> None:
        self._configuration = configuration
        self._user_manager = user_manager
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

        Paramiko's ``set_subsystem_handler`` takes care of starting the SFTP
        subsystem once the client requests it; this method only needs to drive
        the transport until the session ends.

        Args:
            client_socket: The accepted client socket.
            client_address: (host, port) tuple of the remote client.
        """
        transport = paramiko.Transport(client_socket)
        transport.add_server_key(self._host_key)

        sftp_interface = _make_sftp_interface(self._configuration.storage_path)
        transport.set_subsystem_handler("sftp", paramiko.SFTPServer, sftp_interface)

        server_interface = KryosetServerInterface(
            self._user_manager, self._configuration.storage_path
        )
        try:
            transport.start_server(server=server_interface)
            while transport.is_active():
                threading.Event().wait(timeout=1)
        except Exception as error:
            logger.error("Error with client %s: %s", client_address, error)
        finally:
            transport.close()
