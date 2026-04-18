"""
Tests for kryoset.core.sftp_server.

Unit-tests the path-resolution, permission enforcement and anti-traversal
logic of KryosetSFTPServerInterface without needing a real network connection.
"""

from pathlib import Path
from unittest.mock import MagicMock

import paramiko
import pytest

from kryoset.core.audit_logger import AuditLogger
from kryoset.core.permission_store import PermissionStore
from kryoset.core.permissions import Permission, PermissionRule
from kryoset.core.sftp_server import KryosetSFTPServerInterface, generate_host_key

_ALL_PERMISSIONS = (
    Permission.LIST | Permission.PREVIEW | Permission.DOWNLOAD
    | Permission.UPLOAD | Permission.COPY | Permission.RENAME
    | Permission.MOVE | Permission.DELETE | Permission.SHARE
    | Permission.MANAGE_PERMS
)


@pytest.fixture()
def mock_audit_logger(tmp_path: Path) -> AuditLogger:
    """Return a real AuditLogger writing to a temporary directory."""
    return AuditLogger(log_directory=tmp_path / "logs")


@pytest.fixture()
def open_store(tmp_path: Path) -> PermissionStore:
    """
    Return a PermissionStore granting all permissions to 'testuser' on /.

    This simulates a fully open server for tests that focus on SFTP mechanics
    rather than permission logic (which is covered in test_permission_store.py).
    """
    store = PermissionStore(db_path=tmp_path / "perms.db")
    store.initialize()
    store.add_rule(PermissionRule(
        subject_type="user",
        subject_id="testuser",
        path="/",
        permissions=_ALL_PERMISSIONS,
    ))
    return store


@pytest.fixture()
def restricted_store(tmp_path: Path) -> PermissionStore:
    """Return a PermissionStore with no rules (deny-all by default)."""
    store = PermissionStore(db_path=tmp_path / "perms.db")
    store.initialize()
    return store


def _make_mock_server(username: str = "testuser", is_admin: bool = False) -> MagicMock:
    """Return a mock ServerInterface with the attributes the SFTP layer reads."""
    server = MagicMock()
    server.authenticated_username = username
    server.is_admin = is_admin
    server.client_ip = "127.0.0.1"
    return server


def _make_interface(
    storage_path: Path,
    audit_logger: AuditLogger,
    store: PermissionStore,
    username: str = "testuser",
    is_admin: bool = False,
) -> KryosetSFTPServerInterface:
    """Construct a KryosetSFTPServerInterface for testing."""
    return KryosetSFTPServerInterface(
        _make_mock_server(username, is_admin),
        storage_path,
        audit_logger,
        store,
    )


class TestPathResolution:
    """Verify that the SFTP interface keeps resolved paths inside storage_path."""

    def test_root_resolves_to_storage(
        self, temp_storage: Path, mock_audit_logger: AuditLogger, open_store: PermissionStore
    ):
        interface = _make_interface(temp_storage, mock_audit_logger, open_store)
        assert interface._resolve("/") == temp_storage.resolve()

    def test_subdirectory_resolves_correctly(
        self, temp_storage: Path, mock_audit_logger: AuditLogger, open_store: PermissionStore
    ):
        interface = _make_interface(temp_storage, mock_audit_logger, open_store)
        assert interface._resolve("/subdir/file.txt") == (
            temp_storage / "subdir" / "file.txt"
        ).resolve()

    def test_traversal_attack_is_blocked(
        self, temp_storage: Path, mock_audit_logger: AuditLogger, open_store: PermissionStore
    ):
        interface = _make_interface(temp_storage, mock_audit_logger, open_store)
        resolved = interface._resolve("/../../etc/passwd")
        assert str(resolved).startswith(str(temp_storage.resolve()))

    def test_canonicalize_root(
        self, temp_storage: Path, mock_audit_logger: AuditLogger, open_store: PermissionStore
    ):
        interface = _make_interface(temp_storage, mock_audit_logger, open_store)
        assert interface.canonicalize("/") == "/"

    def test_canonicalize_subpath(
        self, temp_storage: Path, mock_audit_logger: AuditLogger, open_store: PermissionStore
    ):
        (temp_storage / "docs").mkdir()
        interface = _make_interface(temp_storage, mock_audit_logger, open_store)
        assert interface.canonicalize("/docs") == "/docs"


class TestListFolder:
    def test_list_empty_storage_shows_only_kryoset_dir(
        self, temp_storage: Path, mock_audit_logger: AuditLogger, open_store: PermissionStore
    ):
        interface = _make_interface(temp_storage, mock_audit_logger, open_store)
        entries = interface.list_folder("/")
        names = {e.filename for e in entries}
        assert names == {".kryoset"}

    def test_list_returns_visible_files(
        self, temp_storage: Path, mock_audit_logger: AuditLogger, open_store: PermissionStore
    ):
        (temp_storage / "hello.txt").write_text("hi")
        (temp_storage / "world.txt").write_text("world")
        interface = _make_interface(temp_storage, mock_audit_logger, open_store)
        entries = interface.list_folder("/")
        names = {e.filename for e in entries}
        assert {"hello.txt", "world.txt"}.issubset(names)

    def test_list_hides_files_without_list_permission(
        self, temp_storage: Path, mock_audit_logger: AuditLogger, restricted_store: PermissionStore
    ):
        (temp_storage / "secret.txt").write_text("private")
        interface = _make_interface(temp_storage, mock_audit_logger, restricted_store)
        entries = interface.list_folder("/")
        names = {e.filename for e in entries}
        assert "secret.txt" not in names

    def test_list_nonexistent_returns_error_code(
        self, temp_storage: Path, mock_audit_logger: AuditLogger, open_store: PermissionStore
    ):
        interface = _make_interface(temp_storage, mock_audit_logger, open_store)
        assert interface.list_folder("/nonexistent") == paramiko.SFTP_NO_SUCH_FILE

    def test_list_virtual_kryoset_root(
        self, temp_storage: Path, mock_audit_logger: AuditLogger, open_store: PermissionStore
    ):
        interface = _make_interface(temp_storage, mock_audit_logger, open_store)
        entries = interface.list_folder("/.kryoset")
        names = {e.filename for e in entries}
        assert {"commands", "shares", "permissions"}.issubset(names)


class TestMkdirRmdir:
    def test_mkdir_creates_directory(
        self, temp_storage: Path, mock_audit_logger: AuditLogger, open_store: PermissionStore
    ):
        interface = _make_interface(temp_storage, mock_audit_logger, open_store)
        assert interface.mkdir("/newdir", MagicMock()) == paramiko.SFTP_OK
        assert (temp_storage / "newdir").is_dir()

    def test_mkdir_duplicate_returns_failure(
        self, temp_storage: Path, mock_audit_logger: AuditLogger, open_store: PermissionStore
    ):
        (temp_storage / "existing").mkdir()
        interface = _make_interface(temp_storage, mock_audit_logger, open_store)
        assert interface.mkdir("/existing", MagicMock()) == paramiko.SFTP_FAILURE

    def test_mkdir_denied_without_upload_permission(
        self, temp_storage: Path, mock_audit_logger: AuditLogger, restricted_store: PermissionStore
    ):
        interface = _make_interface(temp_storage, mock_audit_logger, restricted_store)
        result = interface.mkdir("/newdir", MagicMock())
        assert result == paramiko.SFTP_NO_SUCH_FILE
        assert not (temp_storage / "newdir").exists()

    def test_rmdir_removes_empty_directory(
        self, temp_storage: Path, mock_audit_logger: AuditLogger, open_store: PermissionStore
    ):
        (temp_storage / "todelete").mkdir()
        interface = _make_interface(temp_storage, mock_audit_logger, open_store)
        assert interface.rmdir("/todelete") == paramiko.SFTP_OK
        assert not (temp_storage / "todelete").exists()

    def test_rmdir_denied_without_delete_permission(
        self, temp_storage: Path, mock_audit_logger: AuditLogger, restricted_store: PermissionStore
    ):
        (temp_storage / "todelete").mkdir()
        interface = _make_interface(temp_storage, mock_audit_logger, restricted_store)
        result = interface.rmdir("/todelete")
        assert result == paramiko.SFTP_NO_SUCH_FILE
        assert (temp_storage / "todelete").exists()

    def test_mkdir_on_virtual_path_denied(
        self, temp_storage: Path, mock_audit_logger: AuditLogger, open_store: PermissionStore
    ):
        interface = _make_interface(temp_storage, mock_audit_logger, open_store)
        assert interface.mkdir("/.kryoset/newdir", MagicMock()) == paramiko.SFTP_PERMISSION_DENIED


class TestRemoveRename:
    def test_remove_existing_file(
        self, temp_storage: Path, mock_audit_logger: AuditLogger, open_store: PermissionStore
    ):
        target = temp_storage / "bye.txt"
        target.write_text("goodbye")
        interface = _make_interface(temp_storage, mock_audit_logger, open_store)
        assert interface.remove("/bye.txt") == paramiko.SFTP_OK
        assert not target.exists()

    def test_remove_nonexistent_file_returns_failure(
        self, temp_storage: Path, mock_audit_logger: AuditLogger, open_store: PermissionStore
    ):
        interface = _make_interface(temp_storage, mock_audit_logger, open_store)
        assert interface.remove("/ghost.txt") == paramiko.SFTP_FAILURE

    def test_remove_denied_without_delete_permission(
        self, temp_storage: Path, mock_audit_logger: AuditLogger, restricted_store: PermissionStore
    ):
        target = temp_storage / "secret.txt"
        target.write_text("data")
        interface = _make_interface(temp_storage, mock_audit_logger, restricted_store)
        result = interface.remove("/secret.txt")
        assert result == paramiko.SFTP_NO_SUCH_FILE
        assert target.exists()

    def test_remove_virtual_path_denied(
        self, temp_storage: Path, mock_audit_logger: AuditLogger, open_store: PermissionStore
    ):
        interface = _make_interface(temp_storage, mock_audit_logger, open_store)
        assert interface.remove("/.kryoset/shares/x.json") == paramiko.SFTP_PERMISSION_DENIED

    def test_rename_file(
        self, temp_storage: Path, mock_audit_logger: AuditLogger, open_store: PermissionStore
    ):
        (temp_storage / "old.txt").write_text("data")
        interface = _make_interface(temp_storage, mock_audit_logger, open_store)
        assert interface.rename("/old.txt", "/new.txt") == paramiko.SFTP_OK
        assert (temp_storage / "new.txt").exists()
        assert not (temp_storage / "old.txt").exists()

    def test_rename_denied_without_rename_permission(
        self, temp_storage: Path, mock_audit_logger: AuditLogger, restricted_store: PermissionStore
    ):
        (temp_storage / "old.txt").write_text("data")
        interface = _make_interface(temp_storage, mock_audit_logger, restricted_store)
        result = interface.rename("/old.txt", "/new.txt")
        assert result == paramiko.SFTP_NO_SUCH_FILE
        assert (temp_storage / "old.txt").exists()

    def test_rename_virtual_path_denied(
        self, temp_storage: Path, mock_audit_logger: AuditLogger, open_store: PermissionStore
    ):
        interface = _make_interface(temp_storage, mock_audit_logger, open_store)
        assert interface.rename("/.kryoset/x", "/y") == paramiko.SFTP_PERMISSION_DENIED


class TestStatLstat:
    def test_stat_existing_file(
        self, temp_storage: Path, mock_audit_logger: AuditLogger, open_store: PermissionStore
    ):
        (temp_storage / "file.txt").write_text("hello")
        interface = _make_interface(temp_storage, mock_audit_logger, open_store)
        result = interface.stat("/file.txt")
        assert isinstance(result, paramiko.SFTPAttributes)

    def test_stat_nonexistent_returns_error(
        self, temp_storage: Path, mock_audit_logger: AuditLogger, open_store: PermissionStore
    ):
        interface = _make_interface(temp_storage, mock_audit_logger, open_store)
        assert interface.stat("/ghost.txt") == paramiko.SFTP_NO_SUCH_FILE

    def test_stat_hidden_without_list_permission(
        self, temp_storage: Path, mock_audit_logger: AuditLogger, restricted_store: PermissionStore
    ):
        (temp_storage / "secret.txt").write_text("hidden")
        interface = _make_interface(temp_storage, mock_audit_logger, restricted_store)
        assert interface.stat("/secret.txt") == paramiko.SFTP_NO_SUCH_FILE

    def test_stat_virtual_kryoset(
        self, temp_storage: Path, mock_audit_logger: AuditLogger, open_store: PermissionStore
    ):
        interface = _make_interface(temp_storage, mock_audit_logger, open_store)
        result = interface.stat("/.kryoset")
        assert isinstance(result, paramiko.SFTPAttributes)


class TestOpenFile:
    def test_open_for_read_with_permission(
        self, temp_storage: Path, mock_audit_logger: AuditLogger, open_store: PermissionStore
    ):
        import os
        (temp_storage / "data.txt").write_text("content")
        interface = _make_interface(temp_storage, mock_audit_logger, open_store)
        handle = interface.open("/data.txt", os.O_RDONLY, MagicMock())
        assert isinstance(handle, paramiko.SFTPHandle)
        handle.close()

    def test_open_for_read_denied_without_download(
        self, temp_storage: Path, mock_audit_logger: AuditLogger, restricted_store: PermissionStore
    ):
        import os
        (temp_storage / "data.txt").write_text("content")
        interface = _make_interface(temp_storage, mock_audit_logger, restricted_store)
        result = interface.open("/data.txt", os.O_RDONLY, MagicMock())
        assert result == paramiko.SFTP_NO_SUCH_FILE

    def test_open_for_write_with_permission(
        self, temp_storage: Path, mock_audit_logger: AuditLogger, open_store: PermissionStore
    ):
        import os
        (temp_storage / "out.txt").write_text("")
        interface = _make_interface(temp_storage, mock_audit_logger, open_store)
        handle = interface.open("/out.txt", os.O_WRONLY, MagicMock())
        assert isinstance(handle, paramiko.SFTPHandle)
        handle.close()

    def test_open_for_write_denied_without_upload(
        self, temp_storage: Path, mock_audit_logger: AuditLogger
    , tmp_path: Path):
        import os
        download_only_store = PermissionStore(db_path=tmp_path / "dl.db")
        download_only_store.initialize()
        download_only_store.add_rule(PermissionRule(
            subject_type="user", subject_id="testuser",
            path="/", permissions=Permission.LIST | Permission.DOWNLOAD,
        ))
        (temp_storage / "out.txt").write_text("")
        interface = _make_interface(temp_storage, mock_audit_logger, download_only_store)
        result = interface.open("/out.txt", os.O_WRONLY, MagicMock())
        assert result == paramiko.SFTP_PERMISSION_DENIED


class TestVirtualControlChannel:
    def test_upload_command_file_is_processed(
        self, temp_storage: Path, mock_audit_logger: AuditLogger, open_store: PermissionStore
    ):
        import json, os
        interface = _make_interface(temp_storage, mock_audit_logger, open_store)
        handle = interface.open("/.kryoset/commands/cmd.json", os.O_WRONLY, MagicMock())
        assert not isinstance(handle, int), "Expected an SFTPHandle for command upload"

        command = json.dumps({
            "action": "create_share",
            "path": "/",
            "expires_in_hours": 24,
        }).encode()
        handle.write(0, command)
        handle.close()

    def test_read_nonexistent_share_returns_error(
        self, temp_storage: Path, mock_audit_logger: AuditLogger, open_store: PermissionStore
    ):
        import os
        interface = _make_interface(temp_storage, mock_audit_logger, open_store)
        result = interface.open("/.kryoset/shares/nonexistent.json", os.O_RDONLY, MagicMock())
        assert result == paramiko.SFTP_NO_SUCH_FILE


class TestGenerateHostKey:
    def test_generates_key_file(self, tmp_path: Path):
        key_path = tmp_path / "host_key"
        generate_host_key(key_path)
        assert key_path.exists()

    def test_key_file_permissions(self, tmp_path: Path):
        key_path = tmp_path / "host_key"
        generate_host_key(key_path)
        assert oct(key_path.stat().st_mode)[-3:] == "600"

    def test_existing_key_is_reused(self, tmp_path: Path):
        key_path = tmp_path / "host_key"
        key1 = generate_host_key(key_path)
        key2 = generate_host_key(key_path)
        assert key1.get_base64() == key2.get_base64()
