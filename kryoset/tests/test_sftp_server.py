from pathlib import Path
from unittest.mock import MagicMock

import pytest

from kryoset.core.audit_logger import AuditLogger
from kryoset.core.sftp_server import KryosetSFTPServerInterface, generate_host_key


@pytest.fixture()
def mock_audit_logger(tmp_path: Path) -> AuditLogger:
    """Return a real AuditLogger writing to a temporary directory."""
    return AuditLogger(log_directory=tmp_path / "logs")


class TestPathResolution:
    """Verify that the SFTP interface keeps paths inside storage_path."""

    def _make_interface(
        self, storage_path: Path, audit_logger: AuditLogger
    ) -> KryosetSFTPServerInterface:
        mock_server = MagicMock()
        return KryosetSFTPServerInterface(mock_server, storage_path, audit_logger)

    def test_root_resolves_to_storage(
        self, temp_storage: Path, mock_audit_logger: AuditLogger
    ):
        interface = self._make_interface(temp_storage, mock_audit_logger)
        resolved = interface._resolve("/")
        assert resolved == temp_storage.resolve()

    def test_subdirectory_resolves_correctly(
        self, temp_storage: Path, mock_audit_logger: AuditLogger
    ):
        interface = self._make_interface(temp_storage, mock_audit_logger)
        resolved = interface._resolve("/subdir/file.txt")
        assert resolved == (temp_storage / "subdir" / "file.txt").resolve()

    def test_traversal_attack_is_blocked(
        self, temp_storage: Path, mock_audit_logger: AuditLogger
    ):
        interface = self._make_interface(temp_storage, mock_audit_logger)
        resolved = interface._resolve("/../../etc/passwd")
        assert str(resolved).startswith(str(temp_storage.resolve()))

    def test_canonicalize_root(
        self, temp_storage: Path, mock_audit_logger: AuditLogger
    ):
        interface = self._make_interface(temp_storage, mock_audit_logger)
        assert interface.canonicalize("/") == "/"

    def test_canonicalize_subpath(
        self, temp_storage: Path, mock_audit_logger: AuditLogger
    ):
        (temp_storage / "docs").mkdir()
        interface = self._make_interface(temp_storage, mock_audit_logger)
        result = interface.canonicalize("/docs")
        assert result == "/docs"


class TestListFolder:
    def test_list_empty_storage(
        self, temp_storage: Path, mock_audit_logger: AuditLogger
    ):
        interface = KryosetSFTPServerInterface(
            MagicMock(), temp_storage, mock_audit_logger
        )
        entries = interface.list_folder("/")
        assert entries == []

    def test_list_returns_files(
        self, temp_storage: Path, mock_audit_logger: AuditLogger
    ):
        (temp_storage / "hello.txt").write_text("hi")
        (temp_storage / "world.txt").write_text("world")
        interface = KryosetSFTPServerInterface(
            MagicMock(), temp_storage, mock_audit_logger
        )
        entries = interface.list_folder("/")
        names = {e.filename for e in entries}
        assert names == {"hello.txt", "world.txt"}

    def test_list_nonexistent_returns_error_code(
        self, temp_storage: Path, mock_audit_logger: AuditLogger
    ):
        import paramiko
        interface = KryosetSFTPServerInterface(
            MagicMock(), temp_storage, mock_audit_logger
        )
        result = interface.list_folder("/nonexistent")
        assert result == paramiko.SFTP_NO_SUCH_FILE


class TestMkdirRmdir:
    def test_mkdir_creates_directory(
        self, temp_storage: Path, mock_audit_logger: AuditLogger
    ):
        import paramiko
        interface = KryosetSFTPServerInterface(
            MagicMock(), temp_storage, mock_audit_logger
        )
        result = interface.mkdir("/newdir", MagicMock())
        assert result == paramiko.SFTP_OK
        assert (temp_storage / "newdir").is_dir()

    def test_mkdir_duplicate_returns_failure(
        self, temp_storage: Path, mock_audit_logger: AuditLogger
    ):
        import paramiko
        (temp_storage / "existing").mkdir()
        interface = KryosetSFTPServerInterface(
            MagicMock(), temp_storage, mock_audit_logger
        )
        result = interface.mkdir("/existing", MagicMock())
        assert result == paramiko.SFTP_FAILURE

    def test_rmdir_removes_empty_directory(
        self, temp_storage: Path, mock_audit_logger: AuditLogger
    ):
        import paramiko
        (temp_storage / "todelete").mkdir()
        interface = KryosetSFTPServerInterface(
            MagicMock(), temp_storage, mock_audit_logger
        )
        result = interface.rmdir("/todelete")
        assert result == paramiko.SFTP_OK
        assert not (temp_storage / "todelete").exists()


class TestRemoveRename:
    def test_remove_existing_file(
        self, temp_storage: Path, mock_audit_logger: AuditLogger
    ):
        import paramiko
        target = temp_storage / "bye.txt"
        target.write_text("goodbye")
        interface = KryosetSFTPServerInterface(
            MagicMock(), temp_storage, mock_audit_logger
        )
        result = interface.remove("/bye.txt")
        assert result == paramiko.SFTP_OK
        assert not target.exists()

    def test_remove_nonexistent_file_returns_failure(
        self, temp_storage: Path, mock_audit_logger: AuditLogger
    ):
        import paramiko
        interface = KryosetSFTPServerInterface(
            MagicMock(), temp_storage, mock_audit_logger
        )
        result = interface.remove("/ghost.txt")
        assert result == paramiko.SFTP_FAILURE

    def test_rename_file(
        self, temp_storage: Path, mock_audit_logger: AuditLogger
    ):
        import paramiko
        (temp_storage / "old.txt").write_text("data")
        interface = KryosetSFTPServerInterface(
            MagicMock(), temp_storage, mock_audit_logger
        )
        result = interface.rename("/old.txt", "/new.txt")
        assert result == paramiko.SFTP_OK
        assert (temp_storage / "new.txt").exists()
        assert not (temp_storage / "old.txt").exists()


class TestGenerateHostKey:
    def test_generates_key_file(self, tmp_path: Path):
        key_path = tmp_path / "host_key"
        generate_host_key(key_path)
        assert key_path.exists()

    def test_key_file_permissions(self, tmp_path: Path):
        key_path = tmp_path / "host_key"
        generate_host_key(key_path)
        mode = oct(key_path.stat().st_mode)[-3:]
        assert mode == "600"

    def test_existing_key_is_reused(self, tmp_path: Path):
        key_path = tmp_path / "host_key"
        key1 = generate_host_key(key_path)
        key2 = generate_host_key(key_path)
        assert key1.get_base64() == key2.get_base64()
