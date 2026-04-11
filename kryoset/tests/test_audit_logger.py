from datetime import datetime, timedelta
from pathlib import Path

import pytest

from kryoset.core.audit_logger import LOG_RETENTION_DAYS, AuditLogger


@pytest.fixture()
def log_directory(tmp_path: Path) -> Path:
    """Return a temporary directory used as the log storage root."""
    return tmp_path / "logs"


@pytest.fixture()
def audit_logger(log_directory: Path) -> AuditLogger:
    """Return an AuditLogger writing to a temporary directory."""
    return AuditLogger(log_directory=log_directory)


def _read_log(log_directory: Path) -> str:
    """Return the full content of the current log file."""
    log_file = log_directory / "kryoset.log"
    return log_file.read_text(encoding="utf-8")


class TestLogFormat:
    def test_log_file_is_created(self, audit_logger: AuditLogger, log_directory: Path):
        audit_logger.log_auth_success("alice", "127.0.0.1")
        assert (log_directory / "kryoset.log").exists()

    def test_auth_success_contains_event_type(
        self, audit_logger: AuditLogger, log_directory: Path
    ):
        audit_logger.log_auth_success("alice", "127.0.0.1")
        assert "AUTH_SUCCESS" in _read_log(log_directory)

    def test_auth_success_contains_username(
        self, audit_logger: AuditLogger, log_directory: Path
    ):
        audit_logger.log_auth_success("alice", "127.0.0.1")
        assert "user=alice" in _read_log(log_directory)

    def test_auth_success_contains_ip(
        self, audit_logger: AuditLogger, log_directory: Path
    ):
        audit_logger.log_auth_success("alice", "127.0.0.1")
        assert "ip=127.0.0.1" in _read_log(log_directory)

    def test_auth_failure_is_logged(
        self, audit_logger: AuditLogger, log_directory: Path
    ):
        audit_logger.log_auth_failure("hacker", "10.0.0.1")
        content = _read_log(log_directory)
        assert "AUTH_FAILURE" in content
        assert "user=hacker" in content

    def test_connect_is_logged(self, audit_logger: AuditLogger, log_directory: Path):
        audit_logger.log_connection("alice", "127.0.0.1")
        assert "CONNECT" in _read_log(log_directory)

    def test_disconnect_is_logged(self, audit_logger: AuditLogger, log_directory: Path):
        audit_logger.log_disconnection("alice", "127.0.0.1")
        assert "DISCONNECT" in _read_log(log_directory)

    def test_file_read_is_logged(self, audit_logger: AuditLogger, log_directory: Path):
        audit_logger.log_file_read("alice", "/documents/report.pdf")
        content = _read_log(log_directory)
        assert "FILE_READ" in content
        assert "path=/documents/report.pdf" in content

    def test_file_write_is_logged(self, audit_logger: AuditLogger, log_directory: Path):
        audit_logger.log_file_write("alice", "/documents/upload.pdf")
        content = _read_log(log_directory)
        assert "FILE_WRITE" in content
        assert "path=/documents/upload.pdf" in content

    def test_file_delete_is_logged(
        self, audit_logger: AuditLogger, log_directory: Path
    ):
        audit_logger.log_file_delete("alice", "/documents/old.txt")
        content = _read_log(log_directory)
        assert "FILE_DELETE" in content
        assert "path=/documents/old.txt" in content

    def test_file_rename_contains_both_paths(
        self, audit_logger: AuditLogger, log_directory: Path
    ):
        audit_logger.log_file_rename("alice", "/old.txt", "/new.txt")
        content = _read_log(log_directory)
        assert "FILE_RENAME" in content
        assert "from=/old.txt" in content
        assert "to=/new.txt" in content

    def test_mkdir_is_logged(self, audit_logger: AuditLogger, log_directory: Path):
        audit_logger.log_mkdir("alice", "/backups")
        content = _read_log(log_directory)
        assert "MKDIR" in content
        assert "path=/backups" in content

    def test_rmdir_is_logged(self, audit_logger: AuditLogger, log_directory: Path):
        audit_logger.log_rmdir("alice", "/backups")
        content = _read_log(log_directory)
        assert "RMDIR" in content
        assert "path=/backups" in content

    def test_multiple_events_produce_multiple_lines(
        self, audit_logger: AuditLogger, log_directory: Path
    ):
        audit_logger.log_auth_success("alice", "127.0.0.1")
        audit_logger.log_file_read("alice", "/readme.txt")
        audit_logger.log_disconnection("alice", "127.0.0.1")
        lines = [
            line
            for line in _read_log(log_directory).splitlines()
            if line.strip()
        ]
        assert len(lines) == 3


class TestLogPermissions:
    def test_log_file_has_restrictive_permissions(
        self, audit_logger: AuditLogger, log_directory: Path
    ):
        audit_logger.log_auth_success("alice", "127.0.0.1")
        mode = oct((log_directory / "kryoset.log").stat().st_mode)[-3:]
        assert mode == "600"


class TestLogPurge:
    def test_old_rotated_files_are_deleted(self, log_directory: Path):
        log_directory.mkdir(parents=True, exist_ok=True)
        old_date = datetime.now() - timedelta(days=LOG_RETENTION_DAYS + 5)
        old_file = log_directory / f"kryoset.log.{old_date.strftime('%Y-%m-%d')}"
        old_file.write_text("old entry")

        AuditLogger(log_directory=log_directory)

        assert not old_file.exists()

    def test_recent_rotated_files_are_kept(self, log_directory: Path):
        log_directory.mkdir(parents=True, exist_ok=True)
        recent_date = datetime.now() - timedelta(days=5)
        recent_file = log_directory / f"kryoset.log.{recent_date.strftime('%Y-%m-%d')}"
        recent_file.write_text("recent entry")

        AuditLogger(log_directory=log_directory)

        assert recent_file.exists()

    def test_unrelated_files_are_not_deleted(self, log_directory: Path):
        log_directory.mkdir(parents=True, exist_ok=True)
        unrelated = log_directory / "other_file.txt"
        unrelated.write_text("keep me")

        AuditLogger(log_directory=log_directory)

        assert unrelated.exists()
