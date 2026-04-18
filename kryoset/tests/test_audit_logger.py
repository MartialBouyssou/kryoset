import gzip
import os
from pathlib import Path

import pytest

from kryoset.core.audit_logger import AuditLogger


@pytest.fixture()
def log_dir(tmp_path: Path) -> Path:
    return tmp_path / "logs"


@pytest.fixture()
def audit_logger(log_dir: Path) -> AuditLogger:
    return AuditLogger(log_directory=log_dir, retention_days=30, max_total_size_mb=100)


def _read_log(log_dir: Path) -> str:
    return (log_dir / "kryoset.log").read_text(encoding="utf-8")


class TestLogFormat:
    def test_log_file_created(self, audit_logger, log_dir):
        audit_logger.log_auth_success("alice", "127.0.0.1")
        assert (log_dir / "kryoset.log").exists()

    def test_paris_timezone_in_log(self, audit_logger, log_dir):
        audit_logger.log_auth_success("alice", "127.0.0.1")
        content = _read_log(log_dir)
        assert any(tz in content for tz in ("CET", "CEST", "+01", "+02"))

    def test_auth_success_logged(self, audit_logger, log_dir):
        audit_logger.log_auth_success("alice", "127.0.0.1")
        assert "AUTH_SUCCESS" in _read_log(log_dir)
        assert "user=alice" in _read_log(log_dir)

    def test_auth_failure_logged(self, audit_logger, log_dir):
        audit_logger.log_auth_failure("hacker", "1.2.3.4")
        assert "AUTH_FAILURE" in _read_log(log_dir)

    def test_totp_failure_logged(self, audit_logger, log_dir):
        audit_logger.log_totp_failure("alice", "127.0.0.1")
        assert "TOTP_FAILURE" in _read_log(log_dir)

    def test_totp_success_logged(self, audit_logger, log_dir):
        audit_logger.log_totp_success("alice", "127.0.0.1")
        assert "TOTP_SUCCESS" in _read_log(log_dir)

    def test_connect_logged(self, audit_logger, log_dir):
        audit_logger.log_connection("alice", "127.0.0.1")
        assert "CONNECT" in _read_log(log_dir)

    def test_disconnect_logged(self, audit_logger, log_dir):
        audit_logger.log_disconnection("alice", "127.0.0.1")
        assert "DISCONNECT" in _read_log(log_dir)

    def test_file_read_logged(self, audit_logger, log_dir):
        audit_logger.log_file_read("alice", "/docs/file.pdf")
        content = _read_log(log_dir)
        assert "FILE_READ" in content
        assert "path=/docs/file.pdf" in content

    def test_file_write_logged(self, audit_logger, log_dir):
        audit_logger.log_file_write("alice", "/uploads/doc.pdf")
        assert "FILE_WRITE" in _read_log(log_dir)

    def test_file_delete_logged(self, audit_logger, log_dir):
        audit_logger.log_file_delete("alice", "/old.txt")
        assert "FILE_DELETE" in _read_log(log_dir)

    def test_file_rename_logged(self, audit_logger, log_dir):
        audit_logger.log_file_rename("alice", "/old.txt", "/new.txt")
        content = _read_log(log_dir)
        assert "FILE_RENAME" in content
        assert "from=/old.txt" in content
        assert "to=/new.txt" in content

    def test_mkdir_logged(self, audit_logger, log_dir):
        audit_logger.log_mkdir("alice", "/newdir")
        assert "MKDIR" in _read_log(log_dir)

    def test_rmdir_logged(self, audit_logger, log_dir):
        audit_logger.log_rmdir("alice", "/olddir")
        assert "RMDIR" in _read_log(log_dir)

    def test_quota_exceeded_logged(self, audit_logger, log_dir):
        audit_logger.log_quota_exceeded("alice", "/upload.zip")
        assert "QUOTA_EXCEEDED" in _read_log(log_dir)

    def test_permission_denied_logged(self, audit_logger, log_dir):
        audit_logger.log_permission_denied("alice", "/private", "DOWNLOAD")
        content = _read_log(log_dir)
        assert "PERM_DENIED" in content
        assert "action=DOWNLOAD" in content

    def test_multiple_events_produce_multiple_lines(self, audit_logger, log_dir):
        audit_logger.log_auth_success("alice", "127.0.0.1")
        audit_logger.log_file_read("alice", "/readme.txt")
        audit_logger.log_disconnection("alice", "127.0.0.1")
        lines = [l for l in _read_log(log_dir).splitlines() if l.strip()]
        assert len(lines) == 3

    def test_log_file_permissions_restrictive(self, audit_logger, log_dir):
        audit_logger.log_auth_success("alice", "127.0.0.1")
        mode = oct((log_dir / "kryoset.log").stat().st_mode)[-3:]
        assert mode == "600"


class TestRetentionByAge:
    def test_old_rotated_files_deleted(self, log_dir):
        log_dir.mkdir(parents=True, exist_ok=True)
        old_file = log_dir / "kryoset.log.2020-01-01"
        old_file.write_text("old entry")
        old_file_gz = log_dir / "kryoset.log.2020-01-02.gz"
        old_file_gz.write_bytes(b"fake gz")
        os.utime(old_file, (0, 0))
        os.utime(old_file_gz, (0, 0))
        AuditLogger(log_directory=log_dir, retention_days=30)
        assert not old_file.exists()
        assert not old_file_gz.exists()

    def test_recent_rotated_files_kept(self, log_dir):
        log_dir.mkdir(parents=True, exist_ok=True)
        from kryoset.core.timezone import now_paris
        recent_date = now_paris().strftime("%Y-%m-%d")
        recent_file = log_dir / f"kryoset.log.{recent_date}"
        recent_file.write_text("recent entry")
        AuditLogger(log_directory=log_dir, retention_days=30)
        assert recent_file.exists()

    def test_unrelated_files_not_deleted(self, log_dir):
        log_dir.mkdir(parents=True, exist_ok=True)
        other = log_dir / "other_file.txt"
        other.write_text("keep me")
        os.utime(other, (0, 0))
        AuditLogger(log_directory=log_dir, retention_days=30)
        assert other.exists()


class TestRetentionBySize:
    def test_size_limit_triggers_deletion_of_oldest(self, log_dir):
        log_dir.mkdir(parents=True, exist_ok=True)
        for i in range(5):
            rotated = log_dir / f"kryoset.log.2026-01-0{i+1}"
            rotated.write_bytes(b"x" * 200 * 1024)
            os.utime(rotated, (i * 100, i * 100))
        AuditLogger(log_directory=log_dir, retention_days=365, max_total_size_mb=1)
        remaining = list(log_dir.glob("kryoset.log.*"))
        total_size = sum(f.stat().st_size for f in remaining)
        assert total_size <= 1 * 1024 * 1024

    def test_no_size_limit_keeps_all_files(self, log_dir):
        import time
        log_dir.mkdir(parents=True, exist_ok=True)
        now = time.time()
        for i in range(3):
            rotated = log_dir / f"kryoset.log.2026-02-0{i+1}"
            rotated.write_bytes(b"x" * 100)
            os.utime(rotated, (now - i * 86400, now - i * 86400))
        AuditLogger(log_directory=log_dir, retention_days=365, max_total_size_mb=None)
        assert len(list(log_dir.glob("kryoset.log.*"))) == 3
