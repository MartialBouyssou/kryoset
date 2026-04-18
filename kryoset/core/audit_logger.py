import gzip
import logging
import logging.handlers
import os
import shutil
from datetime import timedelta
from pathlib import Path
from typing import Optional

from kryoset.core.timezone import PARIS_TZ, now_paris

LOG_DIRECTORY = Path.home() / ".kryoset" / "logs"
DEFAULT_RETENTION_DAYS = 30
DEFAULT_MAX_SIZE_MB = 500
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S %Z"


class _FlushingFileHandler(logging.handlers.TimedRotatingFileHandler):
    """
    TimedRotatingFileHandler that flushes after every record and compresses
    rotated files with gzip.
    """

    def emit(self, record: logging.LogRecord) -> None:
        super().emit(record)
        self.flush()

    def doRollover(self) -> None:
        """Rotate the log file and compress the previous file with gzip."""
        super().doRollover()
        self._compress_last_rotated_file()

    def _compress_last_rotated_file(self) -> None:
        """Find the most recently rotated log file and compress it."""
        log_dir = Path(self.baseFilename).parent
        stem = Path(self.baseFilename).name
        for candidate in sorted(log_dir.glob(f"{stem}.*")):
            if not candidate.suffix == ".gz" and candidate.exists():
                gz_path = candidate.with_suffix(candidate.suffix + ".gz")
                try:
                    with open(candidate, "rb") as f_in:
                        with gzip.open(gz_path, "wb") as f_out:
                            shutil.copyfileobj(f_in, f_out)
                    candidate.unlink()
                except OSError:
                    pass
                break


class AuditLogger:
    """
    Structured audit trail for Kryoset server events.

    Writes one line per event to a rotating log file using Paris timezone.
    Rotated files are compressed with gzip. Old files and oversized logs
    are pruned automatically on each startup.

    Log format::

        [2026-04-14 09:32:01 CEST] [AUTH_SUCCESS  ] user=Martial ip=127.0.0.1

    Args:
        log_directory: Directory where log files are written.
        retention_days: Delete rotated files older than this many days.
        max_total_size_mb: Delete oldest rotated files when total size exceeds
            this threshold (in megabytes). Set to None to disable size limit.
    """

    def __init__(
        self,
        log_directory: Path = LOG_DIRECTORY,
        retention_days: int = DEFAULT_RETENTION_DAYS,
        max_total_size_mb: Optional[int] = DEFAULT_MAX_SIZE_MB,
    ) -> None:
        self._log_directory = log_directory
        self._retention_days = retention_days
        self._max_total_size_bytes = (
            max_total_size_mb * 1024 * 1024 if max_total_size_mb else None
        )
        self._log_file = log_directory / "kryoset.log"
        self._logger = self._build_logger()
        self._apply_permissions()
        self._purge_old_logs()
        self._enforce_size_limit()

    def _build_logger(self) -> logging.Logger:
        """Create and configure the rotating file logger."""
        self._log_directory.mkdir(parents=True, exist_ok=True)
        logger_name = f"kryoset.audit.{id(self)}"
        logger = logging.getLogger(logger_name)
        logger.setLevel(logging.INFO)
        logger.propagate = False

        handler = _FlushingFileHandler(
            filename=str(self._log_file),
            when="midnight",
            interval=1,
            backupCount=self._retention_days,
            encoding="utf-8",
        )
        handler.suffix = "%Y-%m-%d"
        _paris_tz = PARIS_TZ

        class _ParisFormatter(logging.Formatter):
            def formatTime(self, record, datefmt=None):
                from datetime import datetime
                dt = datetime.fromtimestamp(record.created, tz=_paris_tz)
                if datefmt:
                    return dt.strftime(datefmt)
                return dt.strftime("%Y-%m-%d %H:%M:%S %Z")

        handler.setFormatter(_ParisFormatter(
            fmt="[%(asctime)s] %(message)s",
            datefmt=LOG_DATE_FORMAT,
        ))
        logger.addHandler(handler)
        return logger

    def _apply_permissions(self) -> None:
        """Set restrictive permissions on the live log file."""
        if self._log_file.exists():
            os.chmod(self._log_file, 0o600)

    def _rotated_files(self) -> list[Path]:
        """Return all rotated log files (plain and gzipped), sorted oldest first."""
        patterns = ["kryoset.log.*"]
        files = []
        for pattern in patterns:
            files.extend(self._log_directory.glob(pattern))
        return sorted(files, key=lambda p: p.stat().st_mtime)

    def _purge_old_logs(self) -> None:
        """
        Delete rotated log files older than *retention_days* days.

        Only files matching ``kryoset.log.*`` are considered.
        """
        cutoff = now_paris() - timedelta(days=self._retention_days)
        for log_file in self._rotated_files():
            try:
                mtime = log_file.stat().st_mtime
                from datetime import datetime
                from kryoset.core.timezone import PARIS_TZ
                file_date = datetime.fromtimestamp(mtime, tz=PARIS_TZ)
                if file_date < cutoff:
                    log_file.unlink()
            except OSError:
                pass

    def _enforce_size_limit(self) -> None:
        """
        Delete oldest rotated files until total log directory size is under
        the configured maximum.
        """
        if self._max_total_size_bytes is None:
            return

        rotated = self._rotated_files()
        live_size = self._log_file.stat().st_size if self._log_file.exists() else 0
        total = live_size + sum(f.stat().st_size for f in rotated)

        for old_file in rotated:
            if total <= self._max_total_size_bytes:
                break
            try:
                total -= old_file.stat().st_size
                old_file.unlink()
            except OSError:
                pass

    def _write(self, event_type: str, details: dict[str, str]) -> None:
        """
        Format and write one audit log line.

        Args:
            event_type: Short uppercase label padded to 14 characters.
            details: Ordered key=value pairs appended after the label.
        """
        label = f"[{event_type:<14}]"
        pairs = " ".join(f"{key}={value}" for key, value in details.items())
        self._logger.info("%s %s", label, pairs)
        self._apply_permissions()

    def log_connection(self, username: str, ip_address: str) -> None:
        """Record a successful client connection."""
        self._write("CONNECT", {"user": username, "ip": ip_address})

    def log_disconnection(self, username: str, ip_address: str) -> None:
        """Record a client disconnection."""
        self._write("DISCONNECT", {"user": username, "ip": ip_address})

    def log_auth_success(self, username: str, ip_address: str) -> None:
        """Record a successful password authentication."""
        self._write("AUTH_SUCCESS", {"user": username, "ip": ip_address})

    def log_auth_failure(self, username: str, ip_address: str) -> None:
        """Record a failed authentication attempt."""
        self._write("AUTH_FAILURE", {"user": username, "ip": ip_address})

    def log_totp_failure(self, username: str, ip_address: str) -> None:
        """Record a failed TOTP verification attempt."""
        self._write("TOTP_FAILURE", {"user": username, "ip": ip_address})

    def log_totp_success(self, username: str, ip_address: str) -> None:
        """Record a successful TOTP verification."""
        self._write("TOTP_SUCCESS", {"user": username, "ip": ip_address})

    def log_file_read(self, username: str, remote_path: str) -> None:
        """Record a file download (get) operation."""
        self._write("FILE_READ", {"user": username, "path": remote_path})

    def log_file_write(self, username: str, remote_path: str) -> None:
        """Record a file upload (put) operation."""
        self._write("FILE_WRITE", {"user": username, "path": remote_path})

    def log_file_delete(self, username: str, remote_path: str) -> None:
        """Record a file deletion."""
        self._write("FILE_DELETE", {"user": username, "path": remote_path})

    def log_file_rename(self, username: str, old_path: str, new_path: str) -> None:
        """Record a file or directory rename."""
        self._write("FILE_RENAME", {"user": username, "from": old_path, "to": new_path})

    def log_mkdir(self, username: str, remote_path: str) -> None:
        """Record a directory creation."""
        self._write("MKDIR", {"user": username, "path": remote_path})

    def log_rmdir(self, username: str, remote_path: str) -> None:
        """Record a directory deletion."""
        self._write("RMDIR", {"user": username, "path": remote_path})

    def log_quota_exceeded(self, username: str, remote_path: str) -> None:
        """Record a refused upload due to quota violation."""
        self._write("QUOTA_EXCEEDED", {"user": username, "path": remote_path})

    def log_permission_denied(self, username: str, remote_path: str, action: str) -> None:
        """Record an access denied event."""
        self._write(
            "PERM_DENIED",
            {"user": username, "path": remote_path, "action": action},
        )
