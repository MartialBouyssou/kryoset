import logging
import logging.handlers
import os
from datetime import datetime, timedelta
from pathlib import Path

LOG_RETENTION_DAYS = 30
LOG_DIRECTORY = Path.home() / ".kryoset" / "logs"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


class _FlushingFileHandler(logging.handlers.TimedRotatingFileHandler):
    """
    TimedRotatingFileHandler that flushes after every record.

    This ensures log entries are immediately visible on disk, which is
    important for security auditing and for tests that read the log file
    right after writing an entry.
    """

    def emit(self, record: logging.LogRecord) -> None:
        super().emit(record)
        self.flush()


class AuditLogger:
    """
    Structured audit trail for Kryoset server events.

    Each public method appends one line to the current day's log file.
    The format is::

        [2026-04-11 14:32:01] [AUTH_SUCCESS ] user=Martial ip=127.0.0.1

    Args:
        log_directory: Directory where log files are written.
            Defaults to ``~/.kryoset/logs/``.
    """

    def __init__(self, log_directory: Path = LOG_DIRECTORY) -> None:
        self._log_directory = log_directory
        self._log_file = log_directory / "kryoset.log"
        self._logger = self._build_logger()
        self._apply_permissions()
        self._purge_old_logs()

    def _build_logger(self) -> logging.Logger:
        """
        Create and configure a rotating file logger writing to log_directory.

        Returns:
            A :class:`logging.Logger` instance with a flushing rotating handler.
        """
        self._log_directory.mkdir(parents=True, exist_ok=True)

        logger_name = f"kryoset.audit.{id(self)}"
        logger = logging.getLogger(logger_name)
        logger.setLevel(logging.INFO)
        logger.propagate = False

        handler = _FlushingFileHandler(
            filename=str(self._log_file),
            when="midnight",
            interval=1,
            backupCount=LOG_RETENTION_DAYS,
            encoding="utf-8",
        )
        handler.suffix = "%Y-%m-%d"
        formatter = logging.Formatter(
            fmt="[%(asctime)s] %(message)s",
            datefmt=LOG_DATE_FORMAT,
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        return logger

    def _apply_permissions(self) -> None:
        """Set restrictive permissions on the log file once it exists."""
        if self._log_file.exists():
            os.chmod(self._log_file, 0o600)

    def _purge_old_logs(self) -> None:
        """
        Delete rotated log files older than LOG_RETENTION_DAYS days.

        Only files matching the pattern ``kryoset.log.YYYY-MM-DD`` are
        considered to avoid accidentally removing unrelated files.
        """
        cutoff = datetime.now() - timedelta(days=LOG_RETENTION_DAYS)
        for log_file in self._log_directory.glob("kryoset.log.*"):
            suffix = log_file.suffix.lstrip(".")
            try:
                file_date = datetime.strptime(suffix, "%Y-%m-%d")
                if file_date < cutoff:
                    log_file.unlink()
            except ValueError:
                pass

    def _write(self, event_type: str, details: dict[str, str]) -> None:
        """
        Format and write one audit log line.

        Args:
            event_type: Short uppercase label (e.g. ``AUTH_SUCCESS``),
                padded to 14 characters for column alignment.
            details: Ordered key=value pairs appended after the label.
        """
        label = f"[{event_type:<14}]"
        pairs = " ".join(f"{key}={value}" for key, value in details.items())
        self._logger.info("%s %s", label, pairs)
        self._apply_permissions()

    def log_connection(self, username: str, ip_address: str) -> None:
        """
        Record a successful client connection.

        Args:
            username: Authenticated username.
            ip_address: Remote IP address of the client.
        """
        self._write("CONNECT", {"user": username, "ip": ip_address})

    def log_disconnection(self, username: str, ip_address: str) -> None:
        """
        Record a client disconnection.

        Args:
            username: Username of the session that ended.
            ip_address: Remote IP address of the client.
        """
        self._write("DISCONNECT", {"user": username, "ip": ip_address})

    def log_auth_success(self, username: str, ip_address: str) -> None:
        """
        Record a successful password authentication.

        Args:
            username: Username that authenticated successfully.
            ip_address: Remote IP address of the client.
        """
        self._write("AUTH_SUCCESS", {"user": username, "ip": ip_address})

    def log_auth_failure(self, username: str, ip_address: str) -> None:
        """
        Record a failed authentication attempt.

        Args:
            username: Username that was attempted.
            ip_address: Remote IP address of the client.
        """
        self._write("AUTH_FAILURE", {"user": username, "ip": ip_address})

    def log_file_read(self, username: str, remote_path: str) -> None:
        """
        Record a file download (get) operation.

        Args:
            username: User who downloaded the file.
            remote_path: Server-side path of the file.
        """
        self._write("FILE_READ", {"user": username, "path": remote_path})

    def log_file_write(self, username: str, remote_path: str) -> None:
        """
        Record a file upload (put) operation.

        Args:
            username: User who uploaded the file.
            remote_path: Server-side path of the file.
        """
        self._write("FILE_WRITE", {"user": username, "path": remote_path})

    def log_file_delete(self, username: str, remote_path: str) -> None:
        """
        Record a file deletion.

        Args:
            username: User who deleted the file.
            remote_path: Server-side path of the deleted file.
        """
        self._write("FILE_DELETE", {"user": username, "path": remote_path})

    def log_file_rename(
        self, username: str, old_path: str, new_path: str
    ) -> None:
        """
        Record a file or directory rename.

        Args:
            username: User who performed the rename.
            old_path: Original server-side path.
            new_path: New server-side path.
        """
        self._write(
            "FILE_RENAME",
            {"user": username, "from": old_path, "to": new_path},
        )

    def log_mkdir(self, username: str, remote_path: str) -> None:
        """
        Record a directory creation.

        Args:
            username: User who created the directory.
            remote_path: Server-side path of the new directory.
        """
        self._write("MKDIR", {"user": username, "path": remote_path})

    def log_rmdir(self, username: str, remote_path: str) -> None:
        """
        Record a directory deletion.

        Args:
            username: User who deleted the directory.
            remote_path: Server-side path of the deleted directory.
        """
        self._write("RMDIR", {"user": username, "path": remote_path})
