import time
from collections import defaultdict, deque
from threading import Lock


class RateLimitExceeded(Exception):
    def __init__(self, retry_after: int) -> None:
        self.retry_after = max(1, retry_after)
        super().__init__(f"Too many attempts. Try again in {self.retry_after} seconds.")


class FailureRateLimiter:
    """Small in-process throttler for local/self-hosted deployments."""

    def __init__(self) -> None:
        self._failures: dict[str, deque[float]] = defaultdict(deque)
        self._blocked_until: dict[str, float] = {}
        self._lock = Lock()

    def check(self, key: str) -> None:
        now = time.monotonic()
        with self._lock:
            until = self._blocked_until.get(key)
            if until and until > now:
                raise RateLimitExceeded(int(until - now))
            if until:
                self._blocked_until.pop(key, None)

    def record_failure(
        self,
        key: str,
        *,
        limit: int,
        window_seconds: int,
        block_seconds: int,
    ) -> None:
        now = time.monotonic()
        with self._lock:
            failures = self._failures[key]
            while failures and failures[0] < now - window_seconds:
                failures.popleft()
            failures.append(now)
            if len(failures) >= limit:
                failures.clear()
                self._blocked_until[key] = now + block_seconds
                raise RateLimitExceeded(block_seconds)

    def reset(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)
            self._blocked_until.pop(key, None)


login_limiter = FailureRateLimiter()
totp_limiter = FailureRateLimiter()
share_limiter = FailureRateLimiter()
