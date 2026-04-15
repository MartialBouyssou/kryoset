from datetime import datetime
from zoneinfo import ZoneInfo

PARIS_TZ = ZoneInfo("Europe/Paris")
UTC_TZ = ZoneInfo("UTC")


def now_paris() -> datetime:
    """Return the current datetime in the Europe/Paris timezone (aware)."""
    return datetime.now(tz=PARIS_TZ)


def now_utc() -> datetime:
    """Return the current datetime in UTC (aware)."""
    return datetime.now(tz=UTC_TZ)


def to_paris(dt: datetime) -> datetime:
    """
    Convert any aware datetime to Europe/Paris timezone.

    Args:
        dt: A timezone-aware datetime object.

    Returns:
        The same instant expressed in Europe/Paris time.
    """
    return dt.astimezone(PARIS_TZ)


def parse_iso(value: str) -> datetime:
    """
    Parse an ISO-8601 string into a timezone-aware datetime.

    Naive strings are assumed to be UTC and converted accordingly.

    Args:
        value: ISO-8601 datetime string.

    Returns:
        Timezone-aware datetime in UTC.
    """
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC_TZ)
    return dt
