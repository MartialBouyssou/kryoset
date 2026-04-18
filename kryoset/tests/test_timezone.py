from datetime import datetime
from zoneinfo import ZoneInfo

import pytest

from kryoset.core.timezone import (
    PARIS_TZ,
    UTC_TZ,
    now_paris,
    now_utc,
    parse_iso,
    to_paris,
)


class TestNowFunctions:
    def test_now_paris_is_aware(self):
        dt = now_paris()
        assert dt.tzinfo is not None

    def test_now_paris_is_paris_tz(self):
        dt = now_paris()
        assert dt.tzinfo is PARIS_TZ or str(dt.tzinfo) == "Europe/Paris"

    def test_now_utc_is_aware(self):
        dt = now_utc()
        assert dt.tzinfo is not None

    def test_now_utc_and_paris_represent_same_instant(self):
        utc = now_utc()
        paris = now_paris()
        diff = abs((utc - paris).total_seconds())
        assert diff < 2


class TestToParisConversion:
    def test_converts_utc_to_paris(self):
        utc_dt = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC_TZ)
        paris_dt = to_paris(utc_dt)
        assert paris_dt.tzinfo is not None
        assert paris_dt.hour in (12, 13)

    def test_preserves_instant(self):
        utc_dt = datetime(2026, 6, 15, 10, 0, 0, tzinfo=UTC_TZ)
        paris_dt = to_paris(utc_dt)
        assert abs((utc_dt - paris_dt).total_seconds()) < 1


class TestParseIso:
    def test_parses_aware_string(self):
        dt = parse_iso("2026-04-14T12:00:00+02:00")
        assert dt.tzinfo is not None

    def test_parses_naive_string_as_utc(self):
        dt = parse_iso("2026-04-14T12:00:00")
        assert dt.tzinfo is UTC_TZ

    def test_roundtrip(self):
        original = now_utc().replace(microsecond=0)
        parsed = parse_iso(original.isoformat())
        assert abs((original - parsed).total_seconds()) < 1
