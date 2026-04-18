import ipaddress
from datetime import datetime, timedelta

import pytest

from kryoset.core.permissions import (
    PRESET_FULL,
    PRESET_READ_ONLY,
    Permission,
    PermissionRule,
    ShareLink,
    TimeWindow,
)


class TestPermissionFlags:
    def test_combine_flags(self):
        combined = Permission.DOWNLOAD | Permission.UPLOAD
        assert Permission.DOWNLOAD in combined
        assert Permission.UPLOAD in combined
        assert Permission.DELETE not in combined

    def test_from_names_valid(self):
        result = Permission.from_names(["DOWNLOAD", "UPLOAD"])
        assert result == Permission.DOWNLOAD | Permission.UPLOAD

    def test_from_names_case_insensitive(self):
        assert Permission.from_names(["download"]) == Permission.DOWNLOAD

    def test_from_names_invalid_raises(self):
        with pytest.raises(ValueError, match="Unknown permission"):
            Permission.from_names(["INVALID"])

    def test_to_names_roundtrip(self):
        original = Permission.DOWNLOAD | Permission.RENAME
        names = original.to_names()
        assert Permission.from_names(names) == original

    def test_none_has_no_names(self):
        assert Permission.NONE.to_names() == []

    def test_presets_contain_expected_flags(self):
        assert Permission.DOWNLOAD in PRESET_READ_ONLY
        assert Permission.UPLOAD not in PRESET_READ_ONLY
        assert Permission.DELETE in PRESET_FULL


class TestTimeWindow:
    def test_active_within_window(self):
        window = TimeWindow(days=[1, 2, 3, 4, 5], hour_from=9, hour_to=18)
        monday_noon = datetime(2026, 4, 13, 12, 0)
        assert window.is_active_now(monday_noon)

    def test_inactive_outside_hours(self):
        window = TimeWindow(days=[1, 2, 3, 4, 5], hour_from=9, hour_to=18)
        monday_night = datetime(2026, 4, 13, 22, 0)
        assert not window.is_active_now(monday_night)

    def test_inactive_on_weekend(self):
        window = TimeWindow(days=[1, 2, 3, 4, 5], hour_from=9, hour_to=18)
        saturday = datetime(2026, 4, 11, 12, 0)
        assert not window.is_active_now(saturday)

    def test_dict_roundtrip(self):
        window = TimeWindow(days=[1, 2], hour_from=8, hour_to=17)
        assert TimeWindow.from_dict(window.to_dict()) == window


class TestPermissionRule:
    def _make_rule(self, **kwargs) -> PermissionRule:
        defaults = dict(
            subject_type="user",
            subject_id="alice",
            path="/photos",
            permissions=Permission.DOWNLOAD,
        )
        defaults.update(kwargs)
        return PermissionRule(**defaults)

    def test_not_expired_by_default(self):
        rule = self._make_rule()
        assert not rule.is_expired()

    def test_expired_rule(self):
        past = datetime.utcnow() - timedelta(hours=1)
        rule = self._make_rule(expires_at=past)
        assert rule.is_expired()

    def test_future_expiry_not_expired(self):
        future = datetime.utcnow() + timedelta(hours=1)
        rule = self._make_rule(expires_at=future)
        assert not rule.is_expired()

    def test_no_time_windows_always_active(self):
        rule = self._make_rule(time_windows=[])
        assert rule.is_time_window_active()

    def test_inactive_time_window(self):
        window = TimeWindow(days=[1], hour_from=9, hour_to=10)
        rule = self._make_rule(time_windows=[window])
        saturday = datetime(2026, 4, 11, 12, 0)
        assert not rule.is_time_window_active(saturday)

    def test_ip_whitelist_allows_listed(self):
        rule = self._make_rule(ip_whitelist=["192.168.1.0/24"])
        assert rule.is_ip_allowed("192.168.1.100")

    def test_ip_whitelist_blocks_unlisted(self):
        rule = self._make_rule(ip_whitelist=["192.168.1.0/24"])
        assert not rule.is_ip_allowed("10.0.0.1")

    def test_ip_blacklist_blocks_listed(self):
        rule = self._make_rule(ip_blacklist=["10.0.0.1"])
        assert not rule.is_ip_allowed("10.0.0.1")

    def test_no_ip_restrictions_allows_all(self):
        rule = self._make_rule()
        assert rule.is_ip_allowed("1.2.3.4")

    def test_user_rule_beats_group_in_specificity(self):
        user_rule = self._make_rule(subject_type="user", path="/a")
        group_rule = self._make_rule(subject_type="group", path="/a")
        assert user_rule.specificity() > group_rule.specificity()

    def test_deeper_path_beats_shallower(self):
        deep = self._make_rule(path="/a/b/c")
        shallow = self._make_rule(path="/a")
        assert deep.specificity() > shallow.specificity()

    def test_is_currently_effective_all_good(self):
        future = datetime.utcnow() + timedelta(hours=1)
        rule = self._make_rule(expires_at=future)
        assert rule.is_currently_effective(ip_address="127.0.0.1")

    def test_is_currently_effective_expired(self):
        past = datetime.utcnow() - timedelta(hours=1)
        rule = self._make_rule(expires_at=past)
        assert not rule.is_currently_effective()


class TestShareLink:
    def _make_link(self, **kwargs) -> ShareLink:
        defaults = dict(
            token="abc123",
            created_by="alice",
            path="/report.pdf",
            permissions=Permission.DOWNLOAD,
        )
        defaults.update(kwargs)
        return ShareLink(**defaults)

    def test_valid_link_with_no_constraints(self):
        assert self._make_link().is_valid()

    def test_expired_link_is_invalid(self):
        past = datetime.utcnow() - timedelta(hours=1)
        assert not self._make_link(expires_at=past).is_valid()

    def test_download_limit_exhausted(self):
        link = self._make_link(download_limit=3, download_count=3)
        assert not link.is_valid()

    def test_download_limit_not_yet_reached(self):
        link = self._make_link(download_limit=3, download_count=2)
        assert link.is_valid()
