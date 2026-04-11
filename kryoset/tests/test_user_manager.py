"""
Tests for kryoset.core.user_manager.

Covers user creation, deletion, authentication, enable/disable,
password management and listing.
"""

import pytest

from kryoset.core.user_manager import UserError, UserManager


class TestAddUser:
    def test_add_valid_user(self, user_manager: UserManager):
        user_manager.add_user("bob", "strongpassword1")
        users = {u["username"] for u in user_manager.list_users()}
        assert "bob" in users

    def test_duplicate_username_raises(self, user_manager_with_alice: UserManager):
        with pytest.raises(UserError, match="already exists"):
            user_manager_with_alice.add_user("alice", "anotherpassword1")

    def test_password_too_short_raises(self, user_manager: UserManager):
        with pytest.raises(UserError, match="8 characters"):
            user_manager.add_user("carol", "short")

    def test_invalid_username_raises(self, user_manager: UserManager):
        with pytest.raises(UserError, match="Invalid username"):
            user_manager.add_user("bad user!", "validpassword1")

    def test_empty_username_raises(self, user_manager: UserManager):
        with pytest.raises(UserError, match="Invalid username"):
            user_manager.add_user("", "validpassword1")

    def test_password_is_not_stored_in_plain_text(self, user_manager: UserManager):
        user_manager.add_user("dave", "myplainpassword")
        raw_users = user_manager._configuration.users
        assert raw_users["dave"]["password_hash"] != "myplainpassword"


class TestRemoveUser:
    def test_remove_existing_user(self, user_manager_with_alice: UserManager):
        user_manager_with_alice.remove_user("alice")
        users = {u["username"] for u in user_manager_with_alice.list_users()}
        assert "alice" not in users

    def test_remove_nonexistent_user_raises(self, user_manager: UserManager):
        with pytest.raises(UserError, match="does not exist"):
            user_manager.remove_user("nobody")


class TestAuthenticate:
    def test_correct_credentials_return_true(
        self, user_manager_with_alice: UserManager
    ):
        assert user_manager_with_alice.authenticate("alice", "securepassword123")

    def test_wrong_password_returns_false(self, user_manager_with_alice: UserManager):
        assert not user_manager_with_alice.authenticate("alice", "wrongpassword")

    def test_nonexistent_user_returns_false(self, user_manager: UserManager):
        assert not user_manager.authenticate("ghost", "anypassword")

    def test_disabled_user_cannot_authenticate(
        self, user_manager_with_alice: UserManager
    ):
        user_manager_with_alice.set_enabled("alice", enabled=False)
        assert not user_manager_with_alice.authenticate("alice", "securepassword123")


class TestSetEnabled:
    def test_disable_user(self, user_manager_with_alice: UserManager):
        user_manager_with_alice.set_enabled("alice", enabled=False)
        users = {u["username"]: u for u in user_manager_with_alice.list_users()}
        assert not users["alice"]["enabled"]

    def test_re_enable_user(self, user_manager_with_alice: UserManager):
        user_manager_with_alice.set_enabled("alice", enabled=False)
        user_manager_with_alice.set_enabled("alice", enabled=True)
        assert user_manager_with_alice.authenticate("alice", "securepassword123")

    def test_enable_nonexistent_user_raises(self, user_manager: UserManager):
        with pytest.raises(UserError, match="does not exist"):
            user_manager.set_enabled("nobody", enabled=True)


class TestChangePassword:
    def test_change_password_allows_new_login(
        self, user_manager_with_alice: UserManager
    ):
        user_manager_with_alice.change_password("alice", "brandnewpassword")
        assert user_manager_with_alice.authenticate("alice", "brandnewpassword")

    def test_old_password_no_longer_works(self, user_manager_with_alice: UserManager):
        user_manager_with_alice.change_password("alice", "brandnewpassword")
        assert not user_manager_with_alice.authenticate("alice", "securepassword123")

    def test_short_new_password_raises(self, user_manager_with_alice: UserManager):
        with pytest.raises(UserError, match="8 characters"):
            user_manager_with_alice.change_password("alice", "tiny")

    def test_change_password_nonexistent_user_raises(self, user_manager: UserManager):
        with pytest.raises(UserError, match="does not exist"):
            user_manager.change_password("ghost", "newpassword123")


class TestListUsers:
    def test_empty_list_when_no_users(self, user_manager: UserManager):
        assert user_manager.list_users() == []

    def test_list_contains_added_users(self, user_manager: UserManager):
        user_manager.add_user("alice", "password123")
        user_manager.add_user("bob", "password456")
        usernames = {u["username"] for u in user_manager.list_users()}
        assert usernames == {"alice", "bob"}

    def test_list_does_not_expose_hashes(self, user_manager_with_alice: UserManager):
        for entry in user_manager_with_alice.list_users():
            assert "password_hash" not in entry


class TestGenerateTemporaryPassword:
    def test_generated_password_allows_login(
        self, user_manager_with_alice: UserManager
    ):
        new_password = user_manager_with_alice.generate_temporary_password("alice")
        assert user_manager_with_alice.authenticate("alice", new_password)

    def test_generated_password_is_at_least_8_chars(
        self, user_manager_with_alice: UserManager
    ):
        new_password = user_manager_with_alice.generate_temporary_password("alice")
        assert len(new_password) >= 8

    def test_generate_for_nonexistent_user_raises(self, user_manager: UserManager):
        with pytest.raises(UserError, match="does not exist"):
            user_manager.generate_temporary_password("ghost")
