from pathlib import Path

import pyotp
import pytest

from kryoset.core.configuration import Configuration
from kryoset.core.totp import TOTPError, TOTPManager
from kryoset.core.user_manager import UserManager


@pytest.fixture()
def user_manager(tmp_path: Path) -> UserManager:
    config_path = tmp_path / "config.json"
    storage = tmp_path / "storage"
    storage.mkdir()
    cfg = Configuration(config_path)
    cfg.initialize(storage_path=str(storage))
    um = UserManager(cfg)
    um.add_user("alice", "securepassword1")
    return um


@pytest.fixture()
def totp_manager(user_manager: UserManager) -> TOTPManager:
    return TOTPManager(user_manager)


class TestGenerateSecret:
    def test_returns_valid_base32_secret(self, totp_manager, user_manager):
        secret = totp_manager.generate_secret("alice")
        assert len(secret) >= 16
        import base64
        base64.b32decode(secret)

    def test_totp_not_enabled_after_generate(self, totp_manager, user_manager):
        totp_manager.generate_secret("alice")
        assert not totp_manager.is_enabled("alice")

    def test_generate_for_nonexistent_user_raises(self, totp_manager):
        with pytest.raises(TOTPError, match="does not exist"):
            totp_manager.generate_secret("ghost")

    def test_regenerating_replaces_pending_secret(self, totp_manager):
        secret1 = totp_manager.generate_secret("alice")
        secret2 = totp_manager.generate_secret("alice")
        assert secret1 != secret2


class TestProvisioningUri:
    def test_uri_contains_username(self, totp_manager):
        totp_manager.generate_secret("alice")
        uri = totp_manager.get_provisioning_uri("alice")
        assert "alice" in uri

    def test_uri_contains_issuer(self, totp_manager):
        totp_manager.generate_secret("alice")
        uri = totp_manager.get_provisioning_uri("alice")
        assert "Kryoset" in uri

    def test_uri_starts_with_otpauth(self, totp_manager):
        totp_manager.generate_secret("alice")
        uri = totp_manager.get_provisioning_uri("alice")
        assert uri.startswith("otpauth://totp/")

    def test_uri_without_secret_raises(self, totp_manager):
        with pytest.raises(TOTPError, match="No TOTP secret"):
            totp_manager.get_provisioning_uri("alice")


class TestConfirmSetup:
    def test_valid_code_enables_totp(self, totp_manager):
        secret = totp_manager.generate_secret("alice")
        code = pyotp.TOTP(secret).now()
        totp_manager.confirm_setup("alice", code)
        assert totp_manager.is_enabled("alice")

    def test_invalid_code_raises(self, totp_manager):
        totp_manager.generate_secret("alice")
        with pytest.raises(TOTPError, match="Invalid TOTP code"):
            totp_manager.confirm_setup("alice", "000000")

    def test_confirm_without_setup_raises(self, totp_manager):
        with pytest.raises(TOTPError, match="No pending TOTP setup"):
            totp_manager.confirm_setup("alice", "123456")

    def test_pending_secret_removed_after_confirm(self, totp_manager, user_manager):
        secret = totp_manager.generate_secret("alice")
        code = pyotp.TOTP(secret).now()
        totp_manager.confirm_setup("alice", code)
        users = user_manager._get_users()
        assert "totp_secret_pending" not in users["alice"]
        assert "totp_secret" in users["alice"]


class TestVerify:
    def test_verify_correct_code_returns_true(self, totp_manager):
        secret = totp_manager.generate_secret("alice")
        code = pyotp.TOTP(secret).now()
        totp_manager.confirm_setup("alice", code)
        fresh_code = pyotp.TOTP(secret).now()
        assert totp_manager.verify("alice", fresh_code)

    def test_verify_wrong_code_returns_false(self, totp_manager):
        secret = totp_manager.generate_secret("alice")
        code = pyotp.TOTP(secret).now()
        totp_manager.confirm_setup("alice", code)
        assert not totp_manager.verify("alice", "000000")

    def test_verify_returns_true_if_totp_not_enabled(self, totp_manager):
        assert totp_manager.verify("alice", "any_code")

    def test_verify_returns_true_for_unknown_user(self, totp_manager):
        assert totp_manager.verify("ghost", "123456")


class TestDisable:
    def test_disable_removes_secret(self, totp_manager, user_manager):
        secret = totp_manager.generate_secret("alice")
        code = pyotp.TOTP(secret).now()
        totp_manager.confirm_setup("alice", code)
        totp_manager.disable("alice")
        assert not totp_manager.is_enabled("alice")
        users = user_manager._get_users()
        assert "totp_secret" not in users["alice"]

    def test_disable_nonexistent_user_raises(self, totp_manager):
        with pytest.raises(TOTPError, match="does not exist"):
            totp_manager.disable("ghost")

    def test_disable_clears_pending_secret(self, totp_manager, user_manager):
        totp_manager.generate_secret("alice")
        totp_manager.disable("alice")
        users = user_manager._get_users()
        assert "totp_secret_pending" not in users["alice"]


class TestGetQrCodePng:
    def test_returns_png_bytes(self, totp_manager):
        totp_manager.generate_secret("alice")
        png = totp_manager.get_qr_code_png("alice")
        assert isinstance(png, bytes)
        assert png[:4] == b"\x89PNG"


class TestServerInterfaceTOTP:
    """Test that KryosetServerInterface correctly enforces TOTP."""

    def _make_server_interface(self, user_manager, tmp_path):
        from unittest.mock import MagicMock
        from kryoset.core.sftp_server import KryosetServerInterface
        from kryoset.core.audit_logger import AuditLogger
        from kryoset.core.permission_store import PermissionStore
        from kryoset.core.totp import TOTPManager

        audit = AuditLogger(log_directory=tmp_path / "logs")
        store = PermissionStore(db_path=tmp_path / "perms.db")
        store.initialize()
        totp_mgr = TOTPManager(user_manager)

        return KryosetServerInterface(
            user_manager=user_manager,
            storage_path=tmp_path / "storage",
            audit_logger=audit,
            permission_store=store,
            client_address=("127.0.0.1", 12345),
            totp_manager=totp_mgr,
        )

    def test_password_only_sufficient_when_totp_disabled(self, user_manager, tmp_path):
        import paramiko
        server = self._make_server_interface(user_manager, tmp_path)
        result = server.check_auth_password("alice", "securepassword1")
        assert result == paramiko.AUTH_SUCCESSFUL

    def test_password_returns_partial_when_totp_enabled(self, user_manager, tmp_path):
        import paramiko, pyotp
        totp_mgr = TOTPManager(user_manager)
        secret = totp_mgr.generate_secret("alice")
        code = pyotp.TOTP(secret).now()
        totp_mgr.confirm_setup("alice", code)

        server = self._make_server_interface(user_manager, tmp_path)
        result = server.check_auth_password("alice", "securepassword1")
        assert result == paramiko.AUTH_PARTIALLY_SUCCESSFUL

    def test_get_allowed_auths_no_totp(self, user_manager, tmp_path):
        server = self._make_server_interface(user_manager, tmp_path)
        assert server.get_allowed_auths("alice") == "password"

    def test_get_allowed_auths_with_totp(self, user_manager, tmp_path):
        import pyotp
        totp_mgr = TOTPManager(user_manager)
        secret = totp_mgr.generate_secret("alice")
        code = pyotp.TOTP(secret).now()
        totp_mgr.confirm_setup("alice", code)

        server = self._make_server_interface(user_manager, tmp_path)
        auths = server.get_allowed_auths("alice")
        assert "keyboard-interactive" in auths
        assert "password" in auths

    def test_valid_totp_code_grants_access(self, user_manager, tmp_path):
        import paramiko, pyotp
        totp_mgr = TOTPManager(user_manager)
        secret = totp_mgr.generate_secret("alice")
        code = pyotp.TOTP(secret).now()
        totp_mgr.confirm_setup("alice", code)

        server = self._make_server_interface(user_manager, tmp_path)
        server.check_auth_password("alice", "securepassword1")

        fresh_code = pyotp.TOTP(secret).now()
        result = server.check_auth_interactive_response([fresh_code])
        assert result == paramiko.AUTH_SUCCESSFUL

    def test_invalid_totp_code_fails(self, user_manager, tmp_path):
        import paramiko, pyotp
        totp_mgr = TOTPManager(user_manager)
        secret = totp_mgr.generate_secret("alice")
        code = pyotp.TOTP(secret).now()
        totp_mgr.confirm_setup("alice", code)

        server = self._make_server_interface(user_manager, tmp_path)
        server.check_auth_password("alice", "securepassword1")

        result = server.check_auth_interactive_response(["000000"])
        assert result == paramiko.AUTH_FAILED

    def test_empty_response_fails(self, user_manager, tmp_path):
        import paramiko, pyotp
        totp_mgr = TOTPManager(user_manager)
        secret = totp_mgr.generate_secret("alice")
        code = pyotp.TOTP(secret).now()
        totp_mgr.confirm_setup("alice", code)

        server = self._make_server_interface(user_manager, tmp_path)
        server.check_auth_password("alice", "securepassword1")

        result = server.check_auth_interactive_response([])
        assert result == paramiko.AUTH_FAILED

    def test_totp_prompt_contains_instructions(self, user_manager, tmp_path):
        server = self._make_server_interface(user_manager, tmp_path)
        prompts = server.get_auth_interactive_prompt("alice", "", "", [])
        assert len(prompts) == 1
        prompt_text, echo = prompts[0]
        assert "TOTP" in prompt_text or "code" in prompt_text.lower()
        assert echo is False
