import signal
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from kryoset.core.audit_logger import AuditLogger
from kryoset.core.configuration import Configuration
from kryoset.core.permission_store import PermissionStore
from kryoset.core.quota import QuotaManager
from kryoset.core.totp import TOTPManager
from kryoset.core.storage_manager import StorageManager
from kryoset.core.user_manager import UserManager


def create_app(
    configuration: Configuration,
    user_manager: UserManager,
    audit_logger: Optional[AuditLogger] = None,
    permission_store: Optional[PermissionStore] = None,
) -> FastAPI:
    """
    Application factory that creates and configures the Kryoset FastAPI instance.

    All injected instances are stored on ``app.state`` so that route handlers
    can access them via ``request.app.state.*``. This design allows tests to
    inject lightweight in-memory replacements without touching the filesystem.

    Args:
        configuration: A loaded :class:`Configuration` instance.
        user_manager: A :class:`UserManager` wrapping the configuration.
        audit_logger: Optional :class:`AuditLogger` for structured event logging.
        permission_store: Optional :class:`PermissionStore` for ACL resolution.

    Returns:
        A fully configured :class:`FastAPI` application.
    """
    app = FastAPI(title="Kryoset API", version="1.0.2")

    app.state.configuration = configuration
    app.state.user_manager = user_manager
    app.state.audit_logger = audit_logger
    app.state.permission_store = permission_store
    app.state.totp_manager = TOTPManager(user_manager)
    app.state.quota_manager = (
        QuotaManager(user_manager, configuration.storage_path)
        if configuration.storage_path.exists()
        else None
    )
    sm = StorageManager(configuration, user_manager, permission_store)
    app.state.storage_manager = sm
    startup_warnings = sm.validate_on_startup()
    for warning in startup_warnings:
        import logging
        logging.getLogger("kryoset").warning(warning)

    def _on_shutdown(*_):
        from kryoset.api.auth import revoke_all_tokens
        revoke_all_tokens()
        if audit_logger:
            try:
                audit_logger.log_server_shutdown()
            except Exception:
                pass

    signal.signal(signal.SIGTERM, _on_shutdown)
    signal.signal(signal.SIGINT, _on_shutdown)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    from kryoset.api.routes import auth, files, logs, permissions, shares, storage, users, web

    app.include_router(web.router)
    app.include_router(auth.router)
    app.include_router(files.router)
    app.include_router(users.router)
    app.include_router(permissions.router)
    app.include_router(shares.router)
    app.include_router(logs.router)
    app.include_router(storage.router)

    @app.get("/health", tags=["health"])
    def health() -> dict:
        """Return server health status. No authentication required."""
        return {"status": "ok"}

    return app
