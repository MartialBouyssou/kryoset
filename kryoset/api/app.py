from typing import Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from kryoset.core.audit_logger import AuditLogger
from kryoset.core.configuration import Configuration
from kryoset.core.permission_store import PermissionStore
from kryoset.core.quota import QuotaManager
from kryoset.core.totp import TOTPManager
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
    app = FastAPI(title="Kryoset API", version="0.1.0")

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

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/health", tags=["health"])
    def health() -> dict:
        """Return server health status. No authentication required."""
        return {"status": "ok"}

    from kryoset.api.routes import auth, files, logs, permissions, shares, users, web

    app.include_router(web.router)
    app.include_router(auth.router)
    app.include_router(files.router)
    app.include_router(users.router)
    app.include_router(permissions.router)
    app.include_router(shares.router)
    app.include_router(logs.router)

    return app