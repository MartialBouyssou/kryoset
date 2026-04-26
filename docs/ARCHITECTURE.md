# Kryoset Architecture

This document gives a practical map of the codebase and runtime flow.

## High-level components

- SFTP server: Paramiko-based SSH/SFTP service.
- REST API: FastAPI application over HTTPS.
- Web UI: static SPA served by FastAPI.
- Core services: users, permissions, quotas, storage budget, audit, TOTP.
- Persistent state: JSON config + SQLite permission store + filesystem data.

## Source layout

- `kryoset/cli.py`
  - Main entrypoint (`kryoset`) and command groups.
- `kryoset/core/`
  - `configuration.py`: JSON config read/write/validation.
  - `user_manager.py`: user auth, enable/disable, admin flag, password lifecycle.
  - `permission_store.py`: SQLite rules, groups, share links.
  - `permissions.py`: permission flags/presets/rule model.
  - `quota.py`: user usage and cache management.
  - `storage_manager.py`: global cap and allocations.
  - `sftp_server.py`: transport, sessions, SFTP interface.
  - `audit_logger.py`: structured security/audit events.
  - `totp.py`: secret generation and code verification.
  - `home_paths.py`: home path normalization and confinement helpers.
- `kryoset/api/`
  - `app.py`: FastAPI app factory + dependency wiring.
  - `auth.py`: JWT issuance/verification/revocation helpers.
  - `routes/*.py`: HTTP endpoints by domain.
- `kryoset/web/static/`
  - `app.html`: authenticated administration UI.
  - `share.html`: public share page.
- `kryoset/tests/`
  - Unit and API tests.

## Runtime dependency graph

1. CLI starts services with loaded `Configuration`.
2. `UserManager`, `PermissionStore`, `QuotaManager`, `StorageManager`, `AuditLogger`, and `TOTPManager` are instantiated.
3. SFTP and API layers call these shared core services.
4. Filesystem writes/reads happen under configured `storage_path`.
5. Security and lifecycle events are emitted to the audit log.

## Authentication and authorization flow

### API

1. `POST /auth/login`: password check.
2. If TOTP enabled: `POST /auth/totp` required.
3. Access/refresh JWTs are issued.
4. Protected routes decode Bearer token and build user context.
5. Path-level permissions are checked by `check_path_permission`.

### SFTP

1. SSH auth with password (+ TOTP challenge when enabled).
2. Session binds username/admin state.
3. Path operation checks are applied (`LIST`, `DOWNLOAD`, `UPLOAD`, etc.).
4. Home-path confinement applies for non-admin users when configured.

## Storage model

Kryoset applies limits in layers:

1. Global budget (`storage_max_bytes`) caps total NAS usage.
2. Entity allocation (`storage_allocations`) can cap users and groups.
3. Effective user quota resolution:
   - direct user allocation wins,
   - otherwise minimum of group allocations,
   - otherwise unlimited (except global budget still applies).
4. Upload and delete operations update usage cache in `QuotaManager`.

## Permission model (summary)

Rules are stored in SQLite and evaluated per path.

- Subject: user or group.
- Path scoped and inheritable.
- Delegation can allow non-admin permission management on subtrees.

For full details see `PERMISSION.md`.

## Share links

- Share metadata stored in SQLite.
- Public downloads use token URL and optional password.
- Download counters are incremented after full stream completion.

## Audit and observability

- Log location: `~/.kryoset/logs/`.
- Current file + rotated gzip archives.
- Typical event families:
  - authentication/TOTP
  - file actions
  - permission denied
  - quota exceeded
  - user/share administration

## Extension points

If you add new features:

- Put domain logic in `kryoset/core/` first.
- Expose via CLI (`kryoset/cli.py`) and/or API route module.
- Reuse existing managers via app/server state injection.
- Add tests in matching `kryoset/tests/` area.
