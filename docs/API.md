# Kryoset REST API Reference

Base URL (default): `https://<host>:8443`

Authentication:

- Access token: JWT Bearer (`Authorization: Bearer <token>`)
- Refresh token flow: `POST /auth/refresh`

## Auth

### `POST /auth/login`
Password step. If TOTP is enabled, returns `totp_required=true`.

Request:

```json
{
  "username": "alice",
  "password": "alicepass1"
}
```

Response (without TOTP):

```json
{
  "access_token": "...",
  "refresh_token": "...",
  "token_type": "bearer"
}
```

Response (with TOTP):

```json
{
  "totp_required": true,
  "username": "alice"
}
```

### `POST /auth/totp`
Completes login after password step.

```json
{
  "username": "alice",
  "code": "123456"
}
```

### `POST /auth/refresh`
Exchanges refresh token for a new access token.

```json
{
  "refresh_token": "..."
}
```

### `POST /auth/logout`
Revokes current token.

### `GET /auth/me`
Returns current user profile:

- `username`, `admin`, `totp_enabled`
- `initial_path` (effective home path)
- `quota_bytes`, `used_bytes`
- `recent_logins`, `recent_failures`

### `GET /auth/quota`
Fast quota snapshot for current user.

## Files

All routes below require authentication.

### `GET /files/list`
Query params:

- `path` (default: empty = root)
- `show_hidden` (default: false)
- `sort_by` (`name`, `size`, `modified`)
- `sort_desc` (bool)

Returns file/directory entries with `name`, `type`, `size`, `modified`, `mime`, `previewable`.

### `GET /files/download`
Downloads a file.

### `GET /files/preview`
Inline preview for supported file extensions.

### `POST /files/upload`
Multipart upload.

- Query param: `path`
- Form field: `file`

Quota/global budget checks are enforced before write.

### `POST /files/mkdir`

```json
{
  "path": "folder/subfolder"
}
```

### `DELETE /files/delete`
Deletes file or directory recursively.

### `POST /files/rename`

```json
{
  "source": "old/name.txt",
  "destination": "new/name.txt"
}
```

## Users

Most endpoints are admin-only, except self-service actions where noted.

### `GET /users/` (admin)
List users with fields including:

- `username`, `enabled`, `admin`
- `totp_enabled`
- `home_path`
- `storage_max_bytes`

### `POST /users/` (admin)
Create user.

```json
{
  "username": "bob",
  "password": "bobpass123",
  "storage_max_bytes": 107374182400,
  "home_path": "/home/bob",
  "group_name": "team"
}
```

### `DELETE /users/{username}` (admin)
### `POST /users/{username}/enable` (admin)
### `POST /users/{username}/disable` (admin)

### `POST /users/{username}/password` (self or admin)

```json
{
  "new_password": "new-strong-password"
}
```

### `POST /users/{username}/reset-password` (admin)
### `POST /users/{username}/admin?grant=true|false` (admin)

Grant requires TOTP enabled for target user.

### TOTP user endpoints (self or admin)

- `POST /users/{username}/totp/setup`
- `GET /users/{username}/totp/qr.png`
- `POST /users/{username}/totp/confirm`
- `DELETE /users/{username}/totp`
- `GET /users/{username}/totp/status`

### Quota user endpoints

- `GET /users/{username}/quota` (self or admin)
- `PUT /users/{username}/quota` (admin)

## Permissions and groups

### Rules

- `GET /permissions/rules` (admin)
- `POST /permissions/rules` (admin or user with `MANAGE_PERMS`)
- `PUT /permissions/rules/{rule_id}` (admin or `MANAGE_PERMS`)
- `DELETE /permissions/rules/{rule_id}` (admin or `MANAGE_PERMS`)
- `GET /permissions/check?path=...` (authenticated)

Rule payload:

```json
{
  "subject_type": "user",
  "subject_id": "alice",
  "path": "/projects",
  "permissions": ["LIST", "DOWNLOAD"],
  "expires_at": "2026-12-31T23:59:59+00:00",
  "can_delegate": false
}
```

### Groups

- `GET /permissions/groups` (admin)
- `POST /permissions/groups/{name}` (admin)
- `DELETE /permissions/groups/{name}` (admin)
- `POST /permissions/groups/{name}/members` (admin)
- `DELETE /permissions/groups/{name}/members/{username}` (admin)

Group creation payload:

```json
{
  "storage_max_bytes": 53687091200,
  "home_path": "/directory",
  "auto_generate_user_home": true
}
```

## Shares

### `POST /shares/`
Create share for authenticated user.

```json
{
  "path": "/reports/q1.pdf",
  "permissions": ["DOWNLOAD"],
  "expires_at": "2026-12-31T23:59:59+00:00",
  "download_limit": 5,
  "password": "optional-password"
}
```

### `GET /shares/`
List shares:

- Admin: all shares
- User: own shares only

### `DELETE /shares/{token}`
Revoke share (creator or admin).

### `GET /shares/public/{token}`
Public download endpoint. Optional query param `password` when required.

## Storage management

### Admin storage endpoints

- `GET /storage/status`
- `PUT /storage/max`
- `GET /storage/allocations`
- `PUT /storage/allocations/user/{username}`
- `DELETE /storage/allocations/user/{username}`
- `PUT /storage/allocations/group/{name}`
- `DELETE /storage/allocations/group/{name}`

Global max payload:

```json
{
  "max_bytes": 1099511627776
}
```

Allocation payload:

```json
{
  "bytes_allocated": 107374182400
}
```

### User quota views

- `GET /storage/quota/me`
- `GET /storage/quota/{username}` (admin)

## Logs

- `GET /logs/?lines=100&filter=AUTH_FAILURE` (admin)
- `GET /logs/files` (admin)

## Web routes

- `GET /` -> admin/user web app
- `GET /share/{token}` -> public share page
- `GET /api/shares/info/{token}` -> public metadata for share page

## HTTP status quick guide

- `200` / `201`: success
- `400`: invalid request
- `401`: unauthenticated / invalid token / wrong password or TOTP
- `403`: authenticated but forbidden by role/permissions
- `404`: resource not found (or hidden by security policy)
- `409`: conflict (already exists)
- `413`: quota/global budget exceeded
- `503`: service component missing (misconfiguration)
