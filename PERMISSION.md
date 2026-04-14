# Kryoset Permissions Guide

This document explains the Kryoset permission system in depth:

- permission flags and presets
- how rule resolution works
- how to manage users/groups/rules with the CLI
- delegation model
- virtual control channel (`/.kryoset/*`)
- practical examples
- current limits and implementation notes

## 1. Core Concepts

Kryoset access control is rule-based.

A rule targets:

- a subject: one user or one group
- one path: `/`, `/docs`, `/projects/client-a`, etc.
- one or more permission flags
- optional constraints (expiry, hours, IP filters, etc.)

Rules are stored in:

- `~/.kryoset/permissions.db`

## 2. Permission Flags

Available flags:

- `LIST`: list directory/stat visibility
- `PREVIEW`: metadata-level preview permission (policy flag)
- `DOWNLOAD`: read/open file for download
- `UPLOAD`: write/upload/create file and mkdir
- `COPY`: copy capability marker (policy flag)
- `RENAME`: rename source permission
- `MOVE`: move/rename destination permission
- `DELETE`: delete files/directories
- `MANAGE_PERMS`: permission administration capability
- `SHARE`: allow share link creation

### Presets (code-level constants)

- `PRESET_READ_ONLY` = `LIST | PREVIEW | DOWNLOAD`
- `PRESET_CONTRIBUTOR` = read-only + `UPLOAD | COPY`
- `PRESET_EDITOR` = contributor + `RENAME | MOVE`
- `PRESET_FULL` = editor + `DELETE | SHARE`
- `PRESET_OWNER` = full + `MANAGE_PERMS`

## 3. Rule Constraints

Each rule can include optional restrictions.

- `expires_at`: absolute expiration datetime
- `time_windows`: active days/hours (for example, weekdays only)
- `ip_whitelist`: allowed IP/CIDR list
- `ip_blacklist`: denied IP/CIDR list (always wins)
- `upload_quota_bytes`: upload quota metadata
- `download_limit`: per-rule download limit metadata
- `password_hash`: extra password requirement metadata
- `can_delegate`: whether this rule can delegate sub-permissions

### Important Behavior Notes

Current runtime enforcement in SFTP operations:

- enforced directly: `LIST`, `DOWNLOAD`, `UPLOAD`, `DELETE`, `RENAME`, `MOVE`
- enforced in control-channel actions: `SHARE`, `MANAGE_PERMS`

Current stored metadata (not fully enforced in standard SFTP path operations yet):

- `upload_quota_bytes`
- `download_limit` on permission rules
- `password_hash` requirement from permission resolution
- policy flags `PREVIEW` and `COPY` (available for future/extended clients)

This means you can already model these constraints now, and they are persisted,
but some are prepared for upcoming enforcement features.

## 4. Resolution Algorithm (How Effective Permissions Are Computed)

When user `U` accesses path `P`, Kryoset does:

1. Collect all rules for `U` and for groups containing `U`.
2. Build ancestor chain of `P`, from `/` to `P`.
   - Example: `/a/b/c` -> `/`, `/a`, `/a/b`, `/a/b/c`
3. For each ancestor level, keep best matching rule:
   - user rule beats group rule on same level
   - deeper path is more specific than shallower
4. Merge along ancestry:
   - child path restricts what parent granted (intersection behavior)
   - direct rule on exact path can override same-level group context

### Example A: Inheritance + Restriction

Rules:

- user `alice` on `/` -> `LIST, DOWNLOAD, UPLOAD`
- user `alice` on `/private` -> `NONE`

Result:

- `/public/readme.txt` -> `LIST, DOWNLOAD, UPLOAD`
- `/private/secret.txt` -> `NONE`

### Example B: Group + User Override

Rules:

- group `editors` on `/docs` -> `LIST, DOWNLOAD, UPLOAD, DELETE`
- user `alice` on `/docs` -> `NONE`

If `alice` belongs to `editors`, effective on `/docs` is `NONE`.

## 5. CLI: Group Management

```bash
# Create a group
kryoset group create editors

# Add members
kryoset group add-member editors alice
kryoset group add-member editors bob

# List
kryoset group list

# Remove one member
kryoset group remove-member editors bob

# Delete group
kryoset group delete editors
```

## 6. CLI: Adding Permission Rules

### Minimal user rule

```bash
kryoset perm add --path /projects --user alice -p LIST -p DOWNLOAD
```

### Group contributor rule

```bash
kryoset perm add --path /shared --group contributors \
  -p LIST -p PREVIEW -p DOWNLOAD -p UPLOAD -p COPY
```

### Rule with expiration + hours + IP filter

```bash
kryoset perm add --path /finance --user alice \
  -p LIST -p DOWNLOAD \
  --expires 7d \
  --hours mon-fri:09-18 \
  --ip-whitelist 10.0.0.0/8,192.168.1.0/24 \
  --ip-blacklist 10.0.13.7
```

### Rule with delegation

```bash
kryoset perm add --path /team-alpha --user lead_alice \
  -p LIST -p DOWNLOAD -p UPLOAD -p SHARE -p MANAGE_PERMS \
  --can-delegate
```

### Rule with password prompt and quota metadata

```bash
kryoset perm add --path /restricted --user alice \
  -p LIST -p DOWNLOAD \
  --password \
  --quota 2GB \
  --download-limit 50
```

## 7. CLI: List, Check, Remove Rules

```bash
# List all rules
kryoset perm list

# Filter by path prefix
kryoset perm list --path /projects

# Check effective permissions for a user/path
kryoset perm check alice /projects/client-a/report.pdf

# Remove rule by id
kryoset perm remove 12
```

Typical output from check:

```text
User 'alice' on '/projects': [LIST, DOWNLOAD]
```

If a rule in the chain carries a password hash, check also prints:

```text
  A path password is required.
```

## 8. Admin Role and Delegation

### Server admin role

Admins can manage all permission/share resources.

```bash
# Grant admin
kryoset user set-admin alice

# Revoke admin
kryoset user set-admin alice --revoke
```

### Delegated managers

A non-admin user can manage permissions only if both conditions are met:

- effective permission on target path contains `MANAGE_PERMS`
- relevant delegated rules include `can_delegate=true`

This model allows scoped ownership (for example, one team lead per subtree).

## 9. Share Links

Share links are persisted objects with token, metadata, and optional password.

### CLI management (server-side)

```bash
# Create
kryoset share create --path /docs/guide.pdf --user alice --expires 24h --download-limit 5

# List all
kryoset share list

# List by creator
kryoset share list --user alice

# Revoke
kryoset share revoke <TOKEN>
```

### Notes

- share link metadata (`download_limit`, password, expiry) is stored in DB
- token generation is cryptographically random
- revocation removes the token record

## 10. Virtual Control Channel (`/.kryoset`)

Inside SFTP, Kryoset exposes a virtual tree:

- `/.kryoset/commands/` (write JSON commands)
- `/.kryoset/shares/` (read share link JSON files)
- `/.kryoset/permissions/` (read delegated rule JSON files)

### Command model

Upload a JSON file into `/.kryoset/commands/` with an `action` field.
Supported actions:

- `create_share`
- `revoke_share`
- `add_permission`
- `remove_permission`

### Example command: create share

```json
{
  "action": "create_share",
  "path": "/alice/report.pdf",
  "permissions": ["DOWNLOAD"],
  "expires_in_hours": 24,
  "download_limit": 3
}
```

### Example command: add delegated permission

```json
{
  "action": "add_permission",
  "subject_type": "user",
  "subject_id": "intern_jane",
  "path": "/alice/subdir",
  "permissions": ["LIST", "DOWNLOAD"],
  "expires_in_hours": 72
}
```

### Common errors returned by control channel

- malformed JSON
- unknown action
- missing required fields
- access denied outside delegated zone
- missing `SHARE` or `MANAGE_PERMS`

## 11. Audit Logs for Permission Workflows

Audit logs are written to:

- `~/.kryoset/logs/kryoset.log`

Useful filters:

```bash
# auth events
kryoset logs --filter AUTH

# file changes
kryoset logs --filter FILE_

# follow live
kryoset logs --follow
```

Sample lines:

```text
[2026-04-14 20:31:08] [AUTH_SUCCESS  ] user=alice ip=192.168.1.44
[2026-04-14 20:31:12] [FILE_READ     ] user=alice path=/projects/spec.pdf
[2026-04-14 20:31:16] [FILE_WRITE    ] user=alice path=/projects/notes.txt
```

## 12. Troubleshooting

### Problem: "I can list but not download"

- You likely have `LIST` but not `DOWNLOAD`.
- Run:

```bash
kryoset perm check <username> <path>
```

### Problem: "Rule exists but does not apply"

Check:

- rule expiration (`--expires`)
- active hours (`--hours`)
- IP allow/deny lists
- a deeper child rule may be restricting parent permissions

### Problem: "Cannot create delegated rules"

Verify:

- your effective permissions include `MANAGE_PERMS`
- delegated zone rule has `can_delegate=true`

## 13. Recommended Operating Pattern

For most teams:

1. Create groups by role (`viewers`, `contributors`, `owners`).
2. Grant at group level first.
3. Use user-level rules only for exceptions.
4. Use path hierarchy intentionally (`/team`, `/team/private`).
5. Keep delegated zones small and explicit.
6. Review rules regularly with `kryoset perm list`.
