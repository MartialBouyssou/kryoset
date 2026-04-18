# Kryoset Permissions Guide

This document covers the Kryoset permission system in depth:

- permission flags and presets
- rule resolution algorithm
- groups, users and delegation model
- CLI reference with practical examples
- virtual control channel (`/.kryoset/*`)
- current enforcement status
- troubleshooting

---

## 1. Core Concepts

Kryoset access control is rule-based and whitelist-only: **no rule = no access**.

A rule targets:

- a **subject**: one user or one group
- a **path**: `/`, `/docs`, `/projects/client-a`, etc.
- one or more **permission flags**
- optional **constraints** (expiry, active hours, IP filters, delegation flag)

Rules are stored in `~/.kryoset/permissions.db` (SQLite).

Admins always receive full permissions (`PRESET_OWNER`) regardless of stored rules.

---

## 2. Permission Flags

| Flag | What it allows |
|---|---|
| `LIST` | See file/directory in listings and stat calls |
| `PREVIEW` | Metadata access (policy flag for future clients) |
| `DOWNLOAD` | Read / open / download a file |
| `UPLOAD` | Write / upload / create a file; create directories |
| `COPY` | Copy marker (policy flag for future clients) |
| `RENAME` | Rename a file (source side) |
| `MOVE` | Move / rename destination |
| `DELETE` | Delete files or directories |
| `MANAGE_PERMS` | Add/remove permission rules inside this path |
| `SHARE` | Create share links for files inside this path |

### Presets

```python
PRESET_READ_ONLY   = LIST | PREVIEW | DOWNLOAD
PRESET_CONTRIBUTOR = READ_ONLY | UPLOAD | COPY
PRESET_EDITOR      = CONTRIBUTOR | RENAME | MOVE
PRESET_FULL        = EDITOR | DELETE | SHARE
PRESET_OWNER       = FULL | MANAGE_PERMS          # admins always get this
```

### Enforcement status

Currently enforced in SFTP operations: `LIST`, `DOWNLOAD`, `UPLOAD`, `DELETE`, `RENAME`, `MOVE`.

Enforced in the control channel: `SHARE`, `MANAGE_PERMS`.

Stored but reserved for future clients: `PREVIEW`, `COPY`, per-rule `upload_quota_bytes`, per-rule `download_limit`, per-rule `password_hash`.

Global per-user storage quotas are enforced separately (see `kryoset user quota`).

---

## 3. Rule Constraints

| Constraint | Description |
|---|---|
| `expires_at` | Rule becomes inactive after this UTC datetime |
| `time_windows` | Active days and hours (Paris timezone) |
| `ip_whitelist` | Only these IPs / CIDRs may use the rule |
| `ip_blacklist` | These IPs are always denied (wins over whitelist) |
| `upload_quota_bytes` | Per-rule upload quota metadata |
| `download_limit` | Per-rule download limit metadata |
| `password_hash` | Extra password stored with the rule |
| `can_delegate` | Subject may manage sub-permissions inside this path |

---

## 4. Resolution Algorithm

When user `U` accesses path `/a/b/c`:

1. Collect all rules for `U` and for groups containing `U`.
2. Build the ancestor chain: `/` → `/a` → `/a/b` → `/a/b/c`.
3. For each ancestor level, keep the single best-matching rule:
   - user rule beats group rule on the same path
   - deeper path beats shallower path
4. Merge along the chain:
   - the first matching ancestor initialises the effective permission set
   - each subsequent level intersects (restricts) — a child can only restrict, never expand
   - a direct rule on the exact target path overrides its parent context

**No rule anywhere in the chain → `NONE` (access denied, invisible).**

### Example A: inheritance and restriction

```
alice → /          : LIST, DOWNLOAD, UPLOAD
alice → /private   : NONE
```

Result on `/public/readme.txt` → `LIST, DOWNLOAD, UPLOAD`
Result on `/private/secret.txt` → `NONE` (invisible)

### Example B: user overrides group

```
group editors → /docs : LIST, DOWNLOAD, UPLOAD, DELETE
alice         → /docs : NONE
```

If alice is in editors, her effective permission on `/docs` is `NONE`.

---

## 5. Groups

```bash
kryoset group create editors
kryoset group add-member editors alice
kryoset group add-member editors bob
kryoset group list
kryoset group remove-member editors bob
kryoset group delete editors
```

---

## 6. Permission Rules CLI

### Minimal user rule

```bash
kryoset perm add --path /projects --user alice -p LIST -p DOWNLOAD
```

### Group contributor rule

```bash
kryoset perm add --path /shared --group contributors \
  -p LIST -p PREVIEW -p DOWNLOAD -p UPLOAD -p COPY
```

### Rule with expiry, active hours and IP filter

```bash
kryoset perm add --path /finance --user alice \
  -p LIST -p DOWNLOAD \
  --expires 7d \
  --hours mon-fri:09-18 \
  --ip-whitelist 10.0.0.0/8,192.168.1.0/24 \
  --ip-blacklist 10.0.13.7
```

### Delegated team-lead rule

```bash
kryoset perm add --path /team-alpha --user lead_alice \
  -p LIST -p DOWNLOAD -p UPLOAD -p SHARE -p MANAGE_PERMS \
  --can-delegate
```

### Rule with path password and quota metadata

```bash
kryoset perm add --path /restricted --user alice \
  -p LIST -p DOWNLOAD \
  --password \
  --quota 2GB \
  --download-limit 50
```

### List, check and remove rules

```bash
kryoset perm list                       # all rules
kryoset perm list --path /projects      # filtered by prefix
kryoset perm check alice /projects/report.pdf
kryoset perm remove 12
```

---

## 7. Admin Role and Delegation

### Server admins

```bash
kryoset user set-admin alice            # grant
kryoset user set-admin alice --revoke   # revoke
```

Admins bypass all rule resolution and receive `PRESET_OWNER` on every path.

### Delegated owners

A non-admin user can manage permissions on a subtree when:

1. Their effective permissions on the target path include `MANAGE_PERMS`.
2. The rule granting `MANAGE_PERMS` has `can_delegate=true`.

This allows one team lead per subtree without granting server-wide admin.

---

## 8. Per-User Storage Quotas

Quotas are global (across the whole NAS), not per-path.

```bash
kryoset user quota set alice 10GB
kryoset user quota set bob 500MB
kryoset user quota set charlie none     # unlimited

kryoset user quota status alice         # alice: 1.2 GB used / 10.0 GB quota (12%)
kryoset user quota list                 # all users
```

Admin accounts are always exempt from quota enforcement.

---

## 9. Share Links

Share links provide token-based access to one path without a Kryoset account.

### Server-side CLI

```bash
kryoset share create --path /docs/guide.pdf --user alice \
  --expires 24h --download-limit 5

kryoset share list
kryoset share list --user alice
kryoset share revoke <TOKEN>
```

### Remote (via control channel)

Upload a JSON command to `/.kryoset/commands/` over SFTP:

```json
{
  "action": "create_share",
  "path": "/alice/report.pdf",
  "permissions": ["DOWNLOAD"],
  "expires_in_hours": 24,
  "download_limit": 3
}
```

The server processes the command and writes the result to `/.kryoset/shares/<token>.json`.

---

## 10. Virtual Control Channel (`/.kryoset/`)

Remote users interact with Kryoset management features through a virtual directory tree injected at the root of their SFTP session. No real files are created on disk.

```
/.kryoset/
├── commands/         Upload JSON command files here
├── shares/           Read your active share links (JSON)
└── permissions/      Read delegated rules you can manage (JSON)
```

Supported command actions:

| Action | Required fields |
|---|---|
| `create_share` | `path`, optionally `permissions`, `expires_in_hours`, `download_limit`, `password` |
| `revoke_share` | `token` |
| `add_permission` | `subject_type`, `subject_id`, `path`, `permissions` |
| `remove_permission` | `rule_id` |

### Example: add a delegated permission

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

This API maps directly to future REST endpoints — the same business logic will be reused.

---

## 11. Two-Factor Authentication (TOTP)

```bash
kryoset user totp setup alice           # generates secret + provisioning URI
kryoset user totp confirm alice 123456  # validates setup with a live code
kryoset user totp status alice
kryoset user totp disable alice
```

Once active, Alice's SSH session requires:

1. Password (`check_auth_password`)
2. TOTP code via keyboard-interactive prompt (`TOTP code (6 digits): `)

Both steps must succeed. A failed TOTP code is logged as `TOTP_FAILURE`.

---

## 12. Audit Logs

```bash
kryoset logs --filter AUTH          # auth events
kryoset logs --filter FILE_         # file operations
kryoset logs --filter TOTP          # 2FA events
kryoset logs --filter PERM_DENIED   # access denied
kryoset logs --follow               # live tail
```

Sample output (Paris timezone):

```text
[2026-04-15 09:31:08 CEST] [AUTH_SUCCESS  ] user=alice ip=192.168.1.44
[2026-04-15 09:31:09 CEST] [TOTP_SUCCESS  ] user=alice ip=192.168.1.44
[2026-04-15 09:31:12 CEST] [FILE_READ     ] user=alice path=/projects/spec.pdf
[2026-04-15 09:31:19 CEST] [PERM_DENIED   ] user=alice path=/finance action=DOWNLOAD
```

Logs rotate daily, old files are compressed with gzip, and purged after 30 days or when the total size exceeds 500 MB (configurable).

---

## 13. Troubleshooting

**"I can list but not download"** — you have `LIST` but not `DOWNLOAD`. Run `kryoset perm check <user> <path>`.

**"Rule exists but does not apply"** — check expiry, active hours, IP lists, and whether a more specific child rule is restricting the parent grant.

**"Cannot create delegated rules"** — verify your effective permissions include `MANAGE_PERMS` and that the relevant rule has `can_delegate=true`.

**"TOTP code rejected"** — ensure your device clock is synchronised (NTP). The server accepts codes ±30 seconds (`valid_window=1`).

---

## 14. Recommended Operating Pattern

1. Create groups by role: `viewers`, `contributors`, `owners`.
2. Grant permissions at group level first.
3. Use user-level rules only for exceptions (e.g. `alice → NONE` on a sensitive path).
4. Design your path hierarchy intentionally: `/team`, `/team/private`, `/team/archive`.
5. Keep delegated zones small and explicit.
6. Review rules regularly with `kryoset perm list`.
7. Enable TOTP for all accounts with remote access.
