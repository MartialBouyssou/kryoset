# Kryoset

> A secure, self-hosted NAS server over SFTP — own your data, control your access.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)

---

## Features

- **SFTP server** — industry-standard encrypted file transfer (SSH under the hood), compatible with any standard SFTP client
- **User management** — add, remove, enable/disable, promote users via CLI; passwords stored as bcrypt hashes with anti-timing-attack protection
- **Two-factor authentication (TOTP)** — per-user opt-in via Google Authenticator, Authy or any TOTP app; QR-code provisioning; enforced at SSH level via keyboard-interactive
- **Granular permissions engine** — 10 combinable permission flags (LIST, DOWNLOAD, UPLOAD, DELETE, SHARE, MANAGE_PERMS, …) assigned to users or groups on any path
- **Groups and delegation** — create groups, assign members, grant rules at group level, delegate permission management to team leads
- **Rule constraints** — expiry date, active hours (e.g. weekdays only), IP whitelist/blacklist, optional path password
- **Share links** — create time-limited token-based links with optional password and download counter
- **Virtual control channel** — remote users manage their own share links and delegated permissions via `/.kryoset/` inside SFTP (REST-ready design)
- **Per-user storage quotas** — admins set byte limits per user; admin accounts are always exempt
- **Audit logging** — Paris-timezone timestamps, daily rotation, gzip compression, configurable retention by age and total size; events include TOTP, quota and permission-denied entries
- **Anti-traversal protection** — all filesystem operations validated; chroot per session
- **Cross-platform** — Linux and Windows (Python 3.11+)

## Roadmap

**Next**
- [ ] REST API with HTTPS
- [ ] Web dashboard

**Future**
- [ ] Prometheus metrics export
- [ ] iOS / Android client app

---

## Requirements

- Python 3.11 or later
- pip

## Installation

```bash
git clone https://github.com/your-username/kryoset.git
cd kryoset
pip install .
```

For development (includes test dependencies):

```bash
pip install -e ".[dev]"
```

---

## Quick Start

### 1 — Initialize the server

```bash
kryoset init /mnt/my_disk
# Custom port
kryoset init /mnt/my_disk --port 3333
```

### 2 — Add users

```bash
kryoset user add alice          # prompts for password
kryoset user list
kryoset user disable alice
kryoset user enable alice
kryoset user reset-password alice
kryoset user set-admin alice    # grant admin role
```

### 3 — Set up two-factor authentication (optional, per user)

```bash
# Generate secret and display provisioning URI + QR code instructions
kryoset user totp setup alice

# Scan the URI with your authenticator app, then confirm with a live code
kryoset user totp confirm alice 123456

# Check status
kryoset user totp status alice

# Disable if needed
kryoset user totp disable alice
```

Once confirmed, the next time Alice connects she will be asked for her password **and** her TOTP code:

```
alice@server's password:
TOTP code (6 digits):
```

### 4 — Set storage quotas (admin only)

```bash
kryoset user quota set alice 10GB
kryoset user quota set bob 500MB
kryoset user quota set charlie none    # remove quota (unlimited)

kryoset user quota status alice        # alice: 1.2 GB used / 10.0 GB quota (12%)
kryoset user quota list                # all users at a glance
```

### 5 — Start the server

```bash
kryoset start
```

Press `Ctrl-C` to stop.

### 6 — Connect with an SFTP client

```bash
sftp -P 2222 alice@localhost
```

GUI clients (FileZilla, Cyberduck, WinSCP): Protocol = SFTP, Port = 2222.

### 7 — Add permission rules

```bash
# Read-only access for alice on /projects
kryoset perm add --path /projects --user alice -p LIST -p PREVIEW -p DOWNLOAD

# Full access for the editors group on /shared
kryoset perm add --path /shared --group editors -p LIST -p DOWNLOAD -p UPLOAD -p RENAME -p MOVE -p DELETE

# Check effective permissions
kryoset perm check alice /projects
```

---

## CLI Reference

### Server

```
kryoset init <STORAGE_PATH> [--port PORT] [--config PATH]
kryoset start [--config PATH]
```

### Users

```
kryoset user add <USERNAME>
kryoset user list
kryoset user remove <USERNAME>
kryoset user enable <USERNAME>
kryoset user disable <USERNAME>
kryoset user change-password <USERNAME>
kryoset user reset-password <USERNAME>
kryoset user set-admin <USERNAME> [--revoke]

kryoset user totp setup <USERNAME>          Generate secret + provisioning URI
kryoset user totp confirm <USERNAME> <CODE> Activate TOTP after scanning QR
kryoset user totp disable <USERNAME>        Deactivate TOTP
kryoset user totp status <USERNAME>         Show enabled/disabled

kryoset user quota set <USERNAME> <SIZE>    e.g. 10GB, 500MB, none
kryoset user quota status <USERNAME>
kryoset user quota list
```

### Groups

```
kryoset group create <GROUP>
kryoset group delete <GROUP>
kryoset group list
kryoset group add-member <GROUP> <USERNAME>
kryoset group remove-member <GROUP> <USERNAME>
```

### Permissions

```
kryoset perm add --path PATH (--user U | --group G) -p FLAG [-p FLAG ...]
             [--expires 24h|7d|ISO_DATE]
             [--password]
             [--quota 500MB|2GB]
             [--download-limit N]
             [--ip-whitelist CIDR[,CIDR]]
             [--ip-blacklist CIDR[,CIDR]]
             [--can-delegate]
             [--hours mon-fri:09-18]

kryoset perm list [--path PREFIX]
kryoset perm remove <RULE_ID>
kryoset perm check <USERNAME> <PATH>
```

### Share Links

```
kryoset share create --path PATH --user USERNAME
              [-p DOWNLOAD] [--expires 24h] [--download-limit N] [--password]
kryoset share list [--user USERNAME]
kryoset share revoke <TOKEN>
```

### Logs

```
kryoset logs [-n LINES] [--follow] [--filter TEXT]
```

---

## Configuration

All state lives in `~/.kryoset/` (all files mode `600`):

```
~/.kryoset/
├── config.json        Server config (storage path, port, users + TOTP secrets + quotas)
├── host_key           SSH host key (generated on first start — back it up)
├── permissions.db     SQLite: groups, rules, share links, upload usage
└── logs/
    ├── kryoset.log    Live audit log (Paris timezone, CEST/CET)
    └── kryoset.log.YYYY-MM-DD.gz   Rotated + gzip-compressed archives
```

---

## Audit Logging

Events are written with Paris-timezone timestamps (CEST/CET). Rotated files are compressed with gzip. Default retention: 30 days or 500 MB total, whichever is hit first.

```bash
kryoset logs                        # last 50 lines
kryoset logs --follow               # live tail
kryoset logs --filter AUTH_FAILURE  # filter by event type
kryoset logs -n 200
```

Event labels: `AUTH_SUCCESS`, `AUTH_FAILURE`, `TOTP_SUCCESS`, `TOTP_FAILURE`, `CONNECT`, `DISCONNECT`, `FILE_READ`, `FILE_WRITE`, `FILE_DELETE`, `FILE_RENAME`, `MKDIR`, `RMDIR`, `QUOTA_EXCEEDED`, `PERM_DENIED`.

Example:

```text
[2026-04-15 09:31:08 CEST] [AUTH_SUCCESS  ] user=alice ip=192.168.1.44
[2026-04-15 09:31:09 CEST] [TOTP_SUCCESS  ] user=alice ip=192.168.1.44
[2026-04-15 09:31:12 CEST] [FILE_READ     ] user=alice path=/projects/spec.pdf
```

---

## Permissions Guide

See [PERMISSION.md](PERMISSION.md) for the full permission model, resolution algorithm, delegation workflows and control-channel usage.

---

## Running Tests

```bash
pytest           # all tests
pytest -v        # verbose
pytest --cov     # with coverage
```

---

## Security Notes

- Never expose port 2222 to the internet without a firewall rule. Use VPN or SSH tunnelling.
- Back up `~/.kryoset/host_key` — clients will warn if it changes.
- Enable TOTP for all accounts that need remote access.
- Review `kryoset logs --filter AUTH_FAILURE` regularly.

---

## License

[MIT](LICENSE) — © 2026 Kryoset Contributors
