# Kryoset

Secure self-hosted NAS over SFTP, with a REST API and web UI for day-to-day administration.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![Version](https://img.shields.io/badge/version-1.0.1-success)](pyproject.toml)

## What Kryoset Includes

- SFTP server (SSH/Paramiko) compatible with standard clients.
- User lifecycle management (create/remove/disable/enable/reset password).
- TOTP two-factor authentication for users and admin hardening.
- Permission engine based on path rules (user/group, delegation, constraints).
- Share links with expiration, password protection and download limits.
- Global storage budget plus per-user/per-group storage allocations.
- HTTPS REST API and a built-in web dashboard.
- Audit logging with rotation and retention.

## Current Status

Kryoset v1.0.1 already provides:

- SFTP service (`kryoset start`)
- HTTPS REST API (`kryoset api`)
- Web app (`/` served by the API)

## Requirements

- Python 3.11+
- pip

## Installation

```bash
git clone https://github.com/your-username/kryoset.git
cd kryoset
pip install .
```

Development install:

```bash
pip install -e ".[dev]"
```

## Quick Start

### 1) Initialize storage

```bash
# Basic
kryoset init /mnt/my_disk

# With custom SFTP port and global storage cap
kryoset init /mnt/my_disk --port 3333 --max-storage 1TB
```

### 2) Create users

```bash
kryoset user add alice
kryoset user add bob
kryoset user list
```

### 3) Configure security

```bash
# TOTP (recommended before admin grant)
kryoset user totp setup alice
kryoset user totp confirm alice 123456

# Promote to admin
kryoset user set-admin alice
```

### 4) Configure storage limits

```bash
# Global NAS budget
kryoset storage set-max 1TB
kryoset storage status

# Per-user effective quota
kryoset user set-max-storage bob 100GB
kryoset user quota status bob
```

### 5) Start services

```bash
# SFTP
kryoset start

# HTTPS API + web UI (in another terminal)
kryoset api --host 0.0.0.0 --port 8443
```

### 6) Connect clients

```bash
# SFTP
sftp -P 3333 alice@localhost
```

Web UI:

- Open `https://localhost:8443/`

## Main CLI Commands

### Server

```text
kryoset init <STORAGE_PATH> [--port PORT] [--max-storage SIZE] [--config PATH]
kryoset start [--config PATH]
kryoset api [--host HOST] [--port PORT] [--cert PEM] [--key PEM] [--config PATH]
```

### Users and TOTP

```text
kryoset user add <USERNAME>
kryoset user remove <USERNAME>
kryoset user list
kryoset user enable <USERNAME>
kryoset user disable <USERNAME>
kryoset user change-password <USERNAME>
kryoset user reset-password <USERNAME>
kryoset user set-admin <USERNAME> [--revoke]

kryoset user totp setup <USERNAME>
kryoset user totp confirm <USERNAME> <CODE>
kryoset user totp disable <USERNAME>
kryoset user totp status <USERNAME>
```

### Storage

```text
kryoset storage set-max <SIZE|none>
kryoset storage status

kryoset user set-max-storage <USERNAME> <SIZE|none>
kryoset user quota set <USERNAME> <SIZE|none>
kryoset user quota status <USERNAME>
kryoset user quota list
```

### Groups and permissions

```text
kryoset group create <GROUP>
kryoset group delete <GROUP>
kryoset group list
kryoset group add-member <GROUP> <USERNAME>
kryoset group remove-member <GROUP> <USERNAME>

kryoset perm add --path PATH (--user U | --group G) -p FLAG [-p FLAG ...]
kryoset perm list [--path PREFIX]
kryoset perm remove <RULE_ID>
kryoset perm check <USERNAME> <PATH>
```

### Share links and logs

```text
kryoset share create --path PATH --user USERNAME [--expires 24h] [--download-limit N] [--password]
kryoset share list [--user USERNAME]
kryoset share revoke <TOKEN>

kryoset logs [-n LINES] [--follow] [--filter TEXT]
```

## Data Layout

Kryoset stores runtime state under `~/.kryoset/`:

```text
~/.kryoset/
├── config.json                # core configuration and users
├── host_key                   # SSH host key
├── permissions.db             # sqlite (rules/groups/shares)
└── logs/
    ├── kryoset.log
    └── kryoset.log.YYYY-MM-DD.gz
```

Important `config.json` keys:

- `storage_path`: NAS root path.
- `storage_max_bytes`: global NAS cap (`null` or missing = unlimited).
- `storage_allocations`: per-user/per-group allocations (`user:<name>`, `group:<name>`).
- `users`: credentials, status, admin flag, optional home path.

## Documentation Map

- Permission model and delegation: [PERMISSION.md](PERMISSION.md)
- REST API reference: [docs/API.md](docs/API.md)
- Architecture and components: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- Operations and security checklist: [docs/OPERATIONS.md](docs/OPERATIONS.md)

## Tests

```bash
pytest
pytest -v
pytest --cov
```

## Security Notes

- Do not expose SFTP/API publicly without firewall + reverse proxy + rate limiting.
- Back up `~/.kryoset/host_key` to avoid host identity drift.
- Enforce TOTP on all privileged users.
- Review failed auth events regularly (`AUTH_FAILURE`, `TOTP_FAILURE`).

## License

[MIT](LICENSE) - Copyright (c) 2026 Kryoset Contributors
