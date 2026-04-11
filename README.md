# Kryoset

> A secure, self-hosted NAS server over SFTP — own your data, control your access.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)

---

## Features (v0.1.0)

- **SFTP server** — industry-standard, encrypted file transfer (SSH under the hood)
- **User management** — add, remove, enable/disable users via CLI
- **Secure passwords** — stored as bcrypt hashes, never in plain text
- **Chroot per session** — clients are confined to the configured storage directory
- **Anti-traversal** — directory traversal attacks are blocked at the protocol layer
- **Cross-platform** — Linux and Windows (Python 3.11+)

## Roadmap

- [ ] Two-factor authentication (TOTP)
- [ ] HTTPS / REST API interface
- [ ] Per-user quotas
- [ ] Audit log

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

### 1 — Initialise the server

Point Kryoset at the directory (or mount point) you want to share:

```bash
kryoset init /mnt/my_disk
```

Use `--port` to change the default port (2222):

```bash
kryoset init /mnt/my_disk --port 2222
```

### 2 — Add users

```bash
kryoset user add alice
# prompts for password
```

### 3 — Start the server

```bash
kryoset start
```

Stop it at any time with `Ctrl-C`.

---

## CLI Reference

```
kryoset init <STORAGE_PATH> [--port PORT]   Initialise the server
kryoset start                               Start the SFTP server
kryoset user add <USERNAME>                 Create a user
kryoset user remove <USERNAME>              Delete a user
kryoset user list                           List all users
kryoset user enable <USERNAME>              Enable a disabled account
kryoset user disable <USERNAME>             Disable an account (keeps data)
kryoset user change-password <USERNAME>     Update a user's password
kryoset user reset-password <USERNAME>      Generate a random temporary password
```

---

## Connecting to the server

Use any standard SFTP client:

```bash
sftp -P 2222 alice@your-server-ip
```

Or with a GUI client such as FileZilla, Cyberduck, or WinSCP — connect using
**SFTP**, port **2222** (or the port you chose during `init`).

---

## Running Tests

```bash
pytest
```

---

## Security Notes

- The server host key is generated on first start and stored at
  `~/.kryoset/host_key` (mode `600`). Keep this file safe.
- The configuration file (`~/.kryoset/config.json`) is stored with
  mode `600` and contains bcrypt password hashes.
- Never expose port 2222 to the internet without a firewall rule; use
  VPN or SSH tunnelling for remote access.

---

## License

[MIT](LICENSE) — © 2026 Kryoset Contributors
