# Kryoset

> A secure, self-hosted NAS server over SFTP — own your data, control your access.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)

---

## Features (v0.1.0)

- **SFTP server** — industry-standard encrypted file transfer (SSH under the hood)
  - Compatible with any standard SFTP client
  - Async I/O for handling multiple concurrent connections
- **User management** — add, remove, enable/disable users via CLI
  - Passwords never stored in plain text
  - Support for account suspension without data loss
- **Secure passwords** — bcrypt hashing with anti-timing-attack protection
  - Configurable work factor (default: 12 rounds)
  - Safe comparison prevents timing-based password guessing
- **Per-session chroot** — clients confined to the configured storage directory
  - Each connection gets isolated filesystem view
  - Prevents accidental or malicious data access outside storage path
- **Anti-traversal protection** — directory traversal attacks blocked at protocol layer
  - Path validation on all filesystem operations
  - Symlink checking to prevent escape attempts
- **Audit logging** — track authentication and file operations
  - Logs stored in `~/.kryoset/logs/`
  - Follow logs in real-time with `kryoset logs --follow`
- **Granular permissions engine** — per user/group rules on any path
  - 10 permission flags (LIST, DOWNLOAD, UPLOAD, DELETE, SHARE, etc.)
  - Rule constraints: expiry, active hours, IP whitelist/blacklist, delegation
  - Effective permission resolution across parent/child paths
- **Groups and delegation** — reusable access management
  - Create groups and assign members
  - Grant rules to users or groups
  - Delegate permission administration on sub-paths
- **Share link store** — create and revoke token-based links
  - Optional expiry, password and download limit metadata
- **Cross-platform** — Linux and Windows (Python 3.11+)

## Roadmap

**v0.2.0** (planned)
- [ ] Two-factor authentication (TOTP)
- [ ] Per-user storage quotas
- [ ] Improved audit log retention policies

**v0.3.0+** (future)
- [ ] REST API with HTTPS
- [ ] Web dashboard for user management

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

Point Kryoset at the directory (or mount point) you want to share:

```bash
# Basic setup with default port 2222
kryoset init /mnt/my_disk

# Or choose a custom port
kryoset init /mnt/my_disk --port 3333

# Or use a custom config location
kryoset init /mnt/my_disk --port 2222 --config ~/.my_kryoset_config
```

This creates `~/.kryoset/config.json` with your settings and generates an SSH host key.

### 2 — Add users

```bash
# Create users (you'll be prompted for a password)
kryoset user add alice
kryoset user add bob

# List all users
kryoset user list
# Output:
# Username             Status
# ------------------------------
# alice                enabled
# bob                  enabled

# Disable a user without deleting their data
kryoset user disable alice

# Re-enable the user
kryoset user enable alice

# Reset a user's password to a temporary random one
kryoset user reset-password alice
# Output: [ok] New password for 'alice': Tr0pic@l_Fr3edomX42
```

### 3 — Start the server

```bash
kryoset start
```

The server will run in the foreground. Press `Ctrl-C` to stop it.

```
[2026-04-11 14:22:33,045] [INFO] Kryoset SFTP server starting on 0.0.0.0:2222
[2026-04-11 14:22:33,052] [INFO] Storage directory: /mnt/my_disk
[2026-04-11 14:22:33,055] [INFO] Listening for connections...
```

### 4 — Connect with an SFTP client

In another terminal:

```bash
sftp -P 2222 alice@localhost
# Connected to localhost.
# sftp> ls
# file1.txt  folder/  document.pdf
# sftp> get file1.txt
# Fetching /file1.txt to file1.txt
# sftp> put local_file.txt
# Uploading local_file.txt to /local_file.txt
# sftp> exit
```

### 5 — Add a first permission rule

```bash
# Give alice read-only access to /projects
kryoset perm add --path /projects --user alice -p LIST -p PREVIEW -p DOWNLOAD

# Check effective permissions
kryoset perm check alice /projects
```

---

## CLI Reference

### Server Management

```bash
kryoset init <STORAGE_PATH> [--port PORT] [--config PATH]
    Initialize a new Kryoset server instance.
    
    STORAGE_PATH    Directory to share over SFTP
    --port PORT     SFTP listening port (default: 2222)
    --config PATH   Custom configuration file location

kryoset start [--config PATH]
    Start the SFTP server (blocking).
    Press Ctrl-C to stop.
```

### User Management

```bash
kryoset user add <USERNAME> [--config PATH]
    Create a new user (prompts for password).

kryoset user list [--config PATH]
    Display all users with their status (enabled/disabled).

kryoset user remove <USERNAME> [--config PATH]
    Delete a user account and all its data.

kryoset user enable <USERNAME> [--config PATH]
    Enable a previously disabled account.

kryoset user disable <USERNAME> [--config PATH]
    Disable an account without deleting data.

kryoset user change-password <USERNAME> [--config PATH]
    Update a user's password (prompts for new password).

kryoset user reset-password <USERNAME> [--config PATH]
    Generate a random temporary password and display it.

kryoset user set-admin <USERNAME> [--revoke] [--config PATH]
  Grant or revoke admin role.
```

### Group Management

```bash
kryoset group create <GROUP_NAME>
  Create an empty group.

kryoset group delete <GROUP_NAME>
  Delete a group and its associated membership/rules.

kryoset group list
  List groups and members.

kryoset group add-member <GROUP_NAME> <USERNAME>
  Add user to a group.

kryoset group remove-member <GROUP_NAME> <USERNAME>
  Remove user from a group.
```

### Permission Management

```bash
kryoset perm add \
  --path /PATH \
  (--user USERNAME | --group GROUP_NAME) \
  -p FLAG [-p FLAG ...] \
  [--expires 24h|7d|ISO_DATE] \
  [--password] \
  [--quota 500MB|2GB] \
  [--download-limit N] \
  [--ip-whitelist CIDR[,CIDR...]] \
  [--ip-blacklist CIDR[,CIDR...]] \
  [--can-delegate] \
  [--hours mon-fri:09-18]

kryoset perm list [--path /PREFIX]
  List rules (optionally filtered by path prefix).

kryoset perm remove <RULE_ID>
  Remove a rule by ID.

kryoset perm check <USERNAME> <PATH>
  Show effective permissions on a path.
```

### Share Links

```bash
kryoset share create \
  --path /PATH \
  --user USERNAME \
  [-p DOWNLOAD] [-p LIST] \
  [--expires 24h|7d|ISO_DATE] \
  [--download-limit N] \
  [--password]

kryoset share list [--user USERNAME]
  List share links.

kryoset share revoke <TOKEN>
  Revoke a share link.
```

### Auditing & Logs

```bash
kryoset logs [-n LINES] [--follow] [--filter TEXT]
    Display the audit log.
    
    -n LINES        Number of lines to display (default: 50)
    --follow, -f    Follow log in real-time (like tail -f)
    --filter TEXT   Show only lines containing TEXT (e.g., AUTH_FAILURE)
```

---

## Connecting to the server

Use any standard SFTP client:

```bash
# Command-line SFTP
sftp -P 2222 alice@your-server-ip

# Or with verbose output for debugging
sftp -P 2222 -v alice@your-server-ip
```

**GUI Clients:** FileZilla, Cyberduck, WinSCP — configure:
- **Host:** your server IP/hostname
- **Protocol:** SFTP
- **Port:** 2222 (or your custom port)
- **Username:** alice (your Kryoset username)
- **Password:** your password

---

## Configuration

Kryoset stores its configuration and state in `~/.kryoset/`:

```
~/.kryoset/
├── config.json          Main configuration (storage path, port, users)
├── host_key             Server SSH host key (generated on first start)
├── permissions.db       SQLite database (groups, rules, share links)
└── logs/
  └── kryoset.log      Audit log (rotated daily)
```

All files are protected with mode `600` (read/write owner only).

To use a custom config location, pass `--config /path/to/config.json` to any command.

---

## Audit Logging

Kryoset logs authentication attempts and file operations to `~/.kryoset/logs/`:

```bash
# View last 50 lines of audit log
kryoset logs

# Follow log in real-time
kryoset logs --follow

# Find all failed authentication attempts
kryoset logs --filter AUTH_FAILURE

# Show last 100 lines
kryoset logs -n 100
```

Common event labels in logs:
- `AUTH_SUCCESS`, `AUTH_FAILURE`
- `CONNECT`, `DISCONNECT`
- `FILE_READ`, `FILE_WRITE`, `FILE_DELETE`, `FILE_RENAME`
- `MKDIR`, `RMDIR`

Example:

```text
[2026-04-14 20:31:08] [AUTH_SUCCESS  ] user=alice ip=192.168.1.44
[2026-04-14 20:31:12] [FILE_READ     ] user=alice path=/projects/spec.pdf
[2026-04-14 20:31:16] [FILE_WRITE    ] user=alice path=/projects/notes.txt
```

---

## Permissions Guide

Detailed permissions model, practical examples, delegation workflows, and control-channel usage are documented in:

- [PERMISSION.md](PERMISSION.md)

---

## Running Tests

Run the full test suite:

```bash
pytest                 # Run all tests
pytest -v              # Verbose output
pytest --cov           # With coverage report
pytest -k test_name    # Run specific test
```

Test coverage includes:
- Configuration loading and validation
- User manager (create, delete, enable/disable, password hashing)
- SFTP path resolution and security (anti-traversal)
- Authentication and session management

---

## Technical Details

### Architecture

- **SFTP Server:** Built on Paramiko (OpenSSH-compatible SSH implementation)
- **Authentication:** Bcrypt password hashing with constant-time comparison
- **Confinement:** Per-session chroot restricts user access to storage directory
- **Security:** Directory traversal attacks blocked at protocol layer

### Security Hardening

1. **Password Storage:** Bcrypt with configurable rounds (12 by default)
2. **Anti-Timing Attacks:** Password comparison completed in constant time
3. **Session Isolation:** Each SFTP connection has its own process space
4. **Path Validation:** All filesystem operations validated before execution
5. **Permissions:** Config files created with restrictive permissions (600)

### Dependencies

- **paramiko (≥3.4.0)** — SSH protocol and SFTP server implementation  
- **bcrypt (≥4.1.0)** — Password hashing
- **click (≥8.1.0)** — CLI framework

---

## Security Notes

⚠️ **Important Security Practices:**

- The server host key is generated on first start and stored at
  `~/.kryoset/host_key` (mode `600`). **Back this up securely** if running multiple instances.
- The configuration file (`~/.kryoset/config.json`) is protected with
  mode `600` and contains bcrypt password hashes.
- **Never expose** port 2222 to the internet without protection. Use:
  - Firewall rules to restrict IP access
  - SSH tunnelling for remote access: `ssh -L 2222:localhost:2222 user@server`
  - VPN to connect securely
- Store the host key safely; if lost, clients will see a "host key changed" warning on reconnect
- Audit the logs regularly for suspicious authentication attempts

---

## License

[MIT](LICENSE) — © 2026 Kryoset Contributors
