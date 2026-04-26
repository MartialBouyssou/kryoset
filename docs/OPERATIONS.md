# Kryoset Operations Guide

Practical runbook for deployment, maintenance, and incident response.

## 1. Initial bootstrap checklist

1. Create dedicated storage mount/path.
2. Initialize Kryoset config:

```bash
kryoset init /srv/kryoset-data --port 2222 --max-storage 2TB
```

3. Create first admin user:

```bash
kryoset user add admin
kryoset user totp setup admin
kryoset user totp confirm admin <CODE>
kryoset user set-admin admin
```

4. Start services:

```bash
kryoset start
kryoset api --host 0.0.0.0 --port 8443
```

## 2. Daily operations

### User lifecycle

```bash
kryoset user list
kryoset user disable <USERNAME>
kryoset user enable <USERNAME>
kryoset user reset-password <USERNAME>
```

### Storage and quotas

```bash
kryoset storage status
kryoset storage set-max <SIZE|none>
kryoset user quota list
kryoset user set-max-storage <USERNAME> <SIZE|none>
```

### Permissions and shares

```bash
kryoset perm list
kryoset perm check <USERNAME> <PATH>
kryoset share list
```

## 3. Logs and monitoring

### Audit tail

```bash
kryoset logs --follow
```

### Focus on auth failures

```bash
kryoset logs --filter AUTH_FAILURE -n 200
kryoset logs --filter TOTP_FAILURE -n 200
```

### Focus on quota and permission events

```bash
kryoset logs --filter QUOTA_EXCEEDED -n 200
kryoset logs --filter PERM_DENIED -n 200
```

## 4. Backup strategy

Back up these assets together:

- `~/.kryoset/config.json`
- `~/.kryoset/host_key`
- `~/.kryoset/permissions.db`
- `~/.kryoset/logs/` (optional but recommended)
- NAS data directory referenced by `storage_path`

Suggested cadence:

- Config/DB/key: daily + pre-change snapshot.
- Data volume: according to RPO/RTO needs.

## 5. Restore strategy

1. Stop running services.
2. Restore `~/.kryoset/` files.
3. Restore NAS data tree.
4. Ensure file permissions are restrictive.
5. Start services and validate:

```bash
kryoset user list
kryoset perm list
kryoset storage status
```

## 6. Security hardening checklist

- Keep SFTP/API behind firewall and trusted network.
- Put HTTPS API behind reverse proxy with TLS policy and rate limiting.
- Enforce TOTP for all admin users.
- Rotate passwords periodically.
- Review failed auth events.
- Restrict Linux service account filesystem permissions.

## 7. Incident response quick actions

### Suspected account compromise

1. Disable account:

```bash
kryoset user disable <USERNAME>
```

2. Rotate password:

```bash
kryoset user reset-password <USERNAME>
```

3. Revoke suspicious shares:

```bash
kryoset share list --user <USERNAME>
kryoset share revoke <TOKEN>
```

4. Inspect logs:

```bash
kryoset logs --filter AUTH_SUCCESS -n 500
kryoset logs --filter FILE_ -n 500
```

### Quota pressure / storage saturation

1. Check global budget and usage:

```bash
kryoset storage status
```

2. Temporarily increase budget or tighten allocations.
3. Audit large datasets and delete/archive stale data.

## 8. Upgrade checklist

1. Snapshot `~/.kryoset/` and data.
2. Update package in controlled environment.
3. Run tests when working from source:

```bash
pytest -v
```

4. Restart services.
5. Validate login, upload/download, permissions, and logs.
