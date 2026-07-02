# Kryoset — RGPD / privacy checklist

Kryoset is a self-hosted file storage service. The software can help with GDPR workflows, but the instance operator remains responsible for the actual legal notice, retention choices, backups and user requests.

## Data categories

- Account metadata: username, enabled/admin flags, home path, group memberships and token version.
- Authentication secrets: password hash, TOTP setup state and TOTP secret. These secrets are never returned by API/CLI exports.
- File metadata and contents: names, virtual paths, sizes, modified dates and uploaded file contents.
- Sharing metadata: shared file path, expiry, download counter/limit and whether a password exists. Share tokens/password hashes are excluded from user exports.
- Audit/security logs: username, IP address, event type, virtual path and timestamps.

## Available workflows

- User access/export:
  - API: `GET /users/{username}/export`
  - CLI: `kryoset user export <username>`
- User erasure/purge:
  - CLI metadata purge: `kryoset user purge <username> --yes`
  - CLI metadata + home files purge: `kryoset user purge <username> --delete-files --yes`
- Log retention:
  - `KRYOSET_LOG_RETENTION_DAYS`
  - `KRYOSET_LOG_MAX_TOTAL_MB`

## Operator tasks before production

1. Complete `/privacy` with the real controller identity, contact email, instance URL and retention policy.
2. Decide whether user files are also removed on account deletion or handled through a separate archive policy.
3. Define encrypted backup retention and document whether purged data can temporarily remain in backups.
4. Restrict admin accounts, require 2FA for admins and rotate secrets after incidents.
5. Run dependency checks in CI with `pip-audit`, local Semgrep rules and secret scanning; keep the Python base image/system packages patched.

## Important limitations

- Kryoset cannot automatically enforce GDPR on external backups, reverse-proxy logs or hosting-provider logs.
- Audit logs are security data and may contain personal data. They should be retained only as long as necessary for the instance purpose.
- The included privacy page is a template, not legal advice.


## Security defaults relevant to personal data

- Browser JWTs are stored in HttpOnly cookies, not in Web Storage.
- Unsafe cookie-authenticated API requests require the `X-Kryoset-CSRF` header to match the readable `kryoset_csrf` cookie.
- In production over HTTPS, set `KRYOSET_COOKIE_SECURE=1` so browsers only send auth cookies over TLS.
- Password-protected ACL rules are disabled; use password-protected share links for temporary external access.
