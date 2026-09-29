# Security Model

## Protected areas

- Flask secret is environment-only.
- Admin bootstrap credentials are environment-only.
- Passwords are stored as Werkzeug password hashes.
- Browser forms use CSRF protection.
- Login and scan endpoints are rate-limited.
- Sessions use HttpOnly and SameSite cookies; Secure is configurable for local HTTP development.
- Generic 500 responses are returned to clients while details are logged server-side.
- Scan payloads and comments have explicit size limits.
- Admin-only routes require an authenticated admin role.
- Scan history and statistics are not public.
- Server-side network probes reject non-public destinations.
- HTTP redirects are validated before following them.
- SQLite uses WAL mode and a busy timeout for concurrent requests.

## Deployment rules

Never commit .env, credentials, production databases, or private API keys. Use HTTPS in production and keep SESSION_COOKIE_SECURE=1.

PhishGuard is a detection aid, not a guarantee. A Safe result must not be interpreted as proof that a site is trustworthy.
