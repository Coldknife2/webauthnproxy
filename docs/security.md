# Security model

[← README](../README.md) · Report a vulnerability: [SECURITY.md](../SECURITY.md)

**What is guaranteed**

- No request reaches the site without a valid session cookie (HMAC-SHA256 signed, expiring, invalidated if the user is deleted).
- Login: single-use challenge (5 min), origin and domain verified, signature counter updated, user verification required.
- Cookie is `HttpOnly`, `SameSite=Lax`, and `Secure` whenever access is over HTTPS; pages are served with a restrictive CSP.
- The post-login redirect (`next`) is limited to local paths, or in forward mode to the sites in `ALLOWED_HOSTS` / `COOKIE_DOMAIN`: no open redirect.
- Forward mode across domains: single-use 60-second tickets, per-host cookies bound to their site, requests for unlisted hosts refused (see [forwardAuth mode](forwardauth.md)).
- Automatic enrollment: session required, bootstrap token compared in constant time, CSRF protection, the last passkey cannot be deleted.
- Import: the file is untrusted and fully revalidated (see [enrollment](enrollment.md)), with a size limit.
- Static tool: no writes, hash-based CSP (`script-src 'sha256-…'`, no `unsafe-inline`).
- The database holds **public keys only**; only `session.key` is secret (leaking it allows forging sessions).

**Assumptions and limits**

- TLS is terminated upstream (Traefik); without HTTPS WebAuthn does not work outside `localhost`.
- No rate limiting, audit log, per-site rules or high availability (single instance, ceremonies kept in memory): complete these at the reverse proxy.
- User handles are derived from the name (SHA-256) so the same name always designates the same user whichever enrollment tool is used.
- One root domain per instance (`RP_ID`).

To report a vulnerability, see [SECURITY.md](../SECURITY.md).
