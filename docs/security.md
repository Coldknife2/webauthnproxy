# Security model

[← README](../README.md) · Report a vulnerability: [SECURITY.md](../SECURITY.md)

**What is guaranteed**

- No request reaches the site without a valid session cookie (HMAC-SHA256 signed, expiring, revoked by sign-out, invalidated if the user is deleted). See [Session tokens](#session-tokens-hmac-signed-cookies).
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

## Session tokens (HMAC-signed cookies)

**Is a signed cookie solid?** Yes, as long as the secret is strong and you accept its limits. A session cookie here is
`user.audience.expiry.generation.signature`, where the signature is HMAC-SHA256 over the other fields.

**What makes it solid**

- Forging a token requires `SESSION_SECRET` (256-bit when generated, **32 characters minimum when you set it**). The signature is compared in constant time.
- No `alg` field, so none of the JWT pitfalls (`alg: none`, algorithm confusion). A fixed algorithm, a fixed layout.
- Every field is covered by the signature, and fields are base64url-encoded so a value can never inject a separator.
- Session cookies and login tickets use separate signing domains: one can never be accepted as the other.
- The audience binds a site's cookie to its host; tickets are single-use and expire after 60 s.
- **Revocation.** Each user has a session generation, stored in `users.json`. Signing out (see [forwardAuth](forwardauth.md)) increments it, so every token issued earlier,
  including a copied one, is refused on the next request, on every site. Deleting a user does the same.
- `HttpOnly`, `SameSite=Lax`, `Secure` over HTTPS.

**Its limits**

- It is a *bearer token*: whoever holds the cookie is the user until it expires (`SESSION_TTL`, 12 h by default) or the user signs out. Use a shorter TTL for sensitive sites.
- The secret is the crown jewel: `SESSION_SECRET` or `DATA_DIR/session.key` allows minting a session for any user and any site. Protect it like a password
  (the generated file is mode `0600`; do not bake it into images). Rotate by changing it; everybody is signed out.
- Revocation is per user ("sign out everywhere"), not per session; there is no list of active sessions.
- Tokens are signed, not encrypted: the holder can read the user name inside.
- There is no device binding (IP or User-Agent); it breaks too often on mobile networks.
- Ticket replay protection is kept in memory and resets on restart (the 60 s window still applies). One instance only.

**Compared with server-side session IDs** (Authelia, Tinyauth): equivalent security with a strong secret. A server-side store can list and revoke single sessions and holds no key that
can forge them, at the cost of a database and a lookup per request. Here, stateless verification is what keeps memory and CPU low
([performance](performance.md)), and per-user revocation covers the main need (a stolen or lost cookie).
