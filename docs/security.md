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

Sections: [cross-domain login threat model](#cross-domain-login-threat-model) · [session tokens](#session-tokens-hmac-signed-cookies) · [reverse proxy and exposure](reverse-proxy.md)

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

## Cross-domain login: threat model

Applies to `MODE=forward` when the protected sites are on domains unrelated to the login host (`ALLOWED_HOSTS`). The flow itself is described in [forwardauth.md](forwardauth.md).

**Trusted:** this service, Traefik, the hosts listed in `ALLOWED_HOSTS` (their backends receive their own site cookie), the operator.
**Not trusted:** every visitor, every other website, every browser.

**The exchange.** A visitor without a cookie for site S is sent to the login host (`/_wap/sso?next=https://S/page`). After a passkey login the login host redirects to
`https://S/_wap/callback?ticket=…`. Traefik passes that request to `/_wap/verify`, which validates the ticket, sets a cookie for S only, and redirects to the page.

| Property | How it is enforced | Covered by |
|---|---|---|
| Ticket lifetime: **60 seconds** | expiry inside the signed ticket | unit test |
| **Single use** | the ticket nonce is remembered (in memory) until it expires | unit tests; e2e: replayed ticket refused |
| **Bound to the target host** | the ticket carries the host it was issued for; `/_wap/callback` compares it with `X-Forwarded-Host` | unit test; e2e: a fresh ticket is refused on another site and accepted on its own |
| **Bound to the user's session generation** | signing out increments it, so tickets issued before are refused | unit test (e2e covers the cookies, not a ticket held across a sign-out) |
| The site cookie is **host-only and bound to its host** | no `Domain` attribute; the audience is signed into the token | unit tests; e2e: a site's cookie is refused on another site |
| **`ALLOWED_HOSTS` is the gate** | hosts outside the list get `403` from `/_wap/verify`; `next` is only honored for listed hosts; tickets are only issued for listed hosts | unit tests; e2e: unlisted host refused |
| **No open redirect** | `next` must be a local path or an absolute URL of a listed host (lookalikes such as `evilsite.com` or `site.com.evil.com` are rejected); the callback accepts a path only and rebuilds the absolute URL itself | unit tests (`//evil`, `/\evil`, `javascript:`, `user@host` tricks); e2e: `next=https://evil.example` is ignored |
| `/_wap/verify` is **not public** | the public router of the login host excludes that path (see [reverse-proxy.md](reverse-proxy.md)) | e2e: 404 on the public router while forwardAuth keeps working |
| Sign-out revokes cookies already issued to sites | per-user session generation | unit and e2e tests |

**Known gaps and residual risks (not covered by a test unless stated):**

- **Replay across a restart.** Used ticket nonces live in memory. A ticket used shortly before a restart could be used once more during the remaining seconds of its 60 s life. *Not mitigated, not tested.*
- **The ticket is in a URL.** `/_wap/callback?ticket=…` can appear in the access logs of Traefik or of the site. Single use and the 60 s limit make a logged ticket almost worthless afterwards,
  but someone who reads logs in real time could race the user. Treat log access as part of the trusted base. *By design, not tested.*
- **Wildcards widen the trust.** `*.example.org` trusts every present and future subdomain; a dangling DNS record (subdomain takeover) would let an attacker receive tickets and cookies for users who visit it
  while signed in. Prefer explicit hosts. *Operator responsibility.*
- **A compromised listed site** sees its own cookie and can act as the signed-in user on that site until the cookie expires or the user signs out. It cannot reach the other sites (the cookie is bound to its host)
  and cannot obtain tickets for them (tickets are issued per requested host, only to a signed-in browser).
- **One set of passkeys for every listed site.** There are no per-site rules: any enrolled user can open every site in the list.
- **Restoring or deleting `users.json`.** Session generations are stored there. A backup older than a sign-out, or a recreated user, restarts at an earlier generation and revives cookies that were revoked or never expired.
  Rotate the session key after a restore or a recovery ([enrollment.md](enrollment.md#account-recovery-lost-passkeys)). *Documented, not tested.*
- **Misconfigured Traefik.** If `trustForwardHeader` is set to `true` without a trusted front proxy, clients can forge `X-Forwarded-Host` and `X-Forwarded-Proto`. *Not tested;* see [reverse-proxy.md](reverse-proxy.md).
- **Login CSRF.** An attacker cannot sign a victim in as someone else without the victim approving a passkey prompt for the attacker's account. `GET /_wap/sso` only redirects; a `GET /_wap/logout` on a site does not revoke anything.
