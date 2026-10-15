# Security model

[← README](../README.md) · Report a vulnerability: [SECURITY.md](../SECURITY.md)

**What is guaranteed**

- No request reaches the site without a valid session: a random cookie value that the server knows (expiring, idle-limited, revocable one by one, ended if the user is deleted). See [Sessions](#sessions-server-side).
- Login: single-use challenge (5 min), origin and domain verified, signature counter updated, user verification required, [rate limited](#rate-limiting) and [audited](#audit-log).
- `X-Forwarded-*` headers are believed **only from declared proxies** ([`TRUSTED_PROXIES`](#trusted-proxies-and-forwarded-headers)); nobody is trusted by default.
- Cookie is `HttpOnly`, `SameSite=Lax`, and `Secure` whenever the connection is HTTPS (or a trusted proxy says so); pages are served with a restrictive CSP.
- The post-login redirect (`next`) is limited to local paths, or in forward mode to the sites in `ALLOWED_HOSTS` / `COOKIE_DOMAIN`: no open redirect.
- Forward mode across domains: single-use 60-second tickets, per-host cookies bound to their site, requests for unlisted hosts refused (see [forwardAuth mode](forwardauth.md) and the [threat model](#cross-domain-login-threat-model)).
- Automatic enrollment: session required, bootstrap token compared in constant time, CSRF protection, the last passkey cannot be deleted.
- Import: the file is untrusted and fully revalidated (see [enrollment](enrollment.md)), with a size limit.
- Static tool: no writes, hash-based CSP (`script-src 'sha256-…'`, no `unsafe-inline`).
- The database holds **public keys only**. There is no signing key to leak: `sessions.json` holds hashes of the cookie values, which cannot be turned back into cookies.

**Assumptions and limits**

- TLS is terminated upstream (Traefik); without HTTPS WebAuthn does not work outside `localhost`.
- No per-site rules and no high availability: a single instance, with ceremonies, tickets and rate-limit counters kept in memory (a restart resets them; sessions are saved to disk and survive).
- Not audited by a third party; one maintainer.
- User handles are derived from the name (SHA-256) so the same name always designates the same user whichever enrollment tool is used.
- One root domain per instance (`RP_ID`).

To report a vulnerability, see [SECURITY.md](../SECURITY.md).

Sections: [sessions](#sessions-server-side) · [idle timeout](#idle-timeout) · [rate limiting](#rate-limiting) · [trusted proxies](#trusted-proxies-and-forwarded-headers) · [audit log](#audit-log) · [cross-domain threat model](#cross-domain-login-threat-model) · [reverse proxy and exposure](reverse-proxy.md)

## Sessions (server side)

A session cookie is **256 random bits**. The server keeps the SHA-256 of that value together with the session's data (user, site, creation, expiry, last activity, optional binding) in memory and in
`DATA_DIR/sessions.json` (mode `0600`, rewritten atomically). The design follows [passkey-forwardauth](https://github.com/QirunGao/passkey-forwardauth)'s server-side sessions, plus persistence, a login/site tree and an admin command.

**What it gives**

- **Revocation one session at a time**, and exact: `sessions list` / `sessions revoke <id>` ([enrollment.md](enrollment.md#listing-and-revoking-passkeys)), `signout <user>` for all of a user's, a sign-out button for "this browser" or "all devices".
- **An exact idle timeout** (`SESSION_IDLE_TIMEOUT`): last activity is recorded server side, so the cookie never has to be re-issued, and **Traefik needs no `addAuthCookiesToResponse`**.
- **Nothing to forge.** There is no signing key, hence nothing to rotate or leak (`SESSION_SECRET` is ignored). A copy of `sessions.json` or of the backup does not give a cookie: only hashes are stored.
- **Sessions survive a restart.** `sessions.json` is written when a session is created or revoked and every 30 s for last-activity times; a crash can only lose a little precision on those.
- **Optional binding** (`SESSION_BIND=ua`, `ip` or `ua,ip`): the session only works with the same User-Agent and/or client address as at sign-in. Off by default: User-Agent strings change with browser updates and addresses change on mobile networks;
  a cookie thief can also copy the User-Agent, so `ua` raises the bar only slightly.
- Cookie flags: `HttpOnly`, `SameSite=Lax`, `Secure` over HTTPS. A site's cookie is host-only and **bound to its host** (audience stored with the session).

**How "this browser" works.** A site session opened through the ticket exchange remembers the login session it came from. Signing out of the login host or of any site ends that login session and every site session opened from it;
signing in again in the same browser replaces the old login session and keeps its sites. Other devices stay signed in. "Sign out of all devices" (`?all=1`, the second button on the login host's page) and `signout <user>` end all of a user's sessions.
Deleting a user's last passkey ends their sessions.

**Its limits**

- It is still a *bearer token*: whoever holds the cookie is the user until it expires (`SESSION_TTL`, 12 h by default), goes idle, or is revoked. Use a shorter TTL for sensitive sites.
- Anyone who can **write** `sessions.json` (the data volume) can open a session for any user by adding the hash of a value they chose. That is the same trust as writing `users.json` and is outside this model.
- Restoring an old `sessions.json` brings back sessions that were revoked after the backup. After a restore or an account recovery, delete `sessions.json` (everybody signs in again).
- A single process owns the table: running two instances against the same data is unsupported.
- The table is bounded: 20,000 sessions in total and `SESSION_MAX_PER_USER` (50) per user, the least recently used going first, so one account signing in in a loop cannot push out other users' sessions or fill memory.
- **Users see and end their own sessions** on `/_wap/sessions` (a link on the login host's page): list, end one, end all the others. The API only ever lists the caller's sessions, a session of another user looks like a missing one, and ending needs the anti-CSRF header.
- Each lookup costs one SHA-256, a read lock and a map access, and updates an atomic timestamp (measured in [performance](performance.md)).

*Tested:* per-user cap (least recently used goes, others untouched, flood keeps the cap), sessions page (own sessions only, other users' ids refused, CSRF, site sessions refused, end others), round trip; random, unique, 43-character values; only hashes in `sessions.json`, mode `0600`; modified, appended, guessed, foreign and old-format cookies refused; expiry and idle timeout (including an active session outliving the idle timeout, and the absolute limit still applying);
restart (sessions kept, revoked ones not, expired ones dropped, corrupt file stops the start); binding on User-Agent and address; revocation scopes (tree, user, id, other users untouched); sign-out of one browser versus all devices; deleted users; table bound.

## Local administration socket

`DATA_DIR/admin.sock` (mode `0600`, Unix socket, never a network port) lets the `passkeys list|revoke`, `sessions list|revoke` and `signout` commands act on the running service ([enrollment.md](enrollment.md#listing-and-revoking-passkeys)).
Anyone who can open it can delete passkeys and sign users out, so it carries the same trust as write access to the data volume. It cannot add a passkey or create a session.
*Tested:* socket mode `0600`; the admin routes are absent from the public, enrolment and tool ports and change nothing when called there; the last passkey cannot be deleted; a stale socket from a previous run does not prevent start.

## Idle timeout

`SESSION_IDLE_TIMEOUT` (off by default) ends a session after that long without activity, in addition to the absolute `SESSION_TTL`. Activity is recorded on the server at each request, so the cookie does not change and
the forwardAuth middleware needs no extra option. *Tested:* unit tests with a fake clock (exact limit, activity keeps the session, absolute limit still applies, proxy mode, forward mode sets no cookie), and an end-to-end test with a real Traefik.

## Rate limiting

Token buckets, one per client address and one global (`RATE_LIMIT_IP`, default 20 per minute; `RATE_LIMIT_GLOBAL`, default 200 per minute), answer `429` with `Retry-After`. They cover the endpoints an attacker can hammer without a session:
`POST /_wap/login/begin` and `/_wap/login/finish` (on the public host and the enrollment host), and the enrollment API (`POST /api/register/begin`, `/api/register/finish`, `DELETE /api/credentials`).
Pages and `/_wap/verify` are not limited (the latter is internal and on the hot path).

- The client address is the connecting peer, or, if the peer is in `TRUSTED_PROXIES`, the right-most `X-Forwarded-For` entry that is not itself a trusted proxy. A forged header from an untrusted peer changes nothing.
  **Behind a proxy you must declare it**, otherwise every visitor shares the proxy's address and one budget.
- IPv6 clients are grouped by /64, so changing the low bits of the address does not give a new budget.
- Counters are in memory and per process: a restart resets them, and the table is bounded (20,000 keys; if an attack fills it with busy keys it is reset rather than growing). A distributed attack from many addresses is only bounded by the global limit,
  which also means such an attack can make legitimate logins answer `429`.
*Tested:* unit tests (burst, refill, isolation between clients, bounded memory, IPv6 grouping, forged `X-Forwarded-For`, per-client budgets behind a trusted proxy, global limit, enrollment routes) and an end-to-end test against the real binary.

## Trusted proxies and forwarded headers

`X-Forwarded-*` and `Forwarded` describe the original request. Any client can send them, so they are believed **only when the connecting peer is listed in `TRUSTED_PROXIES`**; the default is nobody, and forward mode refuses to start without the list.

- `/_wap/verify` answers `403` to a caller outside the list (and logs `untrusted_proxy`): the host, scheme and URI it would act on cannot be forged by a client who reaches it.
- In proxy mode the headers `X-Forwarded-For/Host/Proto/Port/Server`, `X-Real-Ip` and `Forwarded` sent by an untrusted client are dropped before the request reaches your site, and replaced by what the service saw. From a trusted proxy they are kept (and `X-Forwarded-For` is extended).
- The `Secure` flag and the scheme of redirects follow the same rule (`COOKIE_SECURE=auto`).
- Do not use `0.0.0.0/0` outside tests, and prefer the exact network of your proxy over a whole private range such as `10.0.0.0/8`, which trusts every container on it.
*Tested:* unit tests (list parsing, client address selection with forged and chained headers, scheme and `Secure` ignoring forged `X-Forwarded-Proto`, `verify` refusing an untrusted caller, proxy-mode header stripping and preservation, forward mode refusing to start) and the end-to-end suites, which run with the proxy declared.

## Audit log

Security events are written to **standard output as one JSON object per line** (`AUDIT_LOG=false` disables); operational messages stay on standard error.

```json
{"time":"2026-10-14T18:02:11Z","level":"INFO","msg":"audit","event":"login_success","ip":"198.51.100.4","path":"/_wap/login/finish","user":"remi","credential":"HFeQVzNU_LSA"}
```

| Event | When | Main fields |
|---|---|---|
| `login_success`, `login_failure` | passkey login accepted / refused | `user`, `credential` (12-character tag), `reason` |
| `enroll_success`, `enroll_failure` | passkey added or refused (web page, import folder, bad bootstrap token) | `user`, `credential`, `via`, `reason` |
| `credential_deleted`, `passkey_labeled` | a passkey was removed / renamed | `user`, `credential`, `via` |
| `invite_created` | a one-time link to add a passkey was created (never the code) | `user`, `expires` |
| `session_revoked` | one session ended (admin command or the user's sessions page) | `user`, `session`, `via` |
| `sign_out` | all sessions of a user revoked | `user`, `via`, `site` |
| `ticket_issued`, `site_login`, `ticket_rejected` | cross-domain exchange (`reason`: replay, revoked, invalid…) | `user`, `site` |
| `rate_limited` | a request answered `429` | `scope` (client or global) |
| `untrusted_proxy`, `host_denied` | `/_wap/verify` called from an unlisted proxy / for an unlisted site | `peer`, `site` |

Every line carries `ip` (the client address as defined above) and `path`. Cookies, tickets, tokens and keys are never written, and a credential appears only as a short tag. Successful page views and verifications are not logged (volume).
The one-time bootstrap token is printed in the regular log on purpose, so that the operator can read it. Log retention and shipping are up to you.
*Tested:* unit tests (events emitted, JSON shape, no secret in the output, disabled mode) and the end-to-end suite (login and enrollment events present, no cookie in the logs).

## Single use of tickets

A ticket is a random value held **in the memory of the process** that issued it, together with the user, the site and the login session it comes from. It is **removed on first presentation**, whatever the outcome:

| Case | Result | Test |
|---|---|---|
| Same ticket presented twice | second use refused (`403`, audit `ticket_rejected`) | `TestTicketReplaySameProcess` |
| Ticket used, the container restarts, the ticket is presented again (within 60 s) | refused: the table is empty after a restart | `TestTicketReplayAfterRestartRefused` |
| Unused ticket, restart, then presented | refused (the user signs in again) | same |
| Two instances; ticket issued by one, presented to the other | refused on the other; accepted once on the issuer, then refused | `TestTicketTwoInstances` |
| Presented on a site it was not issued for | refused **and burnt** | `TestTicketForTheWrongSiteIsRefusedAndBurnt` |
| Guessed, empty, or a session cookie used as ticket | refused | `TestForgedTicketRefused` |
| Login session ended between issue and use | refused | `TestTicketIssuedBeforeLogoutIsRefused` |

Without rounding: **single use is exact within one process and is not shared or persisted.** A login in flight during a restart fails once and starts again; sessions are unaffected. A multi-instance deployment would need shared state and is not supported.

## Cross-domain login: threat model

Applies to `MODE=forward` when the protected sites are on domains unrelated to the login host (`ALLOWED_HOSTS`). The flow itself is described in [forwardauth.md](forwardauth.md).

**Trusted:** this service, Traefik, the hosts listed in `ALLOWED_HOSTS` (their backends receive their own site cookie), the operator.
**Not trusted:** every visitor, every other website, every browser.

**The exchange.** A visitor without a cookie for site S is sent to the login host (`/_wap/sso?next=https://S/page`). After a passkey login the login host redirects to
`https://S/_wap/callback?ticket=…`. Traefik passes that request to `/_wap/verify`, which validates the ticket, sets a cookie for S only, and redirects to the page.

| Property | How it is enforced | Covered by |
|---|---|---|
| Ticket lifetime: **60 seconds** | expiry stored with the ticket | unit test |
| **Single use** | the ticket nonce is remembered **in memory of the issuing process** until it expires; the ticket carries the identifier of that process, so tickets from another run or instance are refused | unit tests: replay, after a restart, on a second instance, without identifier; e2e: replayed ticket refused |
| **Bound to the target host** | the ticket carries the host it was issued for; `/_wap/callback` compares it with `X-Forwarded-Host` | unit test; e2e: a fresh ticket is refused on another site and accepted on its own |
| **Bound to the login session** | the ticket records the login session it came from; if that session has ended the ticket is refused | unit test (`TestTicketIssuedBeforeLogoutIsRefused`) |
| The site cookie is **host-only and bound to its host** | no `Domain` attribute; the audience is stored with the session | unit tests; e2e: a site's cookie is refused on another site |
| **`ALLOWED_HOSTS` is the gate** | hosts outside the list get `403` from `/_wap/verify`; `next` is only honored for listed hosts; tickets are only issued for listed hosts | unit tests; e2e: unlisted host refused |
| **No open redirect** | `next` must be a local path or an absolute URL of a listed host (lookalikes such as `evilsite.com` or `site.com.evil.com` are rejected); the callback accepts a path only and rebuilds the absolute URL itself | unit tests (`//evil`, `/\evil`, `javascript:`, `user@host` tricks); e2e: `next=https://evil.example` is ignored |
| `/_wap/verify` is **not public** | the public router of the login host excludes that path (see [reverse-proxy.md](reverse-proxy.md)) | e2e: 404 on the public router while forwardAuth keeps working |
| Sign-out revokes the site sessions opened from that login (this browser), or all of a user's | session tree and per-user revocation | unit and e2e tests |

**Known gaps and residual risks (not covered by a test unless stated):**

- **Single use is not persistent and not shared.** Nothing is written to disk and nothing is shared between instances; see [Single use of tickets](#single-use-of-tickets). Running two instances against the same data is unsupported: a login that starts on one and ends on the other fails.
- **The ticket is in a URL.** `/_wap/callback?ticket=…` can appear in the access logs of Traefik or of the site. Single use and the 60 s limit make a logged ticket almost worthless afterwards,
  but someone who reads logs in real time could race the user. Treat log access as part of the trusted base. *By design, not tested.*
- **Wildcards widen the trust.** `*.example.org` trusts every present and future subdomain; a dangling DNS record (subdomain takeover) would let an attacker receive tickets and cookies for users who visit it
  while signed in. Prefer explicit hosts. *Operator responsibility.*
- **A compromised listed site** sees its own cookie and can act as the signed-in user on that site until the cookie expires or the user signs out. It cannot reach the other sites (the cookie is bound to its host)
  and cannot obtain tickets for them (tickets are issued per requested host, only to a signed-in browser).
- **One set of passkeys for every listed site.** There are no per-site rules: any enrolled user can open every site in the list.
- **Restoring `sessions.json`.** A backup older than a revocation brings revoked sessions back. Delete `sessions.json` after a restore or a recovery ([enrollment.md](enrollment.md#account-recovery-lost-passkeys)). *Documented, not tested.*
- **Misconfigured Traefik.** If `trustForwardHeader` is set to `true` without a trusted front proxy, clients can forge `X-Forwarded-Host` and `X-Forwarded-Proto`. *Not tested;* see [reverse-proxy.md](reverse-proxy.md).
- **Login CSRF.** An attacker cannot sign a victim in as someone else without the victim approving a passkey prompt for the attacker's account. `GET /_wap/sso` only redirects; a `GET /_wap/logout` on a site does not revoke anything.
