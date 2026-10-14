# Changelog

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versioning follows [SemVer](https://semver.org/).

## [Unreleased]

### Breaking
- **Forward mode requires `TRUSTED_PROXIES`** (CIDRs of Traefik). `X-Forwarded-*` is believed only from those addresses and `/_wap/verify` answers `403` to anyone else. There is no default.
- The session token gained a last-activity field (`user.aud.exp.gen.seen.signature`): existing cookies are refused once, users sign in again.

### Security
- Cross-domain tickets carry an identifier of the issuing process: a ticket used before a restart can no longer be redeemed again, and an instance refuses tickets it did not issue. Single use remains in-memory only, now documented as such with a test per case (replay, restart, two instances).
- Rate limiting on login and enrolment endpoints, per client address (IPv6 grouped by /64) and globally; `429` with `Retry-After`. `RATE_LIMIT_IP` (default `20/1m`), `RATE_LIMIT_GLOBAL` (default `200/1m`), `off` disables.
- Session key rotation: `SESSION_SECRET_PREVIOUS` / `data/session.key.previous` keep older keys valid for verification only.
- Idle timeout without server state (`SESSION_IDLE_TIMEOUT`); with Traefik it needs `addAuthCookiesToResponse: [wap_session]`.
- Proxy mode removes forged `X-Forwarded-*`/`Forwarded` headers from untrusted clients; `COOKIE_SECURE` (`auto`, `true`, `false`).
- JSON audit log on standard output (`AUDIT_LOG`): sign-in success/failure, enrolment, credential deletion, sign-out, ticket events, denied hosts and callers. No secrets in it.

### Documentation
- README restructured: security notes, limitations, "when not to use it"; prior art cited (Quiq/webauthn_proxy, passkey-forwardauth and others, dated, with sources) in `docs/alternatives.md`, with an experiment showing Tinyauth v5.2.0 does not cover unrelated domains.
- New `docs/reverse-proxy.md` (forwarded headers, `RP_ORIGINS`, what must stay private); cross-domain threat model and test coverage in `docs/security.md`; account recovery procedure; performance figures presented as an experiment.

### Security
- Signing out now **revokes** every session and ticket of the user (per-user session generation stored in `users.json`), on all sites and devices; on a protected site only `POST /_wap/logout` revokes, `GET` just clears that site's cookie.
- `SESSION_SECRET` must now be at least 32 characters (was 16).
- Session token layout gained a generation field (`user.aud.exp.gen.signature`); existing cookies are refused and users sign in again.

### Changed
- Hot path (`/_wap/verify`) optimized: pooled HMAC, no user copy per request, no URL parsing for ordinary requests (~30 % faster, 25 → 17 allocations).

### Added
- `GET /_wap/verify` is excluded from the login host's public router in the forwardAuth example; e2e checks cover host-bound tickets, the open-redirect refusal and that the public router does not expose `/_wap/verify`.
- Footprint comparison with Pocket ID + Tinyauth alongside Authelia (`make bench`), and a language comparison of the hot path in Go, Rust, .NET, Node and Python (`make bench-langs`); see `docs/performance.md` and `docs/language-choice.md`.
- Footprint benchmark against Authelia (`make bench`) and Go micro-benchmarks (`make bench-go`); results in `docs/performance.md`.
- Documentation split: short README (quick start first), details in `docs/`; comparison with Pocket ID + Tinyauth and Authelia; manual run of the CI on `main` to publish images.
- forwardAuth across **unrelated domains**: `auth.com` can protect `anysite.com` and other sites through a shortlist (`ALLOWED_HOSTS`: `host`, `host:port`, `*.domain`), using single-use 60-second tickets and per-host cookies bound to their site; `/_wap/sso`, `/_wap/callback` and `/_wap/logout` endpoints. `COOKIE_DOMAIN` becomes optional (shared-cookie shortcut).
- Container images (`linux/amd64`, `linux/arm64`) built and published to GHCR by GitHub Actions on every push to `main` and on `v*` tags (optional Docker Hub mirror), `--version` flag.
- English by default everywhere (code, logs, errors, web pages); French web pages with `?lang=fr` (remembered in the browser).
- **Proxy** mode: reverse proxy (WebSockets included) requiring a passkey-obtained session; the user is passed in `X-Authenticated-User`, the session cookie is not forwarded.
- **forwardAuth** mode (`MODE=forward`) for Traefik: `/_wap/verify` endpoint, dedicated login host, cookie shared on `COOKIE_DOMAIN`, post-login redirect restricted to that domain.
- **Automatic enrollment** (`ENROLL_ENABLED`, port 8081) protected by existing passkeys; bootstrap token printed in the logs while no passkey exists; the last passkey cannot be deleted.
- **Static enrollment tool** (`TOOL_ENABLED`, port 8082): standalone HTML page producing a JSON file to import by hand into `DATA_DIR/import/`.
- Usernameless login (discoverable credentials), user verification required by default (`USER_VERIFICATION`).
- Database: a single atomically written JSON file.
- Non-root distroless image, Docker Compose / Traefik examples, unit tests and end-to-end tests (Chromium + virtual authenticator, real Traefik).
