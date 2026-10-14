# Changelog

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versioning follows [SemVer](https://semver.org/).
The project started on 2026-10-14. Until 1.0, minor versions may change behavior; every such change is listed here.

## [Unreleased]

## [0.1.0] - 2026-10-14

First release. Everything below is new; nothing is claimed beyond what the tests in this repository cover.

### Added
- **Proxy mode** (`MODE=proxy`): reverse proxy (WebSockets included) requiring a passkey-obtained session; the user is passed in `X-Authenticated-User`, the session cookie is not forwarded.
- **forwardAuth mode** (`MODE=forward`) for Traefik: `GET /_wap/verify`, a login host, and login across **unrelated domains** through a list of allowed sites (`ALLOWED_HOSTS`: `host`, `host:port`, `*.domain`)
  using 60-second tickets and per-host cookies; `COOKIE_DOMAIN` is an optional shared-cookie shortcut.
- Username-less login (discoverable credentials), user verification required by default; users in one atomically written JSON file.
- **Automatic enrolment** (`ENROLL_ENABLED`, port 8081) protected by existing passkeys, with a bootstrap token while no passkey exists; the last passkey cannot be deleted.
  **Static enrolment tool** (`TOOL_ENABLED`, port 8082) producing a JSON file imported by hand into `DATA_DIR/import/`.
- `webauthnproxy passkeys list`, `passkeys revoke <id>` and `signout <user>`, through a private Unix socket (`DATA_DIR/admin.sock`, mode 0600); no more editing `users.json`.
- `GET /_wap/healthz`, `webauthnproxy healthcheck` and a `HEALTHCHECK` in the image; `/data` is owned by the unprivileged user so named volumes work without `chown`.
- Two complete examples run by `make examples` (compose, Chromium with a virtual passkey): `examples/proxy-traefik` and `examples/two-domains`.
- Container images (`linux/amd64`, `linux/arm64`) published to GHCR by GitHub Actions on `main` and on `v*` tags; release binaries and checksums attached to tagged releases.
- English everywhere by default; French web pages with `?lang=fr`.

### Security
- **Rate limiting** on login and enrolment, per client address (IPv6 grouped by /64) and globally: `RATE_LIMIT_IP` (`20/1m`), `RATE_LIMIT_GLOBAL` (`200/1m`), `429` with `Retry-After`.
- **`TRUSTED_PROXIES`**: `X-Forwarded-*` is believed only from the declared CIDRs, never by default. Forward mode requires it and `/_wap/verify` answers `403` to other callers;
  proxy mode strips forged forwarded headers from untrusted clients. `COOKIE_SECURE` (`auto`, `true`, `false`).
- **Session key rotation** without signing anyone out (`SESSION_SECRET_PREVIOUS`, `session.key.previous`).
- **Idle timeout** without server state (`SESSION_IDLE_TIMEOUT`); with Traefik it needs `addAuthCookiesToResponse: [wap_session]`.
- **JSON audit log** on standard output (`AUDIT_LOG`): sign-in success/failure, enrolment, credential deletion, sign-out, ticket and host refusals, rate limiting. No secret in it.
- Signing out **revokes** every session and ticket of the user (per-user generation stored in `users.json`); on a protected site only `POST /_wap/logout` revokes, `GET` just clears that site's cookie.
- Tickets are **single-use in the memory of the issuing process only**; they carry the identifier of that process, so a ticket never survives a restart and another instance refuses it. Tests cover replay, restart and two instances ([docs/security.md](docs/security.md#single-use-of-tickets)).
- `SESSION_SECRET` must have 32 characters at least; tokens are HMAC-SHA256 signed with separate signing domains for sessions and tickets.
- The post-login redirect only accepts a local path or an absolute URL of an allowed site (no open redirect).

### Documentation
- Short README (quick start, two modes, limitations, when not to use it, three differentiators), a French copy, and `docs/`: configuration, enrolment and recovery, forwardAuth, reverse-proxy guide, security model with the cross-domain threat model and its test coverage,
  troubleshooting, prior art and alternatives (dated, sourced, with an experiment showing Tinyauth v5.2.0 does not cover unrelated domains), language choice and performance figures presented as experiments.
- Tests: Go unit tests (race detector), and end-to-end suites with Chromium and a virtual authenticator against a real Traefik.

[Unreleased]: https://github.com/coldknife2/webauthnproxy/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/coldknife2/webauthnproxy/releases/tag/v0.1.0
