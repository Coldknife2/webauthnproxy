# Changelog

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versioning follows [SemVer](https://semver.org/).

## [Unreleased]

### Changed
- Hot path (`/_wap/verify`) optimized: pooled HMAC, no user copy per request, no URL parsing for ordinary requests (~30 % faster, 25 → 17 allocations).

### Added
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
