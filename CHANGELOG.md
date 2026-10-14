# Changelog

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), versioning follows [SemVer](https://semver.org/).

## [Unreleased]

### Added
- Container images (`linux/amd64`, `linux/arm64`) built and published to GHCR by GitHub Actions on every push to `main` and on `v*` tags (optional Docker Hub mirror), `--version` flag.
- English by default everywhere (code, logs, errors, web pages); French web pages with `?lang=fr` (remembered in the browser).
- **Proxy** mode: reverse proxy (WebSockets included) requiring a passkey-obtained session; the user is passed in `X-Authenticated-User`, the session cookie is not forwarded.
- **forwardAuth** mode (`MODE=forward`) for Traefik: `/_wap/verify` endpoint, dedicated login host, cookie shared on `COOKIE_DOMAIN`, post-login redirect restricted to that domain.
- **Automatic enrollment** (`ENROLL_ENABLED`, port 8081) protected by existing passkeys; bootstrap token printed in the logs while no passkey exists; the last passkey cannot be deleted.
- **Static enrollment tool** (`TOOL_ENABLED`, port 8082): standalone HTML page producing a JSON file to import by hand into `DATA_DIR/import/`.
- Usernameless login (discoverable credentials), user verification required by default (`USER_VERIFICATION`).
- Database: a single atomically written JSON file.
- Non-root distroless image, Docker Compose / Traefik examples, unit tests and end-to-end tests (Chromium + virtual authenticator, real Traefik).
