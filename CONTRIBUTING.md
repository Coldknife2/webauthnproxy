# Contributing

Thanks for your interest! The project aims to stay **small and auditable**: one container, one data file, few dependencies.
Contributions that preserve this simplicity are welcome.

## Before you start

- Open an issue to discuss a new feature before writing a lot of code.
- For a security vulnerability, follow [SECURITY.md](SECURITY.md) (no public issue).

## Environment

Requirements: Go (version in `go.mod`), Node 22 and a container runtime (podman or docker) for the e2e tests.

```sh
make check   # gofmt + go vet + go test -race
make e2e     # Chromium + virtual authenticator, and Traefik in a container
make build   # ./webauthnproxy binary
make image   # container image
```

## Rules

- Code formatted with `gofmt`, `go vet` clean, tests green.
- Any user-visible behavior change (environment variable, port, file format, security) must be covered by a test **and**
  documented in the [README](README.md) and the [CHANGELOG](CHANGELOG.md).
- Never trust client-supplied data (headers, import files, `next`): validate it server-side.
- No new dependency without a justification in the PR.
- Clear commits in the imperative mood ("Add…", "Fix…"). One PR, one topic.

## Releasing and publishing images

Images are published by the `image` job of [`ci.yml`](.github/workflows/ci.yml), only after `test` and `e2e` pass:

- every push to `main` publishes `ghcr.io/coldknife2/webauthnproxy` with the tags `latest`, `main` and `sha-<commit>`;
- pushing a tag `vX.Y.Z` publishes `X.Y.Z`, `X.Y` and `X` (no `X` tag for `0.x`); `latest` always follows `main`;
- images are built for `linux/amd64` and `linux/arm64` (cross-compiled, no emulation); pull requests build and smoke-test the image without pushing.

One-time setup for maintainers:

1. **Make the package public**: the first push creates a *private* package. In GitHub: profile or organization → *Packages* → `webauthnproxy` →
   *Package settings* → *Change visibility* → Public. Otherwise `docker pull` answers `denied`.
2. **Optional Docker Hub mirror**: add the repository secrets `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` (an access token with write
   permission). The same tags are then also pushed to `docker.io/<username>/webauthnproxy`. Without these secrets, only GHCR is used.
3. Nothing else to configure: the job requests `packages: write` itself and logs in to GHCR with the built-in `GITHUB_TOKEN` (the image's
   `org.opencontainers.image.source` label links the package to this repository).

To release: update [CHANGELOG.md](CHANGELOG.md), then `git tag v1.0.0 && git push origin v1.0.0`.

## Translations

Logs, errors and code are in English. The web pages are translated client-side: add a language by adding a dictionary to
`web/i18n.js` (login and enrollment pages) and to the inline script of `web/tool.html`, then select it with `?lang=<code>`.
The `/` page of the forwardAuth login host is translated in `app.go` (`home`). Keep English as the default.

## Layout

| File | Role |
|---|---|
| `main.go`, `config.go` | startup, servers, environment-variable configuration |
| `app.go` | handlers: proxy, forwardAuth, login, automatic enrollment, static tool |
| `session.go` | signed session cookies, in-memory WebAuthn ceremonies |
| `store.go` | JSON database (users, passkeys) |
| `import.go` | validation and import of the static tool's JSON files |
| `web/` | embedded pages (login, enrollment, standalone `tool.html`) |
| `test/e2e/` | end-to-end tests (Playwright) |
