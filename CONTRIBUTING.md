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
