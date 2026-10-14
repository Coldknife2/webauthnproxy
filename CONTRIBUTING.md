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
make examples # the two complete examples in examples/ (compose, Chromium)
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

## Set up CI and publish images

The `image` job of [`ci.yml`](.github/workflows/ci.yml) runs after `test` and `e2e` and pushes to `ghcr.io/<owner>/webauthnproxy`
(`linux/amd64` + `linux/arm64`). Pull requests only build and smoke-test the image.

| Event | Tags pushed |
|---|---|
| push to `main` | `latest`, `main`, `sha-<commit>` |
| tag `vX.Y.Z` | `X.Y.Z`, `X.Y`, `X` (no `X` for `0.x`) |
| manual run on `main` (*Actions → CI → Run workflow*) | same as a push to `main` |

**One-time checklist**

1. **Merge the branch into `main`.** Workflows only exist on the branches that contain `.github/workflows/`; until then nothing runs.
2. **Enable Actions**: repository *Settings → Actions → General* → allow actions. Nothing else to configure: the job requests
   `packages: write` itself and logs in with the built-in `GITHUB_TOKEN`.
3. **Check the first run**: *Actions → CI*. All three jobs must be green (`test`, `e2e`, `image`). If `e2e` fails on the runner, its logs show which scenario.
4. **Make the package public**: the first push creates a *private* package. *Profile or organization → Packages → webauthnproxy →
   Package settings → Change visibility → Public*. Until then `docker pull` answers `denied`.
5. **Optional Docker Hub mirror**: add the secrets `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` (token with write access). The same tags are then also pushed
   to `docker.io/<username>/webauthnproxy`. Without them, only GHCR is used.

**Release**: update [CHANGELOG.md](CHANGELOG.md), then `git tag v1.0.0 && git push origin v1.0.0`.

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
| `docs/` | detailed documentation (English only; `README.fr.md` is a short French mirror of the README) |
