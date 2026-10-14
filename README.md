# webauthnproxy

[![CI](https://github.com/coldknife2/webauthnproxy/actions/workflows/ci.yml/badge.svg)](https://github.com/coldknife2/webauthnproxy/actions/workflows/ci.yml)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

🇬🇧 English · 🇫🇷 [Français](README.fr.md)

**Passkey login in front of any site. One container, one JSON file.**
No passwords. No directory. No OIDC provider.

## Quick start

Protect a demo site ([`whoami`](https://github.com/traefik/whoami), it prints the headers it receives).

```sh
docker network create wap
docker run -d --name whoami --network wap docker.io/traefik/whoami     # the site to protect: not published

mkdir -p data && sudo chown 65532 data
docker run -d --name webauthnproxy --network wap \
  -p 8080:8080 -p 127.0.0.1:8081:8081 -v "$PWD/data:/data" \
  -e UPSTREAM=http://whoami:80 \
  -e RP_ID=localhost -e RP_ORIGINS=http://localhost:8080,http://localhost:8081 \
  -e ENROLL_ENABLED=true \
  ghcr.io/coldknife2/webauthnproxy:latest

docker logs webauthnproxy        # copy "Enrollment bootstrap token: …"
```

1. Open <http://localhost:8081>, paste the token, pick a name: **your first passkey**.
2. Open <http://localhost:8080>: passkey prompt, then whoami shows `X-Authenticated-User: <you>`.
3. Done enrolling? Recreate the container without `ENROLL_ENABLED`.

`UPSTREAM` is the site you protect. Use your own: any URL the container can reach.
Podman: swap `docker` for `podman`; rootless: `podman unshare chown 65532:65532 data`.

## Install

```yaml
services:
  webauthnproxy:
    image: ghcr.io/coldknife2/webauthnproxy:latest   # pin a version in production: :1.2.3
    restart: unless-stopped
    environment:
      UPSTREAM: http://mysite:80
      RP_ID: example.com
      RP_ORIGINS: https://app.example.com
    volumes: ["./data:/data"]                        # chown 65532 ./data
```

| Tag | |
|---|---|
| `latest`, `main` | last commit of `main` |
| `1.2.3`, `1.2`, `1` | releases |

`linux/amd64`, `linux/arm64`. Check: `docker run --rm ghcr.io/coldknife2/webauthnproxy --version`.
From source: `docker build -t webauthnproxy .`

HTTPS is required outside `localhost`. Put Traefik in front: [`docker-compose.example.yml`](docker-compose.example.yml).

## Usage

### Two modes

| `MODE=proxy` (default) | `MODE=forward` |
|---|---|
| Relays traffic to `UPSTREAM`. One site. | Traefik `forwardAuth`. **Many sites, any domains.** |
| Adds `X-Authenticated-User`, strips the session cookie. | `auth.com` protects `anysite.com`, `other.org`… |

```sh
# forward mode: one login host, a shortlist of protected sites
MODE=forward
LOGIN_URL=https://auth.com/_wap/login
ALLOWED_HOSTS=anysite.com,other.org,*.example.net
RP_ID=auth.com
RP_ORIGINS=https://auth.com
```
```yaml
# Traefik: attach to any router
- traefik.http.middlewares.passkey.forwardauth.address=http://webauthnproxy:8080/_wap/verify
- traefik.http.middlewares.passkey.forwardauth.authResponseHeaders=X-Authenticated-User
- traefik.http.routers.mysite.middlewares=passkey
```

How the cross-domain login works: [docs/forwardauth.md](docs/forwardauth.md). Example: [`docker-compose.forwardauth.example.yml`](docker-compose.forwardauth.example.yml).

### Enroll passkeys

| | Automatic | Static tool |
|---|---|---|
| Enable | `ENROLL_ENABLED=true` | `TOOL_ENABLED=true` |
| Port | `8081` | `8082` |
| Protected by | your existing passkeys (token for the first one) | nothing needed: no state, no writes |
| Adding a passkey | in the page | copy the JSON it gives you into `data/import/` |

The static tool must be served over HTTPS under your `RP_ID` domain (not `file://`). Details: [docs/enrollment.md](docs/enrollment.md).

### Configure

| Variable | Default | |
|---|---|---|
| `UPSTREAM` | – | proxy mode: site to protect |
| `RP_ID`, `RP_ORIGINS` | – | WebAuthn domain and allowed origins (required) |
| `LOGIN_URL`, `ALLOWED_HOSTS` | – | forward mode: login page, sites shortlist |
| `SESSION_TTL` | `12h` | session lifetime |
| `DATA_DIR` | `/data` | `users.json`, `session.key`, `import/` |

All variables, ports, security model, troubleshooting: [docs/configuration.md](docs/configuration.md) · [docs/security.md](docs/security.md) · [docs/troubleshooting.md](docs/troubleshooting.md).

## Why

Need: passkey-only login in front of self-hosted sites, with nothing else to run. As of 2026-10-14:

- **Traefik** has [no passkey plugin](https://community.traefik.io/t/fido2-passkey-integration-with-traefik/19396).
- **[Pocket ID](https://github.com/pocket-id/pocket-id)** is passkey-only but an OIDC provider, not a proxy: you add [Tinyauth](https://github.com/tinyauthapp/tinyauth) or OAuth2 Proxy in front of non-OIDC apps ([guide](https://pocket-id.org/docs/guides/proxy-services)). Tinyauth's README lists no passkey support.
- **[Authelia](https://www.authelia.com/overview/authentication/security-key/)** has passkey login since v4.39, but a passkey counts as one factor and a password may still be asked for `two_factor` policies.

| | webauthnproxy | Pocket ID + Tinyauth | Authelia |
|---|---|---|---|
| Passkey-only login | ✅ | ✅ | ⚠️ password may still be required |
| Containers to run | 1 | 2 (+ Traefik) | 1 (+ storage) |
| One passkey login for **unrelated domains** | ✅ ticket exchange | not verified | [one cookie per domain](https://authelia.com/configuration/session/introduction); separate sign-ins* |
| Built-in proxy (no Traefik/Caddy/Nginx needed) | ✅ | ❌ | ❌ |
| OIDC SSO for other apps | ❌ | ✅ | ✅ |
| Per-site rules, groups | ❌ | partial | ✅ |
| Maturity | new, unaudited | high | high |

\*per a third-party report, not confirmed in Authelia's docs.

**Pick the others** for per-site rules, groups, several admins, OIDC, or audited software.
**Pick this** for a personal or homelab setup: one passkey, many sites, nothing else.
Official sites (tinyauth.app, docs.pocket-id.org) were unreachable when researching; re-check before deciding.

## Development

```sh
make check   # gofmt, vet, tests (race)
make e2e     # Chromium + virtual passkey; Traefik in a container
make build   # ./webauthnproxy
make image   # container image
```

CI ([`ci.yml`](.github/workflows/ci.yml)) tests, then builds and pushes the image to `ghcr.io` on `main` and `v*` tags.
Setup and releases: [CONTRIBUTING.md](CONTRIBUTING.md#set-up-ci-and-publish-images). Vulnerabilities: [SECURITY.md](SECURITY.md).
Web UI is English; add `?lang=fr` for French.

MIT — [LICENSE](LICENSE)
