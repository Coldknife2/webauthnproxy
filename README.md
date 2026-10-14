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

## Light

| | webauthnproxy | Authelia | Pocket ID + Tinyauth |
|---|---|---|---|
| Idle memory | **9 MiB** | 161 MiB | 109 MiB |
| Idle CPU | **0 %** | 0.05 % | 0.10 % |
| Image | **12 MiB** | 77 MiB | 190 MiB |
| Auth checks, 32 connections | **36k req/s** | 20k req/s | 4.3k req/s |
| Peak memory under load | **16 MiB** | 258 MiB | 119 MiB |

Same machine, same load, authenticated forward-auth check. They do more than we do (next section). Method and caveats: [docs/performance.md](docs/performance.md).

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
| `SESSION_SECRET` | generated | cookie-signing key, 32 characters minimum |
| `SESSION_TTL` | `12h` | session lifetime |
| `DATA_DIR` | `/data` | `users.json`, `session.key`, `import/` |

All variables, ports, security model, troubleshooting: [docs/configuration.md](docs/configuration.md) · [docs/security.md](docs/security.md) · [docs/troubleshooting.md](docs/troubleshooting.md).

## Why

**Pocket ID, Tinyauth and Authelia are good projects, and they do a different job.** They are identity and SSO platforms:
users and groups, OIDC for your apps, access rules per site, admin interfaces, mature and widely used.
webauthnproxy is a gate. It answers one question, *"does this visitor hold a registered passkey?"*, for one or many sites.
If you need the former, use them. If you only need the latter, you should not have to run two or three services and a database for it.

What the sources say (code and READMEs read on 2026-10-14):

- **Traefik** has [no passkey plugin](https://community.traefik.io/t/fido2-passkey-integration-with-traefik/19396).
- **[Pocket ID](https://github.com/pocket-id/pocket-id)**: an OIDC provider that supports passkeys only. It exposes no forward-auth endpoint of its own:
  to protect an app that does not speak OIDC you put a proxy in front, such as [Tinyauth](https://github.com/tinyauthapp/tinyauth) or OAuth2 Proxy ([its guide](https://pocket-id.org/docs/guides/proxy-services)).
- **[Tinyauth](https://github.com/tinyauthapp/tinyauth)**: forward-auth with local users, LDAP and OAuth/OIDC. Its source has no passkey or WebAuthn support.
  It sets one cookie domain, derived from its own URL, and refuses apps outside it (`domain does not match cookie domain`).
- **[Authelia](https://www.authelia.com/overview/authentication/security-key/)**: passkey login since v4.39, but a passkey counts as one factor and a password may still be asked
  for `two_factor` policies. Each cookie domain needs its own `authelia_url` inside that domain, so unrelated domains mean separate portals and separate sign-ins.

| | webauthnproxy | Pocket ID + Tinyauth | Authelia |
|---|---|---|---|
| Containers to run | 1 | 2 (+ Traefik) | 1 (+ storage) |
| One login for **unrelated domains** | ✅ ticket exchange | ❌ one cookie domain | one portal and sign-in per domain |
| Built-in proxy (no Traefik/Caddy/Nginx needed) | ✅ | ❌ | ❌ |
| OIDC SSO for other apps | ❌ | ✅ | ✅ |
| Per-site rules, groups, several admins | ❌ | partial | ✅ |
| Maturity | new, unaudited | high | high |

**Choose them** for OIDC, groups, per-site rules, several administrators, or software that is widely used and audited.
**Choose this** for a personal or homelab setup: one passkey, many sites, nothing else to run.

## Development

```sh
make check   # gofmt, vet, tests (race)
make e2e     # Chromium + virtual passkey; Traefik in a container
make build   # ./webauthnproxy
make image   # container image
make bench   # footprint vs Authelia
```

Why Go and not Rust, .NET, Node or Python: [docs/language-choice.md](docs/language-choice.md).

CI ([`ci.yml`](.github/workflows/ci.yml)) tests, then builds and pushes the image to `ghcr.io` on `main` and `v*` tags.
Setup and releases: [CONTRIBUTING.md](CONTRIBUTING.md#set-up-ci-and-publish-images). Vulnerabilities: [SECURITY.md](SECURITY.md).
Web UI is English; add `?lang=fr` for French.

MIT — [LICENSE](LICENSE)
