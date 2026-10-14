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
TRUSTED_PROXIES=172.18.0.0/16   # Traefik's address range: required, nobody else is believed on X-Forwarded-*
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
| Exposure | **never public**: loopback or private network, only while enrolling | **never public** (harmless if reached, but no reason to publish) |
| Adding a passkey | in the page | copy the JSON it gives you into `data/import/` |

The static tool must be served over HTTPS under your `RP_ID` domain (not `file://`). Details: [docs/enrollment.md](docs/enrollment.md).

### Configure

| Variable | Default | |
|---|---|---|
| `UPSTREAM` | – | proxy mode: site to protect |
| `RP_ID`, `RP_ORIGINS` | – | WebAuthn domain and allowed origins (required) |
| `LOGIN_URL`, `ALLOWED_HOSTS` | – | forward mode: login page, sites shortlist |
| `SESSION_SECRET` | generated | cookie-signing key, 32 characters minimum |
| `TRUSTED_PROXIES` | – | forward mode: CIDRs whose `X-Forwarded-*` are believed (required; never trusted by default) |
| `SESSION_TTL`, `SESSION_IDLE_TIMEOUT` | `12h`, off | session lifetime, sign-out after inactivity |
| `SESSION_SECRET_PREVIOUS` | – | former signing keys still accepted (rotation without signing everyone out) |
| `RATE_LIMIT_IP`, `RATE_LIMIT_GLOBAL` | `20/1m`, `200/1m` | login and enrolment requests per client address / in total (`429`) |
| `AUDIT_LOG` | `true` | JSON audit events on standard output |
| `DATA_DIR` | `/data` | `users.json`, `session.key`, `import/` |

All variables, ports, security model, troubleshooting: [docs/configuration.md](docs/configuration.md) · [docs/security.md](docs/security.md) · [docs/troubleshooting.md](docs/troubleshooting.md).

## Security notes

- **Cross-domain login** uses single-use tickets valid for 60 seconds, bound to the target site; only sites listed in `ALLOWED_HOSTS` can use the login, and each site's cookie is bound to its host.
  Threat model, known gaps and what is tested: [docs/security.md](docs/security.md#cross-domain-login-threat-model).
- **Behind Traefik:** set `TRUSTED_PROXIES` to Traefik's range, keep `trustForwardHeader` off, keep `/_wap/verify` off the public router, and **never expose ports 8081 and 8082**.
  `RP_ORIGINS` is checked against the origin the browser signed, not against `Host` or `X-Forwarded-*`. Details: [docs/reverse-proxy.md](docs/reverse-proxy.md).

## Limitations

- **Browser only.** Signing in needs an interactive browser (passkey prompt and redirects). Native and mobile apps, API clients, WebDAV/CalDAV and Vaultwarden-style clients cannot sign in and get `401`.
  For apps that speak OIDC, prefer an identity provider such as Pocket ID.
- **Stateless cookies.** A session is a signed cookie: revocation is **per user** ("sign out everywhere"), not per session, and a stolen cookie works until `SESSION_TTL` (12 h by default) or until the user signs out.
  Rotate the key without signing anyone out with `SESSION_SECRET_PREVIOUS`; dropping the old key signs everybody out; passkeys are not affected. [Details](docs/security.md#session-tokens-hmac-signed-cookies).
- **No remote account recovery.** If every passkey is lost, you recover from the host: move `users.json` aside, rotate the session key, enroll again with the bootstrap token.
  **Enroll at least two passkeys** on different authenticators. [Procedure](docs/enrollment.md#account-recovery-lost-passkeys).
- **New, unaudited, one maintainer.** First commit 2026-10-14. Rate limiting and the audit log are minimal (per process, in memory), a single instance (no high availability), no per-site rules: any enrolled passkey opens every listed site.

## When not to use it

- Your apps speak OIDC: use an identity provider (Pocket ID, Authelia).
- Native clients, APIs, WebDAV or mobile apps must keep working through the same hostnames.
- You need several users with groups, per-site rules or delegated administration.
- The environment is critical or must be audited, or you need high availability, per-session revocation or IP/device binding.
- You only need nginx `auth_request`: [Quiq/webauthn_proxy](https://github.com/Quiq/webauthn_proxy) has been maintained since 2022 (see below).

## Why

**This is not the first passkey gate.** [Quiq/webauthn_proxy](https://github.com/Quiq/webauthn_proxy) has existed since 2022-01-03 (nginx `auth_request`, last commit 2026-08-18) and
[passkey-forwardauth](https://github.com/QirunGao/passkey-forwardauth) (forward-auth, since 2026-04-17) is close to this project. Dated list, sources and details: [docs/alternatives.md](docs/alternatives.md).

| | this repo | Quiq/webauthn_proxy | passkey-forwardauth |
|---|---|---|---|
| Relays traffic to an upstream itself | ✅ | ❌ | ❌ |
| Traefik `forwardAuth` | ✅ tested end to end | not documented | ✅ |
| One login for **unrelated domains** | ✅ | ❌ one cookie domain | ❌ one cookie domain |
| Username-less login | ✅ | ❌ | ✅ |
| Enrolling | passkey-protected page, or static tool + import without restart | page → paste into `credentials.yml` → restart | loopback bootstrap admin |
| Sessions | signed cookie, revoked per user | signed cookie | server-side, per-session revocation |
| Rate limiting | ✅ login and enrolment, per client and global | ❌ | bootstrap only |
| Image / tests | GHCR from CI / unit + e2e | Docker Hub / none in repo | `.deb`/`.rpm` / unit |
| Time in use | first commit 2026-10-14 | since 2022-01-03 | since 2026-04-17 |

**Added here:** a built-in proxy mode, login across unrelated domains with a list of allowed sites, username-less login, an enrollment path that needs no restart, and an end-to-end suite with a real Traefik.
**Missing here:** per-session revocation, server-side sessions, and above all time in use.

### Identity platforms do a different job

**Pocket ID, Tinyauth and Authelia are good projects, and they do a different job.** They are identity and SSO platforms:
users and groups, OIDC for your apps, access rules per site, admin interfaces, mature and widely used.
webauthnproxy is a gate. It answers one question, *"does this visitor hold a registered passkey?"*, for one or many sites.
If you need the former, use them. If you only need the latter, you should not have to run two or three services and a database for it.

What the official documentation says (read on 2026-10-14):

- **Traefik** has [no passkey plugin](https://community.traefik.io/t/fido2-passkey-integration-with-traefik/19396).
- **[Pocket ID](https://github.com/pocket-id/pocket-id)** supports passkeys only, and "only provides OpenID Connect, so it can't protect an app that has no OIDC support by itself":
  you put an authentication proxy in front, such as Tinyauth, caddy-security or OAuth2 Proxy ([guide](https://pocket-id.org/docs/guides/proxy-services)).
- **[Tinyauth](https://github.com/tinyauthapp/tinyauth)** is that proxy: forward-auth with [username/password (+ TOTP), LDAP and OpenID Connect](https://tinyauth.app/docs/reference/authentication/);
  it has no passkey support of its own and documents [Pocket ID as the way to get passkeys](https://tinyauth.app/docs/guides/pocket-id/).
  It sets its cookie "for the parent domain of the application URL" so that its apps are subdomains of it ([domain configuration](https://tinyauth.app/docs/getting-started/));
  its code refuses apps outside that domain (`domain does not match cookie domain`), which I reproduced with Tinyauth v5.2.0 behind Traefik on 2026-10-14
  ([experiment](docs/alternatives.md#experiment-one-login-for-two-unrelated-domains-with-tinyauth); Pocket ID was not part of that test).
- **[Authelia](https://www.authelia.com/overview/authentication/security-key/)** has passwordless passkey login since v4.39, but "the Passkey itself is a single factor": it may still ask for a password to enforce a `two_factor` policy
  (an experimental option lets a user-verified passkey satisfy it). Each [session cookie domain](https://www.authelia.com/configuration/session/introduction/) is paired with an `authelia_url` inside that domain,
  so unrelated domains mean separate portals and separate sign-ins.

| | webauthnproxy | Pocket ID + Tinyauth | Authelia |
|---|---|---|---|
| Containers to run | 1 | 2 (+ Traefik) | 1 (+ storage) |
| One login for **unrelated domains** | ✅ ticket exchange | ❌ one cookie domain (tested: Tinyauth v5.2.0) | one portal and sign-in per domain (from its documentation, not tested) |
| Built-in proxy (no Traefik/Caddy/Nginx needed) | ✅ | ❌ | ❌ |
| OIDC SSO for other apps | ❌ | ✅ | ✅ |
| Per-site rules, groups, several admins | ❌ | ✅ basic (Tinyauth per-app rules, Pocket ID groups) | ✅ |
| Maturity | new, unaudited | high | high |

**Choose them** for OIDC, groups, per-site rules, several administrators, or software that is widely used and audited.
**Choose this** for a personal or homelab setup: one passkey, many sites, nothing else to run.

## Development

```sh
make check   # gofmt, vet, tests (race)
make e2e     # Chromium + virtual passkey; Traefik in a container
make build   # ./webauthnproxy
make image   # container image
```

Performance measurements are an **experiment**, not a promise: how they were run and what they do and do not show is in [docs/performance.md](docs/performance.md) (`make bench`).

CI ([`ci.yml`](.github/workflows/ci.yml)) tests, then builds and pushes the image to `ghcr.io` on `main` and `v*` tags.
Setup and releases: [CONTRIBUTING.md](CONTRIBUTING.md#set-up-ci-and-publish-images). Vulnerabilities: [SECURITY.md](SECURITY.md).
Web UI is English; add `?lang=fr` for French.

MIT — [LICENSE](LICENSE)
