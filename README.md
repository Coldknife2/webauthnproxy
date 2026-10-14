# webauthnproxy

🇬🇧 English · 🇫🇷 [Français](README.fr.md)

[![CI](https://github.com/coldknife2/webauthnproxy/actions/workflows/ci.yml/badge.svg)](https://github.com/coldknife2/webauthnproxy/actions/workflows/ci.yml)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Protect any self-hosted site with a *passkey* (WebAuthn) login, using a single container and one JSON file.**

No passwords, no directory, no OIDC provider to deploy. Put it in front of a site as a reverse proxy, or behind Traefik as a
`forwardAuth` service that protects several sites at once.

> **Languages:** logs, errors and web pages are in English. The web pages also have a French translation: add `?lang=fr` to any page URL (the choice is remembered by the browser). Other languages can be added in `web/i18n.js` (see [CONTRIBUTING.md](CONTRIBUTING.md)).

## Table of contents

- [Features](#features)
- [How it works](#how-it-works)
- [Quick start](#quick-start)
- [Container images](#container-images)
- [Operating modes](#operating-modes)
- [Enrolling passkeys](#enrolling-passkeys)
- [Configuration](#configuration)
- [Security model](#security-model)
- [Why this project? Alternatives](#why-this-project-alternatives)
- [Troubleshooting](#troubleshooting)
- [Development](#development)
- [Contributing, security, license](#contributing-security-license)

## Features

- 🔐 **Passkey-only** login, no username to type (discoverable credentials), user verification (PIN / biometrics) required by default.
- 🔁 Two modes: built-in **proxy** (with or without Traefik, WebSockets included) or Traefik **forwardAuth** (one deployment, many sites, **on any domains**: `auth.com` protects `anysite.com` through a shortlist of allowed hosts).
- ➕ Two ways to **enroll** passkeys, enabled independently: automatic enrollment protected by existing passkeys, or a static HTML tool plus a manual JSON import.
- 🗃️ **The database is one JSON file** (public keys only), written atomically.
- 📦 **Distroless** image, non-root user, ~13 MB; a few hundred lines of Go to audit.
- ✅ Tested end to end: Chromium with a virtual authenticator and a real Traefik.

## How it works

```
Proxy mode        User ──► (Traefik) ──► webauthnproxy ──► website
                                          │ valid session? otherwise redirect to /_wap/login
                                          └ forwards the request + X-Authenticated-User

forwardAuth mode  User ──► Traefik ──(1) GET /_wap/verify──► webauthnproxy
                             │  (2) 2xx: the request continues ──► website
                             └──── otherwise: redirect to login (browser) or 401
```

1. A user without a session is redirected to the login page (`/_wap/login`).
2. The browser asks for the passkey; the server verifies the signature.
3. A signed session cookie (`wap_session`, HttpOnly, SameSite=Lax) is set and the user returns to the requested page.

The protected site must **not** be reachable any other way than through the proxy (no published port, no direct Traefik router in proxy mode).

## Quick start

You will protect a demo site with a passkey login. The **protected site** is whatever `UPSTREAM` points to; here it is
[`traefik/whoami`](https://github.com/traefik/whoami), a tiny site that prints the request headers it receives, which lets you see the
`X-Authenticated-User` header added by webauthnproxy.

```
Browser ──► http://localhost:8080 ──► webauthnproxy ──► whoami:80
                                      (passkey login)    (the protected site: not published, reachable only through the proxy)
```

The commands work with docker; for podman replace `docker` by `podman` (and see the notes below each step).

**1. Start the site to protect** (note: no `-p`: it is *not* reachable from outside)

```sh
docker network create wap
docker run -d --name whoami --network wap docker.io/traefik/whoami
```

**2. Start webauthnproxy in front of it**

```sh
mkdir -p data && sudo chown 65532 data     # the image runs as uid 65532; rootless podman: podman unshare chown 65532:65532 data
docker run -d --name webauthnproxy --network wap \
  -p 8080:8080 -p 127.0.0.1:8081:8081 -v "$PWD/data:/data" \
  -e UPSTREAM=http://whoami:80 \
  -e RP_ID=localhost -e RP_ORIGINS=http://localhost:8080,http://localhost:8081 \
  -e ENROLL_ENABLED=true \
  ghcr.io/coldknife2/webauthnproxy:latest
```

`UPSTREAM` is the protected site (`whoami` is resolved on the shared `wap` network). Port `8080` is the protected entry point, `8081` the enrollment page
(bound to localhost only). With podman and SELinux, add `:Z` to the volume. See [Container images](#container-images) for tags and other ways to install.

**3. Enroll your first passkey**

```sh
docker logs webauthnproxy      # look for: "Enrollment bootstrap token: …"
```

Open <http://localhost:8081>, paste the **bootstrap token**, type a user name (e.g. `remi`) and create the passkey.

**4. Use the protected site**

Open <http://localhost:8080>: you are asked for your passkey, then whoami's page appears, including `X-Authenticated-User: remi`.
Without the passkey, `whoami` cannot be reached at all.

**5. Close enrollment** once your passkeys are enrolled: recreate the container *without* `-e ENROLL_ENABLED=true` (the data stays in `./data`).

**Protect your own site instead**: set `UPSTREAM` to its URL (any address reachable from the container: another container on the same network,
`http://host.docker.internal:3000`, a LAN address…). In production use HTTPS, set `RP_ID` to your domain and `RP_ORIGINS` to the public URL,
and put Traefik in front: see [`docker-compose.example.yml`](docker-compose.example.yml) (proxy mode) and
[`docker-compose.forwardauth.example.yml`](docker-compose.forwardauth.example.yml) (one deployment protecting several sites).

## Container images

Images are built and published by [GitHub Actions](.github/workflows/ci.yml) to the GitHub Container Registry, for `linux/amd64` and `linux/arm64`,
only after the tests pass:

```sh
docker pull ghcr.io/coldknife2/webauthnproxy:latest
docker run --rm ghcr.io/coldknife2/webauthnproxy:latest --version
```

| Tag | Meaning |
|---|---|
| `latest`, `main` | latest commit of the `main` branch |
| `sha-<commit>` | a specific commit |
| `1.2.3`, `1.2`, `1` | releases (git tag `v1.2.3`); pin one of these in production |

**Install with Docker Compose**

```yaml
services:
  webauthnproxy:
    image: ghcr.io/coldknife2/webauthnproxy:latest   # or a pinned version, e.g. :1.2.3
    restart: unless-stopped
    environment:
      UPSTREAM: http://mysite:80          # the site to protect
      RP_ID: example.com
      RP_ORIGINS: https://app.example.com
    volumes:
      - ./data:/data                      # chown 65532 ./data first
```

**Update**: `docker pull ghcr.io/coldknife2/webauthnproxy:latest`, then recreate the container (`docker compose pull && docker compose up -d`).
Your data (`/data`) is kept in the volume.

**Build from source** instead of pulling: `git clone https://github.com/coldknife2/webauthnproxy && cd webauthnproxy && docker build -t webauthnproxy .`
(then use `webauthnproxy` as the image name above).

If `docker pull` answers `denied`, the package has not been made public yet: see [CONTRIBUTING.md](CONTRIBUTING.md#releasing-and-publishing-images).

## Operating modes

### Proxy mode (`MODE=proxy`, default)

The service receives the traffic and relays it to `UPSTREAM`. For an authenticated request:

- the `X-Authenticated-User` header (renamable with `USER_HEADER`) carries the user; any value sent by the client is overwritten;
- the session cookie is **not** forwarded to the site;
- `Host` is rewritten to the upstream's (`PRESERVE_HOST=true` keeps the client's); `X-Forwarded-*` is set.

Suited to a single site, with or without Traefik. The `/_wap/` prefix is reserved for the service.

### forwardAuth mode (`MODE=forward`)

The service relays nothing: Traefik queries `/_wap/verify` for every request and either lets it through (2xx) or returns the service's
response (a redirect to the login host for browsers, `401` otherwise). **A single deployment protects as many sites as you like**, even on
unrelated domains: `auth.com` can protect `anysite.com`, `other.org`, `app.example.net`…

```yaml
# reusable middleware (declared once, e.g. on the webauthnproxy container)
- traefik.http.middlewares.passkey.forwardauth.address=http://webauthnproxy:8080/_wap/verify
- traefik.http.middlewares.passkey.forwardauth.authResponseHeaders=X-Authenticated-User
# on each router to protect, whatever its domain
- traefik.http.routers.mysite.middlewares=passkey
```

**Why not simply a shared cookie?** A browser never sends the cookie of `auth.com` to `anysite.com`. Cookies can only be shared between
subdomains of one parent domain. For the general case, the login host therefore hands the user over to each site with a short-lived
**ticket**, and each site gets its **own** cookie:

```
1. Browser ─► anysite.com/page ─► Traefik ─► /_wap/verify: no cookie for this site
              └─► 302 https://auth.com/_wap/sso?next=https://anysite.com/page
2. auth.com: not signed in yet ─► passkey login (once)
3. auth.com ─► 302 https://anysite.com/_wap/callback?ticket=…     ticket: signed, single-use, valid 60 s, for anysite.com only
4. Traefik ─► /_wap/verify (callback) ─► sets a cookie for anysite.com only ─► 302 /page
5. Next requests: /_wap/verify checks that cookie.  Another site (other.org): steps 1, 3, 4 again, without a new passkey prompt.
```

**Shortlist of sites: `ALLOWED_HOSTS`.** Only the sites you list can use the login; any other host is refused (`403`) even if a Traefik
router sends it through the middleware, and the post-login redirect can only go to a listed site.
Entries (comma-separated): `anysite.com` (any port), `anysite.com:8443` (that port only), `*.example.org` (any subdomain, **not** `example.org` itself).

```sh
LOGIN_URL=https://auth.com/_wap/login      # public URL of the login page (the only place passkeys are used)
ALLOWED_HOSTS=anysite.com,other.org,*.example.net
RP_ID=auth.com                             # passkeys belong to the login host's domain, not to the protected sites
RP_ORIGINS=https://auth.com
```

**Optional shortcut: `COOKIE_DOMAIN`.** When the login host and the sites share a parent domain (`auth.example.com`, `app.example.com`),
set `COOKIE_DOMAIN=example.com`: the login cookie is then shared by all its subdomains (they are allowed automatically) and the ticket round trip is skipped
for them. You can combine both: sites inside `COOKIE_DOMAIN` use the shared cookie, the others the ticket exchange.

Security properties of the exchange:

- Tickets are HMAC-signed, expire after 60 s, are accepted **once**, and only for the host they were issued for.
- A site's cookie is **bound to its host**: if one protected site's backend leaks the cookie it receives (Traefik forwards cookies), it is useless on any other site.
- Users deleted from the database lose access on the very next request, on every site.
- `https://anysite.com/_wap/logout` signs out of that site (clears its cookie). Signing out of the login host does **not** revoke cookies already issued to sites;
  they remain valid until `SESSION_TTL` expires, so choose it accordingly. The `/_wap/` prefix is reserved on protected sites too.
- `/_wap/verify` must only be reachable by Traefik (internal network). There are no per-site rules: any enrolled passkey grants access to **all** listed sites.

## Enrolling passkeys

A passkey is bound to a **domain** (`RP_ID`): the browser refuses to create one for a domain other than the page's (or one of its parents), and
refuses insecure contexts outside `localhost`. Two tools, enabled independently:

| | **Automatic** enrollment | **Static** tool + manual import |
|---|---|---|
| Enable with | `ENROLL_ENABLED=true` | `TOOL_ENABLED=true` |
| Port | `8081` (`ENROLL_LISTEN`) | `8082` (`TOOL_LISTEN`) |
| Access | **protected**: sign in with an existing passkey | none needed: the page has no state and no write access |
| Recommended exposure | private (defense in depth) | may be public |
| Adding a passkey | instant, from the page | an administrator copies a JSON file into `DATA_DIR/import/` |
| First passkey | bootstrap token (logs) | no token needed |

### Automatic enrollment (port 8081)

The page `http(s)://<host>:8081/` lets you add and delete passkeys.

- **Protected by existing passkeys**: without a session it redirects to its own login page; the API answers `401`.
- **Bootstrap**: while no passkey exists, a **one-time bootstrap token** is generated and written to the logs at startup; it must be entered
  to create the first passkey. As soon as a passkey exists, the token stops working.
- Writes require the `X-Requested-With` header (CSRF protection). The **last passkey cannot be deleted** (no lock-out).
- Any signed-in user can create new users and passkeys: all users are administrators.
- This page's URL must be listed in `RP_ORIGINS` and lie under the `RP_ID` domain.
- A host's cookie is shared across ports: on the same hostname, being signed in to enrollment also grants access to the proxy.

### Static tool (port 8082) and manual import

To enroll **without exposing any write API**: a standalone HTML page ([`web/tool.html`](web/tool.html)) that contacts no server.

1. Open the tool (`http(s)://<host>:8082/`, domain pre-filled with `RP_ID`), enter a name and click **Create the passkey**.
2. The tool shows a **JSON file** (public key and metadata, no secret): download it.
3. Copy it **by hand** into the proxy's import folder: `cp remi-example.com.json data/import/`
   (with a container: `podman cp remi-example.com.json webauthnproxy:/data/import/`).
4. Within seconds the proxy validates and imports the file, then renames it to `.imported` (or `.rejected`, with the reason in the logs).

The page must be served over **HTTPS under the `RP_ID` domain** (e.g. `https://tool.example.com`), or on `localhost` with `RP_ID=localhost`:
**a file opened directly (`file://`) does not work**; this is a browser rule. The tool's origin does not need to be in `RP_ORIGINS`.
The tool can also be hosted as-is (it is a single file) on any static site under the same domain.

What the proxy **checks** on import: format version, passkey created for the right domain (`rpIdHash`), user presence/verification flags, valid COSE
public key, consistent credential ID, user ID consistent with the name, no duplicate. Format (version 1):

```json
{
  "version": 1,
  "rpId": "example.com",
  "user": { "id": "<base64url>", "name": "remi" },
  "credential": { "id": "<base64url>", "authenticatorData": "<base64url>", "transports": ["internal"] }
}
```

The `import/` folder is watched continuously: **only someone who can write to the data volume can add a passkey this way**.
To add a second device to a user, run the tool again with the **same name**.

### Losing all passkeys

Stop the service, delete `data/users.json`, restart with `ENROLL_ENABLED=true`: a new bootstrap token is printed in the logs.
(Or drop a file produced by the static tool into `data/import/`.)

## Configuration

Everything is set through environment variables.

| Variable | Default | Description |
|---|---|---|
| `MODE` | `proxy` | `proxy` or `forward` (Traefik forwardAuth) |
| `UPSTREAM` | – | **Proxy mode.** URL of the site to protect (`http://mysite:80`) |
| `LOGIN_URL` | – | **Forward mode.** Public URL of the login page |
| `ALLOWED_HOSTS` | – | **Forward mode.** Shortlist of sites allowed to use the login: `host`, `host:port`, `*.domain`, comma-separated |
| `COOKIE_DOMAIN` | – | **Forward mode, optional.** Parent domain shared with the login host (`example.com`); its subdomains are allowed automatically. Forward mode needs `ALLOWED_HOSTS` and/or `COOKIE_DOMAIN` |
| `RP_ID` | – (required) | WebAuthn domain: the domain of the page where passkeys are used, or a parent (`example.com`, `localhost`). In forward mode this is the login host's domain |
| `RP_ORIGINS` | – (required) | Origins allowed for login/enrollment, comma-separated (public URL, no trailing `/`) |
| `RP_NAME` | `WebAuthn Proxy` | Name shown by the authenticator |
| `LISTEN` | `:8080` | Proxy / `/_wap/verify` port |
| `ENROLL_ENABLED` | `false` | Enable automatic enrollment |
| `ENROLL_LISTEN` | `:8081` | Automatic enrollment port |
| `TOOL_ENABLED` | `false` | Enable the static enrollment tool |
| `TOOL_LISTEN` | `:8082` | Static tool port |
| `DATA_DIR` | `/data` | `users.json`, `session.key`, `import/` folder (mount as a volume) |
| `SESSION_SECRET` | generated | Cookie-signing secret (≥ 16 characters); otherwise generated in `DATA_DIR/session.key` |
| `SESSION_TTL` | `12h` | Session lifetime |
| `USER_VERIFICATION` | `required` | `preferred` to accept authenticators without PIN/biometrics |
| `PRESERVE_HOST` | `false` | Proxy mode: forward the client's `Host` to the upstream |
| `USER_HEADER` | `X-Authenticated-User` | Header carrying the user |

Ports: only `8080` should be publicly exposed (through Traefik); keep `8081` private; `8082` is harmless but pointless outside enrollment phases.

## Security model

**What is guaranteed**

- No request reaches the site without a valid session cookie (HMAC-SHA256 signed, expiring, invalidated if the user is deleted).
- Login: single-use challenge (5 min), origin and domain verified, signature counter updated, user verification required.
- Cookie is `HttpOnly`, `SameSite=Lax`, and `Secure` whenever access is over HTTPS; pages are served with a restrictive CSP.
- The post-login redirect (`next`) is limited to local paths, or in forward mode to the sites in `ALLOWED_HOSTS` / `COOKIE_DOMAIN`: no open redirect.
- Forward mode across domains: single-use 60-second tickets, per-host cookies bound to their site, requests for unlisted hosts refused (see [forwardAuth mode](#forwardauth-mode-modeforward)).
- Automatic enrollment: session required, bootstrap token compared in constant time, CSRF protection, the last passkey cannot be deleted.
- Import: the file is untrusted and fully revalidated (see above), with a size limit.
- Static tool: no writes, hash-based CSP (`script-src 'sha256-…'`, no `unsafe-inline`).
- The database holds **public keys only**; only `session.key` is secret (leaking it allows forging sessions).

**Assumptions and limits**

- TLS is terminated upstream (Traefik); without HTTPS WebAuthn does not work outside `localhost`.
- No rate limiting, audit log, per-site rules or high availability (single instance, ceremonies kept in memory): complete these at the reverse proxy.
- User handles are derived from the name (SHA-256) so the same name always designates the same user whichever enrollment tool is used.
- One root domain per instance (`RP_ID`).

To report a vulnerability, see [SECURITY.md](SECURITY.md).

## Why this project? Alternatives

**Need**: put *passkey-only* authentication in front of one or several self-hosted sites (behind Traefik or not), with the bare minimum: one
container, one JSON file, no directory, no password, no OIDC provider to deploy, and an enrollment that can be switched off.

**Prior research** (as of 2026-10-14; sources at the end of this section):

- **Traefik plugin**: no WebAuthn/passkey plugin found in the [catalog](https://plugins.traefik.io) or on the
  [community forum](https://community.traefik.io/t/fido2-passkey-integration-with-traefik/19396), where the request went unanswered natively
  (suggested route: ForwardAuth). Existing authentication plugins do basic auth/mTLS ([trauth](https://github.com/leonjza/trauth)), JWT, OIDC or LDAP.
  Plugins also run in an interpreter (Yaegi) with no storage or ceremony state, which suits WebAuthn poorly.
- **[Pocket ID](https://github.com/pocket-id/pocket-id)**: an OIDC/OAuth 2.0 provider supporting **passkeys only** (BSD-2). It is an *identity
  provider*, not a proxy: applications must speak OIDC. Its official guide for apps without OIDC points to a third-party authentication proxy
  (Tinyauth, caddy-security, OAuth2 Proxy or Traefik forward auth) ([guide](https://pocket-id.org/docs/guides/proxy-services), read through a search excerpt).
- **[Tinyauth](https://github.com/tinyauthapp/tinyauth)**: an authentication middleware for Traefik, Nginx and Caddy (AGPL-3.0); cited methods:
  OAuth/OIDC, LDAP, access control, TOTP. Its README mentions **neither passkeys nor WebAuthn**; a
  [discussion](https://github.com/tinyauthapp/tinyauth/discussions) asking for passkey login (Feb 2026) exists, with no maintainer answer I could confirm.
- **Authelia / Authentik**: full solutions (SSO portal, policies, directories), heavier to operate (Authentik needs PostgreSQL; not re-verified in detail here).

**Conclusion**: *Pocket ID + Tinyauth (or OAuth2 Proxy) + Traefik* already provides passkeys through forwardAuth, with real advantages (OIDC SSO, admin UI,
multi-user, community maintenance). But that is **three components** and goes through OIDC. webauthnproxy targets the smaller case:
**one container, no OIDC, no other dependency**, a few hundred lines of Go to audit.

| Need | webauthnproxy | Pocket ID + Tinyauth | Authelia / Authentik |
|---|---|---|---|
| Passkey as the only method | ✅ | ✅ (via Pocket ID) | ✅ (among others) |
| Components to deploy | 1 | 2 (+ Traefik) | 1 to 3 |
| Storage | JSON file | database | database |
| OIDC SSO for other apps | ❌ | ✅ | ✅ |
| Per-site policies / groups | ❌ | partial (Tinyauth) | ✅ |
| Works without Traefik (built-in proxy) | ✅ | ❌ | ❌ |
| Maturity / community | low (new) | high | high |

**Pick something else if** you need SSO for several applications, groups/per-site policies, accounts managed by several administrators, or a widely
audited project. Pocket ID + Tinyauth is then the recommended route.

*Research limits*: the official sites (tinyauth.app, docs.pocket-id.org) were unreachable from the working environment; the information comes
from GitHub repositories and third-party pages. Re-check before deciding: these projects evolve quickly.

Sources: [Pocket ID](https://github.com/pocket-id/pocket-id) ·
[Pocket ID proxy guide](https://pocket-id.org/docs/guides/proxy-services) ·
[Tinyauth](https://github.com/tinyauthapp/tinyauth) ·
[comparison](https://sumguy.com/tinyauth-vs-pocket-id-vs-authelia/) ·
[Traefik community thread](https://community.traefik.io/t/fido2-passkey-integration-with-traefik/19396) ·
[Traefik plugin catalog](https://plugins.traefik.io)

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `SecurityError` when creating the passkey | The page is not on HTTPS (outside `localhost`), or `RP_ID` is not the page's domain / one of its parents. |
| "passkey rejected" at login | The login page URL is not in `RP_ORIGINS` (exact scheme, host **and port**), or the passkey was created for another `RP_ID`. |
| Import: `.rejected` | Read the logs: wrong domain, duplicate, missing user verification, inconsistent name/ID. |
| Import ignored | The file must end in `.json`; the container (uid 65532) must be able to read/write `data/import/`. |
| `permission denied` on `/data` | `chown 65532 data` (rootless podman: `podman unshare chown 65532:65532 data`). |
| `403 host not allowed` in forward mode | The site's host (and port) is not matched by `ALLOWED_HOSTS` / `COOKIE_DOMAIN`. Remember `*.example.org` does not match `example.org` itself. |
| `403 invalid or expired ticket` | The ticket was already used, is older than 60 s, or was issued for another host. Reload the page you wanted; check that `X-Forwarded-Host` reaches the service unchanged. |
| Redirect loop in forward mode | The browser rejects the site cookie: check that the site is reached over the same scheme Traefik reports (`X-Forwarded-Proto`), and that the `/_wap/callback` path is not intercepted by another router or middleware. |
| Can't find the bootstrap token | `podman logs webauthnproxy`, line "Enrollment bootstrap token". |

## Development

Requirements: Go (version in [`go.mod`](go.mod)); Node 22 and podman/docker for the e2e tests.

```sh
make check   # gofmt + go vet + go test -race
make e2e     # Chromium + virtual authenticator; forwardAuth mode against a real Traefik
make build   # ./webauthnproxy binary
make image   # container image
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the code layout. All WebAuthn cryptography is done by the
[`go-webauthn/webauthn`](https://github.com/go-webauthn/webauthn) library.

## Contributing, security, license

- Contributions welcome: [CONTRIBUTING.md](CONTRIBUTING.md) · [Code of conduct](CODE_OF_CONDUCT.md)
- Vulnerabilities: [SECURITY.md](SECURITY.md) · History: [CHANGELOG.md](CHANGELOG.md)
- License: [MIT](LICENSE)
