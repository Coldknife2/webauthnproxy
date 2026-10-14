# Prior art and alternatives

[← README](../README.md)

Checked on **2026-10-14**. Dates and versions come from each repository's commit history and tags (cloned that day); behavior comes from its README, configuration files and source code.
Where something could not be confirmed, it says so. These projects evolve: re-check before deciding.

## Passkey gates: the same job

Small services that put a passkey login in front of other sites.

| Project | What it is | Integration | Commits (first → last) | License |
|---|---|---|---|---|
| [**Quiq/webauthn_proxy**](https://github.com/Quiq/webauthn_proxy) (Go, v0.6) | described as a "standalone reverse-proxy for passwordless Webauthn authentication"; in practice an auth backend (`/webauthn/auth`, `/webauthn/login`, `/webauthn/verify`) | nginx `auth_request`, OpenResty (+ OAuth2 Proxy); Traefik is not documented | 2022-01-03 → 2026-08-18, 70 commits, 7 tags | Apache-2.0 |
| [**QirunGao/passkey-forwardauth**](https://github.com/QirunGao/passkey-forwardauth) (Go, v0.2.0) | forward-auth service with discoverable credentials and server-side sessions | any forward-auth reverse proxy | 2026-04-17 → 2026-07-16, 4 commits | Apache-2.0 |
| [trbroyles1/passkey-authenticator](https://github.com/trbroyles1/passkey-authenticator) (Python) | single-file HTTP reverse proxy with passkey login, JWT sessions, rate limiting, CSRF protection, multi-user | built-in proxy | 2025-10-10 → 2025-11-19, 8 commits | MIT |
| [andrew-d/homeauth](https://github.com/andrew-d/homeauth) (Go) | small identity provider for homelabs: WebAuthn or magic-link login, OIDC, single JSON file. Its README warns it is "not yet considered secure" | OIDC, nginx `auth_request`, Caddy/Traefik `forward_auth` | 2024-09-02 → 2025-06-20, 74 commits | Apache-2.0 |
| [mguinness/NginxWebAuthn](https://github.com/mguinness/NginxWebAuthn) (ASP.NET Core) | WebAuthn for nginx `auth_request`; Docker Hub image | nginx | 2025-02-28 → 2025-03-05, 4 commits | MIT |
| [newhouseb/nginxwebauthn](https://github.com/newhouseb/nginxwebauthn) | single-user WebAuthn in front of an nginx host (NginxWebAuthn above is a port of it) | nginx | 2019-05-23, 1 commit | none found |
| [ashishbhatiya18/homelab: webauthn-proxy](https://github.com/ashishbhatiya18/homelab/tree/main/webauthn-proxy) | passkey forward-auth for Traefik with discoverable credentials, JSON file, encrypted cookies, audit log; a folder of a personal homelab repository, described in [a blog post of 2026-06-02](https://ab18.in/blog/oauth2-proxy-to-webauthn-passkey-auth/) | Traefik `forwardAuth` | not checked | not checked |

### The closest ones, side by side

| | **this repo** | Quiq/webauthn_proxy | QirunGao/passkey-forwardauth |
|---|---|---|---|
| Relays traffic to an upstream itself | ✅ (`MODE=proxy`, WebSockets included) | ❌ auth backend only | ❌ forward-auth only |
| Traefik `forwardAuth` | ✅ tested against a real Traefik in the e2e suite | not documented (nginx/OpenResty) | ✅ any forward-auth proxy |
| **One login for unrelated domains** | ✅ ticket exchange + `ALLOWED_HOSTS` | ❌ one `cookieDomain` | ❌ one `cookie_domain` (+ a redirect allowlist) |
| Username-less login (discoverable credentials) | ✅ | ❌ the user name is entered | ✅ |
| Enrolling | automatic page protected by existing passkeys (bootstrap token for the first), **or** static HTML tool + JSON file imported without a restart | `/webauthn/register` shows a credential to paste into `credentials.yml`, then restart | temporary bootstrap admin on loopback |
| Sessions | signed stateless cookie; sign-out revokes **per user** | signed/encrypted cookie (gorilla), secrets list allows key rotation | **server-side**: per-session revocation, idle timeout, User-Agent/IP checks |
| Rate limiting | ❌ | none found in the code | ✅ on bootstrap enrollment only |
| Trust in `X-Forwarded-*` headers | trusted from any caller; relies on network placement ([reverse-proxy.md](reverse-proxy.md)) | not examined | trusted only from configured proxy CIDRs that also present a shared-secret header |
| Distribution | multi-arch container image built and pushed to GHCR by the CI workflow (first publication pending at the time of writing) | Docker Hub image (per its README) | `.deb`/`.rpm` + systemd unit (no container image found) |
| Automated tests | unit + e2e (Chromium with a virtual authenticator, real Traefik) | none in the repository | unit tests |
| Age | first commit 2026-10-14 | first commit 2022-01-03 | first commit 2026-04-17 |

**What this repo adds** to Quiq/webauthn_proxy: a built-in reverse proxy, Traefik forwardAuth tested end to end, login across unrelated domains with an allowlist of sites, username-less login,
an enrollment page protected by passkeys and an import path that needs no restart, a container image published by CI, and automated tests including a real-browser suite.

**What it lacks** compared with them: per-session revocation, idle timeout and client binding (passkey-forwardauth), rate limiting, trusting forwarded headers only from configured proxies (passkey-forwardauth),
key rotation without signing everybody out (Quiq), `.deb`/`.rpm` packaging, and, most of all, **time in use**: Quiq's project has been maintained since 2022, this one is new and unaudited.

## Identity platforms: a different job

[Pocket ID](https://github.com/pocket-id/pocket-id) + [Tinyauth](https://github.com/tinyauthapp/tinyauth), and [Authelia](https://www.authelia.com/): users, groups, OIDC for your apps, access rules, admin interfaces.
The comparison, with the quotes from their official documentation, is in the [README](../README.md#why). They are the better choice when you need that.

### Experiment: one login for two unrelated domains with Tinyauth

Claim to check: Tinyauth sets its cookie for the parent domain of its own URL, so a site on an unrelated domain cannot share the login.
`test/compare/tinyauth-crossdomain.cjs` runs the official image behind a real Traefik and drives Chromium:

| Tinyauth | Traefik | Date |
|---|---|---|
| v5.2.0 (`ghcr.io/tinyauthapp/tinyauth:v5`) | v3 | 2026-10-14 |

1. `x.test.local` (same parent domain as the login host `auth.test.local`): login works, the site is served. The session cookie has `domain=.test.local`.
2. `a.siteone.test` (unrelated domain) while signed in: **not served**; Tinyauth sends the browser to its `/error` page.
3. Logging in again with `redirect_uri` pointing at that site: Tinyauth shows *"Untrusted redirect: You are trying to redirect to a domain that does not match your configured domain (.test.local)"*; clicking *Continue* ends on `/error`.

Scope of this test: it used a local Tinyauth user, because the cookie scope belongs to Tinyauth, not to the identity source. **Pocket ID was not part of the test.**
Authelia was not tested: its behavior is taken from [its documentation](https://www.authelia.com/configuration/session/introduction/) (each session cookie domain is paired with an `authelia_url` inside that domain).

## Not verified

- Maintenance, license and language of `ashishbhatiya18/homelab: webauthn-proxy` beyond its README and blog post.
- Whether Quiq/webauthn_proxy works behind Traefik's `forwardAuth` (it exposes `/webauthn/auth`; nothing in its documentation covers Traefik).
- Behavior of the other projects was read from their documentation and code, not run, except where stated.
- The list is not exhaustive: it is what two rounds of web searches and the repositories' own links surfaced on the date above.
