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
| Sessions | signed stateless cookie; sign-out revokes **per user**; stateless idle timeout; key rotation (`SESSION_SECRET_PREVIOUS`) | signed/encrypted cookie (gorilla), secrets list allows key rotation | **server-side**: per-session revocation, idle timeout, User-Agent/IP checks |
| Rate limiting | ✅ login and enrolment endpoints, per client address and global (in memory, per process) | none found in the code | ✅ on bootstrap enrollment only |
| Trust in `X-Forwarded-*` headers | trusted only from `TRUSTED_PROXIES` (CIDRs, required in forward mode, never by default); no shared secret ([reverse-proxy.md](reverse-proxy.md)) | not examined | trusted only from configured proxy CIDRs that **also present a shared-secret header** |
| Distribution | multi-arch container image built and pushed to GHCR by the CI workflow (first publication pending at the time of writing) | Docker Hub image (per its README) | `.deb`/`.rpm` + systemd unit (no container image found) |
| Automated tests | unit + e2e (Chromium with a virtual authenticator, real Traefik) | none in the repository | unit tests |
| Age | first commit 2026-10-14 | first commit 2022-01-03 | first commit 2026-04-17 |

**What this repo adds** to Quiq/webauthn_proxy: a built-in reverse proxy, Traefik forwardAuth tested end to end, login across unrelated domains with an allowlist of sites, username-less login,
an enrollment page protected by passkeys and an import path that needs no restart, a container image published by CI, and automated tests including a real-browser suite.

**What it lacks** compared with them: passkey-forwardauth's shared-secret check on the proxy, `.deb`/`.rpm` packaging, and, most of all, **time in use**:
Quiq's project has been maintained since 2022, this one is new and unaudited.

### Why this project rather than passkey-forwardauth?

[passkey-forwardauth](https://github.com/QirunGao/passkey-forwardauth) is the closest project. Read it first. Its server-side sessions (random token, hash stored, per-session revocation, idle limit, User-Agent and IP checks)
are the model this project's sessions were rebuilt on after a first comparison, so that gap is closed rather than a reason to choose either.

**Real differences in favor of this repo:**

1. **A built-in proxy mode.** `MODE=proxy` relays traffic to one upstream, so a site without Traefik, Caddy or nginx in front can be protected with one container. passkey-forwardauth only does forward-auth.
2. **One login for unrelated domains** through a host list (`ALLOWED_HOSTS`): `auth.com` can protect `anysite.com` and `other.org`. passkey-forwardauth shares one `cookie_domain`.
3. **Sessions that survive a restart** (saved to `sessions.json`; in passkey-forwardauth's code they live in memory only, as far as I read), a login/site tree ("sign out of this browser" versus "all devices"), a `sessions list|revoke` command, and a rate limit on every login endpoint (it limits bootstrap only).

**What passkey-forwardauth does better:**

- A shared-secret header on top of the trusted-proxy CIDRs, a `.deb`/`.rpm` and a systemd unit, a bootstrap that only listens on loopback, and User-Agent/IP binding that is always on (here it is opt-in, `SESSION_BIND`).
- It is older by six months (since 2026-04-17, against 2026-10-14 here): little, but more.

**Which one should you pick?**

- **One domain with subdomains, forward-auth with Traefik**: passkey-forwardauth or [Tinyauth](https://tinyauth.app) are enough. The cross-domain feature does not apply to you and the remaining differences are small. Either is a fair choice.
- **A site with no reverse proxy in front, or several unrelated domains** behind one Traefik: this is where this repo has a reason to exist. These are narrow cases.

These lines are about features read in the code and documentation on 2026-10-14 (sessions code re-read at commit 8f8c63b); passkey-forwardauth was not run for this comparison.

## Identity platforms: a different job

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
  ([experiment below](#experiment-one-login-for-two-unrelated-domains-with-tinyauth); Pocket ID was not part of that test).
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
