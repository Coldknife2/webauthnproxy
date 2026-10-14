# Behind a reverse proxy (Traefik)

[← README](../README.md)

## What the service trusts

| Mode | Headers read | Used for |
|---|---|---|
| `forward` | `X-Forwarded-Host` | which site is asking: `ALLOWED_HOSTS` check, audience of the site cookie and of tickets |
| | `X-Forwarded-Uri` | control paths (`/_wap/callback`, `/_wap/logout`) and the page to come back to after login |
| | `X-Forwarded-Proto` | scheme of the page to come back to, `Secure` flag of the site cookie |
| | `X-Forwarded-Method` | `POST /_wap/logout` signs out everywhere, other methods only clear the site cookie |
| | `Cookie`, `Accept` | the session; browser (redirect) or API client (`401`) |
| `proxy` | `Host`, `X-Forwarded-Proto` | `Secure` flag of the cookie; the upstream gets the usual `X-Forwarded-*` |

**`TRUSTED_PROXIES` decides whether these headers are believed.** The service believes `X-Forwarded-*` only when the TCP peer is inside `TRUSTED_PROXIES`
(comma-separated CIDRs or addresses, e.g. `172.18.0.0/16`); the default is empty, i.e. never. Forward mode refuses to start without it, and `/_wap/verify`
answers `403` (audit event `untrusted_proxy`) to any other caller, so a client that reaches the port directly cannot forge the host or scheme.
In proxy mode, forwarded headers from untrusted clients are removed before the request reaches the upstream. Details and tests: [security.md](security.md#trusted-proxies-and-forwarded-headers).

Traefik builds the `X-Forwarded-*` headers of the forwardAuth request itself, from the request it received
([Traefik forwardAuth reference](https://doc.traefik.io/traefik/reference/routing-configuration/http/middlewares/forwardauth/), read 2026-10-14).

**Keep Traefik's defaults.** The same page documents `trustForwardHeader` (deprecated): setting it to `true` makes Traefik trust *every* `X-Forwarded-*` header it receives.
Only do that if Traefik itself sits behind a proxy you control and `forwardedHeaders.trustedIPs` is set on the entry point; otherwise any client can forge the host and scheme.
`TRUSTED_PROXIES` protects this service from direct callers, not from a Traefik that forwards forged headers.

**Idle timeout (`SESSION_IDLE_TIMEOUT`).** The renewed cookie is sent back on the `/_wap/verify` response; Traefik only passes it to the browser with
`addAuthCookiesToResponse: [wap_session]` (label `traefik.http.middlewares.passkey.forwardauth.addAuthCookiesToResponse=wap_session`). Without it, the idle timeout still applies but is never renewed.

## WebAuthn origin validation (`RP_ORIGINS`)

The passkey ceremony is checked against `RP_ID` and `RP_ORIGINS` by the WebAuthn library: the origin comes from the signed client data the browser produced
(and the authenticator signs over the domain), **not from `Host` or `X-Forwarded-*`**. A forged `Host` cannot make a wrong origin pass.
Consequences when deploying:

- `RP_ORIGINS` must list every origin that shows a login or enrollment page, with exact scheme, host and port (behind Traefik on 443: `https://auth.example.com`, no port).
  A mismatch shows as `passkey rejected` ([troubleshooting](troubleshooting.md)).
- In forward mode the passkey is only used on the login host, so `RP_ID`/`RP_ORIGINS` describe that host, not the protected sites.

## What must be reachable, and from where

| Path / port | Who may reach it |
|---|---|
| `8080` login pages: `/_wap/login`, `/_wap/login/*`, `/_wap/sso`, `/_wap/logout`, static files, `/` | the public, through the login host's router |
| `8080` `/_wap/verify` (forward mode) | **Traefik only**, directly (`forwardauth.address=http://webauthnproxy:8080/_wap/verify`). Exclude it from the public router: ``Host(`auth.example.com`) && !PathPrefix(`/_wap/verify`)`` (tested in the e2e suite) |
| `8081` automatic enrollment | **never public.** Loopback or a private network only, and only while you enroll |
| `8082` static enrollment tool | **never public.** It holds no state and cannot grant access, but there is no reason to publish it; same rule as 8081 |

`/_wap/verify` does not authenticate its caller: it answers `200`/`302`/`401` for whatever headers it is given. Without a valid cookie nothing is revealed or granted,
but it is meant to be internal. (Some projects add a shared-secret header or a CIDR check for this; this one relies on network placement.)

To use the static tool on a real domain you need an HTTPS origin under `RP_ID`; serve it over a VPN or an IP-restricted router and remove it afterwards (see [enrollment.md](enrollment.md)).
