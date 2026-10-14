# forwardAuth mode (Traefik)

[← README](../README.md)

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
- **Sign-out revokes everything.** Signing out on the login host (the *Sign out* button of `https://auth.com/`) or sending
  `POST https://anysite.com/_wap/logout` bumps the user's session generation: every cookie and ticket issued before, on any site or device, stops working immediately,
  even if someone copied it. A `GET` on `/_wap/logout` only clears the cookie of that site (a link on a hostile page cannot sign you out everywhere).
  Revocation is per user, not per session. The `/_wap/` prefix is reserved on protected sites too.
- `/_wap/verify` must only be reachable by Traefik: exclude it from the login host's public router. There are no per-site rules: any enrolled passkey grants access to **all** listed sites.
- Threat model, what is tested and what is not: [security.md](security.md#cross-domain-login-threat-model). Traefik headers and exposure: [reverse-proxy.md](reverse-proxy.md).
