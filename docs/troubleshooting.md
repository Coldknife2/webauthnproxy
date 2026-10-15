# Troubleshooting

[← README](../README.md)

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
| `429 too many requests` | The login/enrollment rate limit (`RATE_LIMIT_IP`, `RATE_LIMIT_GLOBAL`). Behind a proxy, declare it in `TRUSTED_PROXIES`, otherwise every visitor shares the proxy's address and one budget. |
| `403 caller is not a trusted proxy` | `/_wap/verify` was called from an address outside `TRUSTED_PROXIES`: put Traefik's network range there (`docker network inspect <network>`). |
| Forward mode refuses to start: `needs TRUSTED_PROXIES` | Same: the service only believes `X-Forwarded-*` headers from declared proxies. |
| Everybody is signed out after an upgrade from a version that used signed cookies | Expected once: sessions are now stored on the server (`DATA_DIR/sessions.json`); users sign in again. |
| Can't find the bootstrap token | `podman logs webauthnproxy`, line "Enrollment bootstrap token". |
