# Configuration

[← README](../README.md)

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
| `SESSION_SECRET` | generated | Cookie-signing secret, **32 characters minimum** (`openssl rand -base64 48`); otherwise 32 random bytes are generated in `DATA_DIR/session.key`. Changing it without `SESSION_SECRET_PREVIOUS` signs everybody out |
| `SESSION_SECRET_PREVIOUS` | – | Former signing keys, comma-separated, still accepted for verification so a rotation signs nobody out. Also read from `DATA_DIR/session.key.previous`. Remove them after `SESSION_TTL` |
| `SESSION_TTL` | `12h` | Absolute session lifetime |
| `SESSION_IDLE_TIMEOUT` | `0` (off) | Sign out after this long without activity (e.g. `30m`); shorter than `SESSION_TTL`. In forward mode add `addAuthCookiesToResponse=wap_session` to the Traefik middleware, otherwise active users are signed out too ([security.md](security.md#idle-timeout)) |
| `TRUSTED_PROXIES` | – | Addresses or CIDR ranges of the reverse proxies whose `X-Forwarded-*` headers are believed (`172.18.0.0/16,10.0.0.5`). **Empty by default: no header is trusted.** Required in forward mode |
| `COOKIE_SECURE` | `auto` | `auto`: `Secure` when the connection is HTTPS or a trusted proxy says so (and the login URL is https); `true` always; `false` never |
| `RATE_LIMIT_IP` | `20/1m` | Login and enrollment requests allowed per client address (`N/duration`, e.g. `60/1h`; `0` or `off` disables). Answers `429` with `Retry-After` |
| `RATE_LIMIT_GLOBAL` | `200/1m` | The same, for all clients together |
| `AUDIT_LOG` | `true` | Security events as JSON lines on standard output ([security.md](security.md#audit-log)); `false` disables |
| `USER_VERIFICATION` | `required` | `preferred` to accept authenticators without PIN/biometrics |
| `PRESERVE_HOST` | `false` | Proxy mode: forward the client's `Host` to the upstream |
| `USER_HEADER` | `X-Authenticated-User` | Header carrying the user |

Ports: only `8080` is meant to be reached by the public (through Traefik). **Never expose `8081` or `8082`**: loopback or a private network, and only while you enroll ([reverse-proxy.md](reverse-proxy.md)).

## Commands

`webauthnproxy` without argument starts the service. With an argument it is a client of the running service (same `DATA_DIR`):

| Command | |
|---|---|
| `passkeys list` | one line per passkey: short id, user, `synced`/`device-bound`, transports, uses |
| `passkeys revoke <id>` | delete a passkey and end its user's sessions; refuses the last passkey ([enrollment.md](enrollment.md#listing-and-revoking-passkeys)) |
| `signout <user>` | end every session of a user, keep the passkeys |
| `healthcheck` | exit status 0 when `GET /_wap/healthz` on `LISTEN` answers `200`; this is the image's `HEALTHCHECK` (no shell or curl in the image) |
| `--version` | print the version |

Run them in the container: `docker exec webauthnproxy /webauthnproxy passkeys list`.
`DATA_DIR/admin.sock` (mode `0600`) is the Unix socket they use ([security.md](security.md#local-administration-socket)).
