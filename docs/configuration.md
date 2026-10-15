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
| `DATA_DIR` | `/data` | `users.json`, `sessions.json`, `import/` folder, `admin.sock` (mount as a volume) |
| `SESSION_MAX_PER_USER` | `50` | Sessions kept per user; beyond it the least recently used goes first (`0` = no limit). Stops one account from filling the table by signing in over and over |
| `SESSION_BIND` | – | `ua`, `ip` or `ua,ip`: a session only works with the User-Agent and/or client address it was opened with. Off by default (browser updates and mobile networks change them; see [security.md](security.md#sessions-server-side)) |
| `SESSION_TTL` | `12h` | Absolute session lifetime |
| `SESSION_IDLE_TIMEOUT` | `0` (off) | End a session after this long without activity (e.g. `30m`); shorter than `SESSION_TTL`. Exact, recorded on the server: no Traefik option needed ([security.md](security.md#idle-timeout)) |
| `TRUSTED_PROXIES` | – | Addresses or CIDR ranges of the reverse proxies whose `X-Forwarded-*` headers are believed (`172.18.0.0/16,10.0.0.5`). **Empty by default: no header is trusted.** Required in forward mode |
| `COOKIE_SECURE` | `auto` | `auto`: `Secure` when the connection is HTTPS or a trusted proxy says so (and the login URL is https); `true` always; `false` never |
| `RATE_LIMIT_IP` | `20/1m` | Login and enrollment requests allowed per client address (`N/duration`, e.g. `60/1h`; `0` or `off` disables). Answers `429` with `Retry-After` |
| `RATE_LIMIT_GLOBAL` | `200/1m` | The same, for all clients together |
| `AUDIT_LOG` | `true` | Security events as JSON lines on standard output ([security.md](security.md#audit-log)); `false` disables |
| `USER_VERIFICATION` | `required` | `preferred` to accept authenticators without PIN/biometrics |
| `PRESERVE_HOST` | `false` | Proxy mode: forward the client's `Host` to the upstream |
| `USER_HEADER` | `X-Authenticated-User` | Header carrying the user |

Ports: only `8080` is meant to be reached by the public (through Traefik). **Never expose `8081` or `8082`**: loopback or a private network, and only while you enroll ([reverse-proxy.md](reverse-proxy.md)).

`SESSION_SECRET` and `SESSION_SECRET_PREVIOUS` from earlier versions are ignored (sessions are server-side and unsigned); a warning is logged if they are set.

## Commands

`webauthnproxy` without argument starts the service. With an argument it is a client of the running service (same `DATA_DIR`):

| Command | |
|---|---|
| `passkeys list` | one line per passkey: short id, user, `synced`/`device-bound`, transports, uses |
| `passkeys label <id> <text>` | name a passkey (shown in `list` and on the enrolment page) |
| `passkeys add <user> [label]` | print a one-time link (15 minutes) to add a passkey from another device ([enrollment.md](enrollment.md#add-a-passkey-from-another-device-a-one-time-link)) |
| `passkeys revoke <id>` | delete a passkey and end its user's sessions; refuses the last passkey ([enrollment.md](enrollment.md#listing-and-revoking-passkeys)) |
| `signout <user>` | end every session of a user, keep the passkeys |
| `sessions list` | one line per live session: short id, user, site, creation, last activity, User-Agent |
| `sessions revoke <id>` | end one session (prefix of 4+ characters of the id) |
| `healthcheck` | exit status 0 when `GET /_wap/healthz` on `LISTEN` answers `200`; this is the image's `HEALTHCHECK` (no shell or curl in the image) |
| `--version` | print the version |

Run them in the container: `docker exec webauthnproxy /webauthnproxy passkeys list`.
`DATA_DIR/admin.sock` (mode `0600`) is the Unix socket they use ([security.md](security.md#local-administration-socket)).
