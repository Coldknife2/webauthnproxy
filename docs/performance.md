# Performance

[← README](../README.md)

webauthnproxy is built to stay out of the way: a single static Go binary, no database server, no password hashing, stateless cookies.
Measured in the same conditions against [Authelia](https://www.authelia.com/) and [Pocket ID](https://github.com/pocket-id/pocket-id) + [Tinyauth](https://github.com/tinyauthapp/tinyauth):

| | webauthnproxy | Authelia v4.39.28 | Pocket ID v2.18 + Tinyauth v5 |
|---|---|---|---|
| Image size | **12 MiB** | 77 MiB | 190 MiB (84 + 106)³ |
| Start to first answer (container creation included) | 0.36 s | 0.80 s | 0.46 s (Tinyauth) + 0.78 s (Pocket ID) |
| Idle memory (RSS, 45 s after start) | **9 MiB** (2 MiB anonymous) | 161 MiB (119 MiB anonymous)¹ | 109 MiB (24 MiB anonymous): 61 + 57 |
| Idle CPU | **0.00 %** | 0.05 % | 0.10 % |
| Authenticated check, 4 connections | **14,067 req/s**, p99 0.91 ms | 10,819 req/s, p99 1.27 ms | 4,026 req/s, p99 2.4 ms |
| … server CPU per 1000 requests | **100 ms** | 141 ms | 388 ms |
| Authenticated check, 32 connections | **36,229 req/s**, p99 4.7 ms | 20,431 req/s, p99 7.9 ms | 4,298 req/s, p99 23.6 ms |
| … server CPU per 1000 requests | **45 ms** | 94 ms | 365 ms |
| Peak memory during the run | **16 MiB** | 258 MiB² | 119 MiB |

¹ After one login and 45 s of idle. The Go runtime later returns part of it: 92 MiB once the load test had finished.
² Reached at the password login (Authelia hashes with Argon2id, 64 MiB per hash by default). webauthnproxy has no password to hash.
³ Pocket ID from Docker Hub, Tinyauth built from its own Dockerfile (see below), so its figure is the binary (which embeds its web UI and SQLite) plus a small base image.

**Reading the numbers.** Memory is the big difference: about 12× less than Pocket ID + Tinyauth and 18× less than Authelia at idle, 7× to 16× less at peak. Image size is 6× to 16× smaller.
Per-request CPU is 1.4× to 2× lower than Authelia and 4× to 8× lower than Tinyauth, whose forward-auth endpoint is the slowest of the three here.

## Method

`test/bench/bench.py` runs the services in containers on the same host, in forwardAuth mode, behind the same load generator
(`test/bench/loadgen.go`: keep-alive connections, fixed concurrency, 10 s per step). Each request is an **authenticated check**, the thing Traefik does
before every request to a protected site. Memory and CPU come from `/proc/<pid>` of the container's process (RSS, utime+stime).
For Pocket ID + Tinyauth, Pocket ID (the identity provider) is only involved at login, so the checks hit Tinyauth; idle memory, idle CPU and image size are the sum of both containers.

```sh
make image          # build the local image
make bench          # ~6 minutes; prints the table above for your machine (needs: pip install bcrypt)
make bench-go       # Go micro-benchmarks of the hot path
```

Measured on a 4-vCPU Intel Xeon 2.8 GHz VM (Linux 6.18, podman 4.9.3, Go 1.26), with the load generator on the same machine.
Absolute numbers will differ on your hardware; the ratios are what matter.

## Caveats

- **They do more.** Authelia and Tinyauth keep server-side sessions (individually revocable) and apply access-control rules; Authelia has a SQLite layer, Tinyauth looks sessions up in SQLite;
  Pocket ID is a complete OIDC provider with an admin UI. webauthnproxy verifies a signed cookie and looks the user up in memory.
  That is the trade-off: no per-site rules, revocation per user instead of per session ([security model](security.md#session-tokens-hmac-signed-cookies)).
- **Login is not compared.** A passkey login (public-key signature check) and a password login (Argon2id, bcrypt) are different operations.
- **Quietest settings for everyone.** Authelia ran at log level `warn`; Tinyauth with `TINYAUTH_LOG_LEVEL=warn` and its HTTP request log off
  (at its defaults it logs every request and handled about 30 % fewer checks per second). Nothing else was tuned (for example no `GOMEMLIMIT`).
- **Tinyauth image.** `ghcr.io` was not reachable from the environment used for the measurement, so Tinyauth was built from its own `Dockerfile` (same build steps, local base images; the official image adds an Alpine base of a few MiB).
  Memory and CPU are those of the same code.
- **Pocket ID** was measured idle and unconfigured (no admin account created), with its analytics heartbeat disabled (`ANALYTICS_DISABLED=true`); a configured instance with users will use somewhat more.
- **One noisy VM.** Run `make bench` yourself before relying on a number.
- **Other products** (Authentik, Keycloak) were not measured. One comparison reports that
  [Authentik needs PostgreSQL and about 2 GB of RAM](https://sumguy.com/tinyauth-vs-pocket-id-vs-authelia/); I did not verify that figure.

## What keeps it light

- Static Go binary in a distroless image: no shell, no package manager, nothing else running.
- No database server: users live in one small JSON file that is read once and kept in memory.
- Sessions and login tickets are HMAC-signed cookies: nothing stored per session, nothing to look up or expire.
- The hot path (`/_wap/verify`) allocates little: a pooled HMAC, no copy of the user record, no URL parsing for ordinary requests
  (`BenchmarkVerify`: about 3 µs and 17 allocations per check).
- Idle means idle: the only background work is a directory check every 5 s for the manual import folder.

Is Go the right language for this? See [language-choice.md](language-choice.md).
