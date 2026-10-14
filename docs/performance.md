# Performance

[← README](../README.md)

webauthnproxy is built to stay out of the way: a single static Go binary, no database server, no password hashing, stateless cookies.
Measured in the same conditions against [Authelia](https://www.authelia.com/) and [Pocket ID](https://github.com/pocket-id/pocket-id) + [Tinyauth](https://github.com/tinyauthapp/tinyauth):

| | webauthnproxy | Authelia v4.39.28 | Pocket ID v2.18 + Tinyauth v5.2 |
|---|---|---|---|
| Image size | **12 MiB** | 77 MiB | 128 MiB (84 + 44) |
| Start to first answer (container creation included) | 0.37 s | 0.96 s | 0.39 s (Tinyauth) + 0.73 s (Pocket ID) |
| Idle memory (RSS, 45 s after start) | **8 MiB** (2 MiB anonymous) | 163 MiB (121 MiB anonymous)¹ | 90 MiB (22 MiB anonymous): 58 + 40 |
| Idle CPU | **0.00 %** | 0.05 % | 0.10 % |
| Authenticated check, 4 connections | **14,344 req/s**, p99 0.91 ms | 11,218 req/s, p99 1.29 ms | 3,798 req/s, p99 2.6 ms |
| … server CPU per 1000 requests | **98 ms** | 135 ms | 414 ms |
| Authenticated check, 32 connections | **34,829 req/s**, p99 4.8 ms | 20,388 req/s, p99 8.1 ms | 3,820 req/s, p99 27.2 ms |
| … server CPU per 1000 requests | **46 ms** | 92 ms | 408 ms |
| Peak memory during the run | **15 MiB** | 208 MiB² | 98 MiB |

¹ After one login and 45 s of idle. The Go runtime later returns part of it: about 90 MiB once the load test had finished.
² Reached at the password login (Authelia hashes with Argon2id, 64 MiB per hash by default); 208 to 258 MiB across runs. webauthnproxy has no password to hash.

**Reading the numbers.** Memory is the big difference: about 11× less than Pocket ID + Tinyauth and 20× less than Authelia at idle, 6× to 14× less at peak. Images are 6× to 11× smaller.
Per-request CPU is 1.4× to 2× lower than Authelia and 4× to 9× lower than Tinyauth, whose forward-auth endpoint is the slowest of the three here.

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

Official images: `docker.io/authelia/authelia:latest` (v4.39.28), `docker.io/pocketid/pocket-id:v2`, `ghcr.io/tinyauthapp/tinyauth:v5` (v5.2.0).
Measured on a 4-vCPU Intel Xeon 2.8 GHz VM (Linux 6.18, podman 4.9.3, Go 1.26), with the load generator on the same machine.
Absolute numbers will differ on your hardware; the ratios are what matter.

## Caveats

- **They do more.** Authelia and Tinyauth keep server-side sessions (individually revocable) and apply access-control rules; Authelia has a SQLite layer, Tinyauth looks sessions up in SQLite;
  Pocket ID is a complete OIDC provider with an admin UI. webauthnproxy verifies a signed cookie and looks the user up in memory.
  That is the trade-off: no per-site rules, revocation per user instead of per session ([security model](security.md#session-tokens-hmac-signed-cookies)).
- **Login is not compared.** A passkey login (public-key signature check) and a password login (Argon2id, bcrypt) are different operations.
- **Quietest settings for everyone.** Authelia ran at log level `warn`; Tinyauth with `TINYAUTH_LOG_LEVEL=warn` and its HTTP request log off
  (at its defaults it logs every request and handled about 30 % fewer checks per second). Nothing else was tuned (for example no `GOMEMLIMIT`).
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
