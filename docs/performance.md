# Performance (experimental)

[← README](../README.md)

> **Experimental.** These numbers come from one experiment on one machine. They are here to document the approach and let you rerun it, not as an argument for choosing this project.
> The products compared do more than this one does, so the comparison is unequal by construction (see [Caveats](#caveats)).

## The approach

**Hypothesis.** The design choices (a static Go binary, users in a JSON file read once, sessions in an in-memory table backed by one small file) should keep memory and CPU low, because a check is one SHA-256 and a map lookup and a map lookup.

**Experiment.** Run the same authenticated forward-auth check against webauthnproxy, [Authelia](https://www.authelia.com/) and [Pocket ID](https://github.com/pocket-id/pocket-id) + [Tinyauth](https://github.com/tinyauthapp/tinyauth)
in containers, with the same load generator, and read memory and CPU from `/proc`.

**What it showed.** Idle memory and image size are much lower here; per-request CPU is lower by a smaller factor. The first run also exposed waste in our own hot path
(a copy of the user record per request, a fresh HMAC per check, URL parsing for ordinary requests); fixing it made a check about 30 % faster. Moving from signed cookies to server-side sessions later made a check faster again (see [What keeps it light](#what-keeps-it-light)).

**What it does not show.** That this project is "better": the others apply access rules and Pocket ID is a complete identity provider.
Lower memory is what you get for not doing those things.

## Results (2026-10-14, server-side sessions)

| | webauthnproxy | Authelia v4.39.28 | Pocket ID v2.18 + Tinyauth v5.2 |
|---|---|---|---|
| Image size | **12 MiB** | 77 MiB | 128 MiB (84 + 44) |
| Start to first answer (container creation included) | 0.31 s | 0.73 s | 2.74 s |
| Idle memory (RSS, 45 s after start) | **9 MiB** (2 MiB anonymous) | 161 MiB (119 MiB anonymous)¹ | 90 MiB (22 MiB anonymous) |
| Idle CPU | **0.00 %** | 0.00 % | 0.15 % |
| Authenticated check, 4 connections | **21,228 req/s**, p99 0.65 ms | 14,122 req/s, p99 1.11 ms | 4,645 req/s, p99 2.3 ms |
| … server CPU per 1000 requests | **64 ms** | 107 ms | 336 ms |
| Authenticated check, 32 connections | **46,733 req/s**, p99 3.7 ms | 26,452 req/s, p99 6.5 ms | 5,086 req/s, p99 20.6 ms |
| … server CPU per 1000 requests | **32 ms** | 71 ms | 305 ms |
| Peak memory during the run | **16 MiB** | 235 MiB² | 97 MiB |

¹ After one login and 45 s of idle. The Go runtime later returns part of it.
² Reached at the password login (Authelia hashes with Argon2id, 64 MiB per hash by default). webauthnproxy has no password to hash.

**Compared with the previous run** (signed cookies, same VM, earlier the same day): webauthnproxy 14,344 and 34,829 req/s, 98 and 46 ms of CPU per 1000 requests; Authelia 11,218 and 20,388 req/s.
Everything came out faster this time, Authelia too, so part of the gain is a quieter VM, not the change. The Go micro-benchmark is the cleaner comparison: `BenchmarkVerify` (the whole `/_wap/verify` handler)
went from about 2.1 µs and 17 allocations with the HMAC cookie to about 1.55 µs and 9 allocations with the session table, on the same machine and Go version, five runs each.
The session file is not read on the hot path; sessions are written to disk when created or revoked and every 30 s for last-activity times, which does not show in idle CPU.

**Reading the numbers.** Memory is the big difference: about 10× less than Pocket ID + Tinyauth and 18× less than Authelia at idle, 6× to 15× less at peak. Images are 6× to 11× smaller.
Per-request CPU is 1.7× to 2.2× lower than Authelia and 5× to 10× lower than Tinyauth, whose forward-auth endpoint is the slowest of the three here.

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

- **They do more.** Authelia and Tinyauth apply access-control rules; Authelia has a SQLite layer, Tinyauth looks sessions up in SQLite;
  Pocket ID is a complete OIDC provider with an admin UI. webauthnproxy looks a hashed cookie up in an in-memory table and the user in memory.
  That is the trade-off: no per-site rules ([security model](security.md#sessions-server-side)). Sessions are server-side here too since this version, so that part is no longer a difference.
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
- Sessions are a map of SHA-256 hashes in memory (about 200 bytes each), saved to one small file; a check is one SHA-256, a read lock and a map access.
- The hot path (`/_wap/verify`) allocates little: no copy of the user record, no URL parsing for ordinary requests
  (`BenchmarkVerify`: about 1.55 µs and 9 allocations per check).
- Idle means idle: the only background work is a directory check every 5 s for the manual import folder and, every 30 s, a pruning of expired sessions that writes the session file only if something changed.

Is Go the right language for this? See [language-choice.md](language-choice.md).
