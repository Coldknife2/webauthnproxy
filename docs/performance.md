# Performance

[← README](../README.md)

webauthnproxy is built to stay out of the way: a single static Go binary, no database server, no password hashing, stateless cookies.
Measured against [Authelia](https://www.authelia.com/) in the same conditions:

| | webauthnproxy | Authelia v4.39.28 |
|---|---|---|
| Image size | **12 MiB** | 77 MiB |
| Start to first answer (container creation included) | **0.34 s** | 0.79 s |
| Idle memory (RSS, 45 s after start) | **9 MiB** (2 MiB anonymous) | 159 MiB (116 MiB anonymous)¹ |
| Idle CPU | **0.00 %** | 0.05 % |
| Authenticated check, 4 connections | **13,526 req/s**, p99 0.95 ms | 10,272 req/s, p99 1.38 ms |
| … server CPU per 1000 requests | **104 ms** | 146 ms |
| Authenticated check, 32 connections | **32,324 req/s**, p99 5.1 ms | 19,481 req/s, p99 7.6 ms |
| … server CPU per 1000 requests | **49 ms** | 101 ms |
| Peak memory during the run | **16 MiB** | 242 MiB² |

¹ After one login and 45 s of idle. The Go runtime later returns part of it: 89–93 MiB once the load test had finished.
² Reached at the password login (Authelia hashes with Argon2id, 64 MiB per hash by default). webauthnproxy has no password to hash.

**Reading the numbers.** Memory is the big difference (roughly 10× at idle, 15× at peak), then image size (6×). CPU per request is within the
same order of magnitude (1.4× to 2× in favor of webauthnproxy): both are Go programs, and most of the time per request goes to the HTTP stack.

## Method

`test/bench/bench.py` runs both services in containers on the same host, in forwardAuth mode, behind the same load generator
(`test/bench/loadgen.go`: keep-alive connections, fixed concurrency, 10 s per step). Each request is an **authenticated check**, the thing Traefik does
before every request to a protected site. Memory and CPU come from `/proc/<pid>` of the container's process (RSS, utime+stime).

```sh
make image          # build the local image
make bench          # ~3 minutes; prints the table above for your machine
make bench-go       # Go micro-benchmarks of the hot path
```

Measured on a 4-vCPU Intel Xeon 2.8 GHz VM (Linux 6.18, podman 4.9.3, Go 1.26), with the load generator on the same machine.
Absolute numbers will differ on your hardware; the ratios are what matter.

## Caveats

- **Not the same work.** Authelia does more per request: server-side sessions (individually revocable), access-control rules, a SQLite storage layer.
  webauthnproxy verifies an HMAC-signed cookie and looks the user up in memory. That is the trade-off: no per-site rules, no server-side session revocation.
- **Login is not compared.** A passkey login (public-key signature check) and a password login (Argon2id) are different operations.
- **Default configurations.** Authelia was run with a minimal file-based configuration and no tuning (for example no `GOMEMLIMIT`); webauthnproxy was not tuned either.
- **One noisy VM.** Run `make bench` yourself before relying on a number.
- **Other products** (Authentik, Keycloak, Pocket ID + Tinyauth) were not measured. One comparison reports that
  [Authentik needs PostgreSQL and about 2 GB of RAM](https://sumguy.com/tinyauth-vs-pocket-id-vs-authelia/); I did not verify that figure.

## What keeps it light

- Static Go binary in a distroless image: no shell, no package manager, nothing else running.
- No database server: users live in one small JSON file that is read once and kept in memory.
- Sessions and login tickets are HMAC-signed cookies: nothing stored per session, nothing to look up or expire.
- The hot path (`/_wap/verify`) allocates little: a pooled HMAC, no copy of the user record, no URL parsing for ordinary requests
  (`BenchmarkVerify`: ~2.9 µs and 17 allocations per check, down from ~4.3 µs and 25 before the optimization).
- Idle means idle: the only background work is a directory check every 5 s for the manual import folder.
