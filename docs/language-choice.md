# Why Go?

[← README](../README.md)

**Short answer:** Go is the right choice for this project. Rust is the only serious alternative: it wins on footprint, by an amount that does not justify a rewrite today.
The others (.NET, Node, Python) use 4 to 7 times the memory and 10 to 14 times the image size of the Go app for this workload.

## Measured: the forwardAuth hot path in six implementations

The hot path (`GET /_wap/verify`: check an HMAC-signed cookie, the host and the user, answer 200 with `X-Authenticated-User`) written the idiomatic way in each language,
run in containers, one process, same load generator and method as [performance.md](performance.md). Go "full app" is the real webauthnproxy.

| | Image | Idle memory | Peak memory | 32 connections | CPU / 1000 req (4 conn.) | CPU / 1000 req (32 conn.) |
|---|---|---|---|---|---|---|
| **Rust** (axum, tokio, static musl) | **1 MiB** | **1 MiB** | **2 MiB** | 35.5k req/s | **55 ms** | 43 ms |
| **Go**, minimal handler | 6 MiB | 6 MiB | 13 MiB | 35.1k req/s | 93 ms | 45 ms |
| **Go**, full webauthnproxy | 12 MiB | 9 MiB | 16 MiB | 35.2k req/s | 91 ms | 45 ms |
| .NET 9 (Kestrel, `aspnet:alpine`) | 116 MiB | 65 MiB | 72 MiB | 19.2k req/s | 132 ms | 78 ms |
| Python 3.13 (uvicorn, one worker) | 153 MiB | 33 MiB | 33 MiB | 11.3k req/s | 105 ms | 83 ms |
| Node 22 (built-in `http`) | 162 MiB | 50 MiB | 65 MiB | 10.5k req/s | 99 ms | 88 ms |

Start to first answer: Rust 0.26 s, Go 0.28 to 0.33 s, Node 0.45 s, Python 0.74 s, .NET 0.79 s. Idle CPU: 0.00 % for Rust and Go, 0.07 % Node, 0.20 % .NET, 0.27 % Python.

**Reading it**

- **Go and Rust are in the same league.** Same throughput and same CPU per request once the server is busy (32 connections); Rust uses about 40 % less CPU when lightly loaded, and a few MiB less memory.
- **.NET, Node and Python are a different league** on this workload: 4 to 7 times the memory and 10 to 14 times the image of the Go app, and about half to a third of the throughput.
  Node and Python run one process here (one core); several processes would raise throughput and multiply memory.
- The Go "full app" costs only about 3 MiB more than a bare Go handler: embedded pages, the WebAuthn library and its JSON/CBOR parsing.

**Caveats**

- These are prototypes of the hot path only. A complete Rust version (WebAuthn library, reverse proxy with WebSocket upgrades, login and enrollment, the JSON store) would use more than the 1 MiB measured; I did not build one.
- The .NET image is the standard framework-dependent one. Native AOT would shrink it a lot; not tested. The JVM (Java, Kotlin) and Bun/Deno were not measured.
- Warm-up was excluded (JIT, caches). One noisy VM; reproduce with `make bench-langs` (builds the five prototypes in `test/bench/langs/`).

## Beyond the numbers

- **The WebAuthn library exists everywhere, so it does not decide.** Go: [go-webauthn/webauthn](https://github.com/go-webauthn/webauthn) (Authelia depends on the same version, v0.18.2, in its `go.mod`);
  Rust: [webauthn-rs](https://github.com/kanidm/webauthn-rs) (used by Kanidm); .NET: [fido2-net-lib](https://github.com/passwordless-lib/fido2-net-lib);
  Node: [SimpleWebAuthn](https://github.com/MasterKale/SimpleWebAuthn); Python: [py_webauthn](https://github.com/duo-labs/py_webauthn); Java: [Yubico java-webauthn-server](https://github.com/Yubico/java-webauthn-server).
  I did not audit any of them.
- **A reverse proxy comes with Go's standard library.** `httputil.ReverseProxy` proxies HTTP and WebSocket upgrades; ours is about 30 lines. In Rust you assemble hyper, hyper-util and upgrade
  handling yourself or add a crate; .NET has Microsoft's YARP; Node and Python need third-party libraries.
- **Few dependencies, easy to audit.** One direct dependency (the WebAuthn library; 22 modules in total, all transitive from it). HTTP server, proxy, HMAC, JSON, embedding and TLS-free networking come from the standard library.
- **One static binary, cross-compiled.** `CGO_ENABLED=0 GOOS=… GOARCH=…` gives the multi-architecture images without any emulation (see the `Dockerfile`). Rust's musl target works too (the prototype uses it);
  Node, Python and .NET ship a runtime in the image.
- **Memory safety** is not a differentiator here: Go, Rust, C#, JavaScript and Python are all memory-safe. Rust additionally rules out data races at compile time, a modest benefit for about 1,400 lines.
- **Ecosystem fit.** Authelia, Tinyauth and the Pocket ID backend are all written in Go (checked in their `go.mod` files), as is Traefik, so contributors in the self-hosting space already know it.
- **Build speed.** The Go app builds in seconds; the Rust prototype, with two direct dependencies, took about a minute.

## Verdict

- **Stay with Go.** It delivers 9 MiB idle and 0 % CPU, one static binary, a proxy in the standard library, and a codebase small enough to read in an afternoon.
- **Consider Rust** if the target becomes tiny machines (a few MiB of RAM) or the lowest CPU at low load matters. Expect a rewrite of about 1,400 lines, a hand-built WebSocket-capable proxy
  and an integration with webauthn-rs, for a memory saving I would estimate in the range of several MiB (not measured) and about 40 % less CPU when idle-ish.
- **.NET** is a fine choice if your team lives in C#, but expect 7 to 10 times the memory without Native AOT. **Node and Python** are pleasant to write and poorly suited to this: single-threaded throughput and a 30 to 50 MiB floor.
