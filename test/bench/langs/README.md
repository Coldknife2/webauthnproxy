# Language prototypes

The forwardAuth hot path (`GET /_wap/verify`: check an HMAC-SHA256-signed session cookie, the host and the user, answer 200 with
`X-Authenticated-User`) written the idiomatic, production-style way in other languages, to compare footprint with the Go implementation.
These are **benchmark prototypes only** (no WebAuthn, no login, no error handling beyond what the benchmark needs).
Run them with `make bench-langs` and read [docs/language-choice.md](../../../docs/language-choice.md).

| Dir | Stack |
|---|---|
| `go/` | Go net/http, same handler without the rest of the application (separates the language from the app) |
| `rust/` | axum (hyper + tokio, multi-thread), `hmac`/`sha2`, static musl binary in `scratch` |
| `dotnet/` | .NET 9 ASP.NET Core minimal API (Kestrel), `aspnet:9.0-alpine` runtime image |
| `node/` | Node 22, built-in `http` + `crypto`, single process |
| `python/` | Python 3.13, raw ASGI app on uvicorn (uvloop + httptools), single worker |
