# Security policy

## Reporting a vulnerability

**Please do not open a public issue.** Use GitHub's private reporting:
the repository's *Security → Report a vulnerability* tab
([`coldknife2/webauthnproxy`](https://github.com/coldknife2/webauthnproxy/security/advisories/new)).

Include the version or commit, reproduction steps and the impact. You will get an acknowledgement within a reasonable time;
a fix and an advisory are published once the issue is resolved.

## Supported versions

The project is young: only the latest release (or the `main` branch) receives fixes.

## Scope

In scope: authentication bypass, session fixation/forgery, ticket replay or cross-site session reuse in forward mode, open redirect, leakage of the session cookie or secrets, CSRF on the
enrollment endpoints, unvalidated passkey import.

Out of scope (see the [Security model](README.md#security-model) in the README): denial of service through request volume
(use your reverse proxy's rate limiting), compromise of the server or the `/data` volume, vulnerabilities in the protected site itself.
