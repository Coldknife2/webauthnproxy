# Enrolling passkeys

[← README](../README.md)

A passkey is bound to a **domain** (`RP_ID`): the browser refuses to create one for a domain other than the page's (or one of its parents), and
refuses insecure contexts outside `localhost`. Two tools, enabled independently:

| | **Automatic** enrollment | **Static** tool + manual import |
|---|---|---|
| Enable with | `ENROLL_ENABLED=true` | `TOOL_ENABLED=true` |
| Port | `8081` (`ENROLL_LISTEN`) | `8082` (`TOOL_LISTEN`) |
| Access | **protected**: sign in with an existing passkey | none needed: the page has no state and no write access |
| Recommended exposure | private (defense in depth) | may be public |
| Adding a passkey | instant, from the page | an administrator copies a JSON file into `DATA_DIR/import/` |
| First passkey | bootstrap token (logs) | no token needed |

## Automatic enrollment (port 8081)

The page `http(s)://<host>:8081/` lets you add and delete passkeys.

- **Protected by existing passkeys**: without a session it redirects to its own login page; the API answers `401`.
- **Bootstrap**: while no passkey exists, a **one-time bootstrap token** is generated and written to the logs at startup; it must be entered
  to create the first passkey. As soon as a passkey exists, the token stops working.
- Writes require the `X-Requested-With` header (CSRF protection). The **last passkey cannot be deleted** (no lock-out).
- Any signed-in user can create new users and passkeys: all users are administrators.
- This page's URL must be listed in `RP_ORIGINS` and lie under the `RP_ID` domain.
- A host's cookie is shared across ports: on the same hostname, being signed in to enrollment also grants access to the proxy.

## Static tool (port 8082) and manual import

To enroll **without exposing any write API**: a standalone HTML page ([`web/tool.html`](../web/tool.html)) that contacts no server.

1. Open the tool (`http(s)://<host>:8082/`, domain pre-filled with `RP_ID`), enter a name and click **Create the passkey**.
2. The tool shows a **JSON file** (public key and metadata, no secret): download it.
3. Copy it **by hand** into the proxy's import folder: `cp remi-example.com.json data/import/`
   (with a container: `podman cp remi-example.com.json webauthnproxy:/data/import/`).
4. Within seconds the proxy validates and imports the file, then renames it to `.imported` (or `.rejected`, with the reason in the logs).

The page must be served over **HTTPS under the `RP_ID` domain** (e.g. `https://tool.example.com`), or on `localhost` with `RP_ID=localhost`:
**a file opened directly (`file://`) does not work**; this is a browser rule. The tool's origin does not need to be in `RP_ORIGINS`.
The tool can also be hosted as-is (it is a single file) on any static site under the same domain.

What the proxy **checks** on import: format version, passkey created for the right domain (`rpIdHash`), user presence/verification flags, valid COSE
public key, consistent credential ID, user ID consistent with the name, no duplicate. Format (version 1):

```json
{
  "version": 1,
  "rpId": "example.com",
  "user": { "id": "<base64url>", "name": "remi" },
  "credential": { "id": "<base64url>", "authenticatorData": "<base64url>", "transports": ["internal"] }
}
```

The `import/` folder is watched continuously: **only someone who can write to the data volume can add a passkey this way**.
To add a second device to a user, run the tool again with the **same name**.

## Losing all passkeys

Stop the service, delete `data/users.json`, restart with `ENROLL_ENABLED=true`: a new bootstrap token is printed in the logs.
(Or drop a file produced by the static tool into `data/import/`.)
