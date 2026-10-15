# Enrolling passkeys

[← README](../README.md)

A passkey is bound to a **domain** (`RP_ID`): the browser refuses to create one for a domain other than the page's (or one of its parents), and
refuses insecure contexts outside `localhost`. Two tools, enabled independently:

| | **Automatic** enrollment | **Static** tool + manual import |
|---|---|---|
| Enable with | `ENROLL_ENABLED=true` | `TOOL_ENABLED=true` |
| Port | `8081` (`ENROLL_LISTEN`) | `8082` (`TOOL_LISTEN`) |
| Access | **protected**: sign in with an existing passkey | none needed: the page has no state and no write access |
| Exposure | **never public**: loopback or a private network, only while you enroll | **never public**: harmless if reached (no state, no writes), but no reason to publish it |
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
To use it on a real domain, serve it over a VPN or an IP-restricted route (see [reverse-proxy.md](reverse-proxy.md)) and take it down afterwards.

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

## Listing and revoking passkeys

Without editing `users.json` and without opening port 8081, from the host that runs the container:

```sh
docker exec webauthnproxy /webauthnproxy passkeys list
docker exec webauthnproxy /webauthnproxy passkeys revoke <id>     # <id>: the tag shown by "list" (a prefix of 6+ characters is enough)
docker exec webauthnproxy /webauthnproxy signout <user>           # end every session of a user, keep the passkeys
docker exec webauthnproxy /webauthnproxy sessions list            # who is signed in: id, user, site, last activity, browser
docker exec webauthnproxy /webauthnproxy sessions revoke <id>     # end one session (a lost laptop, a forgotten tab)
```

(`podman exec` works the same.) `list` prints one line per passkey: short id, user, `synced` or `device-bound`, transports, number of uses.
`revoke` deletes the passkey **and ends every session of its user** (they sign in again with another passkey). It refuses to delete the **last** passkey of the service, an unknown or ambiguous id, and ids shorter than 6 characters.
Each action is written to the audit log with `"via":"cli"`.

How it works: the running service listens on a Unix socket, `DATA_DIR/admin.sock`, created with mode `0600`, and the command talks to it. Nothing is added to the network;
whoever can open that socket can already write to the data volume, which is the trust level this project assumes for recovery and import.
The command needs the service to be running with the same `DATA_DIR`. The enrolment page (port 8081) can also list and delete passkeys.

## Account recovery (lost passkeys)

**There is no remote recovery by design**: no e-mail, no SMS, no recovery code. Whoever can write to the data volume can recover; nobody else can.

**Prevent it: enroll at least two passkeys** per user, on different authenticators (for example a synced platform passkey and a hardware security key kept elsewhere).
The service refuses to delete the last passkey, so you cannot lock yourself out from the enrollment page.

**If every passkey is lost:**

1. Stop the container.
2. Move the user database aside: `mv data/users.json data/users.json.lost`.
3. **End the old sessions**: delete `data/sessions.json`, so no cookie issued before the loss is accepted (a recreated user with the same name would otherwise inherit the old sessions).
4. Start again with `ENROLL_ENABLED=true` and read `Enrollment bootstrap token: …` in the logs.
5. Open the enrollment page, enter the token, create the first passkey, then a second one. Restart without `ENROLL_ENABLED`.

Alternative without opening port 8081: create a passkey with the static tool on a new authenticator and drop the JSON file into `data/import/` (step 3 still applies).

**Same caution when restoring a backup:** an old `sessions.json` brings back sessions revoked after the backup was taken. Delete `sessions.json` after a restore.

*What is tested:* listing, revoking (prefix, ambiguity, last passkey, unknown id), sign-out, the socket mode and the absence of these routes on the network ports are covered by `admin_test.go`.  the empty-database bootstrap (first passkey with the token) and the import path are covered by the unit and e2e tests. The file-deletion procedure above reaches the same empty state but is not exercised as a scenario of its own, and the restore caveat is documented, not tested.
