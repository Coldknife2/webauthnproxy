import hashlib, time

# Same algorithm as the application: SHA-256 of the cookie value, lookup in a table of sessions (one entry, seeded at
# start), audience and expiry checks, user lookup.
TABLE = {hashlib.sha256(b"benchAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").digest(): ("bench", "app.example.com", time.time() + 86400)}
USERS = {"bench"}


def check(h: dict):
    host = h.get(b"x-forwarded-host", b"").decode().lower()
    if host != "app.example.com":
        return None
    tok = None
    for part in h.get(b"cookie", b"").decode().split(";"):
        part = part.strip()
        if part.startswith("wap_session="):
            tok = part[len("wap_session="):]
    if not tok:
        return None
    s = TABLE.get(hashlib.sha256(tok.encode()).digest())
    if not s or s[1] != host or s[2] < time.time():
        return None
    return s[0] if s[0] in USERS else None


async def app(scope, receive, send):
    if scope["type"] != "http":
        return
    user = check(dict(scope["headers"])) if scope["path"] == "/_wap/verify" else None
    headers = [(b"x-authenticated-user", user.encode())] if user else []
    await send({"type": "http.response.start", "status": 200 if user else 401, "headers": headers})
    await send({"type": "http.response.body", "body": b""})
