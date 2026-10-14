import base64, hashlib, hmac, time

SECRET = b"bench-secret-0123456789abcdef0123456789"
USERS = {"bench"}


def b64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def check(h: dict):
    host = h.get(b"x-forwarded-host", b"").decode().lower()
    if host != "app.example.com":
        return None
    tok = None
    for part in h.get(b"cookie", b"").decode().split(";"):
        part = part.strip()
        if part.startswith("wap_session="):
            tok = part[len("wap_session="):]
    if not tok or "." not in tok:
        return None
    payload, _, sig = tok.rpartition(".")
    want = hmac.new(SECRET, b"s|" + payload.encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(want, b64(sig)):
        return None
    f = payload.split(".")
    if len(f) != 4 or int(f[2]) < time.time() or b64(f[1]).decode() != host:
        return None
    user = b64(f[0]).decode()
    return user if user in USERS else None


async def app(scope, receive, send):
    if scope["type"] != "http":
        return
    user = check(dict(scope["headers"])) if scope["path"] == "/_wap/verify" else None
    headers = [(b"x-authenticated-user", user.encode())] if user else []
    await send({"type": "http.response.start", "status": 200 if user else 401, "headers": headers})
    await send({"type": "http.response.body", "body": b""})
