const http = require("http");
const crypto = require("crypto");
const secret = Buffer.from("bench-secret-0123456789abcdef0123456789");
const users = new Set(["bench"]);
const b64 = (s) => Buffer.from(s, "base64url").toString();

function check(h) {
  const host = (h["x-forwarded-host"] || "").toLowerCase();
  if (host !== "app.example.com") return null;
  const m = /(?:^|;\s*)wap_session=([^;]+)/.exec(h.cookie || "");
  if (!m) return null;
  const tok = m[1], i = tok.lastIndexOf(".");
  if (i < 0) return null;
  const payload = tok.slice(0, i);
  const want = crypto.createHmac("sha256", secret).update("s|" + payload).digest();
  const got = Buffer.from(tok.slice(i + 1), "base64url");
  if (got.length !== want.length || !crypto.timingSafeEqual(got, want)) return null;
  const f = payload.split(".");
  if (f.length !== 4 || Number(f[2]) < Date.now() / 1000 || b64(f[1]) !== host) return null;
  const user = b64(f[0]);
  return users.has(user) ? user : null;
}

http.createServer((req, res) => {
  const user = req.url.startsWith("/_wap/verify") ? check(req.headers) : null;
  if (user) { res.writeHead(200, { "X-Authenticated-User": user }); } else { res.writeHead(401); }
  res.end();
}).listen(8080, "0.0.0.0");
