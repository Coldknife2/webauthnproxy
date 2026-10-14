const http = require("http");
const crypto = require("crypto");
const sha = (s) => crypto.createHash("sha256").update(s).digest("base64url");

// Same algorithm as the application: SHA-256 of the cookie value, lookup in a table of sessions (one entry, seeded at
// start), audience and expiry checks, user lookup.
const table = new Map([[sha("benchAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), { user: "bench", aud: "app.example.com", exp: Date.now() / 1000 + 86400 }]]);
const users = new Set(["bench"]);

function check(h) {
  const host = (h["x-forwarded-host"] || "").toLowerCase();
  if (host !== "app.example.com") return null;
  const m = /(?:^|;\s*)wap_session=([^;]+)/.exec(h.cookie || "");
  if (!m) return null;
  const s = table.get(sha(m[1]));
  if (!s || s.aud !== host || s.exp < Date.now() / 1000) return null;
  return users.has(s.user) ? s.user : null;
}

http.createServer((req, res) => {
  const user = req.url.startsWith("/_wap/verify") ? check(req.headers) : null;
  if (user) { res.writeHead(200, { "X-Authenticated-User": user }); } else { res.writeHead(401); }
  res.end();
}).listen(8080, "0.0.0.0");
