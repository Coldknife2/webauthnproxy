// Rate limiting on the login and enrollment endpoints, with the real binary over HTTP:
// 429 + Retry-After once the per-client budget is spent, a forged X-Forwarded-For does not dodge it,
// other endpoints are not limited, and the audit log (JSON on standard output) records the refusals.
const { spawn } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");
const assert = require("assert");

const BIN = process.env.BIN || path.resolve(__dirname, "../../webauthnproxy");
const data = fs.mkdtempSync(path.join(os.tmpdir(), "wap-rl-"));
const out = [];
const proxy = spawn(BIN, [], { env: { ...process.env, DATA_DIR: data, UPSTREAM: "http://127.0.0.1:9", RP_ID: "localhost",
  RP_ORIGINS: "http://localhost:8080", ENROLL_ENABLED: "true", RATE_LIMIT_IP: "5/1m", RATE_LIMIT_GLOBAL: "off" }});
proxy.stdout.on("data", (d) => out.push(String(d)));
proxy.stderr.on("data", (d) => out.push(String(d)));
const step = (m) => console.log("✔", m);
const post = (port, p, headers = {}) => fetch(`http://127.0.0.1:${port}${p}`, { method: "POST", headers: { "X-Requested-With": "wap", ...headers } });

(async () => {
  try {
    for (let i = 0; i < 50 && !(await fetch("http://127.0.0.1:8080/_wap/login").then((r) => r.ok, () => false)); i++) await new Promise((r) => setTimeout(r, 100));
    const codes = [];
    for (let i = 0; i < 7; i++) codes.push((await post(8080, "/_wap/login/begin")).status);
    assert.deepEqual(codes, [200, 200, 200, 200, 200, 429, 429]);
    const refused = await post(8080, "/_wap/login/begin");
    assert.equal(refused.status, 429);
    assert.ok(Number(refused.headers.get("retry-after")) >= 1);
    assert.match((await refused.json()).error, /too many requests/);
    step("login/begin: 5 requests allowed, then 429 with Retry-After");

    assert.equal((await post(8080, "/_wap/login/begin", { "X-Forwarded-For": "198.51.100.77" })).status, 429);
    step("a forged X-Forwarded-For does not give a fresh budget (no proxy is trusted)");

    assert.equal((await post(8081, "/_wap/login/finish?cid=x")).status, 429);
    assert.equal((await post(8081, "/api/register/begin")).status, 429);
    step("the enrollment host shares the client's budget (login and registration endpoints)");

    assert.equal((await fetch("http://127.0.0.1:8080/_wap/login")).status, 200);
    step("pages and other endpoints are not limited");

    const log = out.join("");
    const events = log.split("\n").filter((l) => l.startsWith("{")).map((l) => JSON.parse(l));
    assert.ok(events.some((e) => e.event === "rate_limited" && e.scope === "client" && e.ip === "127.0.0.1"));
    step("audit log: rate_limited events with the client address");
    console.log("\nAll rate-limit scenarios pass.");
  } finally { proxy.kill(); await new Promise((r) => (proxy.exitCode !== null || proxy.signalCode ? r() : proxy.once("exit", r))); fs.rmSync(data, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 }); }
})().catch((e) => { console.error("FAILED:", e); process.exit(1); });
