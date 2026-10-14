// Cross-domain forwardAuth test against a real Traefik: one login host (auth.test.local) protects sites on
// unrelated domains (siteone.test, sitetwo.test) through the ticket exchange; unlisted.test is not allowed.
//   RUNTIME=podman|docker (default: podman if present, else docker), BIN, CHROMIUM as in e2e.cjs
const { chromium } = require("playwright");
const { spawn, execFileSync } = require("child_process");
const http = require("http");
const fs = require("fs");
const os = require("os");
const path = require("path");
const assert = require("assert");

const BIN = process.env.BIN || path.resolve(__dirname, "../../webauthnproxy");
const RUNTIME = process.env.RUNTIME || (() => { try { execFileSync("podman", ["--version"]); return "podman"; } catch { return "docker"; } })();
const data = fs.mkdtempSync(path.join(os.tmpdir(), "wap-xd-"));
const dyn = path.join(data, "dyn.yml");
const site = (name, host) => `    ${name}: {rule: "Host(\`${host}\`)", service: app, entryPoints: [web], middlewares: [wap]}\n`;
fs.writeFileSync(dyn, `http:
  routers:
    auth: {rule: "Host(\`auth.test.local\`)", service: auth, entryPoints: [web]}
${site("one", "a.siteone.test")}${site("two", "b.sitetwo.test")}${site("nope", "c.unlisted.test")}  middlewares:
    wap: {forwardAuth: {address: "http://127.0.0.1:8080/_wap/verify", authResponseHeaders: [X-Authenticated-User]}}
  services:
    auth: {loadBalancer: {servers: [{url: "http://127.0.0.1:8080"}]}}
    app:  {loadBalancer: {servers: [{url: "http://127.0.0.1:9000"}]}}
`);
const log = [];
const step = (m) => console.log("✔", m);
const upstream = http.createServer((q, r) => { r.end(`SECRET user=${q.headers["x-authenticated-user"]} host=${q.headers.host}`); }).listen(9000, "127.0.0.1");
const proxy = spawn(BIN, [], { env: { ...process.env, DATA_DIR: data, MODE: "forward",
  LOGIN_URL: "http://auth.test.local:8000/_wap/login",
  ALLOWED_HOSTS: "a.siteone.test,*.sitetwo.test",   // no COOKIE_DOMAIN: each site gets its own cookie
  RP_ID: "test.local", RP_ORIGINS: "http://auth.test.local:8000,http://enroll.test.local:8081", ENROLL_ENABLED: "true" }});
proxy.stderr.on("data", (d) => log.push(String(d)));
const until = async (f, ms = 15000) => { const t = Date.now(); while (Date.now() - t < ms) { const v = await f(); if (v) return v; await new Promise((r) => setTimeout(r, 200)); } throw new Error("timeout\n" + log.join("")); };

// Raw request through Traefik with a chosen Host/cookie (Node's fetch cannot set Host).
const raw = (host, urlPath, headers = {}) => new Promise((res, rej) => http.get(
  { host: "127.0.0.1", port: 8000, path: urlPath, headers: { Host: host, ...headers } },
  (r) => { let b = ""; r.on("data", (d) => (b += d)); r.on("end", () => res({ status: r.statusCode, headers: r.headers, body: b })); }).on("error", rej));

(async () => {
  execFileSync(RUNTIME, ["run", "-d", "--rm", "--name", "wap-xd-traefik", "--network=host", "-v", `${dyn}:/dyn.yml:ro`,
    "docker.io/library/traefik:v3", "--providers.file.filename=/dyn.yml", "--entrypoints.web.address=:8000", "--log.level=ERROR"]);
  const hosts = ["test.local", "siteone.test", "sitetwo.test", "unlisted.test"].map((d) => `MAP *.${d} 127.0.0.1`).join(",");
  const browser = await chromium.launch({ ...(process.env.CHROMIUM ? { executablePath: process.env.CHROMIUM } : {}), args: [
    `--host-resolver-rules=${hosts}`,
    "--unsafely-treat-insecure-origin-as-secure=http://auth.test.local:8000,http://enroll.test.local:8081"] });
  try {
    const token = (await until(() => /Enrollment bootstrap token: (\S+)/.exec(log.join(""))))[1];
    const ctx = await browser.newContext(); const page = await ctx.newPage();
    const cdp = await ctx.newCDPSession(page); await cdp.send("WebAuthn.enable");
    await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
    await until(async () => { try { return (await raw("a.siteone.test:8000", "/", { Accept: "application/json" })).status === 401; } catch { return false; } });
    step("Traefik started, anonymous API request refused (401)");

    await page.goto("http://a.siteone.test:8000/page?x=1");
    assert.match(page.url(), /^http:\/\/auth\.test\.local:8000\/_wap\/login\?next=http%3A%2F%2Fa\.siteone\.test%3A8000%2Fpage%3Fx%3D1/);
    step("anonymous browser on siteone.test is sent to the login host (another domain)");

    await page.goto("http://enroll.test.local:8081/");
    await page.fill("#token", token); await page.fill("#name", "remi"); await page.click("#f button");
    await page.waitForSelector("#msg.ok"); step("passkey enrolled (bootstrap)");

    let callback;
    page.on("request", (r) => { if (r.url().includes("/_wap/callback")) callback = r.url(); });
    await page.goto("http://a.siteone.test:8000/page?x=1"); await page.click("#go");
    await page.waitForURL("http://a.siteone.test:8000/page?x=1");
    assert.match(await page.textContent("body"), /SECRET user=remi/);
    step("signed in on the login host, back on siteone.test with the user forwarded");

    assert.ok(callback, "callback URL seen");
    const replay = await raw("a.siteone.test:8000", new URL(callback).pathname + new URL(callback).search);
    assert.equal(replay.status, 403); step("the ticket cannot be replayed");

    await page.goto("http://b.sitetwo.test:8000/");   // no passkey prompt: single sign-on
    assert.match(await page.textContent("body"), /SECRET user=remi/);
    step("second site on a third domain: single sign-on, no new passkey prompt");

    const cookies = await ctx.cookies();
    const one = cookies.find((c) => c.name === "wap_session" && c.domain === "a.siteone.test");
    assert.ok(one && cookies.find((c) => c.domain === "b.sitetwo.test"), "one cookie per site");
    assert.ok(!cookies.some((c) => c.name === "wap_session" && c.domain.startsWith(".")), "no shared-domain cookie");
    const stolen = await raw("b.sitetwo.test:8000", "/", { Accept: "application/json", Cookie: `wap_session=${one.value}` });
    assert.equal(stolen.status, 401); step("a site's cookie is useless on another site (bound to its host)");

    assert.equal((await raw("c.unlisted.test:8000", "/", { Accept: "application/json" })).status, 403);
    await page.goto("http://c.unlisted.test:8000/");
    assert.equal(await page.textContent("body").then((t) => t.trim()), "host not allowed");
    step("a host that is not in ALLOWED_HOSTS is refused (403)");

    await page.goto("http://a.siteone.test:8000/_wap/logout");
    assert.ok(!(await ctx.cookies("http://a.siteone.test:8000")).some((c) => c.name === "wap_session" && c.value));
    step("site logout clears that site's cookie");
    console.log("\nAll cross-domain scenarios pass.");
  } finally {
    await browser.close(); proxy.kill(); upstream.close();
    try { execFileSync(RUNTIME, ["kill", "wap-xd-traefik"]); } catch {}
    fs.rmSync(data, { recursive: true, force: true });
  }
})().catch((e) => { console.error("FAILED:", e); process.exit(1); });
