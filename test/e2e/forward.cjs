// forwardAuth mode test against a real Traefik (container). Needs podman or docker.
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
const data = fs.mkdtempSync(path.join(os.tmpdir(), "wap-fwd-"));
const dyn = path.join(data, "dyn.yml");
fs.writeFileSync(dyn, `http:
  routers:
    auth: {rule: "Host(\`auth.test.local\`)", service: auth, entryPoints: [web]}
    app:  {rule: "Host(\`app.test.local\`)",  service: app,  entryPoints: [web], middlewares: [wap]}
  middlewares:
    wap: {forwardAuth: {address: "http://127.0.0.1:8080/_wap/verify", authResponseHeaders: [X-Authenticated-User], addAuthCookiesToResponse: [wap_session]}}
  services:
    auth: {loadBalancer: {servers: [{url: "http://127.0.0.1:8080"}]}}
    app:  {loadBalancer: {servers: [{url: "http://127.0.0.1:9000"}]}}
`);
const log = [];
const step = (m) => console.log("✔", m);
const upstream = http.createServer((q, r) => { r.end(`SECRET user=${q.headers["x-authenticated-user"]}`); }).listen(9000, "127.0.0.1");
const proxy = spawn(BIN, [], { env: { ...process.env, DATA_DIR: data, MODE: "forward",
  LOGIN_URL: "http://auth.test.local:8000/_wap/login", COOKIE_DOMAIN: "test.local", RP_ID: "test.local",
  RP_ORIGINS: "http://auth.test.local:8000,http://enroll.test.local:8081", ENROLL_ENABLED: "true",
  TRUSTED_PROXIES: "127.0.0.1/32,::1/128", SESSION_IDLE_TIMEOUT: "6s", RATE_LIMIT_IP: "500/1m", RATE_LIMIT_GLOBAL: "off" }});
proxy.stderr.on("data", (d) => log.push(String(d)));
const until = async (f, ms = 15000) => { const t = Date.now(); while (Date.now() - t < ms) { const v = await f(); if (v) return v; await new Promise((r) => setTimeout(r, 200)); } throw new Error("timeout\n" + log.join("")); };

(async () => {
  execFileSync(RUNTIME, ["run", "-d", "--rm", "--name", "wap-e2e-traefik", "--network=host", "-v", `${dyn}:/dyn.yml:ro`,
    "docker.io/library/traefik:v3", "--providers.file.filename=/dyn.yml", "--entrypoints.web.address=:8000", "--log.level=ERROR"]);
  const browser = await chromium.launch({ ...(process.env.CHROMIUM ? { executablePath: process.env.CHROMIUM } : {}), args: [
    "--host-resolver-rules=MAP *.test.local 127.0.0.1",
    "--unsafely-treat-insecure-origin-as-secure=http://auth.test.local:8000,http://enroll.test.local:8081"] });
  try {
    const token = (await until(() => /Enrollment bootstrap token: (\S+)/.exec(log.join(""))))[1];
    const ctx = await browser.newContext(); const page = await ctx.newPage();
    const cdp = await ctx.newCDPSession(page); await cdp.send("WebAuthn.enable");
    await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });

    await until(() => new Promise((res) => http.get({ host: "127.0.0.1", port: 8000, headers: { Host: "app.test.local:8000", Accept: "application/json" } },
      (r) => { r.resume(); res(r.statusCode === 401); }).on("error", () => res(false))));
    step("Traefik started, anonymous access refused (401)");
    await page.goto("http://app.test.local:8000/page?x=1");
    assert.match(page.url(), /^http:\/\/auth\.test\.local:8000\/_wap\/login\?next=/); step("browser redirected to the login host");

    await page.goto("http://enroll.test.local:8081/");
    await page.fill("#token", token); await page.fill("#name", "remi"); await page.click("#f button");
    await page.waitForSelector("#msg.ok"); step("enrollment (bootstrap)");

    await page.goto("http://app.test.local:8000/page?x=1"); await page.click("#go");
    await page.waitForURL("http://app.test.local:8000/page?x=1");
    assert.match(await page.textContent("body"), /SECRET user=remi/); step("sign-in, return to the requested page, user forwarded");

    await page.goto("http://auth.test.local:8000/_wap/login?next=" + encodeURIComponent("https://evil.com/")); await page.click("#go");
    await page.waitForTimeout(1500);
    assert.ok(!page.url().includes("evil.com")); step("open redirect (next=evil.com) neutralized");

    // Idle timeout (6 s here): activity keeps the session alive because verify re-issues the cookie (Traefik copies it
    // with addAuthCookiesToResponse); without activity the session ends. No server-side state is involved.
    const sess = async () => (await ctx.cookies()).find((c) => c.name === "wap_session" && c.value)?.value;
    const body = async () => { await page.goto("http://app.test.local:8000/page"); return page.textContent("body"); };
    const v0 = await sess();
    await page.waitForTimeout(4000); assert.match(await body(), /SECRET user=remi/);
    const v1 = await sess(); assert.notEqual(v1, v0, "the cookie was not renewed");
    await page.waitForTimeout(4000); assert.match(await body(), /SECRET user=remi/);   // 8 s after login: still signed in thanks to the renewal
    step("idle timeout: activity renews the cookie through Traefik, the session outlives the idle timeout");
    await page.waitForTimeout(8000);
    await page.goto("http://app.test.local:8000/page");
    assert.match(page.url(), /^http:\/\/auth\.test\.local:8000\/_wap\/login/);
    step("idle timeout: no activity for longer than the timeout, the session is gone");
    console.log("\nAll forwardAuth scenarios pass.");
  } finally {
    await browser.close(); proxy.kill(); upstream.close();
    try { execFileSync(RUNTIME, ["kill", "wap-e2e-traefik"]); } catch {}
    fs.rmSync(data, { recursive: true, force: true });
  }
})().catch((e) => { console.error("FAILED:", e); process.exit(1); });
