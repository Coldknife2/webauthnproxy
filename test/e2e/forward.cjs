// Test du mode forwardAuth contre un vrai Traefik (conteneur). Nécessite podman ou docker.
//   RUNTIME=podman|docker (défaut: podman si présent, sinon docker), BIN, CHROMIUM comme e2e.cjs
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
    wap: {forwardAuth: {address: "http://127.0.0.1:8080/_wap/verify", authResponseHeaders: [X-Authenticated-User]}}
  services:
    auth: {loadBalancer: {servers: [{url: "http://127.0.0.1:8080"}]}}
    app:  {loadBalancer: {servers: [{url: "http://127.0.0.1:9000"}]}}
`);
const log = [];
const step = (m) => console.log("✔", m);
const upstream = http.createServer((q, r) => { r.end(`SECRET user=${q.headers["x-authenticated-user"]}`); }).listen(9000, "127.0.0.1");
const proxy = spawn(BIN, [], { env: { ...process.env, DATA_DIR: data, MODE: "forward",
  LOGIN_URL: "http://auth.test.local:8000/_wap/login", COOKIE_DOMAIN: "test.local", RP_ID: "test.local",
  RP_ORIGINS: "http://auth.test.local:8000,http://enroll.test.local:8081", ENROLL_ENABLED: "true" }});
proxy.stderr.on("data", (d) => log.push(String(d)));
const until = async (f, ms = 15000) => { const t = Date.now(); while (Date.now() - t < ms) { const v = await f(); if (v) return v; await new Promise((r) => setTimeout(r, 200)); } throw new Error("timeout\n" + log.join("")); };

(async () => {
  execFileSync(RUNTIME, ["run", "-d", "--rm", "--name", "wap-e2e-traefik", "--network=host", "-v", `${dyn}:/dyn.yml:ro`,
    "docker.io/library/traefik:v3", "--providers.file.filename=/dyn.yml", "--entrypoints.web.address=:8000", "--log.level=ERROR"]);
  const browser = await chromium.launch({ ...(process.env.CHROMIUM ? { executablePath: process.env.CHROMIUM } : {}), args: [
    "--host-resolver-rules=MAP *.test.local 127.0.0.1",
    "--unsafely-treat-insecure-origin-as-secure=http://auth.test.local:8000,http://enroll.test.local:8081"] });
  try {
    const token = (await until(() => /Jeton d'amorçage de l'enrôlement : (\S+)/.exec(log.join(""))))[1];
    const ctx = await browser.newContext(); const page = await ctx.newPage();
    const cdp = await ctx.newCDPSession(page); await cdp.send("WebAuthn.enable");
    await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });

    await until(() => new Promise((res) => http.get({ host: "127.0.0.1", port: 8000, headers: { Host: "app.test.local:8000", Accept: "application/json" } },
      (r) => { r.resume(); res(r.statusCode === 401); }).on("error", () => res(false))));
    step("Traefik démarré, accès anonyme refusé (401)");
    await page.goto("http://app.test.local:8000/page?x=1");
    assert.match(page.url(), /^http:\/\/auth\.test\.local:8000\/_wap\/login\?next=/); step("navigateur redirigé vers l'hôte de login");

    await page.goto("http://enroll.test.local:8081/");
    await page.fill("#token", token); await page.fill("#name", "remi"); await page.click("#f button");
    await page.waitForSelector("#msg.ok"); step("enrôlement (amorçage)");

    await page.goto("http://app.test.local:8000/page?x=1"); await page.click("#go");
    await page.waitForURL("http://app.test.local:8000/page?x=1");
    assert.match(await page.textContent("body"), /SECRET user=remi/); step("connexion puis retour sur la page demandée, utilisateur transmis");

    await page.goto("http://auth.test.local:8000/_wap/login?next=" + encodeURIComponent("https://evil.com/")); await page.click("#go");
    await page.waitForTimeout(1500);
    assert.ok(!page.url().includes("evil.com")); step("redirection ouverte (next=evil.com) neutralisée");
    console.log("\nTous les scénarios forwardAuth passent.");
  } finally {
    await browser.close(); proxy.kill(); upstream.close();
    try { execFileSync(RUNTIME, ["kill", "wap-e2e-traefik"]); } catch {}
    fs.rmSync(data, { recursive: true, force: true });
  }
})().catch((e) => { console.error("ÉCHEC:", e); process.exit(1); });
