// End-to-end test: starts a fake site and the proxy (compiled binary), and drives Chromium
// with a virtual WebAuthn authenticator.
//   cd test/e2e && npm install && npx playwright install chromium && npm test
// Variables: BIN (binary, default ../../webauthnproxy), CHROMIUM (path of an existing Chromium).
const { chromium } = require("playwright");
const { spawn } = require("child_process");
const http = require("http");
const fs = require("fs");
const os = require("os");
const path = require("path");
const assert = require("assert");

const BIN = process.env.BIN || path.resolve(__dirname, "../../webauthnproxy");
const data = fs.mkdtempSync(path.join(os.tmpdir(), "wap-e2e-"));
const log = [];
const step = (m) => console.log("✔", m);

const upstream = http.createServer((q, r) => {
  r.setHeader("content-type", "text/html");
  r.end(`SECRET user=${q.headers["x-authenticated-user"]} cookie=${q.headers.cookie}`);
}).listen(9000, "127.0.0.1");

const proxy = spawn(BIN, [], { env: {
  ...process.env, DATA_DIR: data, UPSTREAM: "http://127.0.0.1:9000", RP_ID: "localhost",
  RP_ORIGINS: "http://localhost:8080,http://localhost:8081,http://localhost:8082",
  ENROLL_ENABLED: "true", TOOL_ENABLED: "true", RATE_LIMIT_IP: "500/1m", RATE_LIMIT_GLOBAL: "off",
}});
proxy.stderr.on("data", (d) => log.push(String(d)));
proxy.stdout.on("data", (d) => log.push(String(d)));
const until = async (f, ms = 15000) => {
  const t = Date.now();
  while (Date.now() - t < ms) { const v = await f(); if (v) return v; await new Promise((r) => setTimeout(r, 200)); }
  throw new Error("timeout\n" + log.join(""));
};

async function newPage(browser) {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  const cdp = await ctx.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: {
    protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true,
    isUserVerified: true, automaticPresenceSimulation: true } });
  return page;
}

(async () => {
  const browser = await chromium.launch(process.env.CHROMIUM ? { executablePath: process.env.CHROMIUM } : {});
  try {
    const token = (await until(() => /Enrollment bootstrap token: (\S+)/.exec(log.join(""))))[1];
    const api = (u, h = {}) => fetch("http://localhost:8080" + u, { headers: h, redirect: "manual" });

    // 1. The proxy stays closed until authenticated
    assert.equal((await api("/", { Accept: "application/json" })).status, 401);
    const red = await api("/x?y=1", { Accept: "text/html" });
    assert.equal(red.status, 302); assert.match(red.headers.get("location"), /^\/_wap\/login\?next=/);
    step("anonymous access refused (401 / redirect to login)");

    // Language: English by default, French with ?lang=fr
    const lp = await newPage(browser);
    await lp.goto("http://localhost:8080/_wap/login");
    assert.equal(await lp.textContent("#go"), "Sign in with a passkey");
    await lp.goto("http://localhost:8080/_wap/login?lang=fr");
    assert.equal(await lp.textContent("#go"), "Se connecter avec une passkey");
    step("UI is English by default, French with ?lang=fr");

    // 2. Automatic enrollment (8081): token bootstrap, then protected by passkey
    const alice = await newPage(browser);
    await alice.goto("http://localhost:8081/");
    await alice.fill("#name", "alice");
    await alice.fill("#token", "mauvais"); await alice.click("#f button");
    await alice.waitForSelector("#msg.err"); step("invalid bootstrap token refused");
    await alice.fill("#token", token); await alice.click("#f button");
    await alice.waitForSelector("#msg.ok"); step("first passkey created with the bootstrap token");
    await alice.waitForURL(/\/_wap\/login/); step("enrollment now requires a passkey login");
    assert.equal((await fetch("http://localhost:8081/api/users", { headers: { Accept: "application/json" } })).status, 401);
    await alice.click("#go"); await alice.waitForURL("http://localhost:8081/");
    await alice.waitForSelector("#list li"); step("signed in to enrollment with the existing passkey");

    // 3. The proxy lets alice in (a host's cookie is shared across ports) without forwarding it to the site
    await alice.goto("http://localhost:8080/secret");
    const body = await alice.textContent("body");
    assert.match(body, /SECRET user=alice cookie=undefined/); step("proxy: access granted, user forwarded, cookie stripped");

    // 4. Static tool (8082): another user's passkey in another browser, imported by hand
    const bob = await newPage(browser);
    await bob.goto("http://localhost:8082/"); assert.equal(await bob.inputValue("#rp"), "localhost");
    await bob.fill("#name", "bob"); await bob.click("#go"); await bob.waitForSelector("#res:not([hidden])");
    const json = await bob.inputValue("#json");
    assert.equal(JSON.parse(json).user.name, "bob");
    assert.ok(!json.includes("PRIVATE"), "no secret");
    step("static tool: import JSON produced");
    await bob.goto("http://localhost:8080/"); await bob.click("#go");
    await bob.waitForSelector("#err:not(:empty)"); step("bob refused until the file is imported");
    fs.writeFileSync(path.join(data, "import", "bob.json"), json);
    await until(() => fs.existsSync(path.join(data, "import", "bob.json.imported"))); step("file imported by hand");
    await bob.goto("http://localhost:8080/"); await bob.click("#go"); await bob.waitForURL("http://localhost:8080/");
    assert.match(await bob.textContent("body"), /SECRET user=bob/); step("bob signs in with the imported passkey");

    // 5. Deleting a passkey works, deleting the last one does not
    await alice.goto("http://localhost:8081/"); await alice.waitForSelector("#list li >> nth=1");
    alice.once("dialog", (d) => d.accept());
    await alice.click("#list li >> nth=1 >> button");
    await until(async () => (await alice.locator("#list li").count()) === 1); step("deleted a passkey (bob)");
    const last = await alice.evaluate(async () => {
      const u = (await (await fetch("/api/users")).json())[0];
      return (await fetch(`/api/credentials?user=${u.id}&id=${u.credentials[0].id}`, { method: "DELETE", headers: { "X-Requested-With": "wap" } })).status;
    });
    assert.equal(last, 409); step("the last passkey cannot be deleted");
    // The audit log (JSON on standard output) recorded the security events, and no secret
    const out = log.join("");
    for (const ev of ["enroll_success", "enroll_failure", "login_success", "login_failure"]) assert.ok(out.includes(`"event":"${ev}"`), "audit event missing: " + ev);
    assert.ok(!out.includes("wap_session="), "a cookie reached the logs");
    step("audit log: enrollment and login events are recorded as JSON, without cookies");
    console.log("\nAll scenarios pass.");
  } finally {
    await browser.close(); proxy.kill(); upstream.close(); fs.rmSync(data, { recursive: true, force: true });
  }
})().catch((e) => { console.error("FAILED:", e); process.exit(1); });
