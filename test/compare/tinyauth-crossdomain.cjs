// Experiment: does ONE Tinyauth login cover a site on an UNRELATED domain? (Tinyauth sets its cookie for the parent domain of its URL.)
// Real Traefik (forwardAuth) + official Tinyauth image + Chromium. The login method is irrelevant to cookie scoping, so a local user is used
// (Pocket ID would only be the identity source behind Tinyauth's OIDC login; it was not part of this test).
//   RUNTIME=podman|docker, TINYAUTH_IMAGE (default ghcr.io/tinyauthapp/tinyauth:v5), CHROMIUM (path of a Chromium), NODE_PATH (playwright)
const { chromium } = require("playwright");
const { execFileSync } = require("child_process");
const http = require("http");
const fs = require("fs");
const os = require("os");
const path = require("path");
const assert = require("assert");

const RUNTIME = process.env.RUNTIME || (() => { try { execFileSync("podman", ["--version"]); return "podman"; } catch { return "docker"; } })();
const IMAGE = process.env.TINYAUTH_IMAGE || "ghcr.io/tinyauthapp/tinyauth:v5";
const PASSWORD = "benchpass123";
const HASH = "$2b$10$XJOPaa5vIDwb0pXA.ztfauXHGPcU9kzGHdRI1hh9SGk6Ho/sod2eK"; // bcrypt of PASSWORD (test-only)
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "wap-cmp-"));
for (const d of ["resources", "oidc", "tailscale"]) fs.mkdirSync(path.join(tmp, "data", d), { recursive: true });
execFileSync("chmod", ["-R", "a+rwX", tmp]);
fs.writeFileSync(path.join(tmp, "dyn.yml"), fs.readFileSync(path.join(__dirname, "dyn-tinyauth.yml")));
const rm = (n) => { try { execFileSync(RUNTIME, ["rm", "-f", n], { stdio: "ignore" }); } catch {} };
const upstream = http.createServer((q, r) => r.end("UPSTREAM host=" + q.headers.host + " remote-user=" + q.headers["remote-user"])).listen(9000, "127.0.0.1");
const log = (m) => console.log(m);

async function login(page) {
  await page.fill('input[name=username]', "bench");
  await page.fill('input[name=password]', PASSWORD);
  await page.click('button[type=submit]');
}

(async () => {
  rm("cmp-tinyauth"); rm("cmp-traefik");
  execFileSync(RUNTIME, ["run", "-d", "--name", "cmp-tinyauth", "--network=host", "--user", "0", "-v", path.join(tmp, "data") + ":/data",
    "-e", "TINYAUTH_APPURL=http://auth.test.local:8000", "-e", "TINYAUTH_AUTH_USERS=bench:" + HASH, "-e", "TINYAUTH_LOG_LEVEL=warn", IMAGE]);
  execFileSync(RUNTIME, ["run", "-d", "--name", "cmp-traefik", "--network=host", "-v", path.join(tmp, "dyn.yml") + ":/dyn.yml:ro",
    "docker.io/library/traefik:v3", "--providers.file.filename=/dyn.yml", "--entrypoints.web.address=:8000", "--log.level=ERROR"]);
  const version = execFileSync(RUNTIME, ["run", "--rm", IMAGE, "version"]).toString().replace(/\x1b\[[0-9;]*m/g, "").match(/Version: (\S+)/)[1];
  log("Tinyauth " + version + " behind Traefik; login host auth.test.local; sites: x.test.local (same parent domain) and a.siteone.test (unrelated domain)");
  const browser = await chromium.launch({ ...(process.env.CHROMIUM ? { executablePath: process.env.CHROMIUM } : { channel: "chromium" }),
    args: ["--host-resolver-rules=MAP *.test.local 127.0.0.1,MAP *.siteone.test 127.0.0.1"] });
  try {
    const ctx = await browser.newContext(); const page = await ctx.newPage();
    for (let i = 0; i < 50; i++) { try { const r = await page.goto("http://auth.test.local:8000/login"); if (r.ok()) break; } catch {} await new Promise((r) => setTimeout(r, 300)); }

    await page.goto("http://x.test.local:8000/"); await page.waitForURL(/auth\.test\.local:8000\/login/);
    log("1. anonymous visit of x.test.local          -> redirected to the Tinyauth login page");
    await login(page); await page.waitForURL("http://x.test.local:8000/", { timeout: 15000 });
    const body1 = await page.textContent("body");
    assert.match(body1, /remote-user=bench/);
    log("2. after login                               -> back on x.test.local, served: " + body1.trim());
    const cookies = await ctx.cookies();
    log("3. session cookie(s) set by Tinyauth         -> " + cookies.filter((c) => /tinyauth/.test(c.name)).map((c) => c.name.replace(/-[0-9a-f]{8}$/, "-…") + " domain=" + c.domain).join(", "));

    await page.goto("http://a.siteone.test:8000/");
    await page.waitForLoadState("networkidle");
    const landed = page.url();
    const text = (await page.textContent("body")).replace(/\s+/g, " ").trim().slice(0, 200);
    const served = /remote-user=bench/.test(text) && landed.startsWith("http://a.siteone.test");
    log("4. visit a.siteone.test (unrelated domain) while signed in to Tinyauth -> " + (served ? "SERVED" : "NOT served; Tinyauth sent the browser to " + landed + ' and shows: "' + text + '"'));
    assert.ok(!served, "the unrelated domain was served; the limitation does not hold");

    // signing in again does not help: the session cookie is still only valid for the parent domain of Tinyauth's URL
    await page.goto("http://auth.test.local:8000/login?login_for=app&redirect_uri=" + encodeURIComponent("http://a.siteone.test:8000/"));
    await page.waitForLoadState("networkidle");
    if (await page.locator("input[name=username]").count()) { await login(page); await page.waitForTimeout(4000); }
    const text2 = (await page.textContent("body")).replace(/\s+/g, " ").trim().slice(0, 200);
    const served2 = /remote-user=bench/.test(text2) && page.url().startsWith("http://a.siteone.test");
    log("5. explicit login with redirect_uri=a.siteone.test -> " + (served2 ? "SERVED" : "NOT served; browser is on " + page.url() + ' and shows: "' + text2 + '"'));
    assert.ok(!served2, "the unrelated domain was served after login");

    // the "Untrusted redirect" warning can be accepted, but the unrelated site still has no session cookie
    const cont = page.getByRole("button", { name: /continue/i });
    if (await cont.count()) {
      await cont.click(); await page.waitForTimeout(4000); await page.waitForLoadState("networkidle");
      const text3 = (await page.textContent("body")).replace(/\s+/g, " ").trim().slice(0, 160);
      const served3 = /remote-user=bench/.test(text3) && page.url().startsWith("http://a.siteone.test");
      log("6. accept the warning (Continue)             -> " + (served3 ? "SERVED" : "NOT served; browser is on " + page.url() + ' and shows: "' + text3 + '"'));
      assert.ok(!served3, "the unrelated domain was served after accepting the warning");
    }
    log("\nResult: one Tinyauth login covers x.test.local but not a.siteone.test (" + version + ").");
  } finally {
    await browser.close(); upstream.close(); rm("cmp-tinyauth"); rm("cmp-traefik"); fs.rmSync(tmp, { recursive: true, force: true });
  }
})().catch((e) => { console.error("FAILED:", e.message); process.exit(1); });
