// Runs the two complete examples (examples/*/compose.yml) exactly as written, with the locally built image, and
// drives Chromium (virtual passkey) through them. Needs: podman or docker with compose, a built image.
//   IMAGE=localhost/webauthnproxy:examples (default; build with `make image-examples`)
//   CHROMIUM=/path/to/chromium (optional). With podman, the compose provider needs the podman socket:
//   this script starts `podman system service` itself when DOCKER_HOST is unset.
const { chromium } = require("playwright");
const { spawn, execFileSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const assert = require("assert");

const ROOT = path.resolve(__dirname, "../..");
const IMAGE = process.env.IMAGE || "localhost/webauthnproxy:examples";
const usePodman = process.env.RUNTIME ? process.env.RUNTIME === "podman" : (() => { try { execFileSync("podman", ["--version"]); return true; } catch { return false; } })();
let service;
const env = { ...process.env, WAP_IMAGE: IMAGE };
const step = (m) => console.log("✔", m);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function prepare() {
  if (usePodman && !process.env.DOCKER_HOST) {
    const sock = path.join(require("os").tmpdir(), "wap-examples-podman.sock");
    try { fs.unlinkSync(sock); } catch {}
    service = spawn("podman", ["system", "service", "--time=0", "unix://" + sock], { stdio: "ignore" });
    for (let i = 0; i < 50 && !fs.existsSync(sock); i++) await sleep(100);
    env.DOCKER_HOST = "unix://" + sock;
  }
}
const compose = (dir, ...args) => execFileSync("docker", ["compose", "-f", path.join(ROOT, "examples", dir, "compose.yml"), "-p", "wapex-" + dir, ...args],
  { env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });

async function healthy(dir) {
  // the status computed by the engine from the container's HEALTHCHECK (compose's own "ps" does not always report it)
  let status = "";
  for (let i = 0; i < 90; i++) {
    // podman schedules healthchecks with systemd timers, which a minimal environment may lack: run it by hand
    if (usePodman) try { execFileSync("podman", ["healthcheck", "run", `wapex-${dir}-webauthnproxy-1`], { stdio: "ignore" }); } catch {}
    try { status = execFileSync("docker", ["inspect", "--format", "{{.State.Health.Status}}", `wapex-${dir}-webauthnproxy-1`], { env, encoding: "utf8" }).trim(); } catch {}
    if (status === "healthy") return;
    await sleep(1000);
  }
  throw new Error(`webauthnproxy never became healthy (status "${status}")\n` + compose(dir, "logs", "webauthnproxy"));
}

async function newPage(browser) {
  const ctx = await browser.newContext(); const page = await ctx.newPage();
  const cdp = await ctx.newCDPSession(page); await cdp.send("WebAuthn.enable");
  await cdp.send("WebAuthn.addVirtualAuthenticator", { options: { protocol: "ctap2", transport: "internal", hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
  return page;
}
async function enroll(page, dir, host) {
  const token = /Enrollment bootstrap token: (\S+)/.exec(compose(dir, "logs", "webauthnproxy"))[1];
  await page.goto(`http://${host}:8081/`);
  await page.fill("#token", token); await page.fill("#name", "remi"); await page.click("#f button");
  await page.waitForSelector("#msg.ok");
}
// Node cannot resolve *.localhost: connect to the published port and name the site in the Host header.
const http = require("http");
const raw = (host, urlPath) => new Promise((res, rej) => http.get({ host: "127.0.0.1", port: 8000, path: urlPath, headers: { Host: host, Accept: "application/json" } },
  (r) => { r.resume(); res(r.statusCode); }).on("error", rej));
const retry = async (f) => { for (let i = 0; ; i++) { try { return await f(); } catch (e) { if (i > 20) throw e; await sleep(500); } } };

async function proxyExample(browser) {
  const dir = "proxy-traefik";
  compose(dir, "up", "-d"); await healthy(dir); step("proxy example: containers up, container healthcheck passes");
  const page = await newPage(browser);
  await retry(async () => { assert.equal(await raw("app.localhost:8000", "/"), 401); });
  step("proxy example: anonymous API request refused (401)");
  await enroll(page, dir, "app.localhost"); step("proxy example: first passkey enrolled with the bootstrap token");
  await page.goto("http://app.localhost:8000/"); await page.click("#go");
  await page.waitForURL("http://app.localhost:8000/");
  const body = await page.textContent("body");
  assert.match(body, /X-Authenticated-User: remi/i); assert.ok(!/wap_session/.test(body), "the session cookie reached the site");
  step("proxy example: signed in, the site receives X-Authenticated-User and not the session cookie");

  // the command line administration, inside the running container
  const wap = (...a) => { try { return execFileSync("docker", ["exec", "wapex-proxy-traefik-webauthnproxy-1", "/webauthnproxy", ...a], { env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }); } catch (e) { return "ERR " + e.stderr; } };
  const list = wap("passkeys", "list");
  assert.match(list, /user=remi/); step("proxy example: 'passkeys list' shows the passkey");
  const tag = /^(\S+)\s+user=remi/m.exec(list)[1];
  assert.match(wap("passkeys", "revoke", tag), /last passkey/); step("proxy example: 'passkeys revoke' refuses to delete the last passkey");
  assert.match(wap("signout", "remi"), /signed out everywhere/);
  await page.goto("http://app.localhost:8000/");
  assert.match(page.url(), /_wap\/login/); step("proxy example: 'signout remi' ends the session that was open");
}

async function forwardExample(browser) {
  const dir = "two-domains";
  compose(dir, "up", "-d"); await healthy(dir); step("two-domains example: containers up, container healthcheck passes");
  const page = await newPage(browser);
  await retry(async () => { assert.equal(await raw("one.localhost:8000", "/"), 401); });
  step("two-domains example: anonymous API request refused (401)");
  await enroll(page, dir, "auth.localhost"); step("two-domains example: first passkey enrolled");
  await page.goto("http://one.localhost:8000/");
  assert.match(page.url(), /^http:\/\/auth\.localhost:8000\/_wap\/login/);
  await page.click("#go"); await page.waitForURL("http://one.localhost:8000/");
  let body = await page.textContent("body");
  assert.match(body, /X-Authenticated-User: remi/i); assert.match(body, /site-one/);
  step("two-domains example: site one asks for a passkey, then serves with the user header");
  await page.goto("http://two.localhost:8000/");
  assert.match(await page.textContent("body"), /site-two/);
  assert.match(await page.textContent("body"), /X-Authenticated-User: remi/i);
  assert.equal(new URL(page.url()).host, "two.localhost:8000");
  step("two-domains example: site two opens without a second prompt (single sign-on across domains)");
  assert.equal(await raw("auth.localhost:8000", "/_wap/verify"), 404); step("two-domains example: /_wap/verify is not reachable from the public login host");
}

(async () => {
  await prepare();
  const browser = await chromium.launch(process.env.CHROMIUM ? { executablePath: process.env.CHROMIUM } : {});
  let failed = false;
  try {
    for (const run of [["proxy-traefik", proxyExample], ["two-domains", forwardExample]]) {
      try { await run[1](browser); } finally { try { compose(run[0], "down", "-v"); } catch {} }
    }
    console.log("\nBoth examples work as written.");
  } catch (e) { failed = true; console.error("FAILED:", e); }
  await browser.close(); if (service) service.kill();
  process.exit(failed ? 1 : 0);
})();
