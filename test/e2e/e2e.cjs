// Test de bout en bout : démarre un faux site, le proxy (binaire compilé) et pilote Chromium
// avec un authenticator WebAuthn virtuel.
//   cd test/e2e && npm install && npx playwright install chromium && npm test
// Variables : BIN (binaire, défaut ../../webauthnproxy), CHROMIUM (chemin d'un Chromium existant).
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
  ENROLL_ENABLED: "true", TOOL_ENABLED: "true",
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
    const token = (await until(() => /Jeton d'amorçage de l'enrôlement : (\S+)/.exec(log.join(""))))[1];
    const api = (u, h = {}) => fetch("http://localhost:8080" + u, { headers: h, redirect: "manual" });

    // 1. Proxy fermé tant qu'on n'est pas authentifié
    assert.equal((await api("/", { Accept: "application/json" })).status, 401);
    const red = await api("/x?y=1", { Accept: "text/html" });
    assert.equal(red.status, 302); assert.match(red.headers.get("location"), /^\/_wap\/login\?next=/);
    step("accès anonyme refusé (401 / redirection vers le login)");

    // 2. Enrôlement automatique (8081) : amorçage par jeton, puis protégé par passkey
    const alice = await newPage(browser);
    await alice.goto("http://localhost:8081/");
    await alice.fill("#name", "alice");
    await alice.fill("#token", "mauvais"); await alice.click("#f button");
    await alice.waitForSelector("#msg.err"); step("jeton d'amorçage invalide refusé");
    await alice.fill("#token", token); await alice.click("#f button");
    await alice.waitForSelector("#msg.ok"); step("première passkey créée avec le jeton d'amorçage");
    await alice.waitForURL(/\/_wap\/login/); step("l'enrôlement exige maintenant une connexion par passkey");
    assert.equal((await fetch("http://localhost:8081/api/users", { headers: { Accept: "application/json" } })).status, 401);
    await alice.click("#go"); await alice.waitForURL("http://localhost:8081/");
    await alice.waitForSelector("#list li"); step("connexion à l'enrôlement avec la passkey existante");

    // 3. Le proxy laisse passer alice (le cookie d'un hôte est partagé entre ports), sans le transmettre au site
    await alice.goto("http://localhost:8080/secret");
    const body = await alice.textContent("body");
    assert.match(body, /SECRET user=alice cookie=undefined/); step("proxy : accès accordé, utilisateur transmis, cookie retiré");

    // 4. Outil statique (8082) : passkey d'un autre utilisateur dans un autre navigateur, import à la main
    const bob = await newPage(browser);
    await bob.goto("http://localhost:8082/"); assert.equal(await bob.inputValue("#rp"), "localhost");
    await bob.fill("#name", "bob"); await bob.click("#go"); await bob.waitForSelector("#res:not([hidden])");
    const json = await bob.inputValue("#json");
    assert.equal(JSON.parse(json).user.name, "bob");
    assert.ok(!json.includes("PRIVATE"), "pas de secret");
    step("outil statique : JSON d'import produit");
    await bob.goto("http://localhost:8080/"); await bob.click("#go");
    await bob.waitForSelector("#err:not(:empty)"); step("bob refusé tant que le fichier n'est pas importé");
    fs.writeFileSync(path.join(data, "import", "bob.json"), json);
    await until(() => fs.existsSync(path.join(data, "import", "bob.json.imported"))); step("fichier importé à la main");
    await bob.goto("http://localhost:8080/"); await bob.click("#go"); await bob.waitForURL("http://localhost:8080/");
    assert.match(await bob.textContent("body"), /SECRET user=bob/); step("bob se connecte avec la passkey importée");

    // 5. Suppression d'une passkey possible, de la dernière impossible
    await alice.goto("http://localhost:8081/"); await alice.waitForSelector("#list li >> nth=1");
    alice.once("dialog", (d) => d.accept());
    await alice.click("#list li >> nth=1 >> button");
    await until(async () => (await alice.locator("#list li").count()) === 1); step("suppression d'une passkey (bob)");
    const last = await alice.evaluate(async () => {
      const u = (await (await fetch("/api/users")).json())[0];
      return (await fetch(`/api/credentials?user=${u.id}&id=${u.credentials[0].id}`, { method: "DELETE", headers: { "X-Requested-With": "wap" } })).status;
    });
    assert.equal(last, 409); step("la dernière passkey est protégée contre la suppression");
    console.log("\nTous les scénarios passent.");
  } finally {
    await browser.close(); proxy.kill(); upstream.close(); fs.rmSync(data, { recursive: true, force: true });
  }
})().catch((e) => { console.error("ÉCHEC:", e); process.exit(1); });
