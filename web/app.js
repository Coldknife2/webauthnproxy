"use strict";
const P = "/_wap";
const enc = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const dec = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0)).buffer;

async function api(url, method, body) {
  const r = await fetch(url, {
    method, credentials: "same-origin",
    headers: { "Content-Type": "application/json", "X-Requested-With": "wap" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j.error || "erreur " + r.status);
  return j;
}

function credToJSON(c) {
  const r = c.response, out = { id: c.id, rawId: enc(c.rawId), type: c.type, response: {} };
  out.response.clientDataJSON = enc(r.clientDataJSON);
  if (r.attestationObject) {
    out.response.attestationObject = enc(r.attestationObject);
    if (r.getTransports) out.response.transports = r.getTransports();
  } else {
    out.response.authenticatorData = enc(r.authenticatorData);
    out.response.signature = enc(r.signature);
    if (r.userHandle) out.response.userHandle = enc(r.userHandle);
  }
  return out;
}

async function registerPasskey(apiBase, name) {
  const { cid, options } = await api(apiBase + "/register/begin", "POST", { name });
  const pk = options.publicKey;
  pk.challenge = dec(pk.challenge);
  pk.user.id = dec(pk.user.id);
  (pk.excludeCredentials || []).forEach((c) => (c.id = dec(c.id)));
  const cred = await navigator.credentials.create({ publicKey: pk });
  await api(apiBase + "/register/finish?cid=" + encodeURIComponent(cid), "POST", credToJSON(cred));
}

async function loginWithPasskey() {
  const { cid, options } = await api(P + "/login/begin", "POST");
  const pk = options.publicKey;
  pk.challenge = dec(pk.challenge);
  (pk.allowCredentials || []).forEach((c) => (c.id = dec(c.id)));
  const cred = await navigator.credentials.get({ publicKey: pk });
  await api(P + "/login/finish?cid=" + encodeURIComponent(cid), "POST", credToJSON(cred));
}
