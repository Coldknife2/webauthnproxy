const msg = document.getElementById("msg");
const say = (t, c) => { msg.textContent = t; msg.className = c || ""; };
const $ = (id) => document.getElementById(id);

async function refresh() {
  const st = await api("/api/state", "GET");
  $("boot").hidden = $("token").hidden = !st.bootstrap;
  $("token").required = st.bootstrap;
  $("out").hidden = !st.user;
  $("who").textContent = st.user ? "Connecté en tant que " + st.user : "";
  const users = await api("/api/users", "GET");
  const ul = $("list"); ul.replaceChildren();
  if (!users.length) ul.textContent = "Aucune.";
  for (const u of users) for (const [i, c] of u.credentials.entries()) {
    const li = document.createElement("li");
    li.append(u.name + " — passkey #" + (i + 1) + " ");
    const b = document.createElement("button"); b.className = "del"; b.textContent = "Supprimer";
    b.onclick = async () => {
      if (!confirm("Supprimer cette passkey ?")) return;
      try { await api("/api/credentials?user=" + u.id + "&id=" + c.id, "DELETE"); refresh(); }
      catch (e) { say(e.message, "err"); }
    };
    li.append(b); ul.append(li);
  }
}

$("f").onsubmit = async (e) => {
  e.preventDefault(); say("Suivez les instructions du navigateur…");
  extraHeaders = $("token").value ? { "X-Bootstrap-Token": $("token").value } : {};
  try {
    await registerPasskey("/api", $("name").value);
    say("Passkey enregistrée ✔", "ok");
    // Après la première passkey, la page exige une connexion : on recharge.
    setTimeout(() => location.reload(), 800);
  } catch (e) { say(e.message, "err"); }
};
refresh().catch((e) => say(e.message, "err"));
