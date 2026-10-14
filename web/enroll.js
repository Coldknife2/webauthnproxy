 const msg = document.getElementById("msg");
 const say = (t, c) => { msg.textContent = t; msg.className = c || ""; };
 async function refresh() {
   const users = await api("/api/users", "GET");
   const ul = document.getElementById("list"); ul.replaceChildren();
   if (!users.length) ul.textContent = "Aucun utilisateur.";
   for (const u of users) for (const [i, c] of u.credentials.entries()) {
     const li = document.createElement("li");
     li.append(u.name + " — passkey #" + (i + 1) + " ");
     const b = document.createElement("button"); b.className = "del"; b.textContent = "Supprimer";
     b.onclick = async () => {
       if (!confirm("Supprimer cette passkey ?")) return;
       await api("/api/credentials?user=" + u.id + "&id=" + c.id, "DELETE"); refresh();
     };
     li.append(b); ul.append(li);
   }
 }
 document.getElementById("f").onsubmit = async (e) => {
   e.preventDefault(); say("Suivez les instructions du navigateur…");
   try { await registerPasskey("/api", document.getElementById("name").value); say("Passkey enregistrée ✔", "ok"); refresh(); }
   catch (e) { say(e.message, "err"); }
 };
 refresh().catch((e) => say(e.message, "err"));
