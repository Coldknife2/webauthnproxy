const msg = document.getElementById("msg");
const say = (t, c) => { msg.textContent = t; msg.className = c || ""; };
const $ = (id) => document.getElementById(id);
const when = (s) => new Date(s * 1000).toLocaleString(LANG);

async function refresh() {
  const r = await api("/_wap/api/sessions", "GET");
  $("who").textContent = t("signedInAs") + " " + r.user;
  const ul = $("list"); ul.replaceChildren();
  for (const s of r.sessions) {
    const li = document.createElement("li");
    const b = document.createElement("b"); b.textContent = s.site || t("loginHost");
    li.append(b, s.current ? " (" + t("thisOne") + ")" : "", document.createElement("br"));
    const small = document.createElement("small");
    small.textContent = t("since") + " " + when(s.created) + " · " + t("lastSeen") + " " + when(s.lastSeen) + (s.userAgent ? " · " + s.userAgent : "");
    li.append(small, " ");
    const del = document.createElement("button"); del.className = "del"; del.textContent = t("endSession");
    del.onclick = async () => {
      if (!confirm(t("confirmEnd"))) return;
      try { await api("/_wap/api/sessions?id=" + encodeURIComponent(s.id), "DELETE"); s.current ? (location.href = "/_wap/login") : refresh(); }
      catch (e) { say(e.message, "err"); }
    };
    li.append(del); ul.append(li);
  }
}
$("others").onclick = async () => {
  if (!confirm(t("confirmOthers"))) return;
  try { await api("/_wap/api/sessions?others=1", "DELETE"); refresh(); } catch (e) { say(e.message, "err"); }
};
refresh().catch((e) => { if (/401|authentication/.test(e.message)) location.href = "/_wap/login?next=/_wap/sessions"; else say(e.message, "err"); });
