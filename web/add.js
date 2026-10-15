const msg = document.getElementById("msg");
const say = (t, c) => { msg.textContent = t; msg.className = c || ""; };
const $ = (id) => document.getElementById(id);

// The invitation code travels in the URL fragment: browsers never send it to a server, so it stays out of access logs.
const code = decodeURIComponent(location.hash.slice(1));
if (!code) { $("f").hidden = true; say(t("addNoCode"), "err"); }
else {
  extraHeaders = { "X-Invite-Code": code };
  $("f").onsubmit = async (e) => {
    e.preventDefault(); say(t("follow"));
    try {
      await registerPasskey("/_wap", "", $("label").value, { begin: "/_wap/add/begin", finish: "/_wap/add/finish" });
      $("f").hidden = true; say(t("addDone"), "ok");
      history.replaceState(null, "", location.pathname);
    } catch (e) { say(e.message, "err"); }
  };
}
