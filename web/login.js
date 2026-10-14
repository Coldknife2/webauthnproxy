const next = new URLSearchParams(location.search).get("next") || "/";
const btn = document.getElementById("go"), err = document.getElementById("err");
btn.onclick = async () => {
  err.textContent = ""; btn.disabled = true;
  try { const r = await loginWithPasskey(next); location.replace(r.next); }
  catch (e) { err.textContent = e.message; btn.disabled = false; }
};
