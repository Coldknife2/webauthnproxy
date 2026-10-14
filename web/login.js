 const next = new URLSearchParams(location.search).get("next") || "/";
 const dest = next.startsWith("/") && !next.startsWith("//") && !next.startsWith("/\\") ? next : "/";
 const btn = document.getElementById("go"), err = document.getElementById("err");
 btn.onclick = async () => {
   err.textContent = ""; btn.disabled = true;
   try { await loginWithPasskey(); location.replace(dest); }
   catch (e) { err.textContent = e.message; btn.disabled = false; }
 };
