#!/usr/bin/env python3
"""Footprint benchmark: webauthnproxy vs Authelia vs Pocket ID + Tinyauth, same machine, same load generator.

Measures, for each service running in a container (forwardAuth mode, authenticated check on every request):
  startup time, idle memory (RSS) and CPU, memory/CPU/throughput under load, image size.
Pocket ID + Tinyauth are two containers: Pocket ID (the passkey identity provider) is only involved at login, so the
authenticated checks hit Tinyauth; idle memory/CPU and image size are the sum of both.

Needs the Python package bcrypt (pip install bcrypt) to create the Tinyauth user.
Linux only (reads /proc of the container's process). Needs podman or docker, Go, and the images:
  make image RUNTIME=podman            # builds the local "webauthnproxy" image
  python3 test/bench/bench.py          # takes ~6 minutes

Environment: WAP_IMAGE (default webauthnproxy), AUTHELIA_IMAGE (default docker.io/authelia/authelia:latest),
POCKETID_IMAGE (default docker.io/pocketid/pocket-id:v2), TINYAUTH_IMAGE (default ghcr.io/tinyauthapp/tinyauth:v5),
BENCH_SETTLE (seconds to wait before the idle measurement, default 45), BENCH_DURATION (default 10).
"""
import base64, hashlib, json, os, re, shutil, subprocess, sys, tempfile, time, urllib.request

RT = os.environ.get("RUNTIME") or ("podman" if shutil.which("podman") else "docker")
WAP = os.environ.get("WAP_IMAGE", "webauthnproxy")
AUTHELIA = os.environ.get("AUTHELIA_IMAGE", "docker.io/authelia/authelia:latest")
POCKETID = os.environ.get("POCKETID_IMAGE", "docker.io/pocketid/pocket-id:v2")
TINYAUTH = os.environ.get("TINYAUTH_IMAGE", "ghcr.io/tinyauthapp/tinyauth:v5")
SETTLE = int(os.environ.get("BENCH_SETTLE", "45"))
DUR = os.environ.get("BENCH_DURATION", "10") + "s"
HERE = os.path.dirname(os.path.abspath(__file__))
TMP = tempfile.mkdtemp(prefix="wap-bench-")
TOKEN = "benchAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"   # the session cookie value of the benchmark; only its hash is written to sessions.json
TICK = os.sysconf("SC_CLK_TCK")


def sh(*a, check=True):
    p = subprocess.run(a, capture_output=True, text=True)
    if check and p.returncode:
        raise SystemExit(f"command failed ({p.returncode}): {' '.join(a)}\n{p.stderr.strip()}")
    return p.stdout.strip()


def b64(x):
    return base64.urlsafe_b64encode(x).rstrip(b"=").decode()


def seed_sessions(data, aud="app.example.com"):
    """Write a sessions.json holding one live session for TOKEN (the service loads it at start)."""
    now = int(time.time())
    row = {"h": b64(hashlib.sha256(TOKEN.encode()).digest()), "user": "bench", "aud": aud, "created": now, "exp": now + 86400, "seen": now}
    json.dump([row], open(f"{data}/sessions.json", "w"))
    os.chown(f"{data}/sessions.json", 65532, 65532)


def pid_of(name):
    return int(sh(RT, "inspect", "-f", "{{.State.Pid}}", name))


def mem(pid):
    d = {}
    for line in open(f"/proc/{pid}/status"):
        k, _, v = line.partition(":")
        if k in ("VmRSS", "VmHWM", "RssAnon", "RssFile"):
            d[k] = int(v.split()[0]) / 1024
    return d


def cpu_s(pid):
    f = open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()
    return (int(f[11]) + int(f[12])) / TICK


def wait_http(url, timeout=60):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            urllib.request.urlopen(urllib.request.Request(url), timeout=1)
            return time.time() - t0
        except urllib.error.HTTPError:
            return time.time() - t0  # any HTTP answer = up
        except Exception:
            time.sleep(0.05)
    raise SystemExit(f"{url} did not come up")


def load(url, headers, c):
    args = [os.path.join(TMP, "loadgen"), "-url", url, "-c", str(c), "-d", DUR]
    for h in headers:
        args += ["-H", h]
    out = sh(*args)
    m = re.search(r"requests=(\d+) errors=(\d+) rps=(\d+) p50=(\S+) p99=(\S+) codes=map\[(.*)\]", out)
    assert m and m.group(2) == "0" and m.group(6).startswith("200:"), out
    return dict(requests=int(m.group(1)), rps=int(m.group(3)), p99=m.group(5))


def measure(name, pid, url, headers, extra=None, companions=()):
    """Idle figures cover pid plus companion pids; the load test hits url served by pid."""
    r = {"startup_s": extra}
    time.sleep(SETTLE)
    allp = [pid, *companions]
    m = mem(pid)
    r["idle_rss_mib"] = sum(mem(p)["VmRSS"] for p in allp)
    r["idle_anon_mib"] = sum(mem(p)["RssAnon"] for p in allp)
    c0 = sum(cpu_s(p) for p in allp)
    time.sleep(20)
    r["idle_cpu_pct"] = (sum(cpu_s(p) for p in allp) - c0) / 20 * 100
    for c in (4, 32):
        c0 = cpu_s(pid)
        res = load(url, headers, c)
        res["cpu_ms_per_1k"] = (cpu_s(pid) - c0) * 1000 / (res["requests"] / 1000)
        res["rss_mib"] = sum(mem(p)["VmRSS"] for p in allp)
        res["peak_mib"] = mem(pid)["VmHWM"] + sum(mem(p)["VmHWM"] for p in companions)
        r[f"c{c}"] = res
    return r


def image_mib(img):
    return int(sh(RT, "image", "inspect", "-f", "{{.Size}}", img)) / 1048576


def main():
    sh("go", "build", "-o", os.path.join(TMP, "loadgen"), os.path.join(HERE, "loadgen.go"))
    results, names = {}, ["wap-bench", "authelia-bench"]
    for n in names:
        sh(RT, "rm", "-f", n, check=False)
    try:
        # ---- webauthnproxy
        data = os.path.join(TMP, "data"); os.makedirs(data)
        uid = hashlib.sha256(b"webauthnproxy:user:bench").digest()
        json.dump({"users": [{"id": base64.b64encode(uid).decode(), "name": "bench",
                              "credentials": [{"id": "AQID", "publicKey": "AQID"}]}]}, open(f"{data}/users.json", "w"))
        os.chown(data, 65532, 65532); os.chown(f"{data}/users.json", 65532, 65532)
        seed_sessions(data)
        t0 = time.time()
        sh(RT, "run", "-d", "--name", "wap-bench", "-p", "18080:8080", "-v", f"{data}:/data",
           "-e", "MODE=forward", "-e", "LOGIN_URL=https://auth.example.com/_wap/login", "-e", "ALLOWED_HOSTS=app.example.com",
           "-e", "RP_ID=example.com", "-e", "RP_ORIGINS=https://auth.example.com",
           "-e", "TRUSTED_PROXIES=0.0.0.0/0", WAP)  # benchmark only: the load generator is the "proxy"
        wait_http("http://127.0.0.1:18080/_wap/verify"); up = time.time() - t0
        hdr = ["Host: app.example.com", "X-Forwarded-Host: app.example.com", "X-Forwarded-Uri: /",
               "Cookie: wap_session=" + TOKEN]
        results["webauthnproxy"] = measure("wap", pid_of("wap-bench"), "http://127.0.0.1:18080/_wap/verify", hdr, up)
        results["webauthnproxy"]["image_mib"] = image_mib(WAP)
        sh(RT, "rm", "-f", "wap-bench")

        # ---- Authelia (file users, sqlite, one_factor, forward-auth)
        cfg = os.path.join(TMP, "authelia"); os.makedirs(cfg)
        digest = sh(RT, "run", "--rm", AUTHELIA, "authelia", "crypto", "hash", "generate", "argon2", "--password", "benchpass123").split("Digest: ")[1]
        open(f"{cfg}/users.yml", "w").write(f"users:\n  bench:\n    displayname: bench\n    password: '{digest}'\n    email: bench@example.com\n    groups: []\n")
        open(f"{cfg}/configuration.yml", "w").write("""server:
  address: 'tcp://:9091'
  endpoints:
    authz:
      forward-auth:
        implementation: 'ForwardAuth'
log: {level: warn}
identity_validation: {reset_password: {jwt_secret: 'bench-jwt-secret-0123456789abcdef'}}
authentication_backend: {file: {path: /config/users.yml}}
access_control: {default_policy: one_factor}
session:
  secret: 'bench-session-secret-0123456789abcdef'
  cookies: [{domain: example.com, authelia_url: 'https://auth.example.com', default_redirection_url: 'https://app.example.com'}]
storage: {encryption_key: 'bench-encryption-key-0123456789abcdef', local: {path: /config/db.sqlite3}}
notifier: {filesystem: {filename: /config/notification.txt}}
""")
        subprocess.run(["chmod", "-R", "a+rwX", cfg], check=True)
        t0 = time.time()
        sh(RT, "run", "-d", "--name", "authelia-bench", "-p", "19091:9091", "-v", f"{cfg}:/config", AUTHELIA)
        wait_http("http://127.0.0.1:19091/api/health"); up = time.time() - t0
        pid = pid_of("authelia-bench")
        req = urllib.request.Request("http://127.0.0.1:19091/api/firstfactor", method="POST",
            data=json.dumps({"username": "bench", "password": "benchpass123", "keepMeLoggedIn": False}).encode(),
            headers={"Content-Type": "application/json", "X-Forwarded-Proto": "https", "X-Forwarded-Host": "auth.example.com"})
        cookie = re.search(r"authelia_session=([^;]+)", urllib.request.urlopen(req).headers["Set-Cookie"]).group(1)
        hdr = ["X-Forwarded-Method: GET", "X-Forwarded-Proto: https", "X-Forwarded-Host: app.example.com",
               "X-Forwarded-Uri: /", "Cookie: authelia_session=" + cookie]
        login_peak = mem(pid)["VmHWM"]
        results["authelia"] = measure("authelia", pid, "http://127.0.0.1:19091/api/authz/forward-auth", hdr, up)
        results["authelia"]["image_mib"] = image_mib(AUTHELIA)
        results["authelia"]["peak_after_login_mib"] = login_peak
        sh(RT, "rm", "-f", "authelia-bench")

        # ---- Pocket ID (passkey OIDC provider) + Tinyauth (forward-auth, local user)
        pdata = os.path.join(TMP, "pocketid"); os.makedirs(pdata); os.chown(pdata, 1000, 1000)
        tdata = os.path.join(TMP, "tinyauth")
        for d in ("resources", "oidc", "tailscale"):
            os.makedirs(os.path.join(tdata, d))
        subprocess.run(["chmod", "-R", "a+rwX", tdata], check=True)
        t0 = time.time()
        sh(RT, "run", "-d", "--name", "pocketid-bench", "-p", "11411:1411", "-v", f"{pdata}:/app/data",
           "-e", "APP_URL=http://localhost:11411", "-e", "ENCRYPTION_KEY=bench-encryption-key-0123456789",
           "-e", "ANALYTICS_DISABLED=true", POCKETID)
        wait_http("http://127.0.0.1:11411/"); pocket_up = time.time() - t0
        import bcrypt
        pw_hash = bcrypt.hashpw(b"benchpass123", bcrypt.gensalt(10)).decode()
        t0 = time.time()
        sh(RT, "run", "-d", "--name", "tinyauth-bench", "--user", "0", "-p", "13000:3000", "-v", f"{tdata}:/data",
           "-e", "TINYAUTH_APPURL=http://auth.example.com", "-e", f"TINYAUTH_AUTH_USERS=bench:{pw_hash}",
           "-e", "TINYAUTH_LOG_LEVEL=warn", "-e", "TINYAUTH_LOG_STREAMS_HTTP_ENABLED=false", TINYAUTH)  # quietest settings, like the others
        wait_http("http://127.0.0.1:13000/"); tiny_up = time.time() - t0
        req = urllib.request.Request("http://127.0.0.1:13000/api/user/login", method="POST",
            data=json.dumps({"username": "bench", "password": "benchpass123"}).encode(), headers={"Content-Type": "application/json"})
        pair = re.search(r"(tinyauth-session[^=]*=[^;]+)", urllib.request.urlopen(req).headers["Set-Cookie"]).group(1)
        hdr = ["X-Forwarded-Host: app.example.com", "X-Forwarded-Uri: /", "X-Forwarded-Proto: http", "Cookie: " + pair]
        r = measure("tinyauth", pid_of("tinyauth-bench"), "http://127.0.0.1:13000/api/auth/traefik", hdr, tiny_up,
                    companions=[pid_of("pocketid-bench")])
        r["startup_pocketid_s"] = pocket_up
        r["image_mib"] = image_mib(POCKETID) + image_mib(TINYAUTH)
        r["parts"] = {"pocketid_mib": mem(pid_of("pocketid-bench"))["VmRSS"], "tinyauth_mib": mem(pid_of("tinyauth-bench"))["VmRSS"],
                      "pocketid_image_mib": image_mib(POCKETID), "tinyauth_image_mib": image_mib(TINYAUTH)}
        results["pocketid+tinyauth"] = r
    finally:
        for n in names:
            sh(RT, "rm", "-f", n, check=False)
    print(json.dumps(results, indent=2))
    cols = [("webauthnproxy", "webauthnproxy"), ("authelia", "Authelia"), ("pocketid+tinyauth", "Pocket ID + Tinyauth")]
    print("\n| | " + " | ".join(n for _, n in cols) + " |\n|---|" + "---|" * len(cols))
    row = lambda label, f: print(f"| {label} | " + " | ".join(f(results[k]) for k, _ in cols) + " |")
    row("Image size", lambda r: f"{r['image_mib']:.0f} MiB")
    row("Start to first answer (container create included)", lambda r: f"{r['startup_s']:.2f} s")
    row("Idle memory (RSS, anonymous)", lambda r: f"{r['idle_rss_mib']:.0f} MiB ({r['idle_anon_mib']:.0f})")
    row("Idle CPU", lambda r: f"{r['idle_cpu_pct']:.2f} %")
    for c in (4, 32):
        row(f"Auth check, {c} connections", lambda r: f"{r[f'c{c}']['rps']:,} req/s, p99 {r[f'c{c}']['p99']}")
        row("  server CPU per 1000 requests", lambda r: f"{r[f'c{c}']['cpu_ms_per_1k']:.0f} ms")
    row("Peak memory during the run", lambda r: f"{max(r['c4']['peak_mib'], r['c32']['peak_mib']):.0f} MiB")


if __name__ == "__main__":
    try:
        main()
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
