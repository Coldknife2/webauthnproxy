#!/usr/bin/env python3
"""Footprint benchmark: webauthnproxy vs Authelia, same machine, same load generator.

Measures, for each service running in a container (forwardAuth mode, authenticated check on every request):
  startup time, idle memory (RSS) and CPU, memory/CPU/throughput under load, image size.

Linux only (reads /proc of the container's process). Needs podman or docker, Go, and the images:
  make image RUNTIME=podman            # builds the local "webauthnproxy" image
  python3 test/bench/bench.py          # takes ~3 minutes

Environment: WAP_IMAGE (default webauthnproxy), AUTHELIA_IMAGE (default docker.io/authelia/authelia:latest),
BENCH_SETTLE (seconds to wait before the idle measurement, default 45), BENCH_DURATION (default 10).
"""
import base64, hashlib, hmac, json, os, re, shutil, subprocess, sys, tempfile, time, urllib.request

RT = os.environ.get("RUNTIME") or ("podman" if shutil.which("podman") else "docker")
WAP = os.environ.get("WAP_IMAGE", "webauthnproxy")
AUTHELIA = os.environ.get("AUTHELIA_IMAGE", "docker.io/authelia/authelia:latest")
SETTLE = int(os.environ.get("BENCH_SETTLE", "45"))
DUR = os.environ.get("BENCH_DURATION", "10") + "s"
HERE = os.path.dirname(os.path.abspath(__file__))
TMP = tempfile.mkdtemp(prefix="wap-bench-")
SECRET = "bench-secret-0123456789abcdef"
TICK = os.sysconf("SC_CLK_TCK")


def sh(*a, check=True):
    return subprocess.run(a, check=check, capture_output=True, text=True).stdout.strip()


def b64(x):
    return base64.urlsafe_b64encode(x).rstrip(b"=").decode()


def wap_cookie(user, aud):
    p = ".".join([b64(user.encode()), b64(aud.encode()), str(int(time.time()) + 86400)])
    return p + "." + b64(hmac.new(SECRET.encode(), ("s|" + p).encode(), hashlib.sha256).digest())


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


def measure(name, pid, url, headers, extra=None):
    r = {"startup_s": extra}
    time.sleep(SETTLE)
    m = mem(pid)
    r["idle_rss_mib"], r["idle_anon_mib"] = m["VmRSS"], m["RssAnon"]
    c0 = cpu_s(pid)
    time.sleep(20)
    r["idle_cpu_pct"] = (cpu_s(pid) - c0) / 20 * 100
    for c in (4, 32):
        c0 = cpu_s(pid)
        res = load(url, headers, c)
        res["cpu_ms_per_1k"] = (cpu_s(pid) - c0) * 1000 / (res["requests"] / 1000)
        res["rss_mib"], res["peak_mib"] = mem(pid)["VmRSS"], mem(pid)["VmHWM"]
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
        t0 = time.time()
        sh(RT, "run", "-d", "--name", "wap-bench", "-p", "18080:8080", "-v", f"{data}:/data",
           "-e", "MODE=forward", "-e", "LOGIN_URL=https://auth.example.com/_wap/login", "-e", "ALLOWED_HOSTS=app.example.com",
           "-e", "RP_ID=example.com", "-e", "RP_ORIGINS=https://auth.example.com", "-e", f"SESSION_SECRET={SECRET}", WAP)
        wait_http("http://127.0.0.1:18080/_wap/verify"); up = time.time() - t0
        hdr = ["Host: app.example.com", "X-Forwarded-Host: app.example.com", "X-Forwarded-Uri: /",
               "Cookie: wap_session=" + wap_cookie("bench", "app.example.com")]
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
    finally:
        for n in names:
            sh(RT, "rm", "-f", n, check=False)
    print(json.dumps(results, indent=2))
    w, a = results["webauthnproxy"], results["authelia"]
    row = lambda label, f: print(f"| {label} | {f(w)} | {f(a)} |")
    print("\n| | webauthnproxy | Authelia |\n|---|---|---|")
    row("Image size", lambda r: f"{r['image_mib']:.0f} MiB")
    row("Start to first answer (container create included)", lambda r: f"{r['startup_s']:.2f} s")
    row("Idle memory (RSS, anonymous)", lambda r: f"{r['idle_rss_mib']:.0f} MiB ({r['idle_anon_mib']:.0f})")
    row("Idle CPU", lambda r: f"{r['idle_cpu_pct']:.2f} %")
    for c in (4, 32):
        row(f"Auth check, {c} connections", lambda r: f"{r[f'c{c}']['rps']:,} req/s, p99 {r[f'c{c}']['p99']}")
        row(f"  server CPU per 1000 requests", lambda r: f"{r[f'c{c}']['cpu_ms_per_1k']:.0f} ms")
    row("Peak memory under load", lambda r: f"{max(r['c4']['peak_mib'], r['c32']['peak_mib']):.0f} MiB")


try:
    main()
finally:
    shutil.rmtree(TMP, ignore_errors=True)
