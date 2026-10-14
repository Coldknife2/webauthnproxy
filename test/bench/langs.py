#!/usr/bin/env python3
"""Language comparison: the forwardAuth hot path in Go (the real binary), Rust, .NET, Node and Python.

  make image RUNTIME=podman
  for d in go rust dotnet node python; do podman build -t lang-$d test/bench/langs/$d; done
  python3 test/bench/langs.py          # ~7 minutes

Same method as bench.py (see docs/performance.md): containers, /proc RSS and CPU, same load generator.
Environment: BENCH_SETTLE (default 20), BENCH_DURATION (default 10).
"""
import base64, hashlib, json, os, shutil, sys, time, urllib.request

os.environ.setdefault("BENCH_SETTLE", "20")
import bench
from bench import RT, SECRET, TMP, HERE, cpu_s, image_mib, load, mem, pid_of, sh, wait_http, wap_cookie

NAME = "lang-bench"
COOKIE = "wap_session=" + wap_cookie("bench", "app.example.com")
HEADERS = ["Host: app.example.com", "X-Forwarded-Host: app.example.com", "X-Forwarded-Uri: /", "Cookie: " + COOKIE]
URL = "http://127.0.0.1:18090/_wap/verify"


def targets(data):
    return [
        ("Go (minimal handler)", "lang-go", []),
        ("Go (webauthnproxy, full app)", bench.WAP, ["-v", f"{data}:/data", "-e", "MODE=forward", "-e", "LOGIN_URL=https://auth.example.com/_wap/login",
            "-e", "ALLOWED_HOSTS=app.example.com", "-e", "RP_ID=example.com", "-e", "RP_ORIGINS=https://auth.example.com", "-e", f"SESSION_SECRET={SECRET}"]),
        ("Rust (axum)", "lang-rust", []),
        ("Node 22", "lang-node", []),
        ("Python 3.13 (uvicorn)", "lang-python", []),
        (".NET 9 (Kestrel)", "lang-dotnet", []),
    ]


def run(label, image, args, data):
    sh(RT, "rm", "-f", NAME, check=False)
    t0 = time.time()
    sh(RT, "run", "-d", "--name", NAME, "-p", "18090:8080", *args, image)
    wait_http(URL)
    r = {"startup_s": time.time() - t0, "image_mib": image_mib(image)}
    pid = pid_of(NAME)
    # sanity: the authenticated check must really succeed
    req = urllib.request.Request(URL, headers={h.split(": ")[0]: h.split(": ", 1)[1] for h in HEADERS if not h.startswith("Host")})
    assert urllib.request.urlopen(req).status == 200, label
    time.sleep(int(os.environ["BENCH_SETTLE"]))
    m = mem(pid)
    r["idle_rss_mib"] = m["VmRSS"]
    c0 = cpu_s(pid); time.sleep(15); r["idle_cpu_pct"] = (cpu_s(pid) - c0) / 15 * 100
    dur, bench.DUR = bench.DUR, "3s"; load(URL, HEADERS, 8); bench.DUR = dur   # warm-up (JIT, caches)
    for c in (4, 32):
        c0 = cpu_s(pid)
        res = load(URL, HEADERS, c)
        res["cpu_ms_per_1k"] = (cpu_s(pid) - c0) * 1000 / (res["requests"] / 1000)
        r[f"c{c}"] = res
    m = mem(pid)
    r["rss_after_mib"], r["peak_mib"] = m["VmRSS"], m["VmHWM"]
    sh(RT, "rm", "-f", NAME)
    return r


def main():
    sh("go", "build", "-o", os.path.join(TMP, "loadgen"), os.path.join(HERE, "loadgen.go"))
    data = os.path.join(TMP, "data"); os.makedirs(data)
    uid = hashlib.sha256(b"webauthnproxy:user:bench").digest()
    json.dump({"users": [{"id": base64.b64encode(uid).decode(), "name": "bench", "credentials": [{"id": "AQID", "publicKey": "AQID"}]}]},
              open(f"{data}/users.json", "w"))
    os.chown(data, 65532, 65532); os.chown(f"{data}/users.json", 65532, 65532)
    res = {}
    try:
        for label, image, args in targets(data):
            print("…", label, file=sys.stderr, flush=True)
            res[label] = run(label, image, args, data)
    finally:
        sh(RT, "rm", "-f", NAME, check=False)
    print(json.dumps(res, indent=2))
    cols = list(res)
    print("\n| | " + " | ".join(cols) + " |\n|---|" + "---|" * len(cols))
    row = lambda label, f: print(f"| {label} | " + " | ".join(f(res[c]) for c in cols) + " |")
    row("Image", lambda r: f"{r['image_mib']:.0f} MiB")
    row("Start to first answer", lambda r: f"{r['startup_s']:.2f} s")
    row("Idle memory (RSS)", lambda r: f"{r['idle_rss_mib']:.0f} MiB")
    row("Idle CPU", lambda r: f"{r['idle_cpu_pct']:.2f} %")
    for c in (4, 32):
        row(f"{c} connections", lambda r: f"{r[f'c{c}']['rps']:,} req/s, p99 {r[f'c{c}']['p99']}")
        row("  CPU per 1000 requests", lambda r: f"{r[f'c{c}']['cpu_ms_per_1k']:.0f} ms")
    row("Peak memory under load", lambda r: f"{r['peak_mib']:.0f} MiB")


if __name__ == "__main__":
    try:
        main()
    finally:
        shutil.rmtree(TMP, ignore_errors=True)
