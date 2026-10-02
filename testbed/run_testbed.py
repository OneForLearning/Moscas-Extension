#!/usr/bin/env python3
"""Multi-stack testbed (paper v3).

Implementations: OpenSSL 3.5 s_server, nginx (OpenSSL 3.5), HAProxy (OpenSSL 3.5) as TLS
terminator and as TCP load balancer, Go crypto/tls, rustls (aws-lc-rs).
Confounders: a server that requires client certificates (mTLS) and a listener that resets
connections (ACL), to check that the probe does not mistake them for PQ enforcement.
Load-balancer experiment: HAProxy round-robin over an enforcing and a non-enforcing backend.

Run: python3 run_testbed.py   (paths below assume the builds described in README.md)
"""
import json, os, socket, subprocess, sys, tempfile, threading, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "pqprobe"))
from pqprobe import Prober  # noqa: E402

OSSL = os.environ.get("OSSL", "/opt/ossl35/bin/openssl")
NGINX = os.environ.get("NGINX", "/opt/nginx/sbin/nginx")
HAPROXY = os.environ.get("HAPROXY", "/opt/haproxy/haproxy")
GO = os.path.join(HERE, "stacks", "go-server", "go-server")
RUSTLS = os.path.join(HERE, "stacks", "rustls-server", "target", "release", "rustls-server")
C = os.path.join(HERE, "certs")
ECDSA = ["-cert", f"{C}/ecdsa.crt", "-key", f"{C}/ecdsa.key"]
TMP = tempfile.mkdtemp()


def s_server(port, args):
    return [OSSL, "s_server", "-accept", str(port), "-www", "-quiet"] + args


def nginx(port, curves, protocols, prefer=False):
    d = os.path.join(TMP, f"nginx{port}"); os.makedirs(os.path.join(d, "logs"), exist_ok=True)
    conf = os.path.join(d, "nginx.conf")
    open(conf, "w").write(f"""daemon off; worker_processes 1; error_log {d}/logs/error.log; pid {d}/nginx.pid;
events {{ worker_connections 64; }}
http {{ access_log off; client_body_temp_path {d}; proxy_temp_path {d}; fastcgi_temp_path {d}; uwsgi_temp_path {d}; scgi_temp_path {d};
  server {{ listen 127.0.0.1:{port} ssl; ssl_certificate {C}/ecdsa.crt; ssl_certificate_key {C}/ecdsa.key;
    ssl_protocols {protocols}; ssl_ecdh_curve {curves}; ssl_prefer_server_ciphers {"on" if prefer else "off"}; location / {{ root {d}; }} }} }}
""")
    return [NGINX, "-p", d, "-c", conf]


def haproxy_tls(port, curves, minver):
    d = os.path.join(TMP, f"hap{port}"); os.makedirs(d, exist_ok=True)
    conf = os.path.join(d, "h.cfg")
    open(conf, "w").write(f"""global
  log stderr local0 emerg
defaults
  mode http
  timeout connect 2s
  timeout client 5s
  timeout server 5s
frontend f
  bind 127.0.0.1:{port} ssl crt {C}/ecdsa.pem curves {curves} {minver}
  http-request return status 200 content-type text/plain string ok
""")
    return [HAPROXY, "-f", conf, "-db"]


def haproxy_lb(port, backends, balance="random"):
    d = os.path.join(TMP, f"lb{port}"); os.makedirs(d, exist_ok=True)
    conf = os.path.join(d, "h.cfg")
    srv = "\n".join(f"  server b{i} 127.0.0.1:{b}" for i, b in enumerate(backends))
    open(conf, "w").write(f"""global
  log stderr local0 emerg
defaults
  mode tcp
  timeout connect 2s
  timeout client 5s
  timeout server 5s
frontend f
  bind 127.0.0.1:{port}
  default_backend b
backend b
  balance {balance}
{srv}
""")
    return [HAPROXY, "-f", conf, "-db"]


def reset_listener(port, stop):
    """An 'ACL' that accepts TCP and resets every connection."""
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port)); s.listen(16); s.settimeout(0.2)
    while not stop.is_set():
        try:
            c, _ = s.accept()
            c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b"\x01\x00\x00\x00\x00\x00\x00\x00")
            c.close()
        except socket.timeout:
            pass
    s.close()


CONFIGS = [
    # id, stack, description, command builder, expected KEX state
    ("O-A", "OpenSSL", "hybrid only, TLS 1.3 only", lambda p: s_server(p, ["-tls1_3", "-groups", "X25519MLKEM768"] + ECDSA), "Enf"),
    ("O-B", "OpenSSL", "X25519 then hybrid, server order", lambda p: s_server(p, ["-serverpref", "-groups", "X25519:X25519MLKEM768"] + ECDSA), "En"),
    ("O-C", "OpenSSL", "classical only", lambda p: s_server(p, ["-groups", "X25519:P-256"] + ECDSA), "N"),
    ("O-D", "OpenSSL", "hybrid then X25519, server order", lambda p: s_server(p, ["-serverpref", "-groups", "X25519MLKEM768:X25519"] + ECDSA), "Pref*"),
    ("O-D2", "OpenSSL", "as O-D with tuple separator: X25519MLKEM768/X25519", lambda p: s_server(p, ["-serverpref", "-groups", "X25519MLKEM768/X25519"] + ECDSA), "Pref"),
    ("O-E", "OpenSSL", "hybrid only + ML-DSA-65 certificate", lambda p: s_server(p, ["-tls1_3", "-groups", "X25519MLKEM768", "-cert", f"{C}/mldsa.crt", "-key", f"{C}/mldsa.key"]), "Enf"),
    ("O-F", "OpenSSL", "as O-D, psk_ke allowed and preferred", lambda p: s_server(p, ["-serverpref", "-groups", "X25519MLKEM768:X25519", "-allow_no_dhe_kex", "-prefer_no_dhe_kex"] + ECDSA), "Pref"),
    ("O-H", "OpenSSL", "as O-A, psk_ke allowed and preferred", lambda p: s_server(p, ["-tls1_3", "-groups", "X25519MLKEM768", "-allow_no_dhe_kex", "-prefer_no_dhe_kex"] + ECDSA), "Enf"),
    ("O-I", "OpenSSL", "as O-A, 0-RTT early data accepted", lambda p: s_server(p, ["-tls1_3", "-groups", "X25519MLKEM768", "-early_data"] + ECDSA), "Enf"),
    ("O-G", "OpenSSL", "pure ML-KEM-1024 + ML-DSA-87 (PQ-only profile)", lambda p: s_server(p, ["-tls1_3", "-groups", "MLKEM1024", "-cert", f"{C}/mldsa87.crt", "-key", f"{C}/mldsa87.key"]), "Enf"),
    ("N-1", "nginx", "ssl_ecdh_curve X25519MLKEM768, TLSv1.3", lambda p: nginx(p, "X25519MLKEM768", "TLSv1.3"), "Enf"),
    ("N-2", "nginx", "ssl_ecdh_curve X25519MLKEM768:X25519, TLSv1.2+1.3", lambda p: nginx(p, "X25519MLKEM768:X25519", "TLSv1.2 TLSv1.3"), None),
    ("N-3", "nginx", "as N-2, ssl_prefer_server_ciphers on", lambda p: nginx(p, "X25519MLKEM768:X25519", "TLSv1.2 TLSv1.3", prefer=True), None),
    ("H-1", "HAProxy", "curves X25519MLKEM768, ssl-min-ver TLSv1.3", lambda p: haproxy_tls(p, "X25519MLKEM768", "ssl-min-ver TLSv1.3"), "Enf"),
    ("H-2", "HAProxy", "curves X25519MLKEM768:X25519", lambda p: haproxy_tls(p, "X25519MLKEM768:X25519", ""), None),
    ("G-1", "Go 1.24", "CurvePreferences [X25519MLKEM768], TLS 1.3", lambda p: [GO, str(p), f"{C}/ecdsa.crt", f"{C}/ecdsa.key", "enforce"], "Enf"),
    ("G-2", "Go 1.24", "CurvePreferences [X25519MLKEM768, X25519, P-256]", lambda p: [GO, str(p), f"{C}/ecdsa.crt", f"{C}/ecdsa.key", "prefer"], None),
    ("G-3", "Go 1.24", "CurvePreferences [X25519, P-256, X25519MLKEM768]", lambda p: [GO, str(p), f"{C}/ecdsa.crt", f"{C}/ecdsa.key", "classical-first"], None),
    ("R-1", "rustls", "kx_groups [X25519MLKEM768], TLS 1.3", lambda p: [RUSTLS, str(p), f"{C}/ecdsa.crt", f"{C}/ecdsa.key", "enforce"], "Enf"),
    ("R-2", "rustls", "kx_groups [X25519MLKEM768, X25519, P-256]", lambda p: [RUSTLS, str(p), f"{C}/ecdsa.crt", f"{C}/ecdsa.key", "prefer"], None),
    ("X-mTLS", "OpenSSL", "hybrid only, client certificate required", lambda p: s_server(p, ["-tls1_3", "-groups", "X25519MLKEM768", "-Verify", "1"] + ECDSA), "Enf"),
    ("X-ACL", "TCP", "listener that resets every connection", None, "inconclusive"),
]


def launch(cmd):
    p = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.0)
    return p


def probe(port, repeat=1):
    return Prober(f"127.0.0.1:{port}", OSSL, delay=0.0, repeat=repeat).run()


def summary(r):
    return {"kex": r["kex"]["state"], "control": r["kex"]["positive_control"], "classical_tls13": r["kex"]["classical_tls13"],
            "tls12": r["kex"]["tls12"], "auth": r["auth"]["state"], "observed": r["observed_groups"],
            "psk_ke_inherits_classical": r["psk_ke_inherits_classical"], "psk_ke_selected": r["psk_ke_selected"], "early_data_accepted": r["early_data_accepted"],
            "nu_server_side": r["layer_value_from_server_side"], "compliance": r["compliance"],
            "pure_mlkem1024": r["kex"]["pure_mlkem1024"],
            "alerts": sorted({p["failure"] for p in r["probes"] if p["failure"]}), "ciphers": r["observed_ciphers"]}


SKIP_LB = "--skip-lb" in sys.argv
LB_MODES = [("random(1)", [4]), ("roundrobin", [4])] if "--lb-controls" in sys.argv else [("random", [1, 2, 4])]


def main():
    out = {"openssl_client": subprocess.run([OSSL, "version"], capture_output=True, text=True).stdout.strip(), "configs": {}}
    port = 5100
    for cid, stack, desc, build, expected in ([] if "--lb-controls" in sys.argv else CONFIGS):
        port += 1
        stop = threading.Event()
        if build is None:
            th = threading.Thread(target=reset_listener, args=(port, stop), daemon=True); th.start(); time.sleep(0.3); proc = None
        else:
            proc = launch(build(port))
        try:
            runs = [summary(probe(port)) for _ in range(5)]
        finally:
            stop.set()
            if proc:
                proc.terminate(); proc.wait()
        stable = len({json.dumps(r, sort_keys=True) for r in runs}) == 1
        out["configs"][cid] = {"stack": stack, "description": desc, "expected_kex": expected, "result": runs[0], "stable_over_5": stable}
        print(cid, stack, runs[0]["kex"], runs[0]["observed"], runs[0]["classical_tls13"], runs[0]["tls12"], runs[0]["auth"],
              runs[0]["psk_ke_selected"], runs[0]["early_data_accepted"], runs[0]["psk_ke_inherits_classical"], runs[0]["nu_server_side"], runs[0]["compliance"], runs[0]["alerts"], "stable" if stable else "UNSTABLE", flush=True)

    out["load_balancer"] = {}
    if not SKIP_LB:
        for balance, reps in LB_MODES:
            b1, b2, lb = 5201, 5202, 5200
            procs = [launch(s_server(b1, ["-tls1_3", "-groups", "X25519MLKEM768"] + ECDSA)),
                     launch(s_server(b2, ["-serverpref", "-groups", "X25519MLKEM768:X25519"] + ECDSA)),
                     launch(haproxy_lb(lb, [b1, b2], balance))]
            res = {}
            try:
                for R in reps:
                    n = 200
                    states = [probe(lb, repeat=R)["kex"]["state"] for _ in range(n)]
                    res[str(R)] = {"trials": n, **{st: states.count(st) for st in set(states)},
                                   "falseEnf_under_independence": 0.5 ** (2 * R),
                                   "nonheterogeneous_under_independence": min(1.0, 4 * 0.5 ** (2 * R))}
                    print("LB", balance, "repeat", R, res[str(R)], flush=True)
            finally:
                for p in procs:
                    p.terminate(); p.wait()
            out["load_balancer"][balance] = res
    os.makedirs(os.path.join(HERE, "..", "results"), exist_ok=True)
    name = "lb_controls.json" if "--lb-controls" in sys.argv else "testbed.json"
    json.dump(out, open(os.path.join(HERE, "..", "results", name), "w"), indent=2)


if __name__ == "__main__":
    main()
