#!/usr/bin/env python3
"""pqprobe v3 -- external probe of the post-quantum migration state of a TLS endpoint.

What it infers (server side only; the client side of a hop is out of its reach):
  KEX state   N < En < Pref < Enf     (Enf = a classical-only TLS 1.3 client AND a TLS 1.2
                                       client are refused, while a PQ client with otherwise
                                       identical parameters succeeds)
  AUTH state  N < En < Enf            (PQ signature algorithms; Enf = classical-only refused)
  lineage     whether a PQ-only client can be served a resumed session whose keys descend
              from an earlier classical handshake (psk_ke)
  compliance  hybrid-required and PQ-only (ML-KEM-1024 + ML-DSA-87) profiles

Every negative test is paired with a positive control. A refusal counts as enforcement only if
the control succeeded and the refusal is a TLS alert of the handshake-failure family
(handshake_failure 40, insufficient_security 71, protocol_version 70); anything else
(TCP reset, timeout, certificate_required 116, unrecognized_name 112, ...) is INCONCLUSIVE.

--repeat R repeats each probe R times. Behind a load balancer with k backends receiving
connections uniformly, a backend that differs is missed with probability (1-1/k)^R; outcomes
that differ across repeats are reported as HETEROGENEOUS and the weakest outcome is kept.

Requirements: OpenSSL >= 3.5 command-line binary. Probe only endpoints you operate or are
authorized to test. Default pacing: one handshake per second.
"""
import argparse, json, os, re, subprocess, sys, tempfile, time

PQ_GROUPS = ["X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024", "MLKEM768", "MLKEM1024"]
# Every classical TLS 1.3 group known to OpenSSL 3.5: a refusal only demonstrates enforcement
# for the groups offered, so the negative test offers all of them at once.
CLASSICAL_GROUPS = ["X25519", "P-256", "P-384", "P-521", "X448", "ffdhe2048", "ffdhe3072", "ffdhe4096",
                    "ffdhe6144", "ffdhe8192", "brainpoolP256r1tls13", "brainpoolP384r1tls13", "brainpoolP512r1tls13"]
PQ_SIGALGS = ["mldsa44", "mldsa65", "mldsa87"]
CLASSICAL_SIGALGS = ["ecdsa_secp256r1_sha256", "ecdsa_secp384r1_sha384", "ecdsa_secp521r1_sha512", "ed25519",
                     "ed448", "rsa_pss_rsae_sha256", "rsa_pss_rsae_sha384", "rsa_pss_rsae_sha512",
                     "rsa_pss_pss_sha256", "rsa_pkcs1_sha256"]
REFUSAL_ALERTS = {"40", "70", "71"}
GROUP_IDS = {0x11EC: "X25519MLKEM768", 0x11EB: "SecP256r1MLKEM768", 0x11ED: "SecP384r1MLKEM1024",
             0x0200: "MLKEM512", 0x0201: "MLKEM768", 0x0202: "MLKEM1024", 0x001D: "X25519",
             0x001E: "X448", 0x0017: "P-256", 0x0018: "P-384", 0x0019: "P-521",
             0x0100: "ffdhe2048", 0x0101: "ffdhe3072", 0x0102: "ffdhe4096"}
HRR_RANDOM = bytes.fromhex("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")


def server_hellos(msg_output):
    """Parse every ServerHello printed by `s_client -msg` and return a list of dicts with the
    selected key-share group (None if the ServerHello carries no key_share), whether it is a
    HelloRetryRequest, and whether a pre-shared key was accepted (pre_shared_key extension)."""
    out, lines, i = [], msg_output.splitlines(), 0
    while i < len(lines):
        if lines[i].startswith("<<<") and lines[i].rstrip().endswith("ServerHello"):
            hexs, i = [], i + 1
            while i < len(lines) and re.fullmatch(r"\s+([0-9a-f]{2} ?)+\s*", lines[i]):
                hexs.append(lines[i].strip()); i += 1
            b = bytes.fromhex("".join(hexs).replace(" ", ""))
            try:
                p = 4 + 2
                rnd = b[p:p + 32]; p += 32
                p += 1 + b[p]                 # session id
                p += 2 + 1                    # cipher suite, compression
                end = p + 2 + int.from_bytes(b[p:p + 2], "big"); p += 2
                group, psk = None, False
                while p + 4 <= end:
                    et, el = int.from_bytes(b[p:p + 2], "big"), int.from_bytes(b[p + 2:p + 4], "big")
                    body = b[p + 4:p + 4 + el]
                    if et == 0x0033 and len(body) >= 2:
                        gid = int.from_bytes(body[:2], "big"); group = GROUP_IDS.get(gid, hex(gid))
                    if et == 0x0029:
                        psk = True
                    p += 4 + el
                out.append({"hrr": rnd == HRR_RANDOM, "group": group, "psk": psk})
            except Exception:
                out.append({"hrr": None, "group": None, "psk": None})
            continue
        i += 1
    return out
ORDER = ["N", "En", "Pref", "Enf"]


def _grab(text, pat):
    m = re.search(pat, text)
    return m.group(1) if m else None


class Prober:
    def __init__(self, target, openssl="openssl", sni=None, delay=1.0, timeout=10, repeat=1):
        self.target, self.openssl, self.sni = target, openssl, sni
        self.delay, self.timeout, self.repeat = delay, timeout, repeat
        self.log = []

    def handshake(self, name, extra):
        cmd = [self.openssl, "s_client", "-connect", self.target, "-brief", "-ign_eof", "-msg"]
        if self.sni:
            cmd += ["-servername", self.sni]
        cmd += extra
        t0 = time.perf_counter()
        try:
            p = subprocess.run(cmd, input=b"GET / HTTP/1.0\r\n\r\n", capture_output=True, timeout=self.timeout)
            out = p.stderr.decode(errors="replace") + p.stdout.decode(errors="replace").split("HTTP/1.", 1)[0]
        except subprocess.TimeoutExpired:
            out = "TIMEOUT"
        ok = "CONNECTION ESTABLISHED" in out
        alert = _grab(out, r"SSL alert number (\d+)")
        if ok:
            failure = None
        elif alert:
            failure = "alert:" + alert
        elif "TIMEOUT" in out:
            failure = "timeout"
        elif re.search(r"Connection refused|connect:errno|Connection reset|unexpected eof|errno=104", out):
            failure = "transport"
        else:
            failure = "other"
        sh = [h for h in server_hellos(out) if not h["hrr"]]
        last = sh[-1] if sh else None
        r = {"probe": name, "ok": ok, "failure": failure,
             # group selected in the (final) ServerHello, even if the handshake fails later
             "group": last["group"] if last else None,
             "server_hello": last is not None,
             "psk_resumed": bool(last and last["psk"]),
             "psk_ke": bool(last and last["psk"] and last["group"] is None),
             # the client sends EndOfEarlyData only if the server accepted its early data
             "early_data_accepted": "EndOfEarlyData" in out or "Early data was accepted" in out,
             "sig": _grab(out, r"Signature type: (\S+)"), "version": _grab(out, r"Protocol version: (\S+)"),
             "cipher": _grab(out, r"Ciphersuite: (\S+)"),
             "ms": round((time.perf_counter() - t0) * 1000, 1)}
        self.log.append(r)
        time.sleep(self.delay)
        return r

    def repeated(self, name, extra):
        return [self.handshake(name, extra) for _ in range(self.repeat)]

    @staticmethod
    def refusal(rs):
        """'refused' if every attempt was refused by a handshake-family alert, 'accepted' if every
        attempt succeeded, 'heterogeneous' if both happened, otherwise 'inconclusive'."""
        acc = [r["ok"] for r in rs]
        good = [r["failure"] and r["failure"].startswith("alert:") and r["failure"][6:] in REFUSAL_ALERTS for r in rs]
        if all(acc):
            return "accepted"
        if all(good):
            return "refused"
        if any(acc) and all(a or g for a, g in zip(acc, good)):
            return "heterogeneous"
        return "inconclusive"

    def run(self):
        is_pq = lambda g: g is not None and "MLKEM" in g.upper()
        res = {"target": self.target, "repeat": self.repeat}
        obs = self.repeated("observe", ["-groups", "*X25519MLKEM768:*X25519:" + ":".join(CLASSICAL_GROUPS[1:])])
        res["observed_groups"] = sorted({r["group"] for r in obs if r["ok"] and r["group"]})
        res["observed_sigs"] = sorted({r["sig"] for r in obs if r["ok"] and r["sig"]})
        res["observed_ciphers"] = sorted({r["cipher"] for r in obs if r["ok"] and r["cipher"]})
        cap = self.repeated("kex_capable", ["-tls1_3", "-groups", ":".join(PQ_GROUPS)])      # positive control
        # Preference, two variants: (A) the client lists X25519 first and sends BOTH key shares;
        # (B) the client lists X25519 first and sends ONLY an X25519 key share, so selecting the
        # hybrid group requires a HelloRetryRequest. Pref = PQ selected in (A) and (B);
        # Pref* = PQ selected in (A) only (preference conditional on the client's key shares).
        pref = self.repeated("kex_preference", ["-groups", "*X25519:*X25519MLKEM768"])
        prefB = self.repeated("kex_preference_hrr", ["-groups", "*X25519:X25519MLKEM768"])
        neg13 = self.repeated("kex_negative_tls13", ["-tls1_3", "-groups", ":".join(CLASSICAL_GROUPS)])
        neg12 = self.repeated("kex_negative_tls12", ["-tls1_2"])
        cap_ok = [is_pq(r["group"]) for r in cap]
        control = "pass" if all(cap_ok) else ("partial" if any(cap_ok) else "fail")
        n13, n12 = self.refusal(neg13), self.refusal(neg12)
        if control == "fail":
            state = "N" if all(r["failure"] and r["failure"].startswith("alert:") for r in cap) else "inconclusive"
        elif control == "partial" or "heterogeneous" in (n13, n12):
            state = "heterogeneous"
        elif n13 == "refused" and n12 == "refused":
            state = "Enf"
        elif "inconclusive" in (n13, n12) and "accepted" not in (n13, n12):
            state = "inconclusive"
        elif all(r["ok"] and is_pq(r["group"]) for r in pref) and all(r["ok"] and is_pq(r["group"]) for r in prefB):
            state = "Pref"
        elif all(r["ok"] and is_pq(r["group"]) for r in pref):
            state = "Pref*"
        else:
            state = "En"
        res["kex"] = {"state": state, "positive_control": control, "classical_tls13": n13, "tls12": n12,
                      "pure_mlkem1024": self.refusal(self.repeated("kex_pure1024", ["-tls1_3", "-groups", "MLKEM1024"])) == "accepted"}
        acap = self.repeated("auth_capable", ["-tls1_3", "-groups", ":".join(PQ_GROUPS + CLASSICAL_GROUPS),
                                              "-sigalgs", ":".join(PQ_SIGALGS)])
        aneg = self.repeated("auth_negative", ["-tls1_3", "-groups", ":".join(PQ_GROUPS + CLASSICAL_GROUPS),
                                               "-sigalgs", ":".join(CLASSICAL_SIGALGS)])
        a_ok = all(r["ok"] for r in acap)
        an = self.refusal(aneg)
        res["auth"] = {"state": ("Enf" if a_ok and an == "refused" else "heterogeneous" if an == "heterogeneous"
                                 else "En" if a_ok else "N"),
                       "pq_sigs": sorted({r["sig"] for r in acap if r["ok"] and r["sig"]})}
        # Resumption without a fresh key exchange (psk_ke). (a) Does the server SELECT psk_ke when
        # a client offers both modes after a PQ full handshake? (b) If classical handshakes are
        # accepted, can a PQ-only client be served a session keyed by a classical handshake?
        res["psk_ke_selected"] = None
        res["early_data_accepted"] = None
        res["psk_ke_inherits_classical"] = None
        with tempfile.TemporaryDirectory() as td:
            if control != "fail":
                sess = os.path.join(td, "pq.pem")
                self.handshake("resume_first_pq", ["-tls1_3", "-groups", ":".join(PQ_GROUPS), "-sess_out", sess])
                if os.path.exists(sess):
                    again = self.handshake("resume_offer_psk_ke", ["-tls1_3", "-sess_in", sess, "-allow_no_dhe_kex",
                                                                  "-groups", ":".join(PQ_GROUPS)])
                    res["psk_ke_selected"] = bool(again["psk_ke"])
                # 0-RTT: early data is encrypted under keys derived from the resumption secret alone,
                # so it inherits the lineage of the ticket even when the handshake adds a fresh share.
                sess2 = os.path.join(td, "pq2.pem")
                ed = os.path.join(td, "ed.txt")
                with open(ed, "w") as f:
                    f.write("GET / HTTP/1.0\r\n\r\n")
                self.handshake("early_first_pq", ["-tls1_3", "-groups", ":".join(PQ_GROUPS), "-sess_out", sess2])
                if os.path.exists(sess2):
                    e = self.handshake("early_data_offer", ["-tls1_3", "-sess_in", sess2, "-early_data", ed,
                                                           "-groups", ":".join(PQ_GROUPS)])
                    res["early_data_accepted"] = bool(e["early_data_accepted"])
            if n13 == "accepted":
                sess = os.path.join(td, "cl.pem")
                self.handshake("lineage_first_classical", ["-tls1_3", "-groups", ":".join(CLASSICAL_GROUPS), "-sess_out", sess])
                if os.path.exists(sess):
                    again = self.handshake("lineage_resume_pq_only", ["-tls1_3", "-sess_in", sess, "-allow_no_dhe_kex",
                                                                     "-groups", ":".join(PQ_GROUPS)])
                    res["psk_ke_inherits_classical"] = bool(again["psk_ke"])
        # What server-side observations determine about the layer value (paper, Prop. on identifiability)
        if state == "N":
            res["layer_value_from_server_side"] = "0"
        elif state == "Enf" and res["psk_ke_selected"] is False and res["early_data_accepted"] is False:
            res["layer_value_from_server_side"] = "1 (unless psk_ke is accepted when it is the only mode offered)"
        else:
            res["layer_value_from_server_side"] = "unknown"
        g = sorted({r["group"] for r in cap + obs if r["ok"] and is_pq(r["group"])})
        res["pq_groups_served"] = g
        hyb = ("X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024")
        res["compliance"] = {
            "hybrid_required": state == "Enf" and bool(g) and all(x in hyb for x in g),
            "pq_only_1024": state == "Enf" and g == ["MLKEM1024"] and res["auth"]["state"] == "Enf"
                            and bool(res["auth"]["pq_sigs"]) and all(s == "mldsa87" for s in res["auth"]["pq_sigs"]),
        }
        res["evidence"] = {"level": "runtime", "negative_test": state == "Enf", "date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                           "scope": {"target": self.target, "sni": self.sni, "repeats": self.repeat}}
        res["probes"] = self.log
        return res


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target", help="host:port")
    ap.add_argument("--openssl", default=os.environ.get("PQPROBE_OPENSSL", "openssl"))
    ap.add_argument("--sni")
    ap.add_argument("--delay", type=float, default=1.0)
    ap.add_argument("--repeat", type=int, default=1)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    res = Prober(a.target, a.openssl, a.sni, a.delay, repeat=a.repeat).run()
    if a.json:
        print(json.dumps(res, indent=2))
    else:
        print(f"{a.target}: KEX={res['kex']['state']} (control {res['kex']['positive_control']}, "
              f"classical1.3 {res['kex']['classical_tls13']}, tls1.2 {res['kex']['tls12']}) AUTH={res['auth']['state']} "
              f"observed={res['observed_groups']} psk_ke_selected={res['psk_ke_selected']} early_data={res['early_data_accepted']} "
              f"psk_ke_inherits_classical={res['psk_ke_inherits_classical']} nu={res['layer_value_from_server_side']} "
              f"compliance={res['compliance']}")


if __name__ == "__main__":
    sys.exit(main())
