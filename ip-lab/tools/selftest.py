#!/usr/bin/env python3
"""
`python3 tools/selftest.py`  - prove the lab still works after you edit it.
Offline-safe: network-dependent assertions are skipped (not silently passed) when
outbound access is unavailable, and it prints which ones.
"""
from __future__ import annotations

import datetime as _dt
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from lab import canary as C  # noqa: E402
from lab import logs as L  # noqa: E402
from lab import tracer as T  # noqa: E402
from lab.net import ip_kind, parse_pem, truncate_v6, v6_subnet  # noqa: E402

ok, failed, skipped = 0, [], []

# --offline skips every check that needs outbound TLS, and the target itself is overridable,
# because a corporate proxy, an EDR product or an ISP that filters 443 makes "the certificate
# parser works" untestable - and that is a fact about the network, not about this lab.
#   LAB_TLS_HOST / LAB_TLS_PORT / LAB_TLS_TIMEOUT  (e.g. LAB_TLS_HOST=github.com)
OFFLINE = "--offline" in sys.argv


def tls_target() -> tuple[str, int, float]:
    return (os.environ.get("LAB_TLS_HOST", "1.1.1.1"),
            int(os.environ.get("LAB_TLS_PORT", "443")),
            float(os.environ.get("LAB_TLS_TIMEOUT", "8")))


try:                                  # Windows console/encoding shim; no-op elsewhere
    import win
    win.ready()
except ImportError:
    pass


def check(name, cond, detail=""):
    global ok
    if cond:
        ok += 1
        print(f"  PASS {name}")
    else:
        failed.append(name)
        print(f"  FAIL {name}  {detail}")


print("== 1. log parsing ==")
raw = ('203.0.113.9 - alice [11/Sep/2026:04:20:11 +0000] "POST /login HTTP/1.1" 401 612 '
       '"https://app.test/login" "curl/8.5.0" "127.0.0.1, 8.8.8.8"')
e = L.parse([raw])[0]
check("fields", (e["ip"], e["user"], e["status"], e["path"]) == ("203.0.113.9", "alice", 401, "/login"), str(e))
check("xff chain", e["xff_list"] == ["127.0.0.1", "8.8.8.8"], str(e["xff_list"]))
check("timestamp", (e["dt"].hour, e["dt"].utcoffset().total_seconds()) == (4, 0), str(e["dt"]))
check("malformed flagged", L.parse(["garbage line with no shape"])[0].get("malformed") is True)
check("minimal common log format", L.parse(['10.0.0.1 - - [11/Sep/2026:04:20:11 +0000] "GET /a HTTP/1.1" 200 5']) [0]["status"] == 200)

print("== 2. header trust logic ==")
no_proxy = L.real_ip(e, [])
check("no trusted proxy -> peer wins", no_proxy["verdict_ip"] == "203.0.113.9", str(no_proxy))
check("flags spoofed XFF to unproxied server", any("client is lying" in f for f in no_proxy["flags"]), str(no_proxy["flags"]))
with_proxy = L.real_ip(e, ["203.0.113.9"])
check("proxy walk right-to-left", with_proxy["verdict_ip"] == "8.8.8.8", str(with_proxy))
check("untrusted peer cannot append a chain", L.real_ip(e, ["9.9.9.9"])["verdict_ip"] == "203.0.113.9")
imp_cases = [
    ({"ip": "127.0.0.1", "xff_list": ["127.0.0.1"]}, ["127.0.0.1/32"], "127.0.0.1"),
    ({"ip": "127.0.0.1", "xff_list": ["198.51.100.23", "8.8.8.8", "127.0.0.1"]}, ["127.0.0.1/32"], "8.8.8.8"),
    ({"ip": "10.0.0.5", "xff_list": ["203.0.113.9", "173.245.48.5", "10.0.0.5"]},
     ["10.0.0.5", "173.245.48.0/20"], "203.0.113.9"),
]
for e_case, tr, want in imp_cases:
    check(f"real_ip walk {want}", L.real_ip(e_case, tr)["verdict_ip"] == want, str(L.real_ip(e_case, tr)))

ripped = lambda peer, xff, tr, mode="on": L.real_ip(
    {"ip": peer, "xff_list": L.split_xff(xff), "status": 200, "mode": mode}, tr)
sent = "198.51.100.23, 8.8.8.8"
wide = ["127.0.0.1/32", "127.0.0.0/8"]
check("no trusted proxies => peer wins, XFF flagged",
      ripped("127.0.0.1", sent, [])["verdict_ip"] == "127.0.0.1"
      and any("NON-PROXIED SERVER" in f for f in L.real_ip({"ip": "127.0.0.1", "xff_list": L.split_xff(sent)}, [])["flags"]),
      str(L.real_ip({"ip": "127.0.0.1", "xff_list": L.split_xff(sent)}, [])))
check("narrow trust + client junk => attacker wins (the vulnerability)",
      ripped("127.0.0.1", sent + ", 127.0.0.1", ["127.0.0.1/32"])["verdict_ip"] == "8.8.8.8",
      str(ripped("127.0.0.1", sent + ", 127.0.0.1", ["127.0.0.1/32"])))
check("cf -> edge -> app: real client once every hop is trusted",
      ripped("127.0.0.1", "203.0.113.9, 173.245.48.5", ["127.0.0.1/32", "173.245.48.0/20"])["verdict_ip"] == "203.0.113.9",
      str(ripped("127.0.0.1", "203.0.113.9, 173.245.48.5", ["127.0.0.1/32", "173.245.48.0/20"])))
check("edge sees the header as received -> lands on the relay's peer (the VPN exit)",
      ripped("127.0.0.1", sent, wide)["verdict_ip"] == "8.8.8.8"
      and ripped("127.0.0.1", sent, wide)["confidence"] == "high", str(ripped("127.0.0.1", sent, wide)))
check("untrusted tail stops the walk even when earlier entries look fine",
      ripped("127.0.0.1", "1.1.1.1, 8.8.8.8, 127.0.0.1", ["127.0.0.1/32"])["verdict_ip"] == "8.8.8.8",
      str(ripped("127.0.0.1", "1.1.1.1, 8.8.8.8, 127.0.0.1", ["127.0.0.1/32"])))
check("fully trusted chain (client connected to a trusted proxy) => the peer before it",
      ripped("127.0.0.1", "8.8.8.8", ["127.0.0.1/32", "8.8.8.8"])["verdict_ip"] == "127.0.0.1",
      str(ripped("127.0.0.1", "8.8.8.8", ["127.0.0.1/32", "8.8.8.8"])))
# proxy_sim's real_ip_recursive=off semantics (right-most entry, no walk) is pinned here
# by driving the module's own decision function instead of re-implementing it.
import importlib
# This used to be os.path.exists("proxy_lab/proxy_sim.py") - cwd-relative - so running the
# selftest from anywhere but the lab directory itself silently dropped six checks and still printed a green
# result. Anchor on ROOT, and make the miss say so: a skipped check must be visible, or the
# total becomes a number nobody can trust.
_psim_path = os.path.join(ROOT, "proxy_lab", "proxy_sim.py")
psim = None
if os.path.exists(_psim_path):
    try:
        psim = importlib.import_module("proxy_lab.proxy_sim")
    except Exception as exc:  # noqa: BLE001
        print(f"  FAIL proxy_lab.proxy_sim would not import: {type(exc).__name__}: {exc}")
        failed.append("proxy_sim imports")
else:
    skipped.append("6 proxy_sim trust-walk checks (no proxy_lab/proxy_sim.py)")
    print(f"  SKIP proxy_sim checks - expected {_psim_path}")
if psim is not None:
    psim.CFG.update(mode="correct", trusted=["127.0.0.0/8"], real_ip_header="X-Forwarded-For",
                    real_ip_recursive="off", backend_ip="10.9.9.9")
    d = psim.decide("127.0.0.1", "203.0.113.66, 127.0.0.1")
    check("recursive off takes the right-most entry (legacy trap)", d["logged"] == "127.0.0.1", str(d))
    psim.CFG["real_ip_recursive"] = "on"
    d2 = psim.decide("127.0.0.1", "203.0.113.66, 127.0.0.1")
    check("recursive on walks past the trusted tail => attacker-chosen",
          d2["logged"] == "203.0.113.66", str(d2))
    psim.CFG.update(mode="naive")
    d3 = psim.decide("127.0.0.1", "1.1.1.1")
    check("naive mode logs the leftmost claim and forwards it verbatim",
          d3["logged"] == "1.1.1.1" and d3["out_xff"] == "1.1.1.1", str(d3))
    psim.CFG.update(mode="correct", real_ip_recursive="on", strip_inbound=True)
    d5 = psim.decide("127.0.0.1", "1.1.1.1, 8.8.8.8, 203.0.113.66, 127.0.0.1")
    check("strip-then-append: only the peer is logged and forwarded",
          d5["logged"] == "127.0.0.1" and d5["out_xff"] == "127.0.0.1", str(d5))
    psim.CFG.update(strip_inbound=False)
    check("without stripping, the same request logs the attacker's value",
          psim.decide("127.0.0.1", "1.1.1.1, 8.8.8.8, 203.0.113.66, 127.0.0.1")["logged"] == "203.0.113.66",
          "strip_inbound is the fix")
    psim.CFG.update(mode="correct", real_ip_recursive="on")
    d4 = psim.decide("203.0.113.5", "1.1.1.1")
    check("untrusted peer: header ignored, peer logged", d4["logged"] == "203.0.113.5"
          and "ignored" in d4["why"], str(d4))

imp = L.real_ip({"ip": "9.9.9.9", "xff_list": ["127.0.0.1"], "status": 200}, ["9.9.9.9"])
check("impossible leftmost value detected", any("physically impossible" in f for f in imp["flags"]), str(imp))

print("== 3. classification ==")
check("public", ip_kind("8.8.8.8") == "ipv4-public")
check("private", ip_kind("10.10.4.21") == "rfc1918-private")
check("loopback", ip_kind("127.0.0.1") == "loopback")
check("v6 global", ip_kind("2001:db8::1") in ("ipv6-global", "ipv6-unique-local"))
check("garbage", ip_kind("not an ip") == "not-an-ip")
check("truncate v6 to /64", truncate_v6("2001:4488:1060:1c4a:21e:10ff:fe9c:1a2b") == "2001:4488:1060:1c4a::/64",
      truncate_v6("2001:4488:1060:1c4a:21e:10ff:fe9c:1a2b"))
check("v6 subnet label", v6_subnet("2001:4488:1060:1c4a::abcd") == "2001:4488:1060:1c4a::/64")

print("== 4. summariser catches the behaviours we planted ==")
log = os.path.join(ROOT, "data", "target_access.log")
if os.path.exists(log):
    ent = L.parse_file(log)
    s = L.summarise(ent)
    check("dataset parses (736 lines)", len(ent) == 736, str(len(ent)))
    check("scanner flagged for swept paths", "swept_paths" in s["45.148.10.66"]["interesting"])
    check("ATO flagged: success after failures", s["177.154.220.44"]["interesting"].get("successes_after_failures"), "")
    check("Tor false positive has no attack flag", not s["185.220.101.34"]["interesting"], str(s["185.220.101.34"]["interesting"]))
    check("bot UA detected", bool(s["45.148.10.66"]["interesting"].get("botlike_ua")))
    tl = L.timeline(ent, "177.154.220.44")
    check("timeline ordered", tl[0].split()[0] <= tl[-1].split()[0], str(tl[:2]))
else:
    skipped.append("dataset checks (run tools/gen_dataset.py)")
    print("  SKIP dataset missing")

print("== 5. canary consent gates ==")
state_path = os.path.join(ROOT, "out", "canary_state_test.json")
C.STATE = state_path
if os.path.exists(state_path):
    os.remove(state_path)
try:
    C.set_consent(["127.0.0.0/8"], "selftest")
    tok = C.issue("tester", "loopback only")
    hit = C.record(tok, "127.0.0.1", {"User-Agent": "x"}, {"tz": "Africa/Lagos"})
    check("consented hit recorded", hit["consented"] and hit["who"] == "tester", str(hit))
    stray = C.record(tok, "8.8.8.8", {}, None)
    check("out-of-scope hit flagged, not actioned", "NOT IN CONSENT SCOPE" in stray["action_required"], str(stray))
    check("unknown token flagged", "UNKNOWN TOKEN" in C.record("ffffffffff", "127.0.0.1", {}, None)["action_required"])
    try:
        C.issue("", "")
        check("issue() rejects empty consent", False, "no exception raised")
    except ValueError:
        check("issue() rejects empty consent", True)
    C.revoke(tok)
    check("revoke recorded", C._load()["tokens"][tok]["revoked"] is not None)
    import re as _re
    urls = _re.findall(r"""['"](https?:)?//[^'"]+['"]""", C.BEACON_JS)
    check("beacon posts only to relative paths (no exfil to a third host)", not urls, str(urls))
    check("canary has no DNS/HTTP push code", "socket" not in open(os.path.join(ROOT, "lab/canary.py"), encoding="utf-8", errors="replace").read().split("import")[-1])
finally:
    if os.path.exists(state_path):
        os.remove(state_path)

print("== 6. network enrichment (skips cleanly offline) ==")
if OFFLINE:
    skipped.append("--offline: geo/RDNS/RDAP/TLS enrichment")
    print("  SKIP --offline given; no outbound lookups attempted")
    net = None
else:
    net = T.geo("8.8.8.8").get("country")
if net:
    check("geo returns a country for 8.8.8.8", net == "US", net)
    check("anycast 8.8.8.8 lowers traceability", T.traceability("8.8.8.8")["traceability_score"] <= 60, "")
    r = T.rdns("8.8.8.8")
    check("rdns finds dns.google PTR", any("dns.google" in p for p in r["ptr"]), str(r))
    d = T.rdap("185.220.101.34")
    check("RDAP names the Tor exit block", "TOR" in (d.get("network_name") or "").upper(), str(d))
    thost, tport, tto = tls_target()
    c = T.tls_cert(thost, tport, os.environ.get("LAB_TLS_SNI", "one.one.one.one"), timeout=tto)
    if c.get("unreachable"):
        skipped.append(f"TLS SNI cert parse (no usable path to {thost}:{tport})")
        print(f"  SKIP TLS SNI cert - outbound 443 to {thost}:{tport} failed: {str(c.get('error'))[:70]}")
        print("        not a lab defect; re-run without the filter, or LAB_TLS_HOST=<a host you can reach>")
    else:
        check(f"TLS SNI cert parses ({thost}:{tport})", bool(c.get("subject") or c.get("sans")), str(c)[:120])
    if c.get("subject"):
        check("pem decoder working", c.get("decoder") in ("cryptography", "openssl-cli", "ssl-text"), str(c.get("decoder")))
else:
    skipped.append("all network enrichment checks (no outbound access)")
    print("  SKIP no outbound network (or --offline)")

# pure function, no socket - must not be gated on having outbound TLS
_pem0 = parse_pem("")
check("parse_pem degrades without deps (returns a dict, never raises)", isinstance(_pem0, dict), str(_pem0)[:80])

print("== 7. pcap round-trip (write then read back with the same parser) ==")
pcap_path = os.path.join(ROOT, "data", "lab_capture.pcap")
if os.path.exists(pcap_path):
    from lab import detect as DE
    from lab import pcap as P
    pk = list(P.read_pcap(pcap_path))
    check("pcap parses", len(pk) > 300, str(len(pk)))
    check("magic/linktype sane", pk[0][4] == P.LINKTYPE_ETHERNET, str(pk[0][4]))
    fl = P.flows(pcap_path)
    check("flows built", len(fl) > 50, str(len(fl)))
    exfil = [f for k, f in fl.items() if k.startswith("10.0.0.20:49320")]
    check("exfil flow >200kB outbound", exfil and exfil[0]["payload"] > 200_000, str(exfil[:1]))
    swp = {int(k.split("->")[1].rsplit(":", 1)[1]) for k in fl if k.startswith("203.0.113.7:") and "->10.0.0.20:" in k}
    check("port sweep spans 10+ ports", len(swp) >= 10, str(sorted(swp)))
    tflow = P.flows(os.path.join(ROOT, "data", "lab_capture_truncated.pcap"))
    check("truncation detectable (incl>payload)", tflow and all(v["bytes"] > v["payload"] for v in tflow.values()), str(tflow))
    reqs = P.reassemble(pcap_path, "10.0.0.20", 8443)
    check("HTTP reassembly finds the POST", any(any(r["request"].startswith("POST /upload") for r in f["requests"]) for f in reqs), str(reqs)[:120])
    db = DE.connect(":memory:")
    DE.load_flows(db, fl)
    if os.path.exists(os.path.join(ROOT, "data", "lab_capture_access.log")):
        DE.load_http(db, L.parse_file(os.path.join(ROOT, "data", "lab_capture_access.log")))
    res = DE.run_rules(db)
    fired = {r["id"]: r["count"] for r in res if r.get("count")}
    for must in ("http_auth_burst_then_success", "ssh_bruteforce", "egress_anomaly", "port_sweep_single_source",
                 "spoofed_forwarded_header", "truncated_capture",
                 "low_and_slow_port_probe", "uniform_cadence_automation",
                 "distributed_credential_stuffing", "logging_gap_on_http_flow"):
        check(f"rule fires: {must}", fired.get(must, 0) >= 1, str(fired))
    check("rule errors: none", not [r for r in res if r.get("error")], str([r for r in res if r.get("error")]))
    byid = {r["id"]: r for r in res}
    slow = [h for h in byid["low_and_slow_port_probe"]["hits"] if h["src"] == "203.0.113.200"]
    check("slow probe is caught on span, not on port count", slow and slow[0]["span_seconds"] > 900, str(slow[:1]))
    cad = [h for h in byid["uniform_cadence_automation"]["hits"] if h["src"] == "10.0.0.99"]
    check("no-jitter cadence caught (cv < 0.12)", cad and cad[0]["cv"] < 0.12, str(cad[:1]))
    dist = byid["distributed_credential_stuffing"]["hits"]
    check("stuffing caught on the ACCOUNT, with 9 sources", dist and dist[0]["srcs"] >= 9 and dist[0]["account"] == "admin", str(dist[:1]))
    check("per-IP burst rule correctly stays blind to it",
          not [h for h in byid["http_auth_burst_then_success"]["hits"] if h["src"].startswith("198.51.100.5")],
          str(byid["http_auth_burst_then_success"]["hits"]))
    gap = byid["logging_gap_on_http_flow"]["hits"]
    check("silent HTTP flow caught", gap and gap[0]["silent_seconds"] >= 1200, str(gap[:1]))
    check("rules carry FP list + ack procedure",
          all(r.get("false_positives") and r.get("ack") for r in DE.RULES), "missing ack/FP on some rule")
else:
    skipped.append("pcap checks (run tools/gen_pcap.py)")
    print("  SKIP pcap not generated")

print("== 8. audit rules on the two shipped configs ==")
try:
    from tools import audit as AU
    naive = AU.read_blob(os.path.join(ROOT, "proxy_lab/nginx/edge_naive.conf"))
    safe = AU.read_blob(os.path.join(ROOT, "proxy_lab/nginx/edge_safe.conf"))
    fn, fs = AU.audit_blob(naive), AU.audit_blob(safe)
    check("naive config: critical XFF finding", any(f["rule"] == "xff_forwarded_verbatim" and f["sev"] == "critical" for f in fn), str([f["rule"] for f in fn]))
    check("safe config: no critical findings", not [f for f in fs if f["sev"] == "critical"], str([f["rule"] for f in fs]))
    check("safe config still flags over-wide trust", any(f["rule"] == "trusted_too_wide" for f in fs), str([f["rule"] for f in fs]))
    check("audit parses listen ports", naive["listen"] and "8080" in naive["listen"], str(naive["listen"]))
    patch = AU.patch_snippet(fn)
    check("patch fragment emits nginx-ish config", "proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for" in patch
          or "server_tokens off" in patch, patch[:80])
except Exception as exc:  # noqa: BLE001
    failed.append(f"audit import/run: {type(exc).__name__}: {exc}")
    print("  FAIL audit:", exc)

print("== 9. target app behaviours used by the exercises ==")
import importlib.util
spec = importlib.util.spec_from_file_location("labtarget", os.path.join(ROOT, "apps/app.py"))
try:
    tgt = importlib.util.module_from_spec(spec); spec.loader.exec_module(tgt)
    def fake(xff=None, peer="9.9.9.9", cf=None):
        store = {}
        if xff:
            store["X-Forwarded-For"] = xff
        if cf:
            store["CF-Connecting-IP"] = cf if isinstance(cf, list) else [cf]

        class _H:
            def __init__(self, d): self.d = d
            def get(self, k, default=None):
                v = self.d.get(k)
                return (v[-1] if isinstance(v, list) else v) or default
            def get_all(self, k):
                return self.d.get(k, [])

        H = type("H", (), {"client_address": (peer, 1), "headers": _H(store)})
        return H()

    tgt.CFG.update(mode="naive", trusted=[], backend_ip="10.9.9.9")
    v, why = tgt.logged_ip(fake("1.1.1.1"))
    check("naive mode logs the spoofed value", v == "1.1.1.1" and "SPOOFABLE" in why, f"{v}/{why}")
    tgt.CFG.update(mode="safe")
    v2, why2 = tgt.logged_ip(fake("1.1.1.1"))
    check("safe mode ignores it", v2 == "9.9.9.9" and "SAFE" in why2, f"{v2}/{why2}")
    tgt.CFG.update(mode="cloudflare", trusted=[])
    v3, why3 = tgt.logged_ip(fake(cf="1.1.1.1"))
    check("unverified CF header is still believed (the bug) and flagged",
          v3 == "1.1.1.1" and "SPOOFABLE" in why3, f"{v3}/{why3}")
    v3b, why3b = tgt.logged_ip(fake(xff="1.1.1.1"))
    check("unverified peer with no CF header falls back to the peer",
          v3b == "9.9.9.9" and "SPOOFABLE" in why3b, f"{v3b}/{why3b}")
    tgt.CFG.update(trusted=["9.9.9.9/32"])
    v4, why4 = tgt.logged_ip(fake(cf="1.1.1.1"))
    check("verified CF peer's header is believed", v4 == "1.1.1.1" and "verified" in why4, f"{v4}/{why4}")
    v5, why5 = tgt.logged_ip(fake(cf=["1.1.1.1", "2.2.2.2"]))
    check("duplicated CF-Connecting-IP: last one wins and is flagged",
          v5 == "2.2.2.2" and "DUPLICATED" in why5, f"{v5}/{why5}")
except Exception as exc:  # noqa: BLE001
    failed.append(f"target import: {type(exc).__name__}: {exc}")
    print("  FAIL target app:", exc)
import socket
from lab import net as N
pem = ""
try:  # grab a real cert if the network allows it, and confirm the parser reads it
    ctx = __import__("ssl").create_default_context()
    ctx.check_hostname = False; ctx.verify_mode = __import__("ssl").CERT_NONE
    _h, _p, _to = tls_target()
    with socket.create_connection((_h, _p), timeout=_to) as sk:
        with ctx.wrap_socket(sk, server_hostname="one.one.one.one") as ss:
            pem = __import__("ssl").DER_cert_to_PEM_cert(ss.getpeercert(True))
except Exception:                # filtered/unroutable: the check below reports SKIP, not FAIL
    pem = ""
if pem:
    parsed = N.parse_pem(pem)
    check("parse_pem decodes a live cert", bool(parsed.get("subject")), str(parsed)[:100])
else:
    skipped.append("parse_pem live-cert check (no network, or --offline)")
    print("  SKIP no outbound network for cert parse")

print("== 10. footprint model + roe gate ==")
try:
    from tools import footprint as FP
    from tools import roe as ROE
    for scen in ("home", "tor", "vps_chain", "authorized_test"):
        sc, binding = FP.ghostability(FP.SCENARIOS[scen]["hops"])
        check(f"footprint scores {scen}", sc == 0.0 and binding, f"{sc}/{binding}")
    check("every hop has records/owner/retention/compel/identify/delete/note",
          all({"records", "owner", "retention", "compel", "identify", "delete", "note"} <= set(d) for d in FP.HOPS.values()),
          str([k for k, d in FP.HOPS.items() if {"compel", "note"} - set(d)]))
    inv = FP.local_inventory()
    check("local inventory returns typed rows", inv and all("present" in r for r in inv), str(len(inv)))
    check("inventory never prints a secret value",
          not any("://" in r["detail"] or "@" in r["detail"] and "git" not in r["source"] for r in inv if r["detail"]),
          str([r["source"] for r in inv if "@" in (r["detail"] or "")]))
    import subprocess
    rpt = os.path.join(ROOT, "out", "_footprint_selftest.md")
    r = subprocess.run([sys.executable, os.path.join(ROOT, "tools/footprint.py"), "--no-local", "--report", rpt],
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    check("footprint --report runs and writes", r.returncode == 0 and os.path.exists(rpt)
          and "FOOTPRINT MODEL" in open(rpt, encoding="utf-8", errors="replace").read(), (r.stderr or "")[-90:])
    os.remove(rpt)
    md = FP.render("vpn", inv, {"public_address_seen_by_a_server": "1.2.3.4"})
    for must in ("binding constraint", "compellable by", "who else holds a copy"):
        check(f"render includes {must!r}", must in md, "missing")
    # roe: the gate must refuse until signed, allow after, and stay honest about methods
    sc = ROE.default_scope("Selftest Ltd", "selftest", days=1)
    ok_unsigned, why0 = ROE.assess(sc, "http://127.0.0.1:8095/x")
    check("roe refuses until the scope is countersigned", not ok_unsigned and any("NOT SIGNED" in w for w in why0), str(why0))
    sc["authorised_by"]["signed_at"] = "2026-09-13T00:00:00+00:00"
    check("roe allows a signed, in-scope, in-window target", ROE.assess(sc, "http://127.0.0.1:8095/x")[0], "")
    check("roe refuses an out-of-scope host", not ROE.assess(sc, "http://8.8.8.8/")[0], "")
    check("roe refuses a port not listed", not ROE.assess(sc, "http://127.0.0.1:9/x")[0], "")
    check("roe refuses a method outside allowed_methods",
          not ROE.assess(sc, "http://127.0.0.1:8095/x", "TRACE")[0], "")
    check("roe refuses outside the window",
          not ROE.assess(sc, "http://127.0.0.1:8095/x", "GET",
                         when=ROE.NOW + _dt.timedelta(days=400))[0], "")
    check("the never-list survives any signature",
          "log_or_audit_tampering" in sc["never"]["do"] and "person_identification_from_ip" in sc["never"]["do"], str(sc["never"]["do"]))
except Exception as exc:  # noqa: BLE001
    failed.append(f"footprint/roe: {type(exc).__name__}: {exc}")
    print("  FAIL", exc)

# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# 11. web attack surface: apps/shop.py guards + the live A/B of every class
# ---------------------------------------------------------------------------
try:
    import json as _json
    import subprocess as _sp
    import time as _time

    spec = importlib.util.spec_from_file_location("shop", os.path.join(ROOT, "apps", "shop.py"))
    SHOP = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(SHOP)

    def tok(header: dict, claims: dict) -> str:
        return SHOP.b64u(_json.dumps(header).encode()) + "." + SHOP.b64u(_json.dumps(claims).encode()) + "."

    check("shop: raw search is string-formatted SQL", "LIKE '%" in SHOP.product_search("x")[0], "")
    check("shop: safe search uses bound parameters", "?" in SHOP.product_search_safe("x")[0], "")
    check("shop: safe search neutralises LIKE wildcards", SHOP.product_search_safe("%")[1] == [], "")
    check("shop: login_sql is injectable", SHOP.login_sql("' OR 1=1--", "x") is not None, "")
    check("shop: login_hard rejects the same payload", SHOP.login_hard("' OR 1=1--", "x") is None, "")
    check("shop: login_hard accepts the real password",
          SHOP.login_hard("ada@shop.test", "password123") == {"id": 1}, "")

    forged = tok({"alg": "none", "typ": "JWT"}, {"sub": "boss@shop.test", "id": 3, "role": "admin"})
    check("shop: alg=none forgery works while vulnerable",
          (SHOP.jwt_verify(forged) or {}).get("role") == "admin", "")
    check("shop: jwt_guard blocks the forgery", SHOP.jwt_guard(forged) is None, "")
    real = SHOP.jwt_make({"sub": "a@b.c", "id": 1, "exp": _time.time() + 60})
    check("shop: jwt_guard keeps a correctly signed token", (SHOP.jwt_guard(real) or {}).get("sub") == "a@b.c", "")
    check("shop: jwt_guard rejects a flipped payload",
          SHOP.jwt_guard(real.rsplit(".", 1)[0] + "." + SHOP.b64u(b"x")) is None, "")
    expired = SHOP.jwt_make({"sub": "a@b.c", "exp": _time.time() - 1})
    check("shop: jwt_guard enforces exp", SHOP.jwt_guard(expired) is None, "")

    check("shop: safe_path refuses an absolute path", SHOP.safe_path(SHOP.UPLOAD_DIR, "/etc/passwd") is None, "")
    check("shop: safe_path refuses traversal", SHOP.safe_path(SHOP.UPLOAD_DIR, "../" * 5 + "etc/passwd") is None, "")
    check("shop: safe_path containment is realpath-based", SHOP.safe_path("/tmp", "../etc/passwd") is None, "")
    _f = os.path.join(SHOP.UPLOAD_DIR, "selftest.txt")
    os.makedirs(SHOP.UPLOAD_DIR, exist_ok=True)
    open(_f, "w", encoding="utf-8").write("ok")
    check("shop: safe_path still serves a file inside the tree",
          SHOP.safe_path(SHOP.UPLOAD_DIR, "selftest.txt") == os.path.realpath(_f), "")
    os.unlink(_f)

    _xss = SHOP.esc('<svg onload=x>')
    check("shop: esc neutralises markup", "<" not in _xss and "&lt;" in _xss, _xss)
    check("shop: esc neutralises quotes", chr(34) not in SHOP.esc(chr(34)), "")
    check("shop: safe_next keeps relative, kills absolute",
          SHOP.safe_next("/ok") == "/ok" and SHOP.safe_next("//evil.test") == "/"
          and SHOP.safe_next("https://evil.test") == "/", "")
    check("shop: the planted secret is a fixed test value", SHOP.JWT_SECRET == "correct-horse-battery", "")

    r = _sp.run([sys.executable, os.path.join(ROOT, "apps", "shop.py"), "--selftest"],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=90, cwd=ROOT)
    check("shop --selftest exits 0", r.returncode == 0, (r.stdout + r.stderr)[-200:])
    check("shop --selftest reports all guards verified", "all shop guards verified" in r.stdout, r.stdout[-160:])

    r = _sp.run([sys.executable, os.path.join(ROOT, "tools", "webcheck.py")],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180, cwd=ROOT)
    check("webcheck: every class fires when vulnerable and is blocked when hardened",
          r.returncode == 0 and "every class fires" in r.stdout,
          ((r.stdout.splitlines() or [""])[-1]) + (r.stderr[-160:] if r.returncode else ""))
    n_ok = sum(1 for ln in r.stdout.splitlines() if ln.strip().endswith(" ok"))
    check("webcheck: 27 class rows all verdict=ok", n_ok >= 27 and "MISMATCH" not in r.stdout, f"{n_ok} ok rows")
except Exception as exc:  # noqa: BLE001
    failed.append(f"shop/webcheck: {type(exc).__name__}: {exc}")
    print("  FAIL", exc)


# ---------------------------------------------------------------------------
# 12. the tracking / device / phishing tools (pure functions + their own selftests)
# ---------------------------------------------------------------------------
try:
    import re as _re
    mods = {}
    for mod_name, path in (("eyeball", "tools/eyeball.py"), ("phish", "tools/phish.py"),
                           ("netinv", "tools/netinv.py")):
        sp = importlib.util.spec_from_file_location(mod_name, os.path.join(ROOT, path))
        mod = importlib.util.module_from_spec(sp)
        sp.loader.exec_module(mod)
        mods[mod_name] = mod
        r = _sp.run([sys.executable, os.path.join(ROOT, path), "--selftest"],
                    capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120, cwd=ROOT)
        check(f"{mod_name} --selftest exits 0", r.returncode == 0, (r.stdout + r.stderr)[-160:])

    PH = mods["phish"]
    check("phish: a look-alike brand domain scores high",
          PH.analyse_url("http://gtaibank-secure-verify.xyz/login/update?u=me@acme.ng")[0] >= 40, "")
    check("phish: a real banking URL scores low",
          PH.analyse_url("https://dashboard.kuda.com/")[0] < 20, "")
    check("phish: javascript: is refused at the top",
          PH.analyse_url("javascript:fetch('//x.test?c=1')")[0] >= 85, "")
    check("phish: punycode homograph is flagged",
          any("punycode" in r or "non-ASCII" in r for r in PH.analyse_url("https://xn--80ak6aa92e.com/x")[1]), "")
    check("phish: typosquat one edit from a brand is flagged",
          "one edit" in " ".join(PH.analyse_url("http://kudda.com/")[1]), "")
    check("phish: brand-in-path is flagged as decoration",
          "decoration" in " ".join(PH.analyse_url("https://cheap-host.top/paypal-verify/login.php")[1]), "")
    check("phish: verdict() is monotonic in score",
          "LIKELY" in PH.verdict(95) and "SUSPICIOUS" in PH.verdict(45) and "NO OBVIOUS" in PH.verdict(0), "")

    NE = mods["netinv"]
    rows = NE.parse_arp("? (192.168.1.22) at 3c:a5:81:00:11:22 on en0 ifscope [ethernet]\n"
                        "router.lan (192.168.1.254) at aa:bb:cc:dd:ee:ff on en0")
    check("netinv: parses arp -a and bare rows together", len(rows) == 2, str(rows))
    check("netinv: refuses a public address even with ranges given",
          not NE.in_scope("8.8.8.8", ["8.8.8.0/24"])[0], "")
    check("netinv: needs an explicit ownership assertion to plan anything",
          NE.plan(rows, ["192.168.1.0/24"], False)[0] == [] and len(NE.plan(rows, ["192.168.1.0/24"], True)[0]) == 2, "")
    check("netinv: classify finds a camera by name",
          NE.classify({"name": "IPCAM-3A1", "ip": ""}).startswith("camera"), "")
    check("netinv: an unauthenticated 200 with a password form is 2 highs",
          sum(1 for f in NE.analyze_response(200, {"Content-Type": "text/html"},
              '<form><input name=password></form>') if f["sev"] == "high") == 2, "")
    check("netinv: no probe endpoint writes, reboots or logs out",
          not any(_re.search(r"(action\s*=\s*(?:set|put|save)|reboot|reset|factory|logout)", e[0], _re.I)
                  for e in NE.ENDPOINTS), str([e[0] for e in NE.ENDPOINTS]))

    EB = mods["eyeball"]
    big = EB.profile({"canvas": "a", "webgl": "b", "fonts": "c", "storage-id": "d", "timezone": "e",
                      "screen": "f", "user-agent": "g", "peer-ip": "1.2.3.4"})
    small = EB.profile({"user-agent": "g", "accept-language": "en"})
    check("eyeball: a JS-bearing profile scores above a headers-only one",
          big["score_0_100"] > small["score_0_100"], f"{big['score_0_100']} vs {small['score_0_100']}")
    check("eyeball: identical fields give an identical identity",
          EB.profile({"canvas": "a", "fonts": "b"})["identity"] == EB.profile({"canvas": "a", "fonts": "b"})["identity"]
          and EB.profile({"canvas": "a"})["identity"] != EB.profile({"canvas": "z"})["identity"], "")
    st = EB.stability({"canvas": "a", "ip": "1"}, {"canvas": "a", "ip": "2"})
    check("eyeball: stability separates what moved from what never moves",
          st["stable"] == ["canvas"] and st["changed"] == ["ip"], str(st))
    check("eyeball: empty values are not counted as signals", EB.profile({"canvas": ""})["n_fields"] == 0, "")
    # --- 12b. does the lab itself survive Windows? (arp format, console code page, encodings) ---
    import glob as _glob
    import re as _re
    import tempfile as _tempfile
    from lab import win as WIN
    win_arp = (
        "Interface: 192.168.1.5 --- 0xb\r\n"
        "  Internet Address      Physical Address      Type\r\n"
        "  192.168.1.22          3c-a5-81-00-11-22     dynamic\r\n"
    )
    wrows = NE.parse_arp(win_arp)
    check("netinv: a Windows `arp -a` line parses and dash MACs are normalised",
          len(wrows) == 1 and wrows[0]["mac"] == "3c:a5:81:00:11:22", str(wrows))
    group_rows = NE.parse_arp(
        "  224.0.0.251           01-00-5e-00-00-fb     static\r\n"
        "  255.255.255.255       ff-ff-ff-ff-ff-ff     static\r\n")
    check("netinv: multicast/broadcast rows never become scan targets",
          NE.plan(group_rows, ["192.168.0.0/16"], True)[0] == [], str(group_rows))
    with _tempfile.NamedTemporaryFile("wb", suffix=".txt", delete=False) as fh:
        fh.write(win_arp.encode("utf-16"))
        utf16_path = fh.name
    try:
        check("netinv: PowerShell's UTF-16 redirect is sniffed, not garbled",
              len(NE.parse_arp(NE.read_arp_file(utf16_path))) == 1, NE.read_arp_file(utf16_path)[:40])
    finally:
        os.unlink(utf16_path)
    tgt = SHOP.traversal_target("../" * 5 + "etc/passwd")
    check("shop: the C1 payload lands on a readable passwd-shaped file on THIS os",
          os.path.isfile(tgt) and open(tgt, encoding="utf-8", errors="replace").read().startswith("root:x:0:0"),
          tgt)
    check("shop: that substitution does not soften the fix (hard mode still refuses it)",
          SHOP.safe_path(SHOP.UPLOAD_DIR, "../" * 5 + "etc/passwd") is None, "")
    WIN.ready()
    check("win.ready() makes stdout UTF-8 so a stray middle dot cannot kill a run",
          getattr(sys.stdout, "encoding", "").lower().replace("-", "") == "utf8", str(sys.stdout.encoding))
    check("win.python_cmd names an interpreter the user can actually type",
          WIN.python_cmd() in ("py", "python3", "python"), WIN.python_cmd())
    unencoded, clis, guarded = [], 0, 0
    for src_file in sorted(_glob.glob(os.path.join(ROOT, "*", "*.py"))):
        # every package dir at one level down: lab, tools, apps, proxy_lab
        name = os.path.basename(src_file)
        text = open(src_file, encoding="utf-8").read()
        if name != "win.py" and 'if __name__ == "__main__":' in text:
            clis += 1
            guarded += 1 if "win.ready()" in text else 0
        for line in text.splitlines():
            t = line.strip()
            if "open(" not in t or "encoding=" in t:
                continue
            if not _re.search(r"(?<![.\w])open\(", t) or "urlopen" in t:
                continue        # only the builtin call: *_open methods and urlopen are excluded
            if any(q in t for q in ('"rb"', '"wb"', "'rb'", "'wb'")):
                continue
            unencoded.append(name + ": " + t[:52])
    check("every text-mode open() in the lab states encoding=utf-8", not unencoded, " | ".join(unencoded[:3]))
    check("every CLI entry point installs the console shim", clis == guarded and clis >= 20,
          f"{guarded}/{clis} entry points guarded")

    import shutil as _shutil
    _r = _sp.run([sys.executable, os.path.join(ROOT, "tools", "sync.py"), "status"],
                 capture_output=True, text=True, encoding="utf-8", errors="replace", cwd=ROOT)
    if _shutil.which("git") and _r.returncode == 0:
        check("sync.py status reports repo state (the bundle publishing path)",
              "tracked" in _r.stdout and "bundle" in _r.stdout, _r.stdout[:90])
    else:
        skipped.append("sync.py status (no git here, or this tree is a plain copy, not a clone)")
        print("  SKIP sync.py status - needs a git clone to be meaningful")
except Exception as exc:  # noqa: BLE001
    failed.append(f"tracking/device tools: {type(exc).__name__}: {exc}")
    print("  FAIL", exc)

print()
if failed:
    print(f"RESULT: {len(failed)} FAILED of {ok + len(failed)} -> {failed}")
    raise SystemExit(1)
print(f"RESULT: {ok} checks passed" + (f", {len(skipped)} skipped: {skipped}" if skipped else ""))
