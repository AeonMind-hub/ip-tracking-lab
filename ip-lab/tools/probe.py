#!/usr/bin/env python3
"""
Module 4 driver: run each probe against your own lab target three times
(once per logging mode) and print what the server would have believed.

  python3 tools/probe.py --port 8080                 # against one instance
  python3 tools/probe.py --naive 8080 --cf 8081 --safe 8082

Every request goes to 127.0.0.1, i.e. a machine you own. Nothing here touches
a third party. If you point a --target at anything you do not own, stop.
"""
from __future__ import annotations

import argparse
import json
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request

class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Do not swallow 301/302: the redirect IS the finding (login success)."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


# (label, path, headers, body-or-None)
PROBES = [
    ("plain GET /echo", "/echo", {}, None),
    ("forged single XFF", "/echo", {"X-Forwarded-For": "8.8.8.8"}, None),
    ("forged chain XFF", "/echo", {"X-Forwarded-For": "127.0.0.1, 8.8.8.8"}, None),
    ("forged CF-Connecting-IP", "/echo", {"CF-Connecting-IP": "1.1.1.1"}, None),
    ("forged True-Client-IP", "/echo", {"True-Client-IP": "9.9.9.9"}, None),
    ("forged X-Real-IP", "/echo", {"X-Real-IP": "7.7.7.7"}, None),
    ("brute force, wrong pw", "/login", {}, ("POST", b"email=victim%40acme.ng&password=admin123")),
    ("brute force, right pw", "/login", {}, ("POST", b"email=victim%40acme.ng&password=letmein123")),
]


def request(url: str, headers: dict, body=None) -> dict:  # noqa: A002
    parsed = urllib.parse.urlparse(url if "://" in url else "http://" + url)
    ctx = None
    if parsed.scheme == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    data = None
    if body:
        method, data = body
    else:
        method = "GET"
    req = urllib.request.Request(parsed.geturl(), data=data, method=method,
                                 headers={"User-Agent": "Mozilla/5.0 (lab-probe) ip-lab/1.0", **headers})
    opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=ctx) if ctx else urllib.request.BaseHandler)
    try:
        with opener.open(req, timeout=10) as r:
            raw, code, hdrs = r.read(200000), r.status, dict(r.headers.items())
    except urllib.error.HTTPError as e:
        raw, code, hdrs = e.read(200000), e.code, dict((e.headers or {}).items())
    except Exception as exc:  # noqa: BLE001
        return {"error": f"{type(exc).__name__}: {exc}"}

    out = {"status": code, "logged_as": hdrs.get("X-Logged-As"), "log_reason": hdrs.get("X-Log-Reason")}
    try:
        j = json.loads(raw)
        out["echo_peer"] = j.get("peer_ip")
        out["echo_class"] = j.get("peer_class")
    except Exception:
        pass
    if "/debug/vars" not in parsed.path and code == 404:
        out["note"] = "404 - is the path right?"
    return out


def ttl_probe(host: str, port: int = 443) -> dict:
    """
    TTL of a TCP SYN-ACK tells you how many hops away the responder is.
    A CDN origin behind Cloudflare answers ~5-15 hops away; the same origin
    IP answering 1 hop away means it is NOT behind the proxy any more.
    Needs raw sockets (sudo) - degrades to a clear message when unavailable.
    """
    try:
        with socket.create_connection((host, port), timeout=5):
            pass
    except Exception as exc:  # noqa: BLE001
        return {"error": f"connect failed: {exc}"}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.close()
        raw = True
    except OSError:
        raw = False
    if not raw:
        return {"error": "no raw socket permission (run with sudo on your own box) - and see the note in notes/04-tools.md on why TTL is weak evidence"}
    return {"note": "raw sockets available; see tools/README for the TTL recipe"}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8080, help="single instance under test")
    ap.add_argument("--naive", type=int, help="port of --mode naive instance")
    ap.add_argument("--cf", type=int, help="port of --mode cloudflare instance")
    ap.add_argument("--safe", type=int, help="port of --mode safe instance")
    ap.add_argument("--target", help="EXPERT: host:port you own; headers still forged only against it")
    ap.add_argument("--debug-vars", action="store_true", help="also fetch /debug/vars")
    ap.add_argument("--ttl", action="store_true", help="TTL/hop probe (needs raw sockets)")
    a = ap.parse_args()

    targets = {}
    if a.naive:
        targets["naive (leftmost XFF trusted)"] = f"127.0.0.1:{a.naive}"
    if a.cf:
        targets["cloudflare (CF-Connecting-IP, unverified)"] = f"127.0.0.1:{a.cf}"
    if a.safe:
        targets["safe (remote_addr)"] = f"127.0.0.1:{a.safe}"
    if not targets:
        targets[f"single instance on {a.port}"] = f"127.0.0.1:{a.port}"
    if a.target:
        if not a.target.startswith(("127.", "localhost", "10.", "192.168.")):
            print("refusing: --target must be loopback/RFC1918, i.e. a machine you own. Aborting.")
            return 2
        targets["custom (you own this)"] = a.target

    for label, host in targets.items():
        print(f"\n=== target mode: {label} ({host}) ===")
        for name, path, hdrs, body in PROBES:
            r = request(f"http://{host}{path}", hdrs, body)
            flag = ""
            if path == "/login":
                flag = "  <-- LOGIN SUCCEEDED (302)" if r.get("status") == 302 else "  (401)"
            print(f"  {name:<30} -> status={r.get('status') or r.get('error')!s:<12} logged_as={r.get('logged_as')!s:<16}{flag}")
            if r.get("log_reason"):
                print(f"  {'':<30}    {r['log_reason']}")
        if a.debug_vars:
            r = request(f"http://{host}/debug/vars", {})
            print(f"  /debug/vars -> status={r.get('status')}  headers X-Backend-IP / X-Debug-Trace are in the response (curl -i to read them)")
        r = request(f"http://{host}/api/v1/report?q=boom", {})
        print(f"  {'500 with traceback':<30} -> status={r.get('status')}")
    if a.ttl:
        print("\n=== TTL / hop probe ===")
        for host in sorted(set(targets.values())):
            h, _, p = host.partition(":")
            print(f"  {host}: {json.dumps(ttl_probe(h, int(p or 443)))}")
    print("\nNext: tail out/target_access_sim.log and run  python3 tools/dossier.py out/target_access_sim.log --xff")
    return 0


if __name__ == "__main__":
    try:                            # Windows console/encoding shim; no-op elsewhere
        import sys as _sys, os as _os
        _sys.path.insert(0, _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "..", "lab"))
        import win
        win.ready()
    except ImportError:
        pass
    raise SystemExit(main())
