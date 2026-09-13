#!/usr/bin/env python3
"""
Module 8 - deliberate web vulns, on a target that is physically only you.

The guard is not decoration: every request goes to a loopback or RFC1918 address
and the script refuses anything else. If you want the same classes against real
targets, you do them in an authorised scope (a deliberately-vulnerable image, a
lab platform, or a bug-bounty programme whose policy you have read) - that is
exactly what makes the same skill employable instead of criminal.

  python3 apps/app.py --port 8095 --mode safe &
  python3 tools/web.py --port 8095
  python3 tools/web.py --port 8095 --exercise ssrf --chain-canary
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from lab import tracer as T  # noqa: E402


def allowed_host(host: str) -> bool:
    try:
        a = ipaddress.ip_address(host)
    except ValueError:
        return host in ("localhost",) or host.endswith((".internal", ".lab", ".test"))
    return a.is_loopback or a.is_private or a.is_link_local


SCOPE: dict | None = None      # set by main() when --scope is given


def scope_gate(url: str, method: str) -> tuple[bool, list[str]]:
    """Every request goes through the signed scope. This is the one habit that separates
    an engagement from an offence, so it is enforced in code rather than remembered."""
    if SCOPE is None:
        return True, []
    try:
        import importlib
        roe = importlib.import_module("tools.roe")
    except Exception as exc:  # noqa: BLE001
        return False, [f"cannot load tools/roe.py ({type(exc).__name__}) - refusing to run unsupervised"]
    return roe.assess(SCOPE, url, method)


def call(base: str, path: str, headers: dict | None = None, method: str = "GET", data: bytes | None = None,
         timeout: float = 8.0):
    url = base.rstrip("/") + path
    ok, why = scope_gate(url, method)
    if not ok:
        return None, ("REFUSED-BY-SCOPE: " + "; ".join(why)).encode(), {}
    req = urllib.request.Request(url, data=data, method=method, headers={"User-Agent": "Mozilla/5.0 (ip-lab)", **(headers or {})})
    # deliberately do NOT follow redirects: the status code is the finding in the auth
    # and open-redirect exercises, and urllib would swallow the 302 for us.
    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, r.read(8000), dict(r.headers.items())
    except urllib.error.HTTPError as e:
        return e.code, e.read(8000), dict((e.headers or {}).items())
    except Exception as exc:  # noqa: BLE001
        return None, f"{type(exc).__name__}: {exc}".encode(), {}


def show(name, ok, detail, lesson, fix):
    print(f"\n[{ 'HIT ' if ok else 'miss'}] {name}")
    print(f"        observed: {detail}")
    print(f"        why it matters: {lesson}")
    print(f"        fix: {fix}")
    return ok


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8095)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--exercise", choices=["all", "idor", "ssrf", "header-diff", "leak", "auth", "xff"], default="all")
    ap.add_argument("--chain-canary", action="store_true", help="also fetch the canary page through the SSRF")
    ap.add_argument("--canary-port", type=int, default=8090)
    ap.add_argument("--scope", help="signed scope from tools/roe.py; every request is checked against it")
    a = ap.parse_args()

    global SCOPE
    if a.scope:
        import importlib
        roe = importlib.import_module("tools.roe")
        SCOPE = roe.load_scope(a.scope)
        ok, why = roe.assess(SCOPE, f"http://{a.host}:{a.port}/", "GET")
        print(f"scope gate: {'ALLOWED' if ok else 'REFUSED'}  ({a.scope})")
        for w in why:
            print(f"   - {w}")
        for note in roe.advisories(SCOPE):
            print(f"   note: {note}")
        if not ok:
            print("   Nothing was sent. Amend the scope (tools/roe.py) or stop.")
            return 1

    if not allowed_host(a.host):
        print(f"REFUSED: {a.host} is not loopback/private. This tool only aims at machines you own.")
        return 2
    base = f"http://{a.host}:{a.port}"
    code, _, _ = call(base, "/")
    if code not in (200, 404):
        print(f"cannot reach {base} ({code}) - start it:  python3 apps/app.py --port {a.port} --mode safe")
        return 1

    score, ran = 0, 0
    ex = a.exercise

    if ex in ("all", "idor"):
        ran += 1
        c, b, _ = call(base, "/api/v1/user/1")
        leaked = c == 200 and b"invoice_total" in b
        score += show("IDOR: object reference with no ownership check", leaked,
                      f"GET /api/v1/user/1 -> {c} {b[:60]!r}",
                      "an 'unauthenticated read of another tenant's record' is a data breach even if nothing was 'hacked'. "
                      "Enumeration of /2 /3 /4 turns one leak into a dump.",
                      "check ownership in the query (WHERE owner_id = session.user_id), and prefer opaque ids (uuid/ulid) "
                      "so the reference itself carries no information; add per-principal rate limits")
        ran += 1
        c2, b2, _ = call(base, "/api/v1/user/1?token=anything")
        show("IDOR is not fixed by adding a meaningless parameter", c2 == 200,
             f"?token=anything -> {c2}", "the classic 'fix' that is not a fix: attacker just omits or guesses it",
             "authorisation is a decision about the *session*, never a parameter the client can choose")

    if ex in ("all", "ssrf"):
        ran += 1
        meta = f"http://{a.host}:{a.port}/internal/metadata"
        c, b, _ = call(base, "/fetch?" + urllib.parse.urlencode({"url": meta}))
        got = c == 200 and b"AccessKeyId" in b
        score += show("SSRF: server-side fetch reaches link-local/metadata", got,
                      f"/fetch?url={meta} -> {c} {b[:70]!r}",
                      "the fetch is made BY YOUR SERVER, so no browser policy, no CORS, no firewall at the edge applies. "
                      "Metadata endpoints hand out cloud credentials; that is how 'IP leak' stories become 'account takeover'.",
                      "deny-by-default egress from the app role; resolve the URL yourself and re-check every IP version "
                      "(127.0.0.1, 0.0.0.0, [::1], 169.254.169.254, decimal/octal encodings, DNS-rebind 1s TTL); block "
                      "non-http(s) schemes; and use IMDSv2-style hop limits + a metadata proxy")
        if a.chain_canary:
            c3, b3, _ = call(base, "/fetch?" + urllib.parse.urlencode({"url": f"http://127.0.0.1:{a.canary_port}/"}))
            show("SSRF into the canary: the *server* shows up in the log, not the client", c3 == 200,
                 f"{c3} {b3[:50]!r}", "this is why an 'IP leak' link in an issue tracker reveals infrastructure: the "
                 "request comes from the fetching service, with its IP and its user-agent",
                 "same egress controls; treat any user-supplied URL as untrusted input to a network call")
        dec = str(int.from_bytes(bytes(map(int, "127.0.0.1".split("."))), "big"))
        variants = [
            ("localhost alias", f"http://localhost:{a.port}/internal/metadata"),
            ("decimal IP", f"http://{dec}:{a.port}/internal/metadata"),
            ("IPv6 loopback", f"http://[::1]:{a.port}/internal/metadata"),
            ("0.0.0.0", f"http://0.0.0.0:{a.port}/internal/metadata"),
            ("DNS name -> 127.0.0.1", f"http://localhost.localdomain:{a.port}/internal/metadata"),
            ("redirect hop (3xx)", f"http://localhost:{a.port}/redirect-me"),
        ]
        for note, v in variants:
            cc, bb, _ = call(base, f"/fetch?url={urllib.parse.quote(v, safe='')}", timeout=3.0)
            bypassed = b"AccessKeyId" in bb
            verdict = "BYPASSED the string-prefix allow-list (metadata readable)" if bypassed else \
                f"no leak this time -> {cc} {(bb or b'-')[:52].decode('latin-1', 'replace')}"
            print(f"        {note:<24} {v[:44]:<46} {verdict}")
        print("        a prefix allow-list is not a security control. Patch with ssrf_guarded() at the")
        print("        bottom of apps/app.py, then rerun this and watch every line go to 'blocked'.")
        print("        (and the DNS-rebind/timeout shapes: 10.0.0.1:9 will HANG the handler for its")
        print("         full connect timeout - that is a real availability lesson too: no connect")
        print("         timeout, no egress proxy, no circuit breaker = your worker pool is now the attacker's.)")

    if ex in ("all", "header-diff"):
        ran += 1
        c, b, h = call(base, "/nothing-here", {"X-Original-URL": "/admin"})
        score += show("Parser differential: X-Original-URL rewrites the route *after* the filter",
                      c == 200 and b'"admin": true' in b, f"GET /nothing-here + X-Original-URL: /admin -> {c} {b[:50]!r}",
                      "the edge/WAF matched /nothing-here, the origin matched /admin. Any allow/deny list built on the "
                      "path is only as good as the *agreement* between the components.",
                      "delete X-Original-URL/X-Rewrite-URL at the edge; keep one normalised path representation "
                      "everywhere (and remember `..;/`, `//`, `%2e`, trailing-dot and case tricks are the same class of bug)")
        ran += 1
        c2, b2, _ = call(base, "/admin/..;/x")
        show("Same class: path-normalisation disagreement", c2 == 200,
             f"/admin/..;/x -> {c2} "
             + ("ORIGIN MATCHED /admin - vulnerable stack" if c2 == 200 else
                "our lab target normalises, so 404. On a real stack this exact shape returns 200: the edge sees "
                "/admin/..;/x, the framework sees /admin. Try it in a DVWA/Juice Shop/PortSwigger lab.")[:200],
             "each stack (nginx, app framework, WAF, CDN) normalises differently", "normalise-then-match, once, at the edge")

    if ex in ("all", "leak"):
        ran += 1
        c, b, h = call(base, "/debug/vars")
        score += show("Config/topology disclosure via debug endpoint + response headers",
                      c == 200 and "x-backend-ip" in {k.lower() for k in h},
                      f"/debug/vars -> {c}, X-Backend-IP={h.get('X-Backend-IP')}, X-Debug-Trace={h.get('X-Debug-Trace')}",
                      "this is the leak that turns a scan into a target list. Anyone reading your headers learns your "
                      "internal naming scheme and origin address.",
                      "run tools/audit.py against your real config; hide/strip these at the edge; delete the route")
        ran += 1
        c2, b2, _ = call(base, "/api/v1/report?q=boom")
        show("500 with a traceback (paths, logged IP, sometimes secrets)", c2 == 500 and b"Traceback" in b2,
             f"/api/v1/report?q=boom -> {c2} {b2[:60]!r}",
             "the response told the visitor which IP the log recorded. Error bodies are an information channel.",
             "return a generic error + a request id; keep the detail server-side, joined by that id")

    if ex in ("all", "auth"):
        ran += 1
        results = {}
        for user, pw in (("victim@acme.ng", "admin123"), ("victim@acme.ng", "password"),
                         ("victim@acme.ng", "letmein123"), ("nosuchuser@acme.ng", "whatever")):
            c, b, h = call(base, "/login", method="POST",
                           headers={"Content-Type": "application/x-www-form-urlencoded"},
                           data=f"email={user}&password={pw}".encode())
            results[(user, pw)] = (c, (h.get("Set-Cookie") or ""), b)
        hit = results[("victim@acme.ng", "letmein123")]
        miss = results[("victim@acme.ng", "password")]
        unknown = results[("nosuchuser@acme.ng", "whatever")]
        score += show("Successful login is a 302, and the cookie it sets has no flags",
                      hit[0] == 302,
                      f"correct pw -> {hit[0]}, Set-Cookie={hit[1][:60]!r}   wrong pw -> {miss[0]}",
                      "no lockout, no backoff, no MFA; and a session cookie without Secure/HttpOnly/SameSite "
                      "is readable by any script or plain-HTTP response you accidentally serve",
                      "rate-limit + progressive delay on the *pair* (account, principal), MFA for admin roles, "
                      "cookie flags Secure; HttpOnly; SameSite=Lax, and a short session with rotation on privilege change")
        score += show("User enumeration: unknown account answers differently from a wrong password",
                      (unknown[0], unknown[2][:24]) != (miss[0], miss[2][:24]),
                      f"unknown user -> {unknown[0]} {unknown[2][:40]!r}  vs  wrong pw -> {miss[0]} {miss[2][:40]!r}",
                      "one request per address turns your login form into a user-existence oracle; that is the "
                      "recon step that makes targeted credential stuffing cheap",
                      "identical response body + status + timing for both cases; verify with 100 requests each, "
                      "diff the distributions, not the single response")

    if ex in ("all", "xff"):
        ran += 1
        c, b, h = call(base, "/echo", {"X-Forwarded-For": "1.1.1.1"})
        try:
            doc = json.loads(b)
        except Exception:  # noqa: BLE001
            doc = {}
        logged = doc.get("logged_ip")
        spoofed = logged == "1.1.1.1"
        score += show("Logged client address is attacker-controlled (XFF)", spoofed,
                      f"/echo logged_ip={logged} reason={doc.get('log_reason', '?')}",
                      "everything downstream (geo, blocklists, rate limits, incident reports) inherits this lie.",
                      "app must not trust XFF unless the peer is a verified proxy. See proxy_lab/ + audit.py; "
                      "run  bash proxy_lab/chain_demo.sh  to watch the same spoof survive or die at each hop")
        if not spoofed and logged:
            d = T.traceability(logged)
            print(f"        (and if you *had* been an attacker: your address {logged} traces to "
                  f"'{d['ceiling']}' - {d['traceability_score']}/100)")

    print(f"\n{'='*72}\n{score}/{ran} exercises produced a real finding on YOUR lab target.")
    print("Rerun the same battery against `--mode safe`: exactly ONE exercise flips (the XFF")
    print("one), because the modes change only the logging decision. IDOR, SSRF, the header")
    print("differential and the debug endpoint are application bugs - no proxy config fixes")
    print("them. That split (config bug vs code bug) is the first thing to establish in any")
    print("real finding, because it decides who owns the fix and how fast it can ship.")
    print("Every class here is a defensive lesson first: write the fix, apply it, rerun this")
    print("and watch *your* class go to zero. That diff is portfolio material.")
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
