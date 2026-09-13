#!/usr/bin/env python3
"""app.py — the Module 2/4/10 lab target: one app, three logging policies.

    python3 apps/app.py --port 8095 --mode naive
    python3 apps/app.py --port 8085 --mode safe --backend-ip 10.0.0.7
    python3 apps/app.py --port 8096 --mode cloudflare

Then drive it with `tools/probe.py`, `tools/web.py`, or `proxy_lab/chain_demo.sh`.

Why it lives in `apps/` and not `target/`: `target` is a build-output directory name
in most sync/backup tooling (and in this lab's own snapshot rules), so a directory with
that name is not reliably persisted. Lesson worth keeping: never put source under a name
your tools are configured to throw away.

Three modes, one difference — *what the access log records as the client address*:

  safe        the socket peer only; XFF is logged as a lie
  naive       the leftmost X-Forwarded-For value is believed (the classic bug)
  cloudflare  CF-Connecting-IP believed when the peer verified; duplicate headers -> last wins

Everything else in this file is the application half of the story: an IDOR route, a
`/fetch` whose only control is a URL *prefix* (SSRF), a debug endpoint that leaks
topology, a 500 with a traceback, an `X-Original-URL` differential, an open redirect,
a login form with no flags on the cookie and distinguishable errors, and - for the
session classes in notes/11 - fixation and cookie-theft shapes. `logged_ip()` is pure,
which is how tools/selftest.py can pin it without a socket. `ssrf_guarded()` at the
bottom is the model answer for /fetch.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CFG = {"mode": "safe", "trusted": ["127.0.0.0/8"], "backend_ip": None,
       "log": os.path.join(ROOT, "out", "target_access_sim.log")}

FORWARD_HEADERS = ("X-Forwarded-For", "CF-Connecting-IP", "True-Client-IP", "X-Real-IP")
USERS = {"victim@acme.ng": "letmein123"}          # the lab's only credential, on purpose
AUDIT: list[dict] = []                             # what /debug/vars leaks


# ------------------------------------------------------------------ the decision
def _net_trusted(ip: str, trusted: list[str]) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in ipaddress.ip_network(c, strict=False) for c in trusted or [])


def logged_ip(handler) -> tuple[str, str]:
    """Return (address that goes in the log, why). Pure: no sockets, so it is testable.

    This one function is the whole of module 2. Everything a defender or an analyst
    believes about "who did this" is decided here, by policy, in the wrong direction
    in `naive` mode.
    """
    peer = handler.client_address[0]
    h = handler.headers
    mode = CFG["mode"]

    def last_or_dup(name: str) -> tuple[str | None, bool]:
        raw = h.get_all(name)
        if raw is None:
            raw = [h.get(name)] if h.get(name) else []      # tolerate a scalar from a fake handler
        if isinstance(raw, str):
            raw = [raw]
        vals = [v for v in raw if v]
        if len(vals) > 1:
            return vals[-1], True          # nginx keeps the LAST duplicate header
        return (vals[0] if vals else None), False

    if mode == "cloudflare":
        cf, dup = last_or_dup("CF-Connecting-IP")
        if cf:
            why = "CF-Connecting-IP believed"
            if dup:
                why += " (DUPLICATED header: last one wins)"
            if _net_trusted(peer, CFG["trusted"]):
                return cf.strip(), why + " - peer verified"
            return cf.strip(), why + " - SPOOFABLE: peer is not in the trusted list"
        return peer, ("SPOOFABLE: no CF-Connecting-IP, socket peer used - but this mode believes "
                      "the header the moment it appears")

    if mode == "naive":
        xff, dup = last_or_dup("X-Forwarded-For")
        if xff:
            left = xff.split(",")[0].strip()
            why = "leftmost X-Forwarded-For believed"
            if dup:
                why += " (DUPLICATED header: last one wins)"
            return left, why + " - SPOOFABLE, anyone can type it"
        return peer, "no XFF; socket peer used (naive mode is still wrong when XFF arrives)"

    # safe
    xff, _ = last_or_dup("X-Forwarded-For")
    if xff:
        return peer, "SAFE: XFF present but ignored (peer not verified as a trusted proxy)"
    return peer, "SAFE: socket peer only"


def peer_class(ip: str) -> str:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return "unparsable"
    for name, attr in (("loopback", "is_loopback"), ("private", "is_private"),
                       ("link-local", "is_link_local"), ("multicast", "is_multicast"),
                       ("reserved", "is_reserved")):
        if getattr(a, attr):
            return name
    return "global"


def logline(handler, status: int, logged: str, why: str) -> str:
    """Combined-ish format so tools/dossier.py can parse it unchanged."""
    ts = time.strftime("%d/%b/%Y:%H:%M:%S +0000")
    q = handler.path.replace('"', "")
    ua = handler.headers.get("User-Agent", "-")
    return (f'{logged} - - [{ts}] "{handler.command} {q} HTTP/1.1" {status} 250 "-" "{ua}" '
            f'xff="{handler.headers.get("X-Forwarded-For", "-")}" reason="{why}"')


# ------------------------------------------------------------------- the handler
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        return

    # -- plumbing
    def emit(self, code: int, body: str, ctype: str = "application/json",
             extra: dict | None = None, log: bool = True):
        logged, why = logged_ip(self)
        if log:
            os.makedirs(os.path.dirname(CFG["log"]), exist_ok=True)
            with open(CFG["log"], "a", encoding="utf-8") as fh:
                fh.write(logline(self, code, logged, why) + "\n")
            AUDIT.append({"ts": ts_now(), "path": self.path, "status": code, "logged_as": logged})
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Logged-As", logged)
        self.send_header("X-Log-Reason", why)
        if CFG["backend_ip"]:
            self.send_header("X-Backend-IP", CFG["backend_ip"])
        if code >= 500:
            self.send_header("X-Debug-Trace", "1")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def route(self) -> str:
        """The differential: some stacks rewrite the route from a header *after* the filter.
        Here it is the bug, spelled out in ten lines."""
        path = urllib.parse.urlparse(self.path).path
        override = self.headers.get("X-Original-URL") or self.headers.get("X-Rewrite-URL")
        return override if override else path

    # -- GET
    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        path, q = u.path, {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
        route = self.route()

        if route.startswith("/admin"):
            # the whole point of the differential: this handler runs for /nothing-here too
            return self.emit(200, json.dumps({"admin": True, "matched_route": route,
                                              "requested_path": path,
                                              "note": "filter saw one path, handler saw the other"}))
        if path == "/":
            return self.emit(200, json.dumps({"app": "ip-lab target", "mode": CFG["mode"],
                                              "routes": ["/echo", "/login", "/api/v1/user/<id>",
                                                         "/api/v1/report", "/fetch", "/internal/metadata",
                                                         "/debug/vars", "/admin", "/redirect-me", "/session",
                                                         "/whoami"]}))
        if path == "/echo":
            logged, why = logged_ip(self)
            fwd = {k: self.headers.get(k) for k in FORWARD_HEADERS if self.headers.get(k)}
            return self.emit(200, json.dumps({
                "peer_ip": self.client_address[0], "peer_class": peer_class(self.client_address[0]),
                "logged_ip": logged, "log_reason": why, "forwarded_headers_seen": fwd,
                "mode": CFG["mode"], "trusted": CFG["trusted"]}, indent=2))
        if path.startswith("/api/v1/user/"):
            uid = path.rsplit("/", 1)[-1]
            # BUG (IDOR): no ownership check. `?token=...` proves a fake check is not a check.
            return self.emit(200, json.dumps({"id": uid, "email": f"user{uid}@acme.ng",
                                              "invoice_total": 412500, "currency": "NGN",
                                              "invoice_pdf": f"/files/{uid}.pdf",
                                              "note": "no ownership check on this object reference"}))
        if path == "/api/v1/report":
            if q.get("q"):
                try:
                    1 / int(q["q"])                      # deliberately fragile
                except ZeroDivisionError as exc:
                    import traceback
                    return self.emit(500, json.dumps({"error": "ZeroDivisionError",
                                                      "traceback": traceback.format_exc(),
                                                      "logged_ip": logged_ip(self)[0]} | {"exc": str(exc)}))
                except ValueError:
                    import traceback
                    return self.emit(500, json.dumps({"error": "int() failed",
                                                       "traceback": traceback.format_exc(),
                                                       "q": q["q"]}))
            return self.emit(200, json.dumps({"report": "ok"}))
        if path == "/fetch":
            url = q.get("url", "")
            # BUG: the entire control is a string prefix. It says nothing about the host,
            # the resolved IP, the redirect chain, or the scheme after resolution.
            if not url.startswith(("http://", "https://")):
                return self.emit(400, json.dumps({"rejected": "scheme must be http(s)", "url": url}))
            try:
                with urllib.request.urlopen(url, timeout=3.0) as r:
                    return self.emit(200, f'{{"via":"server","status":{r.status},"body":'
                                          f'{json.dumps(r.read(4000).decode(errors="replace"))}}}')
            except urllib.error.HTTPError as e:
                return self.emit(e.code, json.dumps({"via": "server", "status": e.code,
                                                      "body": e.read(2000).decode(errors="replace")}))
            except Exception as exc:  # noqa: BLE001
                return self.emit(502, json.dumps({"via": "server", "error": f"{type(exc).__name__}: {exc}"}))
        if path == "/internal/metadata":
            # stand-in for 169.254.169.254/latest/meta-data/iam/security-credentials/*
            return self.emit(200, json.dumps({"AccessKeyId": "AKIALABLABLABLABLA",
                                             "SecretAccessKey": "lab-not-a-real-key",
                                             "Token": "lab-instance-identity", "Type": "Machine",
                                             "region": "eu-west-1", "iam_role": "app-prod"}))
        if path == "/debug/vars":
            return self.emit(200, json.dumps({"mode": CFG["mode"], "trusted": CFG["trusted"],
                                              "backend_ip": CFG["backend_ip"], "log_path": CFG["log"],
                                              "env": {k: v for k, v in os.environ.items()
                                                      if any(s in k.upper() for s in ("PASS", "KEY", "SECRET", "TOKEN"))},
                                              "recent": AUDIT[-15:]}, indent=2))
        if path == "/redirect-me":
            # lets /fetch hop through a 3xx to the metadata endpoint (the redirect bypass)
            return self.emit(302, "", "text/plain",
                             {"Location": f"http://{self.headers.get('Host', '127.0.0.1')}/internal/metadata"})
        if path in ("/logout", "/go"):
            nxt = q.get("next", "/")
            # BUG: open redirect - any absolute URL accepted, so the app vouches for it
            return self.emit(302, "", "text/plain", {"Location": nxt})
        if path == "/session":
            sid = q.get("sid") or ("S" + str(int(time.time() * 1000) % 10**8))
            # BUG (fixation): a client-supplied sid is adopted and never rotated
            SESSIONS.setdefault(sid, {"sub": None, "profiles": []})
            note = "sid accepted from the client and will survive login (that is the bug)"
            if CFG.get("rotate_on_auth"):
                note = "sid accepted, but it is rotated on login (hard mode)"
            resp = self.emit(200, json.dumps({"sid": sid, "note": note}))
            self._sid = sid
            return resp
        if path == "/whoami":
            sid = self.headers.get("Cookie", "").partition("sid=")[2].partition(";")[0]
            s = SESSIONS.get(sid, {})
            return self.emit(200, json.dumps({"sid": sid or None, "sub": s.get("sub"),
                                              "profiles": s.get("profiles", []),
                                              "peer": self.client_address[0],
                                              "ua": self.headers.get("User-Agent")}))
        if path == "/healthz":
            return self.emit(200, json.dumps({"ok": True, "mode": CFG["mode"]}), log=False)
        return self.emit(404, json.dumps({"error": "no route", "path": path}))

    # -- POST
    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n).decode(errors="replace") if n else ""
        f = {k: v[0] for k, v in urllib.parse.parse_qs(raw).items()}
        path = urllib.parse.urlparse(self.path).path
        if path == "/login":
            email, pw = f.get("email", ""), f.get("password", "")
            if email not in USERS:
                # BUG: enumeration - unknown account answers differently from a wrong pw
                return self.emit(404, json.dumps({"error": "no such account", "tried": email}))
            if USERS[email] != pw:
                return self.emit(401, json.dumps({"error": "invalid credentials"}))
            sid = self.headers.get("Cookie", "").partition("sid=")[2].partition(";")[0] or "S" + str(os.getpid())
            if CFG.get("rotate_on_auth"):
                sid = "S" + str(int(time.time() * 1000) % 10**8)     # the fix: rotate on privilege change
            SESSIONS.setdefault(sid, {"sub": None, "profiles": []})
            SESSIONS[sid]["sub"] = email
            SESSIONS[sid]["profiles"].append({"ua": self.headers.get("User-Agent"),
                                              "peer": self.client_address[0], "ts": ts_now()})
            cookie = f"sid={sid}; Path=/"                            # BUG: no HttpOnly/Secure/SameSite
            return self.emit(302, json.dumps({"login": "ok", "sid": sid}), "text/plain",
                             {"Location": "/", "Set-Cookie": cookie})
        return self.emit(404, json.dumps({"error": "no route", "path": path}))

    def do_HEAD(self):
        self.do_GET()


SESSIONS: dict[str, dict] = {}


def ts_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


# --------------------------------------------------------------- the model answer
def ssrf_guarded(url: str, allow_hosts: tuple[str, ...] = ()) -> tuple[bool, str]:
    """Fix for /fetch. The policy runs on the *resolved address*, after the scheme is
    checked, and it must run again for every redirect hop (the caller re-calls this).

    Returns (allowed, why). Refuses: non-http(s), literal private/loopback/link-local
    addresses, and any host whose DNS answers with one of those (the rebinding shape -
    a real fix also pins the resolved IP for the connection's lifetime and sets a short TTL).
    """
    try:
        u = urllib.parse.urlsplit(url)
    except ValueError as exc:  # noqa: PERF203
        return False, f"unparsable url: {exc}"
    if u.scheme not in ("http", "https"):
        return False, f"scheme {u.scheme!r} not allowed (file/gopher/dict are how these become LFI)"
    host = u.hostname or ""
    if not host:
        return False, "no host"
    if host in allow_hosts:
        return True, f"{host} explicitly allowed"
    try:
        infos = socket.getaddrinfo(host, u.port or 80, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        return False, f"dns failed: {exc}"
    for fam, _t, _p, _c, sa in infos:
        ip = ipaddress.ip_address(sa[0])
        bad = (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
               or ip.is_reserved or ip.is_unspecified)
        if fam == socket.AF_INET6 and (ip.is_private or ip.is_loopback):
            bad = True
        if bad:
            return False, f"{host} resolves to {ip} ({ip.__class__.__name__}: " \
                          f"{'/'.join(n for n in ('private','loopback','link-local','multicast','reserved','unspecified') if getattr(ip, 'is_' + n, False)) or 'blocked'}"
    return True, "resolved to a public address and allowed"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--port", type=int, default=8095)
    ap.add_argument("--mode", choices=["safe", "naive", "cloudflare"], default="safe")
    ap.add_argument("--trusted", default="127.0.0.0/8", help="comma-separated CIDRs allowed to forward")
    ap.add_argument("--backend-ip", default=None, help="if set, leaked in X-Backend-IP (the disclosure exercise)")
    ap.add_argument("--log", default=CFG["log"])
    ap.add_argument("--rotate-on-auth", action="store_true", help="rotation on login (fixes session fixation)")
    a = ap.parse_args()
    CFG.update(mode=a.mode, trusted=[t.strip() for t in a.trusted.split(",") if t.strip()],
               backend_ip=a.backend_ip, log=a.log, rotate_on_auth=a.rotate_on_auth)
    print(f"[app] 127.0.0.1:{a.port} mode={a.mode} trusted={CFG['trusted']} log={a.log}")
    if a.mode != "safe":
        print(f"[app] mode={a.mode}: the access log will record a value the client controls.")
    ThreadingHTTPServer(("127.0.0.1", a.port), Handler).serve_forever()
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
