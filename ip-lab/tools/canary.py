#!/usr/bin/env python3
"""
Canary server + CLI for Module 5.

  python3 tools/canary.py consent --cidr 127.0.0.0/8 --cidr 10.0.0.0/8 \
      --note "self + lab VLAN only, agreed 2026-09-13 in #lab channel"
  python3 tools/canary.py issue --who "me (Ayo, lab box)" --scope "self-test of my own doc link"
  python3 tools/canary.py serve --port 8090
  python3 tools/canary.py report

Consent model: hits outside the consent CIDRs are RECORDED AND FLAGGED, never
acted on. There is no feature here that turns an IP into a person, on purpose.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from lab import canary as C  # noqa: E402

TOKEN_RE = re.compile(r"^/c/([0-9a-f]{4,40})(?:/(open\.png|ping))?$")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "canary-lab/0.1"
    sys_version = ""

    def log_message(self, fmt, *args):
        pass

    def _read_body(self) -> dict | None:
        n = int(self.headers.get("Content-Length") or 0)
        if not n:
            return None
        raw = self.rfile.read(min(n, 65536))
        try:
            return json.loads(raw.decode("utf-8", "replace"))
        except Exception:  # noqa: BLE001
            return {"raw": raw[:500].decode("utf-8", "replace")}

    def _handle(self, body: bool = True):
        m = TOKEN_RE.match(self.path)
        if not m:
            if self.path == "/":
                st = C._load()
                payload = json.dumps({"tokens": list(st["tokens"]), "consent": st["consent"]}, indent=2).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                return self.wfile.write(payload)
            return self.send_error(404, "unknown path")
        tok, kind = m.group(1), m.group(2)
        client_ip = self.client_address[0]
        headers = dict(self.headers.items())
        payload = self._read_body() if body else None
        if kind == "open.png":
            hit = C.record(tok, client_ip, headers, None)
            self.send_response(204)
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Canary", "logged")
            self.send_header("Content-Length", "0")
            self.end_headers()
            print(f"  open.png {tok} from {client_ip} consented={hit['consented']}")
            return
        if kind == "ping":
            hit = C.record(tok, client_ip, headers, payload)
            self.send_response(204)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", "0")
            self.end_headers()
            print(f"  ping     {tok} from {client_ip} consented={hit['consented']} fields={sorted((payload or {}).keys())[:6]}")
            return
        meta = C._load()["tokens"].get(tok)
        body_html = C.PAGE_TMPL.format(
            token=tok,
            who=(meta or {}).get("who", "UNKNOWN TOKEN - you did not issue this"),
            scope=(meta or {}).get("scope", "-"),
            js=C.BEACON_JS.replace("BEACON", tok),
            captured="on page load only (this HTML is the telemetry carrier)",
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body_html)))
        self.send_header("Referrer-Policy", "unsafe-url")  # deliberate: so you can SEE referrer capture
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body_html)
        print(f"  page     {tok} -> {client_ip}")

    def do_GET(self):  # noqa: N802
        self._handle(body=False)

    def do_POST(self):  # noqa: N802
        self._handle(body=True)

    def do_HEAD(self):  # noqa: N802
        self._handle(body=False)


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("serve"); p.add_argument("--port", type=int, default=8090)
    p = sub.add_parser("issue"); p.add_argument("--who", required=True); p.add_argument("--scope", required=True)
    p.add_argument("--path", default="/lab/report-4471"); p.add_argument("--base", default="", help="public base URL to print")
    p = sub.add_parser("revoke"); p.add_argument("token")
    p = sub.add_parser("consent"); p.add_argument("--cidr", action="append", default=[]); p.add_argument("--note", default="")
    sub.add_parser("report")
    sub.add_parser("selftest")
    a = ap.parse_args()

    if a.cmd == "serve":
        print(f"canary listening on 0.0.0.0:{a.port}. Open http://127.0.0.1:{a.port}/c/<token> from a browser you are allowed to instrument.")
        ThreadingHTTPServer(("0.0.0.0", a.port), Handler).serve_forever()
    elif a.cmd == "issue":
        tok = C.issue(a.who, a.scope, path=a.path)
        base = (a.base or "http://127.0.0.1:8090").rstrip("/")
        print(f"token: {tok}\nurl:   {base}/c/{tok}")
        print("Remember: put the link somewhere ONLY the named person can click it, and tell them it is instrumented.")
    elif a.cmd == "revoke":
        print("revoked" if C.revoke(a.token) else "no such token")
    elif a.cmd == "consent":
        C.set_consent(a.cidr, a.note)
        print("consent scope saved:", a.cidr)
    elif a.cmd == "selftest":
        C.set_consent(["127.0.0.0/8", "10.0.0.0/8"], "selftest")
        tok = C.issue("selftest", "loopback only")
        hit = C.record(tok, "127.0.0.1", {"User-Agent": "selftest"}, {"tz": "Africa/Lagos"})
        stray = C.record("deadbeef01", "8.8.8.8", {}, None)
        assert hit["consented"] is True and hit["who"] == "selftest", hit
        assert stray["token_known"] is False and "UNKNOWN TOKEN" in stray["action_required"], stray
        assert "NOT IN CONSENT SCOPE" in C.record(tok, "8.8.8.8", {}, None)["action_required"]
        print("canary selftest OK\n")
        print(C.report())
    elif a.cmd == "report":
        print(C.report())
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
