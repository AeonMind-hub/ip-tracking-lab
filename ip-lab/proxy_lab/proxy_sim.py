"""
A 200-line HTTP proxy that lets you *be* the nginx hop, so the whole three-hop
lesson runs anywhere Python runs (including boxes with no nginx installed).

Two modes, exactly mirroring the two config files in this directory:

  --mode naive   : forwards the client's X-Forwarded-For verbatim (the bug),
                   and logs $remote_addr, which is *this* proxy from the app's side.
  --mode correct : appends the peer it saw ($proxy_add_x_forwarded_for), and, when
                   --real-ip-header is set, resolves the client by walking the chain
                   right-to-left over --trusted ranges and rewrites the header.
                   --real-ip-recursive off  = nginx plain mode (right-most entry only).
                   --strip-inbound-xff      = drop what the client sent before appending,
                                              i.e. `proxy_set_header X-Forwarded-For
                                              $remote_addr`. The actual fix; watch both
                                              sides of it in proxy_lab/chain_demo.sh §C.

  python3 proxy_lab/proxy_sim.py --listen 127.0.0.1:8080 --upstream 127.0.0.1:8081 --mode naive
  python3 proxy_lab/proxy_sim.py --listen 127.0.0.1:8088 --upstream 127.0.0.1:8081 --mode correct \
          --trusted 127.0.0.0/8 --real-ip-header X-Forwarded-For

Log lines land in out/proxy_<port>_access.log in combined format, so
`tools/dossier.py` reads them directly.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import ipaddress
import os
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
from lab import logs as L  # noqa: E402

CFG: dict = {}
LOCK = threading.Lock()


def log(entry: dict) -> None:
    path = CFG["log"]
    os.makedirs(os.path.dirname(path), exist_ok=True)
    line = (f'{entry["ip"]} - - [{_dt.datetime.now(_dt.timezone.utc):%d/%b/%Y:%H:%M:%S} +0000] '
            f'"{entry["method"]} {entry["path"]} HTTP/1.1" {entry["status"]} {entry["size"]} '
            f'"{entry.get("ref","-")}" "{entry.get("ua","-")}" "{entry.get("xff","-")}"')
    with LOCK, open(path, "a", encoding="utf-8") as fh:
        fh.write(line + "\n")


def decide(peer: str, incoming_xff: str) -> dict:
    """The one decision that produces 'the client IP' in this hop's log line.

    Kept separate from the socket plumbing so `tools/selftest.py` can pin its
    behaviour directly, and so you can read the policy without the HTTP noise.
    """
    if CFG.get("strip_inbound") and CFG["mode"] != "naive":
        # "strip, then append": the chain this hop forwards contains only addresses this
        # hop observed, so every downstream hop's walk is over data nobody but the proxies
        # wrote. This is the actual fix for the trust-list problem, and it is what
        # nginx's `proxy_set_header X-Forwarded-For $remote_addr` (not $proxy_add_...) does.
        incoming_xff = ""
    if CFG["mode"] == "naive":
        # nginx: log_format ... '$http_x_forwarded_for'  (the bug)
        leftmost = (L.split_xff(incoming_xff) or [peer])[0]
        return {"logged": leftmost, "out_xff": incoming_xff,
                "why": "naive: forwarded AND logged the client's own XFF value"}

    out_xff = f"{incoming_xff}, {peer}".strip(", ") if incoming_xff else peer
    # a hop may only believe a forwarded value that arrived from a peer it actually
    # owns. Untrusted peer => the header is the client's typing.
    peer_is_trusted = bool(CFG["trusted"]) and any(
        ipaddress.ip_address(peer) in ipaddress.ip_network(t.strip(), strict=False)
        for t in CFG["trusted"])
    chain = L.split_xff(incoming_xff)
    if CFG["real_ip_recursive"] == "off":
        # nginx plain mode: only the RIGHT-MOST value is considered, taken as-is,
        # and only when this hop's peer is in set_real_ip_from. No walk.
        pick = chain[-1] if (chain and peer_is_trusted) else peer
        verdict = {"verdict_ip": pick,
                   "why": f"real_ip_recursive off: right-most entry {pick!r} used without a walk"}
    else:
        verdict = L.real_ip({"ip": peer, "xff_list": chain}, CFG["trusted"])
    logged = verdict["verdict_ip"] if (CFG["real_ip_header"] and peer_is_trusted) else peer
    why = (f"correct: appended peer; real_ip -> {logged}  ({verdict['why']})"
           f"{'' if peer_is_trusted else ' [peer not in trusted set, header ignored]'}")
    return {"logged": logged, "out_xff": out_xff, "why": why, "chain": chain,
            "peer_is_trusted": peer_is_trusted, "verdict": verdict}


class Proxy(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "proxy-sim/1.0"
    sys_version = ""

    def log_message(self, *a):
        pass

    def _proxy(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(min(length, 4_000_000)) if length else b""
        peer = self.client_address[0]
        incoming_xff = self.headers.get("X-Forwarded-For", "")
        d = decide(peer, incoming_xff)
        logged, out_xff, why = d["logged"], d["out_xff"], d["why"]

        req = f"{self.command} {self.path} HTTP/1.1\r\n"
        sent = set()
        for k, v in self.headers.items():
            kl = k.lower()
            if kl in ("host", "content-length", "connection", "proxy-connection", "x-forwarded-for", "keep-alive"):
                continue
            req += f"{k}: {v}\r\n"
            sent.add(kl)
        host_hdr = self.headers.get("Host") or f"{CFG['up'][0]}:{CFG['up'][1]}"
        req += f"Host: {host_hdr}\r\nX-Forwarded-For: {out_xff}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n"

        s = socket.create_connection(CFG["up"], timeout=10)
        s.sendall(req.encode("latin-1") + body)
        chunks = []
        s.settimeout(10)
        try:
            while True:
                d = s.recv(65536)
                if not d:
                    break
                chunks.append(d)
        except socket.timeout:
            pass
        finally:
            s.close()
        raw = b"".join(chunks)
        head, _, rbody = raw.partition(b"\r\n\r\n")
        status = 502
        lines = head.split(b"\r\n")
        resp_headers = []
        if lines and lines[0].startswith(b"HTTP/"):
            try:
                status = int(lines[0].split(b" ")[1])
            except Exception:  # noqa: BLE001
                pass
            for hl in lines[1:]:
                k, _, v = hl.partition(b":")
                kl = k.decode("latin-1").lower().strip()
                if CFG["mode"] == "naive":
                    resp_headers.append((k.decode("latin-1"), v.decode("latin-1").strip()))
                    continue
                if kl in ("server", "x-backend-ip", "x-debug-trace", "x-powered-by", "x-log-reason"):
                    continue                                   # strip disclosures at the edge
                if kl in ("content-length", "transfer-encoding", "connection"):
                    continue
                resp_headers.append((k.decode("latin-1"), v.decode("latin-1").strip()))
        resp_headers.append(("X-Proxy-Sim-Logged", logged))
        resp_headers.append(("X-Proxy-Sim-Mode", why))
        self.send_response(status)
        for k, v in resp_headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(rbody)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(rbody)
        log({"ip": logged, "method": self.command, "path": self.path, "status": status,
             "size": len(rbody), "ua": self.headers.get("User-Agent", "-"),
             "ref": self.headers.get("Referer", "-"), "xff": out_xff or "-"})
        print(f"{status} {self.command} {self.path}  peer={peer} logged={logged}  out_xff={out_xff!r}")

    do_GET = do_POST = do_HEAD = do_PUT = do_DELETE = do_OPTIONS = _proxy


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", default="127.0.0.1:8080")
    ap.add_argument("--upstream", default="127.0.0.1:8085")
    ap.add_argument("--mode", choices=["naive", "correct"], default="naive")
    ap.add_argument("--trusted", action="append", default=[])
    ap.add_argument("--real-ip-header", default="")
    ap.add_argument("--real-ip-recursive", choices=["on", "off"], default="off",
                    help="off (default) = nginx plain mode: walk ONE trusted hop. "
                         "on = recursive mode: trust the whole trusted prefix, so a client that can "
                         "reach this hop through a trusted range can still choose the logged IP. "
                         "See notes/06-proxy-lab.md - this flag IS the demo.")
    ap.add_argument("--strip-inbound-xff", action="store_true",
                    help="drop any X-Forwarded-For the client sent before appending (the real fix)")
    a = ap.parse_args()
    h, _, p = a.listen.partition(":")
    uh, _, up = a.upstream.partition(":")
    CFG.update(mode=a.mode, trusted=a.trusted, real_ip_header=a.real_ip_header,
               real_ip_recursive=a.real_ip_recursive, strip_inbound=a.strip_inbound_xff,
               up=(uh, int(up or 80)), log=os.path.join(ROOT, "out", f"proxy_{p}_access.log"))
    print(f"proxy-sim {a.listen} -> {a.upstream}  mode={a.mode} trusted={a.trusted} real_ip_header={a.real_ip_header or '-'}")
    print(f"log: {CFG['log']}")
    ThreadingHTTPServer((h, int(p)), Proxy).serve_forever()


try:                                  # Windows console/encoding shim; no-op elsewhere
    import os as _os, sys as _sys
    _sys.path.insert(0, _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "..", "lab"))
    import win
    win.ready()
except ImportError:
    pass


if __name__ == "__main__":
    main()
