#!/usr/bin/env python3
"""
Module 7 - synthetic, self-consistent evidence: one pcap AND one access log
describing the same traffic. That pairing is the whole point: pcap tells you
what the wire said, the log tells you what the application decided, and an
incident is only understood when the two agree (or when you can explain why
they don't).

Planted, in order (the answer key is printed at the end, and also in data/key.json):
  · two real visitors doing normal GETs                     (noise)
  · a port sweep from 203.0.113.7 across 12 ports           (recon)
  · 11 SSH connection attempts from 203.0.113.7             (brute force)
  · 7x 401 then a 302 on /login from 198.51.100.23,         (ATO - and it arrives
    carrying X-Forwarded-For: 8.8.8.8                          through a proxy config bug)
  · a 220 KB POST to an attacker listener                    (exfil, ratio anomaly)
  · one long flow with 4 retransmissions                      (broken MTU decoy)
  · one flow whose captured length < wire length              (truncation gotcha)
  · ARP + ICMP noise

  python3 tools/gen_pcap.py            # writes data/lab_capture.pcap (+ .log, + .trunc.pcap)
"""
from __future__ import annotations

import json
import os
import random
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from lab import pcap as K  # noqa: E402

T0 = 1_760_140_800          # 2025-10-11 00:00:00 UTC-ish; any fixed base is fine
MAC_GW = b"\x02\x00\x00\x00\x00\x01"
MAC_SV = b"\x02\x00\x00\x00\x00\x02"
SV = "10.0.0.20"
GW = "10.0.0.1"
W = random.Random(24)
log_lines: list[str] = []


def fmt(t: float) -> str:
    import datetime as _dt
    return _dt.datetime.fromtimestamp(t, _dt.timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")


def session(w: K.PcapWriter, t: float, client: str, sport: int, server: str, dport: int,
            req: bytes, resp: bytes, *, rst_at_end: bool = False, fin: bool = True,
            ttl_c: int = 52, ttl_s: int = 64, cseq_start: int = 1000, retrans: int = 0,
            syn_only: bool = False, chunk: int = 1400, write_log: dict | None = None) -> tuple[float, dict]:
    """One TCP exchange, with correct seq/ack arithmetic. Returns (next t, summary)."""
    seq, ack = cseq_start, 0
    # SYN -> SYN/ACK
    w.write(K.eth(MAC_GW, MAC_SV, payload=K.ipv4(20, 6, client, server, ttl=ttl_c,
            payload=K.tcp(sport, dport, seq, 0, K.SYN, window=64240))), t)
    t += 0.011
    w.write(K.eth(MAC_SV, MAC_GW, payload=K.ipv4(20, 6, server, client, ttl=ttl_s,
            payload=K.tcp(dport, sport, 5000, seq + 1, K.SYN | K.ACK, window=28960))), t)
    t += 0.004
    seq += 1
    ack = 5001
    w.write(K.eth(MAC_GW, MAC_SV, payload=K.ipv4(20, 6, client, server, ttl=ttl_c,
            payload=K.tcp(sport, dport, seq, ack, K.ACK))), t)
    t += 0.002
    if syn_only:
        w.write(K.eth(MAC_SV, MAC_GW, payload=K.ipv4(20, 6, server, client, ttl=ttl_s,
                payload=K.tcp(dport, sport, ack, seq, K.RST | K.ACK))), t)
        return t + 0.003, {"syn_only": True}
    # client payload (may retransmit the last segment `retrans` times)
    sent = 0
    for i, off in enumerate(range(0, len(req), chunk)):
        part = req[off:off + chunk]
        w.write(K.eth(MAC_GW, MAC_SV, payload=K.ipv4(len(part), 6, client, server, ttl=ttl_c,
                payload=K.tcp(sport, dport, seq, ack, K.PSH | K.ACK, payload=part))), t)
        sent = len(part)
        seq += len(part)
        t += 0.006
    for _ in range(retrans):
        t += 0.2
        w.write(K.eth(MAC_GW, MAC_SV, payload=K.ipv4(sent, 6, client, server, ttl=ttl_c,
                payload=K.tcp(sport, dport, seq - sent, ack, K.PSH | K.ACK))), t)
    # server response
    off = 0
    while off < len(resp):
        part = resp[off:off + chunk]
        w.write(K.eth(MAC_SV, MAC_GW, payload=K.ipv4(len(part), 6, server, client, ttl=ttl_s,
                payload=K.tcp(dport, sport, ack, seq, K.PSH | K.ACK, payload=part))), t)
        ack += len(part)
        off += len(part)
        t += 0.008
    w.write(K.eth(MAC_GW, MAC_SV, payload=K.ipv4(20, 6, client, server, ttl=ttl_c,
            payload=K.tcp(sport, dport, seq, ack, K.ACK))), t)
    t += 0.002
    if rst_at_end:
        w.write(K.eth(MAC_SV, MAC_GW, payload=K.ipv4(20, 6, server, client, ttl=ttl_s,
                payload=K.tcp(dport, sport, ack, seq, K.RST | K.ACK))), t)
    elif fin:
        w.write(K.eth(MAC_GW, MAC_SV, payload=K.ipv4(20, 6, client, server, ttl=ttl_c,
                payload=K.tcp(sport, dport, seq, ack, K.FIN | K.ACK))), t)
        t += 0.003
        w.write(K.eth(MAC_SV, MAC_GW, payload=K.ipv4(20, 6, server, client, ttl=ttl_s,
                payload=K.tcp(dport, sport, ack, seq + 1, K.FIN | K.ACK))), t)
        t += 0.003
        w.write(K.eth(MAC_GW, MAC_SV, payload=K.ipv4(20, 6, client, server, ttl=ttl_c,
                payload=K.tcp(sport, dport, seq + 1, ack + 1, K.ACK))), t)
    t += 0.5
    if write_log:
        d = write_log
        log_lines.append(f'{d["ip"]} - {d.get("user") or "-"} [{fmt(t)}] "{d["method"]} {d["path"]} HTTP/1.1" '
                         f'{d["status"]} {d.get("size", len(resp))} "{d.get("ref", "-")}" "{d["ua"]}" "{d.get("xff", "-")}"')
    return t, {}


def http_get(path: str, host: str = "app.aeonlabs.test", ua: str = "Mozilla/5.0", cookie: str = "") -> bytes:
    c = f"Cookie: {cookie}\r\n" if cookie else ""
    return (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\nAccept: */*\r\n{c}"
            f"Connection: keep-alive\r\n\r\n").encode()


def http_post(path: str, body: bytes, host: str = "app.aeonlabs.test", ua: str = "Mozilla/5.0",
              cookie: str = "", extra: dict | None = None) -> bytes:
    hdrs = "".join(f"{k}: {v}\r\n" for k, v in (extra or {}).items())
    c = f"Cookie: {cookie}\r\n" if cookie else ""
    return (f"POST {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {ua}\r\nContent-Type: application/x-www-form-urlencoded\r\n"
            f"Content-Length: {len(body)}\r\n{c}{hdrs}Connection: keep-alive\r\n\r\n").encode() + body


def resp(code: int, reason: str, body: bytes, extra: dict | None = None) -> bytes:
    h = "".join(f"{k}: {v}\r\n" for k, v in (extra or {}).items())
    return (f"HTTP/1.1 {code} {reason}\r\nServer: nginx/1.24.0\r\nDate: Fri, 11 Oct 2025 00:00:00 GMT\r\n"
            f"Content-Type: text/html; charset=utf-8\r\nContent-Length: {len(body)}\r\n{h}Connection: keep-alive\r\n\r\n").encode() + body


def main() -> None:
    data = os.path.join(ROOT, "data")
    os.makedirs(data, exist_ok=True)
    pcap_path = os.path.join(data, "lab_capture.pcap")
    w = K.PcapWriter(pcap_path)
    tw = K.PcapWriter(os.path.join(data, "lab_capture_truncated.pcap"))
    t = float(T0)

    # --- noise: two legitimate visitors -------------------------------------
    for i, (ip, path, ua) in enumerate([("102.89.33.4", "/api/dashboard", "Mozilla/5.0 (Windows NT 10.0)"),
                                         ("197.210.58.9", "/api/invoices", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4)")]):
        t, _ = session(w, t, ip, 40000 + i, SV, 80,
                       http_get(path, ua=ua, cookie="sid=valid9f2"), resp(200, "OK", b"{}\n" * 40),
                       write_log={"ip": ip, "method": "GET", "path": path, "status": 200, "ua": ua, "size": 160})
        t, _ = session(w, t, ip, 40010 + i, SV, 80, http_get("/static/app.css", ua=ua),
                       resp(200, "OK", b"body{}" * 90), write_log={"ip": ip, "method": "GET", "path": "/static/app.css",
                                                                   "status": 200, "ua": ua, "size": 450, "ref": "https://app.aeonlabs.test/"})

    # --- recon: port sweep (SYN only, RST back) -----------------------------
    for p in list(range(20, 32)) + [22, 80, 443, 3306, 5432, 6379, 8080, 9200]:
        t, _ = session(w, t, "203.0.113.7", 51000 + p, SV, p, b"", b"", syn_only=True)

    # --- ssh brute force -----------------------------------------------------
    for i in range(11):
        payload = (b"\x00\x00\x00\x1c" + b"service-ssh" + bytes([0x21 + i]) * 12)
        t, _ = session(w, t, "203.0.113.7", 52000 + i, SV, 22, payload, b"SSH-2.0-OpenSSH_9.6\r\n" + b"\x00" * 20,
                       rst_at_end=True)
        t += 1.7

    # --- the ATO, arriving through a broken proxy config --------------------
    for i in range(7):
        t, _ = session(w, t, "198.51.100.23", 44100 + i, SV, 80,
                       http_post("/login", b"email=adeola.o%40acme.ng&password=Q" + str(i).encode() * 6,
                                 ua="Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/126.0"),
                       resp(401, "Unauthorized", b"<p>invalid</p>"),
                       write_log={"ip": "10.0.0.1", "user": "-", "method": "POST", "path": "/login", "status": 401,
                                  "ua": "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/126.0",
                                  "xff": "198.51.100.23, 8.8.8.8", "size": 15})
        t += 2.0
    t, _ = session(w, t, "198.51.100.23", 44170, SV, 80,
                   http_post("/login", b"email=adeola.o%40acme.ng&password=letmein123",
                             ua="Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/126.0"),
                   resp(302, "Found", b"", {"Set-Cookie": "sid=stolen123; Path=/", "Location": "/dashboard"}),
                   write_log={"ip": "10.0.0.1", "user": "adeola.o", "method": "POST", "path": "/login", "status": 302,
                              "ua": "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/126.0",
                              "xff": "198.51.100.23, 8.8.8.8", "size": 0})
    for j, (p, st) in enumerate([("/api/profile/email", 200), ("/api/billing/export", 200)]):
        t, _ = session(w, t, "198.51.100.23", 44300 + j, SV, 80, http_get(p, cookie="sid=stolen123",
                       ua="Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/126.0"),
                       resp(st, "OK", b'{"ok":true}' * 12),
                       write_log={"ip": "10.0.0.1", "user": "adeola.o", "method": "GET", "path": p, "status": st,
                                  "ua": "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/126.0",
                                  "xff": "198.51.100.23, 8.8.8.8", "size": 120})

    # --- exfil: big POST out to an attacker listener ------------------------
    blob = (b"Zm9yLXlvdS1ub3QtdGhlLXBvbGljZQ==" * 10_000)[:220_000]
    body = b"------boundary\r\nContent-Disposition: form-data; name=\"f\"\r\n\r\n" + blob + b"\r\n------boundary--\r\n"
    t, _ = session(w, t, SV, 49320, "203.0.113.99", 8443, http_post("/upload", body, host="drop.203-0-113-99.example"),
                   resp(200, "OK", b"ok"), chunk=1400)

    # --- decoy: retransmissions on a long flow (MTU/tunnel, not an attack) --
    t, _ = session(w, t, "102.89.33.4", 49500, SV, 8443, http_get("/api/sync"),
                   resp(200, "OK", b"x" * 40_000), retrans=4, ttl_c=64)

    # --- stealth shapes: four ways an operator tries to be quiet, and what gives it away
    #     (this is the module-10 planting block; `tools/triage.py` has the matching rules)
    # (a) low-and-slow port probe: 12 ports, 150 s apart - below every "scan" threshold
    ts = t + 20.0
    for i, port in enumerate(range(8000, 8012)):
        ts, _ = session(w, t + 20.0 + i * 150.0, "203.0.113.200", 41000 + i, SV, port, b"", b"",
                        syn_only=True, ttl_c=54)
    # (b) machine cadence: 24 requests 2.000 s apart - no human jitter in the gaps
    for i in range(24):
        session(w, t + 60.0 + i * 2.0, "10.0.0.99", 44600 + i, SV, 80,
                http_get(f"/api/v1/report?id={i}"), resp(200, "OK", b'{"ok":true}'),
                write_log={"ip": "10.0.0.99", "user": "svc-sync", "method": "GET",
                           "path": f"/api/v1/report?id={i}", "status": 200,
                           "ua": "python-requests/2.32", "size": 40})
    # (c) distributed credential stuffing: 9 addresses x 2 tries on ONE account, so every
    #     per-source rule is satisfied and only an account-keyed rule sees it
    for i in range(9):
        for j in range(2):
            session(w, t + 200.0 + i * 3.0 + j * 0.4, f"198.51.100.{50 + i}", 46000 + i * 4 + j, SV, 80,
                    http_post("/login", f"u=admin&p=pass{j}".encode()),
                    resp(401, "Unauthorized", b"<p>no</p>"),
                    write_log={"ip": f"198.51.100.{50 + i}", "user": "admin", "method": "POST",
                               "path": "/login", "status": 401,
                               "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "size": 12})
    # (d) a connection that stayed open on the web port and produced NO log line:
    #     keep-alive, a dead collector, or `access_log off` decided mid-incident
    silent = t + 400.0
    w.write(K.eth(MAC_GW, MAC_SV, payload=K.ipv4(20, 6, "10.0.0.77", SV, ttl=64,
            payload=K.tcp(50199, 80, 1000, 0, K.SYN, window=65535))), silent)
    w.write(K.eth(MAC_SV, MAC_GW, payload=K.ipv4(20, 6, SV, "10.0.0.77", ttl=64,
            payload=K.tcp(80, 50199, 7000, 1001, K.SYN | K.ACK, window=28960))), silent + 0.011)
    w.write(K.eth(MAC_GW, MAC_SV, payload=K.ipv4(20, 6, "10.0.0.77", SV, ttl=64,
            payload=K.tcp(50199, 80, 1001, 7001, K.ACK))), silent + 1300.0)

    # (e) a beacon: ten check-ins nominally 60 s apart with +-9 s jitter, fresh socket each
    #     time, tiny payloads. This is the shape `beacon_periodicity` exists to find - an
    #     operator can randomise *when* they call home, far fewer of them randomise the fact
    #     that the gaps have a period.
    jit = [0, 7, -5, 3, -8, 6, -4, 9, -6]
    beacon_req = b"\x17\x03\x03\x00\x20" + bytes(range(32))
    beacon_resp = b"\x17\x03\x03\x00\x08" + b"\x00" * 8
    for i in range(10):
        bt = t + 500.0 + i * 60.0 + (sum(jit[:i]) if i else 0.0)
        session(w, bt, "10.0.0.88", 52100 + i, "203.0.113.9", 443, beacon_req, beacon_resp,
                ttl_c=64, fin=False)
    # (f) one session id, two devices - the cookie was cloned and replayed 60 s later from a
    #     box with a different client profile. Nothing about either request is malformed.
    for ip, sport, ua in (("10.0.0.31", 53100, "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X)"),
                          ("198.51.100.77", 53101, "curl/8.4.0")):
        session(w, t + 700.0 + (sport - 53100) * 60.0, ip, sport, SV, 80,
                http_get("/account/orders?sid=S777", ua=ua), resp(200, "OK", b"<html>orders</html>"),
                write_log={"ip": ip, "user": "ada@shop.test", "method": "GET",
                           "path": "/account/orders?sid=S777", "status": 200, "ua": ua, "size": 210})

    # --- ARP + ICMP noise (written before close, so they are really in the file) ---
    arp = K.eth(MAC_GW, b"\xff" * 6, 0x0806, payload=K.arp(MAC_GW, GW, b"\xff" * 6, "10.0.0.30"))
    for i in range(3):
        w.write(arp, T0 + 12 * i, 400_000)
    icmp = K.eth(MAC_SV, MAC_GW, payload=K.ipv4(28, 1, SV, "203.0.113.7", ttl=64,
                payload=struct.pack("!BBH", 3, 3, 0) + K.ipv4(20, 6, "203.0.113.7", SV, ttl=64,
                        payload=K.tcp(51020, 9999, 0, 0, K.ACK))[:28]))
    w.write(icmp, T0 + 3.2)

    # --- truncation demo: same flow, but captured with snaplen 96 -----------
    tw.write(K.eth(MAC_GW, MAC_SV, payload=K.ipv4(1400, 6, "102.89.33.4", SV, ttl=64,
             payload=K.tcp(49600, 80, 1000, 5001, K.PSH | K.ACK, payload=http_get("/api/big")))), t, wire_len=1514)
    tw.write(K.eth(MAC_SV, MAC_GW, payload=K.ipv4(1400, 6, SV, "102.89.33.4", ttl=64,
             payload=K.tcp(80, 49600, 5001, 1120, K.PSH | K.ACK, payload=resp(200, "OK", b"y" * 1300)))), t + 0.02, wire_len=1514)
    w.close()          # flush before anything re-reads the file - a key computed from a
    tw.close()         # half-written pcap would "verify" the wrong numbers

    log_path = os.path.join(data, "lab_capture_access.log")
    with open(log_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(log_lines) + "\n")

    print(f"pcap     -> {pcap_path}")
    print(f"truncated-> {os.path.join(data,'lab_capture_truncated.pcap')}")
    print(f"accesslog-> {log_path} ({len(log_lines)} lines)")

    # re-read what we just wrote, so the answer key is verified, not assumed
    flows = K.flows(pcap_path)
    tf = K.flows(os.path.join(data, "lab_capture_truncated.pcap"))
    key = {
        "note": "generated from the same code path the analyst tools will read",
        "flows": len(flows),
        "truncation_demo": {k: {"incl": v["bytes"], "payload": v["payload"]} for k, v in tf.items()},
        "planted": {
            "port_sweep": {"src": "203.0.113.7", "dst": SV,
                           "ports": len({int(k.split("->")[1].rsplit(":", 1)[1]) for k in flows
                                        if k.startswith("203.0.113.7:") and "->10.0.0.20:" in k})},
            "ssh_bruteforce": {"src": "203.0.113.7", "dport": 22, "conns": sum(1 for k in flows if k.startswith("203.0.113.7:") and k.endswith("->10.0.0.20:22"))},
            "ato_via_proxy_bug": {"true_client": "198.51.100.23", "logged_as": "10.0.0.1",
                                  "xff_claim": "198.51.100.23, 8.8.8.8",
                                  "log_lines": sum(1 for l in log_lines if l.startswith("10.0.0.1"))},
            "exfil": {"out_bytes_planted": len(body)},
            "retrans_decoy": {"flow": f"102.89.33.4:49500->{SV}:8443", "retrans": 4},
            "stealth_shapes": {
                "low_and_slow_probe": {"src": "203.0.113.200", "ports": 12, "spacing_seconds": 150},
                "uniform_cadence": {"src": "10.0.0.99", "requests": 24, "gap_seconds": 2.0},
                "distributed_stuffing": {"account": "admin", "sources": 9, "tries_per_source": 2,
                                         "why_it_is_quiet": "2 failures per source is under every per-IP threshold"},
                "beacon": {"src": "10.0.0.88", "dst": "203.0.113.9", "dport": 443,
                           "planted_connections": 10, "nominal_period_seconds": 60,
                           "jitter_seconds": 9,
                           "connections_in_pcap": sum(1 for k in flows if k.startswith("10.0.0.88:"))},
                "session_split_brain": {"sid": "S777", "hits_planted": 2,
                                        "profiles": ["10.0.0.31 via iPhone Safari",
                                                     "198.51.100.77 via curl/8.4.0"]},
                "silent_http_flow": {"src": "10.0.0.77", "dport": 80, "open_seconds": 1300,
                                      "why_it_matters": "traffic without a log line is a finding by itself"},
            },
        },
        "read_first": "notes/07-detection.md",
    }
    with open(os.path.join(data, "lab_capture_key.json"), "w", encoding="utf-8") as fh:
        json.dump(key, fh, indent=2)
    print(json.dumps(key["planted"], indent=2))
    print(f"\nflow summary ({len(flows)} flows, pcap re-read by lab/pcap.py):")
    for k, f in sorted(flows.items(), key=lambda kv: -kv[1]["payload"])[:8]:
        print(f"  {k:<34} pkts={f['pkts']:<4} payload={f['payload']:<8} syn={f['syn']} rst={f['rst']} "
              f"retrans={f['retrans']} ttl={f['ttl']} dur={f['duration']}")


if __name__ == "__main__":
    try:                            # Windows console/encoding shim; no-op elsewhere
        import sys as _sys, os as _os
        _sys.path.insert(0, _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "..", "lab"))
        import win
        win.ready()
    except ImportError:
        pass
    main()
