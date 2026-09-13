#!/usr/bin/env python3
"""
Generate a synthetic-but-realistic incident dataset for the ip-lab.

Everything here is FICTIONAL: the "victim" app, the accounts, and the IP/UA
combinations are invented. Some public IP blocks are real allocations (that is
what makes RDAP/geo lookups worth practising), but nothing in this lab targets
or describes a real person, account or network intrusion.

Run:  python3 tools/gen_dataset.py
"""
from __future__ import annotations

import json
import os
import random
from datetime import datetime, timedelta

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")

# Log format we write (combined + XFF so the parser has something to chew on):
#   IP - - [time] "METHOD path HTTP/1.1" status bytes "referer" "ua" "xff"
LINE = '{ip} - {user} [{ts}] "{method} {path} HTTP/1.1" {status} {size} "{ref}" "{ua}" "{xff}"'

WIN = random.Random(1337)

WALLACE = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
IPHONE = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1"
CURL = "curl/8.5.0"
PY = "python-requests/2.31.0"
NMAP = "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"
FF = "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0"


def ts(dt: datetime) -> str:
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0000")


def write_log(path: str, rows: list[dict]) -> None:
    rows = sorted(rows, key=lambda r: r["_dt"])
    with open(path, "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(LINE.format(
                ip=r["ip"], user=r.get("user", "-"), ts=ts(r["_dt"]),
                method=r.get("method", "GET"), path=r["path"],
                status=r["status"], size=r.get("size", WIN.randint(200, 9000)),
                ref=r.get("ref", "-"), ua=r["ua"], xff=r.get("xff", "-"),
            ) + "\n")
        fh.write("\n")


def main() -> None:
    os.makedirs(DATA, exist_ok=True)
    t0 = datetime(2026, 9, 11, 0, 0, 0)
    rows: list[dict] = []
    key: dict[str, dict] = {}

    def add(mins: float, **kw) -> None:
        d = t0 + timedelta(minutes=mins)
        kw["_dt"] = d
        rows.append(kw)

    # ---- background noise: normal users of the SaaS dashboard -------------
    for m in range(0, 1440, 9):
        add(m + WIN.random() * 6, ip="102.89.34.17", path="/api/dashboard", status=200, ua=WIN.choice([WALLACE, IPHONE, FF]))
        add(m + WIN.random() * 6, ip="197.210.58.9", path="/api/invoices", status=200, ua=WIN.choice([WALLACE, IPHONE, FF]))
        add(m + WIN.random() * 6, ip="41.203.83.12", path="/login", status=200, ua=WIN.choice([WALLACE, IPHONE, FF]))
        add(m + WIN.random() * 6, ip="154.160.32.5", path="/static/app.css", status=200, ua=WALLACE, ref="/dashboard")

    # ---- CASE 1  anonymous scanner, spoofed XFF, exits a commercial VPN --
    # "logs in" nothing; just maps the app. IP is a real hosting block.
    k1 = {
        "title": "Recon sweep from a rented VPS, XFF spoofed",
        "answer_ip": "45.148.10.66",
        "verdict": "Automated enumeration from a datacenter, not a person.",
        "lesson": [
            "remote_addr (the TCP peer) is the only field the client cannot fake.",
            "X-Forwarded-For: 127.0.0.1,8.8.8.8 is the attacker inventing values. A trusted proxy APPENDS the peer IP on the right.",
            "Geo says Frankfurt because that is where the rented box lives, not where the human lives.",
            "RDAP name field says 'limited privacy issue' -> the RIPE abuse contact exists but is only for the network operator.",
        ],
    }
    for i in range(38):
        add(WIN.uniform(260, 330), ip="45.148.10.66", path=WIN.choice(
            ["/", "/admin", "/.env", "/wp-login.php", "/phpmyadmin/", "/.git/config",
             "/api/v1/users", "/api/v1/debug", "/xmlrpc.php", "/config.php", "/server-status"]),
            status=WIN.choice([404] * 6 + [403, 401, 200]), ua=WIN.choice([CURL, PY, NMAP]),
            xff="127.0.0.1, 8.8.8.8")

    # ---- CASE 2  home-router NAT, real success, ISP is the only road further
    k2 = {
        "title": "Account takeover from a residential connection",
        "answer_ip": "177.154.220.44",
        "verdict": "Subscriber-level attribution requires the ISP, i.e. law enforcement or the ISP's own abuse desk.",
        "lesson": [
            "No XFF at all -> remote_addr IS the client (direct connection, no proxy).",
            "Reverse DNS for BR154 is a real, documented pattern: ISPs encode the customer IP in the PTR name.",
            "Geo city is ~10-50 km accurate on broadband and is NOT evidence. It is an investigative lead only.",
            "You can go from IP -> ISP abuse contact. You cannot go IP -> human. That jump needs a legal process.",
        ],
    }
    for i in range(9):
        add(WIN.uniform(700, 712), ip="177.154.220.44", path="/login", status=401, ua=WALLACE, user="-")
    add(713, ip="177.154.220.44", path="/login", status=302, user="adeola.o", ua=WALLACE, size=210, ref="/login")
    for i, p in enumerate(["/api/account/reset-init", "/api/profile/email", "/api/profile/email", "/api/billing/invoices/export"]):
        add(714 + i * 3, ip="177.154.220.44", path=p, status=200, user="adeola.o", ua=WALLACE)

    # ---- CASE 3  the leak: a debug header exposes an internal address -----
    k3 = {
        "title": "Leaked headers + an authorized bug-bounty probe that looks like an attack",
        "answer_ip": "102.89.44.7",
        "verdict": "Two different things: your OWN config leaked X-Backend-IP/Server, and the 'attack' traffic is an authorized tester with a signed scope header.",
        "lesson": [
            "Response headers are an attribution gift to whoever is looking: X-Backend-IP, X-Powered-By, Server, X-Debug-Trace.",
            "A legit tester can look exactly like an attacker. Program context (HackerOne request headers, X-Request-Context, valid session) is what separates them.",
            "X-Request-Context: safe@aeonlabs is what your WAF tag looks like from the inside. Do not assume 'odd header = bad guy'.",
        ],
    }
    add(900, ip="102.89.44.7", path="/robots.txt", status=200, ua=FF, ref="-")
    add(901, ip="102.89.44.7", path="/.env", status=404, ua=FF)
    add(902, ip="102.89.44.7", path="/api/v1/report", status=500, ua=FF, size=14120)
    add(903, ip="102.89.44.7", path="/api/v1/report?debug=1", status=200, ua=FF, size=61233)
    add(904, ip="102.89.44.7", path="/debug/vars", status=200, ua=FF, size=42010)

    # ---- CASE 4  IPv6, retention policy destroyed the attribution ---------
    k4 = {
        "title": "Credential stuffing from a dual-stack campus network",
        "answer_ip": "2001:4488:1060:1c4a:21e:10ff:fe9c:1a2b",
        "verdict": "You can prove a /64 subnet did it. The individual host is gone because logs stored only 4 segments.",
        "lesson": [
            "IPv6: the last 64 bits are usually the interface id; SLAAC randomisation makes even that unreliable.",
            "A /64 to a university network is one building, possibly thousands of machines.",
            "Retention policy IS an investigation policy. Truncated IPv6 + no request IDs = case closed before it opened.",
            "Activity windows (04:00-07:00 local in the victim's timezone, plus a sleep gap) can hint at where the human sleeps. It is a probabilistic tell, not proof.",
        ],
    }
    for m in range(230, 340, 4):
        add(m, ip="2001:4488:1060:1c4a:%x:%x:fe9c:1a2b" % (WIN.randrange(1, 65535), WIN.randrange(1, 65535)),
            path="/login", status=401, ua=PY, size=612, xff="-")
    for m in range(230, 340, 26):
        add(m + 1, ip="2001:4488:1060:1c4a:21e:10ff:fe9c:1a2b", path="/login", status=429, ua=PY)

    # ---- CASE 5  false positive: Tor exit hitting a public webhook --------
    k5 = {
        "title": "The 'hacker' who was just a customer behind Tor",
        "answer_ip": "185.220.101.34",
        "verdict": "Tor exit node, yes. Attack, no. 6 requests to a public webhook, all 200.",
        "lesson": [
            "Tor exit IPs are famous: dnsbl-style listings + geo 'unknown' + a hostname ending in .exit.",
            "Presence on a privacy network is not an attack. Volume, path, and outcome decide.",
            "Blocking Tor may block the journalist, the activist, and the person whose ISP is garbage. Rate-limit, do not ban reflexively.",
        ],
    }
    for m in range(1200, 1206):
        add(m, ip="185.220.101.34", path="/api/webhooks/incoming", status=200, ua=WALLACE, ref="https://app.customer.example/")

    key["case1_recon_vpn"] = k1
    key["case2_home_router_ato"] = k2
    key["case3_leaky_headers"] = k3
    key["case4_ipv6_truncated"] = k4
    key["case5_tor_false_positive"] = k5

    write_log(os.path.join(DATA, "target_access.log"), rows)

    # ---- canary beacon log: who opened a link you (legally) control -------
    t1 = datetime(2026, 9, 12, 8, 0, 0)
    crow: list[dict] = []

    def addc(mins: float, **kw) -> None:
        d = t1 + timedelta(minutes=mins)
        kw["_dt"] = d
        kw.setdefault("ua", WALLACE)
        kw.setdefault("path", "/c/tok_9f3a1c")
        kw.setdefault("status", 302)
        crow.append(kw)

    # consented test (self + colleague on the lab VLAN)
    addc(0, ip="127.0.0.1", ua=WALLACE, ref="https://mail.aeonlabs.test/")
    addc(4, ip="10.10.4.21", ua=IPHONE, ref="https://mail.aeonlabs.test/")
    addc(4, ip="10.10.4.21", ua=IPHONE, path="/c/tok_9f3a1c/open.png", status=200)
    # a stranger clicks a link you posted publicly (issue tracker) -> capture
    addc(91, ip="45.148.10.66", ua=PY, ref="https://github.com/aeonlabs/security/issues/12")
    addc(91, ip="45.148.10.66", ua=PY, path="/c/tok_9f3a1c/open.png", status=200)
    addc(140, ip="102.69.187.2", ua=IPHONE, ref="https://t.co/xyz")
    addc(140, ip="102.69.187.2", ua=IPHONE, path="/c/tok_9f3a1c/open.png", status=200)
    write_log(os.path.join(DATA, "canary.log"), crow)
    key["canary"] = {
        "title": "Link canary hits",
        "answer_ip": "127.0.0.1, 10.10.4.21, 45.148.10.66, 102.69.187.2",
        "verdict": "Two consented testers, one scanner bot, one unknown mobile user.",
        "lesson": [
            "A canary tells you WHO-OPENED-WHAT-WHEN from the receiver side. It is a consent-boundary instrument: it is fine on your own issue tracker or your own doc, and it is a crime-adjacent tool the moment you target a specific person with it.",
            "10.10.4.21 is a private RFC1918 address -> it only means 'someone inside your network'; NAT means you cannot map it to a person without your own DHCP logs, and touching those needs authority + policy.",
            "open.png with status 200 = the click was confirmed by an image fetch (a plain redirect can be pre-fetched by link scanners and gives false positives).",
        ],
    }

    with open(os.path.join(DATA, "key.json"), "w", encoding="utf-8") as fh:
        json.dump(key, fh, indent=2)

    print(f"wrote {os.path.join(DATA,'target_access.log')} ({len(rows)} lines)")
    print(f"wrote {os.path.join(DATA,'canary.log')} ({len(crow)} lines)")
    print(f"wrote {os.path.join(DATA,'key.json')} ({len(key)} cases)")


if __name__ == "__main__":
    try:                            # Windows console/encoding shim; no-op elsewhere
        import sys as _sys, os as _os
        _sys.path.insert(0, _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "..", "lab"))
        import win
        win.ready()
    except ImportError:
        pass
    main()
