#!/usr/bin/env python3
"""
Module 3 CLI: infrastructure fingerprinting for a target you own.

  python3 tools/passive.py --domain app.aeonlabs.test
  python3 tools/passive.py --url https://app.aeonlabs.test/login
  python3 tools/passive.py --domain lab.local --common-subdomains
  python3 tools/passive.py --ip 10.0.0.7 --internal        # no network calls, just classification

Everything is read-only and passive-by-design: DNS, TLS handshake, and the
response headers of a normal GET. No ports are scanned, no paths are fuzzed.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from lab import passive as P  # noqa: E402
from lab import tracer as T  # noqa: E402
from lab.net import human_table, ip_kind  # noqa: E402

COMMON = ["www", "api", "admin", "dashboard", "staging", "dev", "test", "git",
          "jenkins", "grafana", "kibana", "internal", "origin", "direct", "mail", "smtp"]


def main() -> int:
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--domain")
    g.add_argument("--url")
    g.add_argument("--ip")
    ap.add_argument("--internal", action="store_true", help="offline mode: no lookups, classification only")
    ap.add_argument("--common-subdomains", action="store_true")
    ap.add_argument("--out", default=os.path.join(ROOT, "out"))
    a = ap.parse_args()

    if a.ip:
        print(f"{a.ip}: {ip_kind(a.ip)}")
        if a.internal or ip_kind(a.ip) != "ipv4-public":
            print("  stops at the NAT. Traceable only with your own DHCP/firewall logs, and only with authority.")
            return 0
        print(json.dumps(T.dossier(a.ip), indent=2))
        return 0

    blob = {}
    if a.domain:
        dns = P.resolve(a.domain)
        print(f"== DNS for {a.domain} ==")
        rows = [[k, ", ".join(v)[:78]] for k, v in dns.items()]
        print(human_table(rows, ["type", "answers"]) if rows else "  (nothing resolved)")
        blob["dns"] = dns
        print("\n== who answers for this IP (TLS SNI + edge ASN) ==")
        f = P.front_of(a.domain)
        for k in ("addresses", "edge_org", "edge_loc", "sni_cert", "default_cert", "default_verdict", "verdict"):
            if f.get(k):
                print(f"  {k}: {json.dumps(f[k]) if not isinstance(f[k], str) else f[k]}")
        blob["front"] = f
        if a.common_subdomains:
            print("\n== same-zone names that resolve (no scanning, just A lookups) ==")
            hits = []
            for sub in COMMON:
                r = P.resolve(f"{sub}.{a.domain}", ("A", "AAAA"))
                addrs = r.get("A", [])
                if addrs and addrs != ["NXDOMAIN"]:
                    hits.append([f"{sub}.{a.domain}", ", ".join(addrs)[:40]])
            print(human_table(hits, ["name", "addresses"]) if hits else "  none resolved")
            blob["subdomains"] = hits
    if a.url:
        print(f"\n== response headers / leak check for {a.url} ==")
        h = P.headers(a.url)
        for k in ("status", "cert_subject", "cert_issuer", "cert_notafter"):
            if h.get(k):
                print(f"  {k}: {h[k]}")
        if h.get("leaks"):
            print("  LEAKS:")
            for leak in h["leaks"]:
                print(f"    ! {leak['header']}: {leak['value']}\n      ({leak['why']})")
            blob["leaks"] = h["leaks"]
        else:
            print("  no known-disclosure headers found (that is the goal)")
        if h.get("notes"):
            print("  notes:")
            for n in h["notes"]:
                print(f"    - {n}")
        blob["headers"] = h

    os.makedirs(a.out, exist_ok=True)
    dest = os.path.join(a.out, "passive_report.json")
    with open(dest, "w", encoding="utf-8") as fh:
        json.dump(blob, fh, indent=2, default=str)
    print(f"\nfull report -> {dest}")
    print("reminder: run this against things you own. For public sites, their")
    print("bug-bounty/robots policy decides; passive DNS reading is fine, hammering is not.")
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
