#!/usr/bin/env python3
"""
The write-up. Attribution is worthless until it is a document someone else can
check, and a professional one always states the limits of its own evidence.

  python3 tools/casefile.py data/target_access.log --title "ATO on invoices API"
  python3 tools/casefile.py out/target_access_sim.log --title "XFF spoof on our own nginx" --no-net
"""
from __future__ import annotations

import argparse
import datetime as _dt
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from lab import logs as L  # noqa: E402
from lab import tracer as T  # noqa: E402
from lab.net import v6_subnet  # noqa: E402

DISCLAIMER = """\
> **Scope & limits of this document.** Produced from logs belonging to the writer's own
> service. Findings describe *networks*, not people. No attempt was made, and none is
> authorised by this document, to identify an individual from an address; that step belongs
> to law enforcement and the ISP's own process. Geolocation values are estimates (tens of
> km for broadband, region-wide for mobile, meaningless for datacenter/VPN/anycast ranges)
> and must not be presented as evidence of location."""

METHOD = """\
1. Parsed `%(src)s` with the lab parser (combined + `X-Forwarded-For` tail).
2. Grouped by source address, then by behaviour class (sweep / credential attack /
   authenticated session / background traffic).
3. Reconciled each address against `remote_addr` vs. forwarded-header claims
   (`lab/logs.real_ip`) - the only step most write-ups skip and the one that
   decides whether the whole timeline is trustworthy.
4. Enriched with public registry data (RDAP), reverse DNS, and geolocation.
5. Scored traceability, i.e. how far this address can lawfully be taken.
"""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("logfile", nargs="?", default=os.path.join(ROOT, "data", "target_access.log"))
    ap.add_argument("--title", default="IP attribution case file")
    ap.add_argument("--no-net", action="store_true")
    ap.add_argument("--min-hits", type=int, default=2)
    ap.add_argument("--out", default=os.path.join(ROOT, "out"))
    a = ap.parse_args()
    path = a.logfile if os.path.isabs(a.logfile) else os.path.join(ROOT, a.logfile)
    entries = L.parse_file(path)
    summary = L.summarise(entries)

    n4 = sum(1 for e in entries if ":" not in e["ip"])
    n6 = len(entries) - n4
    times = [e["dt"] for e in entries if e.get("dt")]
    span = f"{min(times):%Y-%m-%d %H:%M} -> {max(times):%Y-%m-%d %H:%M} UTC" if times else "n/a"
    xff_lines = [e for e in entries if e["xff_list"]]

    md: list[str] = [f"# {a.title}", f"_generated {now()}_\n", DISCLAIMER, "\n## 1. Source material",
                     f"- file: `{os.path.relpath(path, ROOT)}`",
                     f"- lines: {len(entries)} (IPv4 {n4} / IPv6 {n6}), malformed {sum(1 for e in entries if e.get('malformed'))}",
                     f"- time window: {span}",
                     f"- distinct source addresses: {len(summary)}",
                     f"- lines carrying `X-Forwarded-For`: {len(xff_lines)} (all of them client-supplied: this app has no trusted proxy configured)",
                     "\n## 2. Method", METHOD % {"src": os.path.relpath(path, ROOT)},
                     "\n## 3. Findings by address\n",
                     "| address | hits | window | classes | behaviour | traceability |",
                     "|---|---|---|---|---|---|"]

    ranked = sorted(((ip, p) for ip, p in summary.items() if p["n"] >= a.min_hits or p["interesting"]),
                    key=lambda kv: -kv[1]["n"])
    for ip, p in ranked:
        cls = " ".join(f"{k}:{v}" for k, v in p["status_classes"].items())
        beh = ", ".join(p["interesting"]) or "benign/normal"
        tr = "n/a (offline)"
        if not a.no_net and ":" not in ip:
            tr = f"{T.traceability(ip, log_lines=p['n'])['traceability_score']}/100"
        elif ":" in ip:
            tr = f"{T.traceability(ip, log_lines=p['n'])['traceability_score']}/100 (v6)"
        window = f"{(p['first'] or '')[11:16]}-{(p['last'] or '')[11:16]}"
        md.append(f"| `{ip}` | {p['n']} | {window} | {cls} | {beh} | {tr} |")

    md.append("\n## 4. Detail on the notable ones\n")
    for ip, p in ranked[:4]:
        md.append(f"### `{ip}` - {p['n']} requests")
        md.append(f"- paths: {', '.join(f'`{x}`({c})' for x, c in p['top_paths'][:6])}")
        md.append(f"- user agents: {'; '.join(p['uas'])[:180] or '-'}")
        if p["users"]:
            md.append(f"- accounts touched: {', '.join(p['users'])}")
        if p["xff_chains"]:
            md.append(f"- forwarded chains seen: {' | '.join(p['xff_chains'])}")
        if not a.no_net and ":" not in ip:
            d = T.dossier(ip, log_lines=p["n"])
            g, r, rd = d["geo"], d["rdap"], d["rdns"]
            md.append(f"- ownership: {r.get('network_name') or '?'} ({r.get('cidr') or '?'}) country={r.get('country') or '?'} abuse={r.get('abuse_email') or 'none listed'}")
            md.append(f"- estimated geo: {g.get('city')}/{g.get('region')}/{g.get('country')} org={g.get('org') or '?'} - *estimate, see disclaimer*")
            md.append(f"- PTR: {', '.join(rd.get('ptr') or []) or 'none'} {('; hints: ' + ', '.join(rd.get('hints') or [])) if rd.get('hints') else ''}")
            md.append(f"- **ceiling**: {d['traceability']['ceiling']}")
            for nline in d["traceability"]["notes"]:
                md.append(f"  - {nline}")
        else:
            v6 = v6_subnet(ip)
            md.append(f"- IPv6: the log retains the full host address; your *retention policy* is what decides whether {v6} is even meaningful. A /64 is a building, not a person.")
        md.append("")

    md += ["\n## 5. Recommendations (defensive - this is the part that actually reduces incidents)",
           "1. Log `remote_addr` unconditionally; store forwarded headers as a *separate* field so a future analyst can tell the two apart.",
           "2. Configure the trusted-proxy list explicitly (nginx `real_ip_trusted_addresses` / `set_real_ip_from`); never `trust proxy = true` blindly.",
           "3. Strip inbound `X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP` at the edge unless the hop is verified; add `True-Client-IP` only if you run the signing CDN.",
           "4. Remove response-header disclosures (`Server`, `X-Powered-By`, `X-Backend-IP`, `/debug/*`) from every public vhost.",
           "5. Decide your log retention now: 90+ days full fidelity on auth events, and *do not* truncate IPv6 host bits if you want to attribute anything later.",
           "6. Put abuse@ + a documented reporting path on your site; most 'attacks' are resolved with one abuse email to the right network.",
           "\n## 6. Reproduce this file",
           "```bash",
           f"python3 tools/dossier.py {os.path.relpath(path, ROOT)} --xff --only-sus",
           f"python3 tools/casefile.py {os.path.relpath(path, ROOT)} --title \"{a.title}\"",
           "```", ""]

    os.makedirs(a.out, exist_ok=True)
    dest = os.path.join(a.out, os.path.basename(path).replace(".log", "") + "_case.md")
    with open(dest, "w", encoding="utf-8") as fh:
        fh.write("\n".join(md))
    print(f"wrote {dest} ({len(md)} blocks, {len(' '.join(md))} chars)")
    print("\n".join(md[:18]))
    return 0


def now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


if __name__ == "__main__":
    try:                            # Windows console/encoding shim; no-op elsewhere
        import sys as _sys, os as _os
        _sys.path.insert(0, _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "..", "lab"))
        import win
        win.ready()
    except ImportError:
        pass
    raise SystemExit(main())
